package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	metafake "k8s.io/client-go/metadata/fake"
)

func owner(kind, name string) []metav1.OwnerReference {
	t := true
	return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &t}}
}

func res(cpuReq, memReq, cpuLim, memLim string) corev1.ResourceRequirements {
	r := corev1.ResourceRequirements{Requests: corev1.ResourceList{}, Limits: corev1.ResourceList{}}
	if cpuReq != "" {
		r.Requests[corev1.ResourceCPU] = resource.MustParse(cpuReq)
	}
	if memReq != "" {
		r.Requests[corev1.ResourceMemory] = resource.MustParse(memReq)
	}
	if cpuLim != "" {
		r.Limits[corev1.ResourceCPU] = resource.MustParse(cpuLim)
	}
	if memLim != "" {
		r.Limits[corev1.ResourceMemory] = resource.MustParse(memLim)
	}
	return r
}

func mkPod(ns, name, node string, phase corev1.PodPhase, owners []metav1.OwnerReference, r corev1.ResourceRequirements, created time.Time) *corev1.Pod {
	ready := corev1.ConditionFalse
	state := corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
	if phase == corev1.PodRunning {
		ready = corev1.ConditionTrue
	}
	if phase == corev1.PodSucceeded {
		state = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed"}}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + ns + "-" + name),
			OwnerReferences: owners, CreationTimestamp: metav1.NewTime(created)},
		Spec: corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "app", Resources: r}}},
		Status: corev1.PodStatus{Phase: phase,
			Conditions:        []corev1.PodCondition{{Type: corev1.PodReady, Status: ready}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "app", State: state, Ready: ready == corev1.ConditionTrue}}},
	}
}

func mkNode(name string) *corev1.Node {
	rl := corev1.ResourceList{
		corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("16Gi"),
		corev1.ResourceEphemeralStorage: resource.MustParse("100Gi"), corev1.ResourcePods: resource.MustParse("110"),
	}
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{Capacity: rl, Allocatable: rl,
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
}

func partial(apiVersion, kind, ns, name string, owners []metav1.OwnerReference) runtime.Object {
	return &metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: apiVersion, Kind: kind},
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, OwnerReferences: owners}}
}

// testMetadata: os donos que o agente consulta só pelos metadados (ReplicaSet, Job e CronJob).
func testMetadata() []runtime.Object {
	return []runtime.Object{
		partial("apps/v1", "ReplicaSet", "prod", "api-7d9f", owner("Deployment", "api")),
		partial("batch/v1", "CronJob", "prod", "report", nil),
		partial("batch/v1", "Job", "prod", "report-29001", owner("CronJob", "report")),
	}
}

// testCluster: Deployment api (2 pods), CronJob report (Job atual e um Job já removido), StatefulSet db em
// CrashLoopBackOff, um DaemonSet e um pod estático no kube-system.
func testCluster(created time.Time) []runtime.Object {
	db := mkPod("prod", "db-0", "node-b", corev1.PodRunning, owner("StatefulSet", "db"), res("500m", "1Gi", "", "2Gi"), created)
	db.Status.Conditions[0].Status = corev1.ConditionFalse
	db.Status.ContainerStatuses[0] = corev1.ContainerStatus{Name: "app", RestartCount: 5,
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}

	api1 := mkPod("prod", "api-7d9f-x1", "node-a", corev1.PodRunning, owner("ReplicaSet", "api-7d9f"), res("250m", "256Mi", "500m", "512Mi"), created)
	api2 := mkPod("prod", "api-7d9f-x2", "node-b", corev1.PodRunning, owner("ReplicaSet", "api-7d9f"), res("250m", "256Mi", "500m", "512Mi"), created)
	api1.Labels = map[string]string{"pod-template-hash": "7d9f"}
	api2.Labels = map[string]string{"pod-template-hash": "7d9f"}

	return []runtime.Object{
		mkNode("node-a"), mkNode("node-b"),
		api1, api2, db,
		mkPod("prod", "report-29001-abc", "node-a", corev1.PodSucceeded, owner("Job", "report-29001"), res("100m", "128Mi", "", ""), created),
		mkPod("prod", "report-28999-old", "node-a", corev1.PodSucceeded, owner("Job", "report-28999"), res("100m", "128Mi", "", ""), created),
		mkPod("kube-system", "fluentd-abc", "node-a", corev1.PodRunning, owner("DaemonSet", "fluentd"), res("100m", "200Mi", "", "500Mi"), created),
		mkPod("kube-system", "etcd-node-a", "node-a", corev1.PodRunning, owner("Node", "node-a"), res("100m", "100Mi", "", ""), created),
	}
}

// fakeSummary gera o JSON do summary do kubelet com um uso que varia com o tempo.
func fakeSummary(c *Collector, node string, now time.Time) []byte {
	wave := (math.Sin(float64(now.Unix())/900) + 1) / 2 // 0..1, período de ~1h30
	type stat = map[string]any
	var pods []stat
	var nodeCPU, nodeMem uint64
	all, _ := c.pods.List(labels.Everything())
	for i, p := range all {
		if p.Spec.NodeName != node || p.Status.Phase != corev1.PodRunning {
			continue
		}
		cpu := uint64((50 + 400*wave + float64(i*20)) * 1e6)
		mem := uint64((150 + 300*wave + float64(i*10)) * 1024 * 1024)
		nodeCPU += cpu
		nodeMem += mem
		pods = append(pods, stat{"podRef": stat{"uid": string(p.UID)}, "cpu": stat{"usageNanoCores": cpu},
			"memory": stat{"workingSetBytes": mem}, "ephemeral-storage": stat{"usedBytes": 20 * 1024 * 1024}})
	}
	raw, _ := json.Marshal(stat{
		"node": stat{"cpu": stat{"usageNanoCores": nodeCPU + 300e6}, "memory": stat{"workingSetBytes": nodeMem + 2<<30},
			"fs": stat{"capacityBytes": uint64(100 << 30), "usedBytes": uint64(35<<30) + uint64(wave*5*(1<<30))}},
		"pods": pods,
	})
	return raw
}

func newTestCollector(t *testing.T, cfg *Config, creds *Credentials, created time.Time, extra ...runtime.Object) (*Collector, *Store, *time.Time) {
	store := openTestStore(t, cfg, creds)
	cs := fake.NewClientset(append(testCluster(created), extra...)...)
	scheme := metafake.NewTestScheme()
	metav1.AddMetaToScheme(scheme)
	mc := metafake.NewSimpleMetadataClient(scheme, testMetadata()...)
	col := NewCollector(cfg, cs, mc, store)
	now := created
	col.now = func() time.Time { return now }
	col.fetchSummary = func(_ context.Context, node string) ([]byte, error) { return fakeSummary(col, node, now), nil }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := col.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return col, store, &now
}

func TestWorkloadResolution(t *testing.T) {
	cfg, creds := testConfig(t)
	col, _, _ := newTestCollector(t, cfg, creds, time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
	cases := map[string][2]string{
		"api-7d9f-x1":      {"Deployment", "api"},
		"report-29001-abc": {"CronJob", "report"},
		"report-28999-old": {"CronJob", "report"}, // Job já removido
		"db-0":             {"StatefulSet", "db"},
	}
	for name, want := range cases {
		p, err := col.pods.Pods("prod").Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if k, n := col.workloadOf(p); k != want[0] || n != want[1] {
			t.Errorf("%s: %s/%s, esperado %s/%s", name, k, n, want[0], want[1])
		}
	}
	etcd, _ := col.pods.Pods("kube-system").Get("etcd-node-a")
	if k, n := col.workloadOf(etcd); k != "StaticPod" || n != "etcd" {
		t.Errorf("etcd-node-a: %s/%s, esperado StaticPod/etcd", k, n)
	}
	db, _ := col.pods.Pods("prod").Get("db-0")
	if ready, restarts, reason, _ := podStatus(db); ready || restarts != 5 || reason != "CrashLoopBackOff" {
		t.Errorf("status do db-0: ready=%v restarts=%d reason=%q", ready, restarts, reason)
	}
}

func TestSample(t *testing.T) {
	ctx := context.Background()
	cfg, creds := testConfig(t)
	start := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	col, store, now := newTestCollector(t, cfg, creds, start)
	for i := 0; i < 3; i++ {
		*now = start.Add(time.Duration(i) * time.Minute)
		if err := col.Sample(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// 5 pods ativos x 3 coletas + 2 pods encerrados uma vez só
	samples, _ := readTable[PodSampleRow](t, store, "pod_samples")
	if len(samples) != 17 {
		t.Errorf("pod_samples: %d, esperado 17", len(samples))
	}
	if rows, _ := readTable[WorkloadRow](t, store, "workloads"); len(rows) != 5 {
		t.Errorf("workloads: %d, esperado 5 (api, report, db, fluentd, etcd)", len(rows))
	}
	if rows, _ := readTable[PodRow](t, store, "pods"); len(rows) != 7 {
		t.Errorf("pods: %d, esperado 7", len(rows))
	}
	if rows, _ := readTable[ClusterRow](t, store, "clusters"); len(rows) != 1 || rows[0].Name != cfg.ClusterName {
		t.Errorf("clusters: %+v", rows)
	}
	// requests do node-a: api-x1 250m + fluentd 100m + etcd 100m (pods encerrados não reservam recurso)
	nodes, _ := readTable[NodeSampleRow](t, store, "node_samples")
	nodeA := nodeID(cfg.ClusterName, "node-a")
	for _, n := range nodes {
		if n.NodeID == nodeA && n.CPURequestM != 450 {
			t.Errorf("cpu requested do node-a: %v, esperado 450", n.CPURequestM)
		}
	}
	apiX1 := podID(cfg.ClusterName, "uid-prod-api-7d9f-x1")
	for _, p := range samples {
		if p.PodID == apiX1 && (p.CPUPctRequest == nil || *p.CPUPctRequest <= 0 || p.WorkloadID == nil) {
			t.Errorf("api-x1 sem percentual de CPU do request ou sem workload: %+v", p)
		}
	}

	// No dia seguinte as dimensões são gravadas de novo (cada dia do storage é completo sozinho)
	*now = start.Add(24 * time.Hour)
	if err := col.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if rows, _ := readTable[PodRow](t, store, "pods"); len(rows) != 14 {
		t.Errorf("pods depois de um dia: %d, esperado 14", len(rows))
	}
}

// HPA do Deployment api (2 de 4 réplicas) e um pod Pending sem nó por falta de CPU
func TestHPAAndUnschedulable(t *testing.T) {
	ctx := context.Background()
	cfg, creds := testConfig(t)
	minR := int32(1)
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "api"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{MinReplicas: &minR, MaxReplicas: 4,
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Name: "api"}},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{CurrentReplicas: 2, DesiredReplicas: 3},
	}
	created := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	pending := mkPod("prod", "api-7d9f-x3", "", corev1.PodPending, owner("ReplicaSet", "api-7d9f"), res("250m", "256Mi", "500m", "512Mi"), created)
	pending.Labels = map[string]string{"pod-template-hash": "7d9f"}
	pending.Status.ContainerStatuses = nil
	pending.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse,
		Reason: "Unschedulable", Message: "0/2 nodes are available: 2 Insufficient cpu."}}
	col, store, _ := newTestCollector(t, cfg, creds, created, hpa, pending)
	if err := col.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	api := workloadID(cfg.ClusterName, "prod", "Deployment", "api")
	hpas, _ := readTable[HPASampleRow](t, store, "hpa_samples")
	if len(hpas) != 1 || hpas[0].WorkloadID != api || hpas[0].MaxReplicas != 4 || hpas[0].CurrentReplicas != 2 || hpas[0].DesiredReplicas != 3 {
		t.Errorf("hpa_samples: %+v", hpas)
	}
	samples, _ := readTable[PodSampleRow](t, store, "pod_samples")
	found := false
	for _, s := range samples {
		if s.PodID == podID(cfg.ClusterName, "uid-prod-api-7d9f-x3") {
			found = true
			if s.Reason == nil || *s.Reason != "Unschedulable" || s.Message == nil || !strings.Contains(*s.Message, "Insufficient cpu") ||
				s.WorkloadID == nil || *s.WorkloadID != api {
				t.Errorf("pod pendente: %+v", s)
			}
		}
	}
	if !found {
		t.Error("pod pendente não coletado")
	}
	// O cache do informer guarda a condição de agendamento (slimPod)
	p, _ := col.pods.Pods("prod").Get("api-7d9f-x3")
	if _, _, reason, msg := podStatus(p); reason != "Unschedulable" || msg == "" {
		t.Errorf("slimPod perdeu a condição PodScheduled: %q %q", reason, msg)
	}
}

func TestExcludeNamespaces(t *testing.T) {
	ctx := context.Background()
	cfg, creds := testConfig(t)
	cfg.ExcludeNS = csvSet(defaultExcludeNS)
	col, store, _ := newTestCollector(t, cfg, creds, time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
	if err := col.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// fluentd e etcd (kube-system) ficam de fora das telas
	if rows, _ := readTable[PodSampleRow](t, store, "pod_samples"); len(rows) != 5 {
		t.Errorf("pod_samples: %d, esperado 5", len(rows))
	}
	if rows, _ := readTable[NamespaceRow](t, store, "namespaces"); len(rows) != 1 || rows[0].Name != "prod" {
		t.Errorf("namespaces: %+v", rows)
	}
	// mas continuam no total do nó
	nodeA := nodeID(cfg.ClusterName, "node-a")
	nodes, _ := readTable[NodeSampleRow](t, store, "node_samples")
	for _, n := range nodes {
		if n.NodeID == nodeA && (n.CPURequestM != 450 || n.PodsCount != 3) {
			t.Errorf("node-a: cpu requested %v, pods %d; esperado 450 e 3", n.CPURequestM, n.PodsCount)
		}
	}
}

// Pods dos Jobs de varredura ficam fora da coleta (só os totais do nó)
func TestScanPodsIgnored(t *testing.T) {
	cfg, creds := testConfig(t)
	scan := mkPod("nanobot", "nanobot-scan-abc-x", "node-a", corev1.PodRunning, owner("Job", "nanobot-scan-abc"), res("50m", "128Mi", "", ""),
		time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
	scan.Labels = map[string]string{"app.kubernetes.io/name": scanLabelApp, "job-name": "nanobot-scan-abc"}
	col, store, _ := newTestCollector(t, cfg, creds, time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC), scan)
	if err := col.Sample(context.Background()); err != nil {
		t.Fatal(err)
	}
	cached, err := col.pods.Pods("nanobot").Get("nanobot-scan-abc-x")
	if err != nil || !isScanPod(cached) {
		t.Fatalf("label do Job de varredura no cache: %v %v", err, cached.Labels)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	pods, _ := readTable[PodRow](t, store, "pods")
	for _, p := range pods {
		if strings.HasPrefix(p.Name, "nanobot-scan-") {
			t.Fatal("pod do Job de varredura coletado")
		}
	}
}

func TestSlimPod(t *testing.T) {
	p := testCluster(time.Now())[2].(*corev1.Pod)
	p.Annotations = map[string]string{"big": strings.Repeat("x", 1000)}
	p.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kubectl"}}
	p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "A", Value: "1"}}
	s := slimPod(p)
	if s.Annotations != nil || s.ManagedFields != nil || s.Spec.Containers[0].Env != nil {
		t.Errorf("campos não usados continuam no cache: %+v", s)
	}
	if s.Labels["pod-template-hash"] != "7d9f" || s.Spec.Containers[0].Resources.Requests.Cpu().MilliValue() != 250 ||
		len(s.OwnerReferences) != 1 || s.Status.Conditions[0].Type != corev1.PodReady {
		t.Errorf("campos usados sumiram: %+v", s)
	}
}

// TestDemoData grava 6h de dados sintéticos para testar as telas do Nanobot (go test -run Demo).
// DEMO_OUT: storage (diretório ou s3://...); DEMO_CREDENTIALS: JSON com as credenciais (obrigatório num bucket);
// DEMO_CLUSTER: nome do cluster (padrão demo); DEMO_END: fim dos dados em RFC3339 (padrão agora).
func TestDemoData(t *testing.T) {
	out := os.Getenv("DEMO_OUT")
	if out == "" {
		t.Skip("DEMO_OUT não definido")
	}
	ctx := context.Background()
	cfg, _ := testConfig(t)
	cfg.StoragePath, cfg.ClusterName = strings.TrimRight(out, "/"), env("DEMO_CLUSTER", "demo")
	end := time.Now().UTC().Truncate(time.Minute)
	if v := os.Getenv("DEMO_END"); v != "" {
		var err error
		if end, err = time.Parse(time.RFC3339, v); err != nil {
			t.Fatal(err)
		}
	}
	start := end.Add(-6 * time.Hour)
	var creds *Credentials
	if f := os.Getenv("DEMO_CREDENTIALS"); f != "" {
		var err error
		if creds, err = LoadCredentials(f); err != nil {
			t.Fatal(err)
		}
	}
	col, store, now := newTestCollector(t, cfg, creds, start)
	msgs := []string{"GET /health 200 1ms", "POST /api/orders 201 35ms", "ERROR timeout calling payments", "WARN slow query 1200ms"}
	for ts := start; !ts.After(end); ts = ts.Add(time.Minute) {
		*now = ts
		if err := col.Sample(ctx); err != nil {
			t.Fatal(err)
		}
		pods, _ := col.pods.List(labels.Everything())
		for _, p := range pods {
			if p.Status.Phase != corev1.PodRunning {
				continue
			}
			ref := col.RegisterPod(p, ts)
			for i := 0; i < 3; i++ {
				store.T.Logs.Append(LogRow{TS: ts.Add(time.Duration(i*17) * time.Second), PodID: ref.id, WorkloadID: ref.workloadID,
					NamespaceID: ref.namespaceID, Container: "app", Message: fmt.Sprintf("%s %s", p.Name, msgs[(ts.Minute()+i)%len(msgs)])})
			}
		}
		if ts.Minute()%30 == 0 {
			if err := store.Flush(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 { // compacta as horas fechadas e apaga os arquivos substituídos
		if err := store.Maintain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("dados de demonstração em %s", cfg.ClusterPath())
}

// Mudança de estado de um pod avisa o loop principal; a coleta reativa traz o estado novo com o uso da coleta anterior
func TestReactiveSample(t *testing.T) {
	ctx := context.Background()
	cfg, creds := testConfig(t)
	start := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	col, store, now := newTestCollector(t, cfg, creds, start)
	if err := col.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-col.Changes():
		t.Fatal("a lista inicial não deveria avisar")
	default:
	}
	p, _ := col.cs.CoreV1().Pods("prod").Get(ctx, "api-7d9f-x1", metav1.GetOptions{})
	p.Status.Conditions[0].Status = corev1.ConditionFalse
	p.Status.ContainerStatuses[0].Ready = false
	p.Status.ContainerStatuses[0].RestartCount = 1
	p.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}
	if _, err := col.cs.CoreV1().Pods("prod").UpdateStatus(ctx, p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-col.Changes():
	case <-time.After(5 * time.Second):
		t.Fatal("mudança de estado do pod não avisou")
	}
	if err := col.SampleReactive(ctx); err != nil { // mesmo segundo da coleta completa: ignorada
		t.Fatal(err)
	}
	*now = start.Add(10 * time.Second)
	// o informer pode levar um instante para refletir o status novo no cache
	deadline := time.Now().Add(5 * time.Second)
	for {
		cached, _ := col.pods.Pods("prod").Get("api-7d9f-x1")
		if _, _, reason, _ := podStatus(cached); reason == "CrashLoopBackOff" || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := col.SampleReactive(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	samples, _ := readTable[PodSampleRow](t, store, "pod_samples")
	byTS := map[time.Time]int{}
	var reactive *PodSampleRow
	for i, s := range samples {
		byTS[s.TS]++
		if s.TS.Equal(start.Add(10*time.Second)) && s.PodID == podID(cfg.ClusterName, "uid-prod-api-7d9f-x1") {
			reactive = &samples[i]
		}
	}
	// 5 pods ativos + 2 encerrados na primeira; 5 ativos na reativa (encerrados entram uma vez só)
	if byTS[start] != 7 || byTS[start.Add(10*time.Second)] != 5 || len(byTS) != 2 {
		t.Errorf("coletas por horário: %v", byTS)
	}
	if reactive == nil || reactive.Ready || reactive.Reason == nil || *reactive.Reason != "CrashLoopBackOff" || reactive.CPUUsageM == nil {
		t.Errorf("coleta reativa do api-x1: %+v", reactive)
	}
}
