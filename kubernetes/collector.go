package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	autoscalinglisters "k8s.io/client-go/listers/autoscaling/v2"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/tools/cache"
)

// Collector lê o estado do cluster pelos informers e as métricas de uso pelo summary do kubelet
// (/api/v1/nodes/<nó>/proxy/stats/summary), sem depender do metrics-server.
//
// O cache dos informers é a maior parte da memória do agente: pods e nós ficam só com os campos usados (slimPod,
// slimNode) e ReplicaSets, Jobs e CronJobs só com os metadados (o dono é tudo o que importa deles).
type Collector struct {
	cfg     *Config
	cs      kubernetes.Interface
	store   *Store
	cluster int64

	factory   informers.SharedInformerFactory
	meta      metadatainformer.SharedInformerFactory
	pods      corelisters.PodLister
	nodes     corelisters.NodeLister
	rsets     cache.GenericLister
	jobs      cache.GenericLister
	cronjobs  cache.GenericLister
	hpas      autoscalinglisters.HorizontalPodAutoscalerLister // nil: sem permissão ou sem a API autoscaling/v2
	podInform cache.SharedIndexInformer

	now          func() time.Time
	fetchSummary func(ctx context.Context, node string) ([]byte, error)

	changes chan struct{} // mudanças de estado de pods/HPAs (coleta reativa); buffer 1: rajadas viram um aviso só

	mu            sync.Mutex
	lastSummaries map[string]*statsSummary // uso da última coleta completa (a reativa não consulta o kubelet)
	lastTS        time.Time                // horário da última coleta: duas no mesmo segundo somariam os pods em dobro
	version       string                   // versão do Kubernetes (dimensão do cluster)
	terminalSeen  map[string]bool          // pods encerrados já registrados uma vez (não repete a cada coleta)
	lastSampleOK  time.Time
}

type podRef struct {
	id, namespaceID int64
	workloadID      *int64 // nil: pod sem dono
}

var (
	gvrReplicaSets = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}
	gvrJobs        = schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}
	gvrCronJobs    = schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}
)

func NewCollector(cfg *Config, cs kubernetes.Interface, mc metadata.Interface, store *Store) *Collector {
	f := informers.NewSharedInformerFactoryWithOptions(cs, 0, informers.WithTransform(slimObject))
	m := metadatainformer.NewSharedInformerFactoryWithOptions(mc, 0, metadatainformer.WithTransform(slimMetadata))
	c := &Collector{
		cfg:          cfg,
		cs:           cs,
		store:        store,
		cluster:      clusterID(cfg.ClusterName),
		factory:      f,
		meta:         m,
		pods:         f.Core().V1().Pods().Lister(),
		nodes:        f.Core().V1().Nodes().Lister(),
		rsets:        m.ForResource(gvrReplicaSets).Lister(),
		jobs:         m.ForResource(gvrJobs).Lister(),
		cronjobs:     m.ForResource(gvrCronJobs).Lister(),
		podInform:    f.Core().V1().Pods().Informer(),
		terminalSeen: map[string]bool{},
		now:          time.Now,
		changes:      make(chan struct{}, 1),
	}
	c.fetchSummary = func(ctx context.Context, node string) ([]byte, error) {
		return cs.CoreV1().RESTClient().Get().Resource("nodes").Name(node).
			SubResource("proxy").Suffix("stats/summary").SetHeader("Accept", "application/json").Do(ctx).Raw()
	}
	return c
}

func (c *Collector) Start(ctx context.Context) error {
	// HPA é opcional: com o chart antigo (sem RBAC de autoscaling) ou um cluster sem autoscaling/v2, o informer
	// nunca sincronizaria e o agente não subiria
	if _, err := c.cs.AutoscalingV2().HorizontalPodAutoscalers("").List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		slog.Warn("HPAs não serão coletados (sem acesso a autoscaling/v2 horizontalpodautoscalers)", "error", redact(err.Error()))
	} else {
		c.hpas = c.factory.Autoscaling().V2().HorizontalPodAutoscalers().Lister()
	}
	c.watchChanges()
	c.factory.Start(ctx.Done())
	c.meta.Start(ctx.Done())
	for typ, ok := range c.factory.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("cache do informer %v não sincronizou", typ)
		}
	}
	for gvr, ok := range c.meta.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("cache do informer %v não sincronizou", gvr)
		}
	}
	return nil
}

// Changes avisa quando o estado de um pod (fase, pronto, restarts, motivo, nó) ou de um HPA (réplicas) mudou.
func (c *Collector) Changes() <-chan struct{} { return c.changes }

func (c *Collector) notify() {
	select {
	case c.changes <- struct{}{}:
	default: // já há um aviso pendente
	}
}

func podState(obj any) string {
	if t, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = t.Obj
	}
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return ""
	}
	ready, restarts, reason, _ := podStatus(p)
	return fmt.Sprintf("%s|%v|%d|%s|%s|%v", p.Status.Phase, ready, restarts, reason, p.Spec.NodeName, p.DeletionTimestamp != nil)
}

func hpaState(obj any) string {
	h, ok := obj.(*autoscalingv2.HorizontalPodAutoscaler)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d|%d|%d", h.Status.CurrentReplicas, h.Status.DesiredReplicas, h.Spec.MaxReplicas)
}

// watchChanges liga os avisos aos informers (a lista inicial não conta: é o estado que a primeira coleta já lê).
func (c *Collector) watchChanges() {
	handler := func(state func(any) string) cache.ResourceEventHandler {
		return cache.ResourceEventHandlerDetailedFuncs{
			AddFunc: func(obj any, initial bool) {
				if !initial {
					c.notify()
				}
			},
			UpdateFunc: func(old, cur any) {
				if state(old) != state(cur) {
					c.notify()
				}
			},
			DeleteFunc: func(any) { c.notify() },
		}
	}
	c.podInform.AddEventHandler(handler(podState))
	if c.hpas != nil {
		c.factory.Autoscaling().V2().HorizontalPodAutoscalers().Informer().AddEventHandler(handler(hpaState))
	}
}

// registerCluster grava a dimensão do cluster uma vez por dia, com a versão do Kubernetes do momento.
func (c *Collector) registerCluster(now time.Time) {
	if c.store.Seen("clusters", c.cluster, now) {
		return
	}
	if v, err := c.cs.Discovery().ServerVersion(); err == nil {
		c.mu.Lock()
		c.version = v.GitVersion
		c.mu.Unlock()
	}
	c.mu.Lock()
	version := c.version
	c.mu.Unlock()
	c.store.T.Clusters.Append(ClusterRow{ID: c.cluster, Name: c.cfg.ClusterName, K8sVersion: version, FirstSeen: now})
}

// ownerOf devolve o controlador do objeto de um informer de metadados (nil se ele não existe mais).
func ownerOf(l cache.GenericLister, ns, name string) (*metav1.OwnerReference, bool) {
	obj, err := l.ByNamespace(ns).Get(name)
	if err != nil {
		return nil, false
	}
	m, ok := obj.(metav1.Object)
	if !ok {
		return nil, false
	}
	return metav1.GetControllerOf(m), true
}

// workloadOf sobe pelos donos do pod: ReplicaSet -> Deployment, Job -> CronJob e Node -> StaticPod.
func (c *Collector) workloadOf(pod *corev1.Pod) (kind, name string) {
	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return "", ""
	}
	switch ref.Kind {
	case "ReplicaSet":
		if o, exists := ownerOf(c.rsets, pod.Namespace, ref.Name); exists {
			if o != nil {
				return o.Kind, o.Name
			}
			return "ReplicaSet", ref.Name
		}
		// ReplicaSet já removido: o nome é <deployment>-<pod-template-hash>
		if h := pod.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(ref.Name, "-"+h) {
			return "Deployment", strings.TrimSuffix(ref.Name, "-"+h)
		}
		return "ReplicaSet", ref.Name
	case "Job":
		if o, exists := ownerOf(c.jobs, pod.Namespace, ref.Name); exists {
			if o != nil {
				return o.Kind, o.Name
			}
			return "Job", ref.Name
		}
		// Job já removido (histórico da CronJob): o nome é <cronjob>-<número>
		if i := strings.LastIndex(ref.Name, "-"); i > 0 && isDigits(ref.Name[i+1:]) {
			if _, exists := ownerOf(c.cronjobs, pod.Namespace, ref.Name[:i]); exists {
				return "CronJob", ref.Name[:i]
			}
		}
		return "Job", ref.Name
	case "Node":
		// Pod estático (etcd, kube-apiserver...): o nome é <componente>-<nó>; agrupa o componente de todos os nós
		return "StaticPod", strings.TrimSuffix(pod.Name, "-"+ref.Name)
	}
	return ref.Kind, ref.Name
}

// RegisterPod grava as dimensões do pod (namespace, workload e o próprio pod) na primeira vez no dia e devolve os ids.
func (c *Collector) RegisterPod(pod *corev1.Pod, now time.Time) podRef {
	cl := c.cfg.ClusterName
	ref := podRef{
		id:          podID(cl, string(pod.UID)),
		namespaceID: namespaceID(cl, pod.Namespace),
	}
	t := c.store.T
	if !c.store.Seen("namespaces", ref.namespaceID, now) {
		t.Namespaces.Append(NamespaceRow{ID: ref.namespaceID, ClusterID: c.cluster, Name: pod.Namespace, FirstSeen: now})
	}
	kind, name := c.workloadOf(pod)
	if kind != "" {
		ref.workloadID = ptr(workloadID(cl, pod.Namespace, kind, name))
		if !c.store.Seen("workloads", *ref.workloadID, now) {
			t.Workloads.Append(WorkloadRow{ID: *ref.workloadID, ClusterID: c.cluster, NamespaceID: ref.namespaceID,
				Kind: kind, Name: name, FirstSeen: now})
		}
	}
	if !c.store.Seen("pods", ref.id, now) {
		t.Pods.Append(PodRow{ID: ref.id, ClusterID: c.cluster, NamespaceID: ref.namespaceID, WorkloadID: ref.workloadID,
			Name: pod.Name, UID: string(pod.UID), OwnerKind: strPtr(kind), CreatedAt: pod.CreationTimestamp.Time.UTC(), FirstSeen: now})
	}
	return ref
}

// ---------------------------------------------------------------------------
// Summary do kubelet
// ---------------------------------------------------------------------------

type cpuStats struct {
	UsageNanoCores *uint64 `json:"usageNanoCores"`
}
type memStats struct {
	WorkingSetBytes *uint64 `json:"workingSetBytes"`
}
type fsStats struct {
	CapacityBytes *uint64 `json:"capacityBytes"`
	UsedBytes     *uint64 `json:"usedBytes"`
}
type statsSummary struct {
	Node struct {
		CPU    *cpuStats `json:"cpu"`
		Memory *memStats `json:"memory"`
		Fs     *fsStats  `json:"fs"`
	} `json:"node"`
	Pods []struct {
		PodRef struct {
			UID       string `json:"uid"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"podRef"`
		CPU              *cpuStats `json:"cpu"`
		Memory           *memStats `json:"memory"`
		EphemeralStorage *fsStats  `json:"ephemeral-storage"`
	} `json:"pods"`
}

type usage struct {
	cpuM      *float64 // milicores (nil: sem dado)
	memBytes  *int64
	ephemeral *int64
}

func (c *Collector) fetchSummaries(ctx context.Context, nodes []*corev1.Node) map[string]*statsSummary {
	out := map[string]*statsSummary{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, c.cfg.SummaryConcurrency))
	for _, n := range nodes {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			raw, err := c.fetchSummary(rctx, name)
			if err != nil {
				slog.Warn("summary do kubelet", "node", name, "err", err)
				return
			}
			var s statsSummary
			if err := json.Unmarshal(raw, &s); err != nil {
				slog.Warn("summary do kubelet inválido", "node", name, "err", err)
				return
			}
			mu.Lock()
			out[name] = &s
			mu.Unlock()
		}(n.Name)
	}
	wg.Wait()
	return out
}

// ---------------------------------------------------------------------------
// Coleta
// ---------------------------------------------------------------------------

type nodeAlloc struct {
	cpuReq, cpuLim, memReq, memLim, ephReq int64
	pods                                   int64
}

// Sample registra uma amostra de todos os pods e nós com o mesmo timestamp (agregação por workload no Nanobot).
// Sample é a coleta completa: estado dos pods e nós e o uso pelo summary do kubelet.
func (c *Collector) Sample(ctx context.Context) error {
	return c.sample(ctx, true)
}

// SampleReactive é a coleta de uma mudança de estado: todos os pods (o mesmo horário para todos, como as telas e os
// alertas esperam), com o uso da última coleta completa, sem consultar o kubelet.
func (c *Collector) SampleReactive(ctx context.Context) error {
	return c.sample(ctx, false)
}

func (c *Collector) sample(ctx context.Context, full bool) error {
	ts := c.now().UTC().Truncate(time.Second)
	c.mu.Lock()
	if !ts.After(c.lastTS) {
		c.mu.Unlock()
		return nil
	}
	c.lastTS = ts
	c.mu.Unlock()
	cl := c.cfg.ClusterName

	nodes, err := c.nodes.List(labels.Everything())
	if err != nil {
		return err
	}
	pods, err := c.pods.List(labels.Everything())
	if err != nil {
		return err
	}
	var summaries map[string]*statsSummary
	if full {
		summaries = c.fetchSummaries(ctx, nodes)
		c.mu.Lock()
		c.lastSummaries = summaries
		c.mu.Unlock()
	} else {
		c.mu.Lock()
		summaries = c.lastSummaries
		c.mu.Unlock()
	}
	c.registerCluster(ts)

	podUsage := map[string]usage{}
	for _, s := range summaries {
		for _, p := range s.Pods {
			u := usage{}
			if p.CPU != nil && p.CPU.UsageNanoCores != nil {
				u.cpuM = ptr(float64(*p.CPU.UsageNanoCores) / 1e6)
			}
			if p.Memory != nil && p.Memory.WorkingSetBytes != nil {
				u.memBytes = ptr(int64(*p.Memory.WorkingSetBytes))
			}
			if p.EphemeralStorage != nil && p.EphemeralStorage.UsedBytes != nil {
				u.ephemeral = ptr(int64(*p.EphemeralStorage.UsedBytes))
			}
			podUsage[p.PodRef.UID] = u
			// Pod estático: o kubelet usa o uid do manifesto, diferente do uid do mirror pod na API
			podUsage[p.PodRef.Namespace+"/"+p.PodRef.Name] = u
		}
	}

	alloc := map[string]*nodeAlloc{}
	aliveUID := map[string]bool{}
	podRows := make([]PodSampleRow, 0, len(pods))
	for _, pod := range pods {
		aliveUID[string(pod.UID)] = true
		terminal := pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed
		r := podResources(pod)

		if !terminal && pod.Spec.NodeName != "" {
			a := alloc[pod.Spec.NodeName]
			if a == nil {
				a = &nodeAlloc{}
				alloc[pod.Spec.NodeName] = a
			}
			a.cpuReq += r.cpuReq
			a.cpuLim += r.cpuLim
			a.memReq += r.memReq
			a.memLim += r.memLim
			a.ephReq += r.ephReq
			a.pods++
		}

		if c.cfg.ExcludeNS[pod.Namespace] {
			continue
		}
		ref := c.RegisterPod(pod, ts)
		// Pod encerrado (Job/CronJob concluído) entra uma vez só, não a cada coleta até ser removido
		c.mu.Lock()
		skip := terminal && c.terminalSeen[string(pod.UID)]
		if terminal {
			c.terminalSeen[string(pod.UID)] = true
		}
		c.mu.Unlock()
		if skip {
			continue
		}

		u, ok := podUsage[string(pod.UID)]
		if !ok {
			u = podUsage[pod.Namespace+"/"+pod.Name]
		}
		var nid *int64
		if pod.Spec.NodeName != "" {
			nid = ptr(nodeID(cl, pod.Spec.NodeName))
		}
		ready, restarts, reason, message := podStatus(pod)
		podRows = append(podRows, PodSampleRow{
			TS: ts, PodID: ref.id, WorkloadID: ref.workloadID, NamespaceID: ref.namespaceID, NodeID: nid,
			Phase: string(pod.Status.Phase), Ready: ready, Restarts: restarts, Reason: strPtr(reason), Message: strPtr(message),
			CPUUsageM: u.cpuM, CPURequestM: positiveF(r.cpuReq), CPULimitM: positiveF(r.cpuLimOrZero()),
			MemUsageBytes: u.memBytes, MemRequestBytes: positive(r.memReq), MemLimitBytes: positive(r.memLimOrZero()),
			EphemeralUsageBytes: u.ephemeral,
			CPUPctRequest:       pct(u.cpuM, r.cpuReq), CPUPctLimit: pct(u.cpuM, r.cpuLimOrZero()),
			MemPctRequest: pctI(u.memBytes, r.memReq), MemPctLimit: pctI(u.memBytes, r.memLimOrZero()),
		})
	}

	nodeRows := make([]NodeSampleRow, 0, len(nodes))
	for _, n := range nodes {
		id := nodeID(cl, n.Name)
		if !c.store.Seen("nodes", id, ts) {
			c.store.T.Nodes.Append(NodeRow{ID: id, ClusterID: c.cluster, Name: n.Name, FirstSeen: ts})
		}
		a := alloc[n.Name]
		if a == nil {
			a = &nodeAlloc{}
		}
		row := NodeSampleRow{
			TS: ts, NodeID: id, Ready: nodeReady(n), Unschedulable: n.Spec.Unschedulable,
			CPURequestM: float64(a.cpuReq), CPULimitM: float64(a.cpuLim),
			MemRequestBytes: a.memReq, MemLimitBytes: a.memLim, EphemeralRequestBytes: a.ephReq, PodsCount: a.pods,
		}
		if s := summaries[n.Name]; s != nil {
			if s.Node.CPU != nil && s.Node.CPU.UsageNanoCores != nil {
				row.CPUUsageM = ptr(float64(*s.Node.CPU.UsageNanoCores) / 1e6)
			}
			if s.Node.Memory != nil && s.Node.Memory.WorkingSetBytes != nil {
				row.MemUsageBytes = ptr(int64(*s.Node.Memory.WorkingSetBytes))
			}
			if s.Node.Fs != nil && s.Node.Fs.CapacityBytes != nil && s.Node.Fs.UsedBytes != nil {
				row.FsCapacityBytes, row.FsUsedBytes = ptr(int64(*s.Node.Fs.CapacityBytes)), ptr(int64(*s.Node.Fs.UsedBytes))
			}
		}
		capa, allo := n.Status.Capacity, n.Status.Allocatable
		row.CPUCapacityM, row.CPUAllocatableM = float64(capa.Cpu().MilliValue()), float64(allo.Cpu().MilliValue())
		row.MemCapacityBytes, row.MemAllocatableBytes = capa.Memory().Value(), allo.Memory().Value()
		row.EphemeralAllocatableBytes, row.PodsCapacity = allo.StorageEphemeral().Value(), allo.Pods().Value()
		nodeRows = append(nodeRows, row)
	}

	c.store.T.PodSamples.Append(podRows...)
	c.store.T.NodeSamples.Append(nodeRows...)
	c.store.T.HPASamples.Append(c.hpaRows(ts)...)

	c.mu.Lock()
	for uid := range c.terminalSeen {
		if !aliveUID[uid] {
			delete(c.terminalSeen, uid)
		}
	}
	c.lastSampleOK = time.Now()
	c.mu.Unlock()
	slog.Debug("coleta", "pods", len(podRows), "nodes", len(nodeRows))
	return nil
}

// hpaRows liga cada HPA ao workload que ele escala (o mesmo id dos pods do Deployment/StatefulSet).
func (c *Collector) hpaRows(ts time.Time) []HPASampleRow {
	if c.hpas == nil {
		return nil
	}
	hpas, err := c.hpas.List(labels.Everything())
	if err != nil {
		slog.Warn("lista de HPAs", "error", err)
		return nil
	}
	cl := c.cfg.ClusterName
	rows := make([]HPASampleRow, 0, len(hpas))
	for _, h := range hpas {
		if c.cfg.ExcludeNS[h.Namespace] || h.Spec.ScaleTargetRef.Name == "" {
			continue
		}
		var minReplicas int64 = 1
		if h.Spec.MinReplicas != nil {
			minReplicas = int64(*h.Spec.MinReplicas)
		}
		rows = append(rows, HPASampleRow{
			TS: ts, WorkloadID: workloadID(cl, h.Namespace, h.Spec.ScaleTargetRef.Kind, h.Spec.ScaleTargetRef.Name),
			NamespaceID: namespaceID(cl, h.Namespace), Name: h.Name,
			MinReplicas: minReplicas, MaxReplicas: int64(h.Spec.MaxReplicas),
			CurrentReplicas: int64(h.Status.CurrentReplicas), DesiredReplicas: int64(h.Status.DesiredReplicas),
		})
	}
	return rows
}

func (c *Collector) LastSampleOK() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastSampleOK
}

// ---------------------------------------------------------------------------
// Requests/limits e status
// ---------------------------------------------------------------------------

type podRes struct {
	cpuReq, cpuLim, memReq, memLim, ephReq int64
	cpuLimSet, memLimSet                   bool
}

func (r podRes) cpuLimOrZero() int64 {
	if r.cpuLimSet {
		return r.cpuLim
	}
	return 0
}

func (r podRes) memLimOrZero() int64 {
	if r.memLimSet {
		return r.memLim
	}
	return 0
}

// podResources segue a conta do scheduler: soma dos containers (e sidecars), o maior init container e o overhead.
// O limite só vale quando todos os containers têm limite; senão o pod não tem teto (fica nulo).
func podResources(p *corev1.Pod) podRes {
	r := podRes{cpuLimSet: true, memLimSet: true}
	add := func(c corev1.Container) {
		r.cpuReq += c.Resources.Requests.Cpu().MilliValue()
		r.memReq += c.Resources.Requests.Memory().Value()
		r.ephReq += c.Resources.Requests.StorageEphemeral().Value()
		if q, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
			r.cpuLim += q.MilliValue()
		} else {
			r.cpuLimSet = false
		}
		if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
			r.memLim += q.Value()
		} else {
			r.memLimSet = false
		}
	}
	for _, c := range p.Spec.Containers {
		add(c)
	}
	var initCPU, initMem, initEph int64
	for _, c := range p.Spec.InitContainers {
		if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			add(c) // sidecar roda junto com os containers
			continue
		}
		initCPU = max(initCPU, c.Resources.Requests.Cpu().MilliValue())
		initMem = max(initMem, c.Resources.Requests.Memory().Value())
		initEph = max(initEph, c.Resources.Requests.StorageEphemeral().Value())
	}
	r.cpuReq, r.memReq, r.ephReq = max(r.cpuReq, initCPU), max(r.memReq, initMem), max(r.ephReq, initEph)
	if oh := p.Spec.Overhead; oh != nil {
		r.cpuReq += quantity(oh, corev1.ResourceCPU, true)
		r.memReq += quantity(oh, corev1.ResourceMemory, false)
	}
	return r
}

func quantity(l corev1.ResourceList, name corev1.ResourceName, milli bool) int64 {
	q, ok := l[name]
	if !ok {
		return 0
	}
	if milli {
		return q.MilliValue()
	}
	return q.Value()
}

// podStatus devolve se está pronto, o total de restarts e o motivo mais útil (CrashLoopBackOff, OOMKilled...).
func podStatus(p *corev1.Pod) (ready bool, restarts int64, reason, message string) {
	for _, cond := range p.Status.Conditions {
		switch cond.Type {
		case corev1.PodReady:
			ready = cond.Status == corev1.ConditionTrue
		case corev1.PodScheduled:
			// Sem nó que comporte o pod: o motivo é Unschedulable e a mensagem diz o que falta no cluster
			if cond.Status == corev1.ConditionFalse && cond.Reason != "" {
				reason, message = cond.Reason, cond.Message
			}
		}
	}
	if p.Status.Reason != "" {
		reason = p.Status.Reason
	}
	statuses := append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
	for _, cs := range statuses {
		restarts += int64(cs.RestartCount)
	}
	if reason == "" {
		for _, cs := range statuses {
			if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "ContainerCreating" && w.Reason != "PodInitializing" {
				reason = w.Reason
				break
			}
		}
	}
	if reason == "" {
		for _, cs := range statuses {
			if t := cs.State.Terminated; t != nil && t.Reason != "" && t.Reason != "Completed" {
				reason = t.Reason
				break
			}
			if t := cs.LastTerminationState.Terminated; !cs.Ready && t != nil && t.Reason != "" {
				reason = t.Reason
				break
			}
		}
	}
	return ready, restarts, reason, message
}

func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Helpers de valores nulos
// ---------------------------------------------------------------------------

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func positive(v int64) *int64 {
	if v <= 0 {
		return nil
	}
	return &v
}

func positiveF(v int64) *float64 {
	if v <= 0 {
		return nil
	}
	return ptr(float64(v))
}

// pct é o uso em relação ao request/limit (nulo quando não há uso medido ou o request/limit não existe).
func pct(used *float64, total int64) *float64 {
	if total <= 0 || used == nil {
		return nil
	}
	return ptr(*used / float64(total) * 100)
}

func pctI(used *int64, total int64) *float64 {
	if used == nil {
		return nil
	}
	return pct(ptr(float64(*used)), total)
}
