package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestImageRef(t *testing.T) {
	cases := []struct{ spec, id, digest, ref string }{
		{"nginx:1.27", "docker.io/library/nginx@sha256:aa", "sha256:aa", "docker.io/library/nginx@sha256:aa"},
		{"nginx:1.27", "docker-pullable://nginx@sha256:bb", "sha256:bb", "nginx@sha256:bb"},
		{"us-docker.pkg.dev/p/r/app:v1", "us-docker.pkg.dev/p/r/app@sha256:cc", "sha256:cc", "us-docker.pkg.dev/p/r/app@sha256:cc"},
		{"local/app:dev", "sha256:dd", "sha256:dd", "local/app:dev"},
		{"local/app:dev", "docker://sha256:ee", "sha256:ee", "local/app:dev"},
		{"x", "", "", ""},
	}
	for _, c := range cases {
		d, r := imageRef(c.spec, c.id)
		if d != c.digest || r != c.ref {
			t.Errorf("imageRef(%q, %q) = %q, %q; esperado %q, %q", c.spec, c.id, d, r, c.digest, c.ref)
		}
	}
}

func TestNextRun(t *testing.T) {
	sunday := 0
	now := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC) // quinta-feira
	cases := []struct {
		name string
		cfg  SecurityConfig
		last time.Time
		want time.Time
	}{
		{"primeiro, ainda hoje", SecurityConfig{EveryDays: 7, HourUTC: 15}, time.Time{}, time.Date(2026, 10, 22, 15, 0, 0, 0, time.UTC)},
		{"primeiro, amanhã", SecurityConfig{EveryDays: 1, HourUTC: 5}, time.Time{}, time.Date(2026, 10, 23, 5, 0, 0, 0, time.UTC)},
		{"primeiro, domingo", SecurityConfig{EveryDays: 7, HourUTC: 5, Weekday: &sunday}, time.Time{}, time.Date(2026, 10, 25, 5, 0, 0, 0, time.UTC)},
		{"semanal", SecurityConfig{EveryDays: 7, HourUTC: 5, Weekday: &sunday}, time.Date(2026, 10, 18, 5, 2, 0, 0, time.UTC),
			time.Date(2026, 10, 25, 5, 0, 0, 0, time.UTC)},
		// Último ciclo agendado numa quarta (agenda mudada para domingo): o domingo depois de 7 dias
		{"agenda mudada", SecurityConfig{EveryDays: 7, HourUTC: 5, Weekday: &sunday}, time.Date(2026, 10, 21, 13, 0, 0, 0, time.UTC),
			time.Date(2026, 11, 1, 5, 0, 0, 0, time.UTC)},
		{"atrasado roda já", SecurityConfig{EveryDays: 1, HourUTC: 3}, time.Date(2026, 10, 20, 3, 0, 0, 0, time.UTC),
			time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		cfg := c.cfg
		cfg.normalize()
		if got := nextRun(cfg, c.last, now); !got.Equal(c.want) {
			t.Errorf("%s: %s, esperado %s", c.name, got, c.want)
		}
	}
}

func TestSecurityConfigNormalize(t *testing.T) {
	bad := 9
	c := SecurityConfig{EveryDays: 0, HourUTC: 30, Weekday: &bad, Severities: []string{"high", "critical", "HIGH", "rm -rf"}}
	c.normalize()
	if c.EveryDays != 1 || c.HourUTC != 23 || c.Weekday != nil || strings.Join(c.Severities, ",") != "HIGH,CRITICAL" {
		t.Fatalf("normalize: %+v", c)
	}
	sat := 6
	c = SecurityConfig{EveryDays: 3, Weekday: &sat}
	c.normalize()
	if c.Weekday != nil || strings.Join(c.Severities, ",") != "CRITICAL,HIGH,MEDIUM" {
		t.Fatalf("weekday só com múltiplos de 7 e severidades padrão: %+v", c)
	}
}

const trivySample = `{
  "Metadata": {"OS": {"Family": "debian", "Name": "12.7"}},
  "Results": [
    {"Target": "app (debian 12.7)", "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [
      {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.1", "FixedVersion": "3.0.15",
       "Status": "fixed", "Severity": "CRITICAL", "Title": "openssl: falha", "Description": "descrição longa",
       "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0001", "PublishedDate": "2024-01-10T15:00:00Z",
       "CVSS": {"nvd": {"V3Score": 9.8, "V2Score": 7.5}, "redhat": {"V3Score": 8.1}}}
    ]},
    {"Target": "app/lib/jackson-databind-2.9.0.jar", "Class": "lang-pkgs", "Type": "jar", "Vulnerabilities": [
      {"VulnerabilityID": "GHSA-xxxx", "PkgName": "com.fasterxml.jackson.core:jackson-databind", "PkgPath": "app/lib/jackson-databind-2.9.0.jar",
       "InstalledVersion": "2.9.0", "Status": "affected", "Severity": "HIGH", "CVSS": {"ghsa": {"V2Score": 5.0}}}
    ]},
    {"Target": "Python", "Class": "lang-pkgs", "Type": "python-pkg"}
  ]
}`

func TestScanResultRoundTrip(t *testing.T) {
	out := scanOutput{Digest: "sha256:aa", Vulns: []scanVuln{}}
	if err := parseTrivy([]byte(trivySample), &out); err != nil {
		t.Fatal(err)
	}
	if out.OSFamily != "debian" || len(out.Vulns) != 2 {
		t.Fatalf("parse: %+v", out)
	}
	if v := out.Vulns[0]; *v.Score != 9.8 || v.Fixed != "3.0.15" || v.Target != "debian 12.7 (OS packages)" || v.Type != "debian" {
		t.Fatalf("vuln do SO: %+v", v)
	}
	if v := out.Vulns[1]; *v.Score != 5.0 || v.PkgPath != "app/lib/jackson-databind-2.9.0.jar" || v.Fixed != "" {
		t.Fatalf("vuln do jar (sem V3: usa o V2): %+v", v)
	}
	line, err := encodeScanResult(out)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeScanResult([]byte("outra linha\n" + line + "\n"))
	if err != nil || got.Digest != "sha256:aa" || len(got.Vulns) != 2 {
		t.Fatalf("decode: %v %+v", err, got)
	}
	if _, err := decodeScanResult([]byte("FATAL erro qualquer")); err == nil {
		t.Fatal("log sem resultado deveria dar erro")
	}
}

// O helper roda o comando, sai com 0 mesmo com erro e põe o erro na linha do resultado.
func TestRunScan(t *testing.T) {
	dir := t.TempDir()
	ok := dir + "/ok.sh"
	os.WriteFile(ok, []byte("#!/bin/sh\ncat <<'EOF'\n"+trivySample+"\nEOF\n"), 0o755)
	fail := dir + "/fail.sh"
	os.WriteFile(fail, []byte("#!/bin/sh\necho 'FATAL unable to scan' >&2\nexit 1\n"), 0o755)
	// Variáveis da imagem varrida não chegam ao Trivy
	envDump := dir + "/env.sh"
	os.WriteFile(envDump, []byte("#!/bin/sh\nenv >&2\nexit 3\n"), 0o755)
	t.Setenv("TRIVY_SEVERITY", "LOW")
	t.Setenv("SSL_CERT_FILE", "/nanobot-scan/ca.crt")
	if out := runScan("sha256:aa", []string{envDump}); strings.Contains(out.Error, "TRIVY_SEVERITY") || !strings.Contains(out.Error, "SSL_CERT_FILE") {
		t.Fatalf("ambiente do Trivy: %s", out.Error)
	}
	if err := installHelper(dir + "/job"); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(dir + "/job/.trivyignore"); err != nil || st.Size() != 0 {
		t.Fatalf(".trivyignore vazio: %v", err)
	}
	if st, err := os.Stat(dir + "/job/scan-helper"); err != nil || st.Mode()&0o111 == 0 {
		t.Fatalf("helper copiado: %v", err)
	}
	if out := runScan("sha256:aa", []string{ok}); out.Exit != 0 || len(out.Vulns) != 2 {
		t.Fatalf("ok: %+v", out)
	}
	if out := runScan("sha256:aa", []string{fail}); out.Exit != 1 || !strings.Contains(out.Error, "unable to scan") {
		t.Fatalf("fail: %+v", out)
	}
	if out := runScan("sha256:aa", []string{dir + "/nao-existe"}); out.Exit != -1 || out.Error == "" {
		t.Fatalf("comando inexistente: %+v", out)
	}
}

func testSecurityConfig(cfg *Config) {
	cfg.PodNamespace, cfg.AgentImage, cfg.TrivyImage = "nanobot", "amopromo/nanobot-k8s-agent:test", "aquasec/trivy:0.75.0"
	cfg.ScanCPURequest, cfg.ScanCPULimit, cfg.ScanMemoryRequest = "50m", "500m", "128Mi"
	cfg.ScanMemoryLimit, cfg.ScanMemoryLimitRetry, cfg.ScanWorkdirSize = "384Mi", "768Mi", "4Gi"
	cfg.ScanImagesPerJob, cfg.ScanImageTimeout, cfg.ScanJobGap = 2, 5*time.Minute, time.Millisecond
	cfg.ScanPriorityClass = "nanobot-scan"
	cfg.ExcludeNS = map[string]bool{"kube-system": true}
}

func TestBuildScanJob(t *testing.T) {
	cfg, _ := testConfig(t)
	testSecurityConfig(cfg)
	s := &Security{cfg: cfg}
	b := scanBatch{node: "node-a", targets: []*scanTarget{
		{digest: "sha256:aa", ref: "repo/api@sha256:aa", image: "repo/api:1"},
		{digest: "sha256:bb", ref: "repo/db@sha256:bb", image: "repo/db:2"},
	}}
	c := SecurityConfig{Severities: []string{"CRITICAL", "HIGH"}}
	job := s.buildScanJob(b, c, time.Now())
	spec := job.Spec.Template.Spec
	var names []string
	for _, ic := range spec.InitContainers {
		names = append(names, ic.Name)
	}
	if strings.Join(names, ",") != "helper,trivy-db,scan-0,scan-1" || spec.Containers[0].Name != "done" {
		t.Fatalf("containers: %v", names)
	}
	if job.Namespace != "nanobot" || spec.PriorityClassName != "nanobot-scan" || *spec.AutomountServiceAccountToken {
		t.Fatalf("job: %+v", job.ObjectMeta)
	}
	term := spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0]
	if term.MatchFields[0].Key != "metadata.name" || term.MatchFields[0].Values[0] != "node-a" {
		t.Fatalf("afinidade: %+v", term)
	}
	scan := spec.InitContainers[2]
	if scan.Image != "repo/api@sha256:aa" || scan.ImagePullPolicy != corev1.PullIfNotPresent {
		t.Fatalf("imagem varrida: %s %s", scan.Image, scan.ImagePullPolicy)
	}
	cmd := strings.Join(append(scan.Command, scan.Args...), " ")
	for _, want := range []string{"scan-helper scan sha256:aa --", "rootfs /", "--scanners vuln", "--severity CRITICAL,HIGH",
		"--skip-db-update", "--disable-telemetry", "--list-all-pkgs=false", "--skip-dirs /proc,/sys,/dev,/nanobot-scan",
		"--ignorefile /nanobot-scan/.trivyignore"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("comando sem %q: %s", want, cmd)
		}
	}
	if scan.Resources.Limits.Memory().String() != "384Mi" || !*scan.SecurityContext.ReadOnlyRootFilesystem ||
		*scan.SecurityContext.AllowPrivilegeEscalation {
		t.Fatalf("limites/segurança: %+v %+v", scan.Resources, scan.SecurityContext)
	}
	b.retry = true
	if m := s.buildScanJob(b, c, time.Now()).Spec.Template.Spec.InitContainers[2].Resources.Limits.Memory().String(); m != "768Mi" {
		t.Fatalf("limite da segunda tentativa: %s", m)
	}
}

func imagePod(ns, name, node string, owners []metav1.OwnerReference, image, imageID string) *corev1.Pod {
	p := mkPod(ns, name, node, corev1.PodRunning, owners, res("100m", "128Mi", "", ""), time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
	p.Spec.Containers[0].Image = image
	p.Status.ContainerStatuses[0].ImageID = imageID
	return p
}

// fakeScanJobs simula o kubelet: cada Job criado ganha um pod terminado, com o resultado de cada container no "log".
// oom: digests cujo container estoura a memória na primeira tentativa.
type fakeScanJobs struct {
	mu      sync.Mutex
	jobs    []*batchv1.Job
	logs    map[string]string // pod/container -> log
	oom     map[string]bool
	created int
}

func (f *fakeScanJobs) install(cs *fake.Clientset) {
	cs.PrependReactor("create", "jobs", func(a k8stesting.Action) (bool, runtime.Object, error) {
		job := a.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.created++
		job.Name = fmt.Sprintf("nanobot-scan-%d", f.created)
		f.jobs = append(f.jobs, job.DeepCopy())
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: job.Name + "-pod", Namespace: job.Namespace,
			Labels: map[string]string{"job-name": job.Name, "app.kubernetes.io/name": scanLabelApp}},
			Spec:   corev1.PodSpec{NodeName: job.Annotations["nanobot.io/node"]},
			Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}
		done := corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, Reason: "Completed"}}
		for _, ic := range job.Spec.Template.Spec.InitContainers {
			st := corev1.ContainerStatus{Name: ic.Name, State: done}
			if strings.HasPrefix(ic.Name, "scan-") {
				digest := ic.Args[2]
				retry := ic.Resources.Limits.Memory().String() == "768Mi"
				if f.oom[digest] && !retry {
					st.State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "OOMKilled"}}
					pod.Status.Phase = corev1.PodFailed
					pod.Status.InitContainerStatuses = append(pod.Status.InitContainerStatuses, st)
					break // os containers seguintes não rodam
				}
				out := scanOutput{Digest: digest, Vulns: []scanVuln{}}
				parseTrivy([]byte(trivySample), &out)
				line, _ := encodeScanResult(out)
				f.logs[pod.Name+"/"+ic.Name] = line
			}
			pod.Status.InitContainerStatuses = append(pod.Status.InitContainerStatuses, st)
		}
		if err := cs.Tracker().Add(pod); err != nil {
			return true, nil, err
		}
		return false, job, nil // segue para o tracker (grava o Job com o nome)
	})
}

func TestSecurityCycle(t *testing.T) {
	cfg, creds := testConfig(t)
	testSecurityConfig(cfg)
	scanPollInterval = time.Millisecond
	extra := []runtime.Object{
		// Mesma imagem em dois nós e dois pods: um digest, varrido uma vez
		imagePod("prod", "web-1", "node-a", owner("StatefulSet", "web"), "repo/web:1", "repo/web@sha256:web"),
		imagePod("prod", "web-2", "node-b", owner("StatefulSet", "web"), "repo/web:1", "repo/web@sha256:web"),
		imagePod("prod", "worker-1", "node-a", owner("StatefulSet", "worker"), "repo/worker:3", "repo/worker@sha256:worker"),
		imagePod("staging", "big-1", "node-b", owner("StatefulSet", "big"), "repo/big:1", "repo/big@sha256:big"),
		imagePod("kube-system", "proxy", "node-a", owner("DaemonSet", "proxy"), "k8s/proxy:1", "k8s/proxy@sha256:proxy"),
	}
	col, store, _ := newTestCollector(t, cfg, creds, time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC), extra...)
	cs := col.cs.(*fake.Clientset)
	f := &fakeScanJobs{logs: map[string]string{}, oom: map[string]bool{"sha256:big": true}}
	f.install(cs)

	s := NewSecurity(cfg, col, store)
	s.now = func() time.Time { return time.Date(2026, 10, 25, 5, 0, 0, 0, time.UTC) }
	s.readLog = func(_ context.Context, pod, container string) string { return f.logs[pod+"/"+container] }
	ctx := context.Background()
	sunday := 0
	if err := s.putJSON(ctx, securityConfigKey, SecurityConfig{Enabled: true, EveryDays: 7, Weekday: &sunday, HourUTC: 5,
		Severities: []string{"CRITICAL", "HIGH"}}); err != nil {
		t.Fatal(err)
	}
	s.check(ctx)

	if s.state.Status != "idle" || s.state.Images != 3 || s.state.Scanned != 3 || s.state.Failed != 0 || s.state.Vulns != 6 {
		t.Fatalf("estado: %+v", s.state)
	}
	if s.state.NextRun != "2026-11-01T05:00:00Z" || s.state.LastStarted != "2026-10-25T05:00:00Z" {
		t.Fatalf("próximo ciclo: %+v", s.state)
	}
	// 2 imagens por Job: o nó b fica com big (o a com web e worker); big estoura e roda de novo sozinha com mais memória
	if f.created != 3 {
		t.Fatalf("jobs criados: %d", f.created)
	}
	jobs, _ := cs.BatchV1().Jobs("nanobot").List(ctx, metav1.ListOptions{})
	if len(jobs.Items) != 0 {
		t.Fatalf("Jobs não apagados: %d", len(jobs.Items))
	}
	var stored SecurityState
	if found, err := s.getJSON(ctx, securityStateKey, &stored); !found || err != nil || stored.Scanned != 3 {
		t.Fatalf("estado no storage: %v %v %+v", found, err, stored)
	}

	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	uses, _ := readTable[ImageWorkloadRow](t, store, "image_workloads")
	scans, _ := readTable[ImageScanRow](t, store, "image_scans")
	vulns, _ := readTable[VulnerabilityRow](t, store, "vulnerabilities")
	if len(uses) != 3 || len(scans) != 3 || len(vulns) != 6 {
		t.Fatalf("linhas: uses=%d scans=%d vulns=%d", len(uses), len(scans), len(vulns))
	}
	for _, u := range uses {
		if u.Digest == "sha256:web" && (u.Pods != 2 || u.WorkloadID == nil) {
			t.Fatalf("uso da imagem web: %+v", u)
		}
		if u.Digest == "sha256:proxy" {
			t.Fatal("namespace ignorado entrou no inventário")
		}
	}
	for _, sc := range scans {
		if sc.Status != "ok" || sc.Critical != 1 || sc.High != 1 || *sc.OSFamily != "debian" {
			t.Fatalf("image_scans: %+v", sc)
		}
	}
	if !slices.ContainsFunc(vulns, func(v VulnerabilityRow) bool {
		return v.VulnID == "CVE-2024-0001" && v.Digest == "sha256:big" && *v.Score == 9.8 && v.Published != nil
	}) {
		t.Fatal("vulnerabilidade da imagem big (varrida na segunda tentativa) não gravada")
	}

	// Mesmo dia: não roda de novo sem o "Scan now"; com ele, varre tudo de novo
	s.check(ctx)
	if f.created != 3 {
		t.Fatalf("rodou fora da agenda: %d jobs", f.created)
	}
	if err := s.putJSON(ctx, securityConfigKey, SecurityConfig{Enabled: true, EveryDays: 7, Weekday: &sunday, HourUTC: 5,
		RequestedAt: "2026-10-25T05:01:00Z"}); err != nil {
		t.Fatal(err)
	}
	s.check(ctx)
	if f.created != 6 || s.state.HandledRequest != "2026-10-25T05:01:00Z" || s.state.Pending != 3 || s.state.Scanned != 3 {
		t.Fatalf("scan now: jobs=%d estado=%+v", f.created, s.state)
	}
	if s.state.NextRun != "2026-11-01T05:00:00Z" || s.state.LastScheduled != "2026-10-25T05:00:00Z" {
		t.Fatalf("scan now mudou a agenda: %+v", s.state)
	}

	// Ciclo da agenda interrompido (o agente reiniciou): no ciclo seguinte, as imagens varridas há pouco ficam de fora
	s.state.LastScheduled = ""
	s.check(ctx)
	if f.created != 6 || s.state.Pending != 0 || s.state.Images != 3 {
		t.Fatalf("retomada da agenda: jobs=%d estado=%+v", f.created, s.state)
	}

	// "Scan now" numa quinta, com a agenda de domingo e nenhum ciclo agendado ainda: o próximo continua no domingo
	s2 := NewSecurity(cfg, col, store)
	s2.now = func() time.Time { return time.Date(2026, 10, 22, 15, 0, 0, 0, time.UTC) }
	s2.readLog = s.readLog
	s2.state = SecurityState{}
	if err := s2.putJSON(ctx, securityConfigKey, SecurityConfig{Enabled: true, EveryDays: 7, Weekday: &sunday, HourUTC: 5,
		RequestedAt: "2026-10-22T14:59:00Z"}); err != nil {
		t.Fatal(err)
	}
	s2.check(ctx)
	if s2.state.LastStarted != "2026-10-22T15:00:00Z" || s2.state.LastScheduled != "" || s2.state.NextRun != "2026-10-25T05:00:00Z" {
		t.Fatalf("scan now mudou a agenda: %+v", s2.state)
	}

	// Desligado: estado disabled e nenhum ciclo
	if err := s.putJSON(ctx, securityConfigKey, SecurityConfig{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	s.check(ctx)
	raw, _ := json.Marshal(s.state)
	if s.state.Status != "disabled" || s.state.NextRun != "" {
		t.Fatalf("desligado: %s", raw)
	}
}
