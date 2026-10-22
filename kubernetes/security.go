package main

// Varredura de vulnerabilidades das imagens em uso (Trivy), ligada pelo Nanobot no cadastro do cluster.
//
// O Nanobot grava <cluster>/_config/security.json no storage (ligado, a cada quantos dias, dia da semana, hora e
// severidades); o agente lê a cada SCAN_CONFIG_INTERVAL e, na hora marcada, roda um ciclo:
//
//  1. inventário: pods Running (uma listagem paginada da API, fora do cache dos informers), agrupados pelo digest
//     da imagem. Uma imagem usada por vários workloads é varrida uma vez só (image_workloads guarda quem usa).
//  2. varredura: um Job por vez no namespace do agente, preso a um nó onde a imagem já está (está rodando lá). Os
//     containers de init rodam em sequência: o helper (o próprio binário do agente), o download do banco do Trivy e
//     um container por imagem, com a própria imagem varrida rodando o Trivy copiado para o emptyDir (trivy rootfs /).
//     A imagem já está no cache do nó: nada é baixado do registry e não precisa de credencial.
//  3. resultado: o helper imprime uma linha com o resultado resumido; o agente lê o log de cada container e grava
//     image_scans e vulnerabilities. O Job é apagado no fim.
//
// O arquivo de configuração só liga, desliga e agenda: a imagem do Trivy, os limites e os comandos vêm do chart.
// O estado (último ciclo, próximo, andamento) fica em <cluster>/_state/security.json para o Nanobot mostrar.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	scanMount         = "/nanobot-scan" // emptyDir dos Jobs (caminho improvável de existir nas imagens varridas)
	scanLabelApp      = "nanobot-k8s-scan"
	scanRecentlyOK    = 20 * time.Hour // digest varrido com sucesso há menos que isso não é varrido de novo (ciclo da agenda)
	scanPendingLimit  = 10 * time.Minute
	agentBinary       = "/usr/local/bin/nanobot-k8s-monitoring"
	maxScanLogBytes   = 64 << 20
	securityConfigKey = "_config/security.json"
	securityStateKey  = "_state/security.json"
)

var allowedSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

var scanPollInterval = 5 * time.Second // variável para os testes

// SecurityConfig é o _config/security.json gravado pelo Nanobot.
type SecurityConfig struct {
	Enabled     bool     `json:"enabled"`
	EveryDays   int      `json:"every_days"`
	Weekday     *int     `json:"weekday"` // 0 = domingo; só vale quando every_days é múltiplo de 7
	HourUTC     int      `json:"hour_utc"`
	Severities  []string `json:"severities"`
	RequestedAt string   `json:"requested_at"` // "Scan now" no Nanobot: roda se for mais novo que o último atendido
}

func (c *SecurityConfig) normalize() {
	c.EveryDays = min(max(c.EveryDays, 1), 30)
	c.HourUTC = min(max(c.HourUTC, 0), 23)
	if c.Weekday != nil && (*c.Weekday < 0 || *c.Weekday > 6 || c.EveryDays%7 != 0) {
		c.Weekday = nil
	}
	var sev []string
	for _, s := range c.Severities {
		if s = strings.ToUpper(strings.TrimSpace(s)); slices.Contains(allowedSeverities, s) && !slices.Contains(sev, s) {
			sev = append(sev, s)
		}
	}
	if len(sev) == 0 {
		sev = []string{"CRITICAL", "HIGH", "MEDIUM"}
	}
	c.Severities = sev
}

// SecurityState é o _state/security.json (lido pelo Nanobot).
type SecurityState struct {
	Status         string            `json:"status"` // disabled, idle, running
	LastStarted    string            `json:"last_cycle_started,omitempty"`
	LastFinished   string            `json:"last_cycle_finished,omitempty"`
	LastScheduled  string            `json:"last_scheduled,omitempty"` // início do último ciclo da agenda (o "Scan now" não muda a agenda)
	NextRun        string            `json:"next_run,omitempty"`
	HandledRequest string            `json:"handled_request,omitempty"`
	Images         int               `json:"images"`  // digests no inventário do ciclo
	Pending        int               `json:"pending"` // a varrer neste ciclo
	Scanned        int               `json:"scanned"`
	Failed         int               `json:"failed"`
	Skipped        int               `json:"skipped"`
	Vulns          int               `json:"vulns"`
	Current        string            `json:"current,omitempty"` // imagens do Job em andamento
	LastError      string            `json:"last_error,omitempty"`
	TrivyImage     string            `json:"trivy_image,omitempty"`
	ScannedAt      map[string]string `json:"scanned_at,omitempty"` // digest -> última varredura com sucesso
	UpdatedAt      string            `json:"updated_at"`
}

type Security struct {
	cfg   *Config
	col   *Collector
	store *Store
	now   func() time.Time
	state SecurityState
	// log de um container do pod do Job (nos testes, o resultado simulado)
	readLog func(ctx context.Context, pod, container string) string
}

func NewSecurity(cfg *Config, col *Collector, store *Store) *Security {
	s := &Security{cfg: cfg, col: col, store: store, now: time.Now}
	s.readLog = s.containerLog
	return s
}

// ---------------------------------------------------------------------------
// Arquivos JSON no storage (configuração e estado)
// ---------------------------------------------------------------------------

func isNotFound(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || minio.ToErrorResponse(err).Code == "NoSuchKey"
}

func (s *Security) getJSON(ctx context.Context, key string, v any) (bool, error) {
	if err := os.MkdirAll(s.cfg.BufferDir, 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(s.cfg.BufferDir, "security-*.json")
	if err != nil {
		return false, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := s.store.blob.Get(ctx, s.store.prefix+key, tmp.Name()); err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	raw, err := os.ReadFile(tmp.Name())
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, v)
}

func (s *Security) putJSON(ctx context.Context, key string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.cfg.BufferDir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(s.cfg.BufferDir, "security-state.json")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	return s.store.blob.Put(ctx, s.store.prefix+key, tmp)
}

func (s *Security) saveState(ctx context.Context) {
	s.state.UpdatedAt = s.now().UTC().Format(time.RFC3339)
	s.state.TrivyImage = s.cfg.TrivyImage
	if err := s.putJSON(ctx, securityStateKey, &s.state); err != nil {
		slog.Warn("varredura: estado não gravado no storage", "err", redact(err.Error()))
	}
}

// ---------------------------------------------------------------------------
// Agenda
// ---------------------------------------------------------------------------

func parseTime(v string) time.Time {
	t, _ := time.Parse(time.RFC3339, v)
	return t
}

// nextRun é o próximo horário do ciclo: hour_utc do dia (e do dia da semana, se definido) a every_days do último.
// Sem ciclo anterior, o primeiro horário a partir de agora.
func nextRun(c SecurityConfig, last, now time.Time) time.Time {
	at := func(d time.Time) time.Time {
		d = d.UTC()
		return time.Date(d.Year(), d.Month(), d.Day(), c.HourUTC, 0, 0, 0, time.UTC)
	}
	toWeekday := func(t time.Time) time.Time {
		if c.Weekday == nil {
			return t
		}
		return t.AddDate(0, 0, (*c.Weekday-int(t.Weekday())+7)%7)
	}
	if last.IsZero() {
		t := toWeekday(at(now))
		if t.Before(now) {
			if c.Weekday != nil {
				t = t.AddDate(0, 0, 7)
			} else {
				t = t.AddDate(0, 0, 1)
			}
		}
		return t
	}
	return toWeekday(at(last.AddDate(0, 0, c.EveryDays)))
}

// Run confere a configuração periodicamente e roda os ciclos (um por vez, nesta goroutine).
func (s *Security) Run(ctx context.Context) {
	if s.cfg.PodNamespace == "" || s.cfg.AgentImage == "" {
		slog.Warn("varredura de vulnerabilidades desligada: POD_NAMESPACE ou AGENT_IMAGE vazios (chart antigo?)")
		return
	}
	if _, err := s.getJSON(ctx, securityStateKey, &s.state); err != nil {
		slog.Warn("varredura: estado não lido do storage", "err", redact(err.Error()))
	}
	s.cleanupJobs(ctx)
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.check(ctx)
		timer.Reset(s.cfg.ScanConfigInterval)
	}
}

func (s *Security) check(ctx context.Context) {
	var c SecurityConfig
	found, err := s.getJSON(ctx, securityConfigKey, &c)
	if err != nil {
		slog.Warn("varredura: configuração não lida do storage", "err", redact(err.Error()))
		return
	}
	if !found || !c.Enabled {
		if s.state.Status != "disabled" {
			s.state.Status, s.state.NextRun = "disabled", ""
			s.saveState(ctx)
		}
		return
	}
	c.normalize()
	now := s.now().UTC()
	next := nextRun(c, parseTime(s.state.LastScheduled), now)
	requested := c.RequestedAt != "" && parseTime(c.RequestedAt).After(parseTime(s.state.HandledRequest))
	if !requested && now.Before(next) {
		if s.state.Status != "idle" || s.state.NextRun != next.Format(time.RFC3339) {
			s.state.Status, s.state.NextRun = "idle", next.Format(time.RFC3339)
			s.saveState(ctx)
		}
		return
	}
	scheduled := !now.Before(next)
	if requested {
		s.state.HandledRequest = c.RequestedAt
	}
	// "Scan now" varre tudo de novo; na agenda, as imagens varridas há pouco ficam de fora (um ciclo interrompido
	// por um restart do agente continua de onde parou)
	s.runCycle(ctx, c, requested && !scheduled)
	if scheduled {
		s.state.LastScheduled = s.state.LastStarted
	}
	s.state.NextRun = nextRun(c, parseTime(s.state.LastScheduled), s.now().UTC()).Format(time.RFC3339)
	s.saveState(ctx)
}

// ---------------------------------------------------------------------------
// Inventário
// ---------------------------------------------------------------------------

type scanTarget struct {
	digest string
	ref    string // o que o Job usa: repositório@sha256:... (ou a imagem do pod, se o runtime não deu o digest)
	image  string // como está no pod
	nodes  map[string]bool
}

type imageUse struct {
	digest, image, container string
	namespaceID              int64
	workloadID               *int64
	pods                     int64
}

// imageRef tira o digest do imageID do status do container. Formatos: "repo@sha256:..." (containerd/CRI-O),
// "docker-pullable://repo@sha256:..." (dockershim/cri-dockerd) e "sha256:..." (imagem local, sem repositório).
func imageRef(specImage, imageID string) (digest, ref string) {
	id := imageID
	if i := strings.Index(id, "://"); i >= 0 {
		id = id[i+3:]
	}
	at := strings.LastIndex(id, "@sha256:")
	switch {
	case at > 0:
		return id[at+1:], id
	case strings.HasPrefix(id, "sha256:"):
		return id, specImage
	}
	return "", ""
}

// inventory lista os pods Running (paginado, sem passar pelo cache dos informers) e agrupa por digest.
func (s *Security) inventory(ctx context.Context, now time.Time) (map[string]*scanTarget, []imageUse, error) {
	targets := map[string]*scanTarget{}
	uses := map[string]*imageUse{}
	opts := metav1.ListOptions{FieldSelector: "status.phase=Running", Limit: 500}
	for {
		list, err := s.col.cs.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
		for i := range list.Items {
			pod := &list.Items[i]
			if pod.Status.Phase != corev1.PodRunning || s.cfg.ExcludeNS[pod.Namespace] ||
				pod.Labels["app.kubernetes.io/name"] == scanLabelApp || pod.Spec.NodeName == "" {
				continue
			}
			ref := s.col.RegisterPod(pod, now)
			images := map[string]string{}
			for _, c := range pod.Spec.Containers {
				images[c.Name] = c.Image
			}
			for _, st := range pod.Status.ContainerStatuses {
				if st.State.Running == nil {
					continue
				}
				digest, r := imageRef(images[st.Name], st.ImageID)
				if digest == "" || r == "" {
					continue
				}
				t := targets[digest]
				if t == nil {
					t = &scanTarget{digest: digest, ref: r, image: images[st.Name], nodes: map[string]bool{}}
					targets[digest] = t
				}
				t.nodes[pod.Spec.NodeName] = true
				wid := int64(0)
				if ref.workloadID != nil {
					wid = *ref.workloadID
				}
				key := fmt.Sprintf("%s|%d|%d|%s", digest, ref.namespaceID, wid, st.Name)
				u := uses[key]
				if u == nil {
					u = &imageUse{digest: digest, image: images[st.Name], container: st.Name, namespaceID: ref.namespaceID,
						workloadID: ref.workloadID}
					uses[key] = u
				}
				u.pods++
			}
		}
		if list.Continue == "" {
			break
		}
		opts.Continue = list.Continue
	}
	out := make([]imageUse, 0, len(uses))
	for _, u := range uses {
		out = append(out, *u)
	}
	return targets, out, nil
}

// plan distribui os digests pelos nós (o nó com menos imagens atribuídas primeiro) e devolve os lotes de cada Job.
// Nós cordoned ou não prontos ficam de fora.
func (s *Security) plan(targets []*scanTarget) (batches []scanBatch, skipped []*scanTarget) {
	usable := func(name string) bool {
		n, err := s.col.nodes.Get(name)
		return err == nil && !n.Spec.Unschedulable && nodeReady(n)
	}
	perNode := map[string][]*scanTarget{}
	sort.Slice(targets, func(i, j int) bool { return targets[i].digest < targets[j].digest })
	for _, t := range targets {
		var nodes []string
		for n := range t.nodes {
			if usable(n) {
				nodes = append(nodes, n)
			}
		}
		if len(nodes) == 0 {
			skipped = append(skipped, t)
			continue
		}
		sort.Strings(nodes)
		best := nodes[0]
		for _, n := range nodes[1:] {
			if len(perNode[n]) < len(perNode[best]) {
				best = n
			}
		}
		perNode[best] = append(perNode[best], t)
	}
	nodes := make([]string, 0, len(perNode))
	for n := range perNode {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	size := max(1, s.cfg.ScanImagesPerJob)
	for _, n := range nodes {
		list := perNode[n]
		for i := 0; i < len(list); i += size {
			batches = append(batches, scanBatch{node: n, targets: list[i:min(i+size, len(list))]})
		}
	}
	return batches, skipped
}

type scanBatch struct {
	node    string
	targets []*scanTarget
	retry   bool // segunda tentativa de uma imagem que estourou a memória (limite maior)
}

// ---------------------------------------------------------------------------
// Ciclo
// ---------------------------------------------------------------------------

type scanResult struct {
	target *scanTarget
	node   string
	status string
	err    string
	out    *scanOutput
}

func (s *Security) runCycle(ctx context.Context, c SecurityConfig, force bool) {
	cycle := s.now().UTC()
	s.state = SecurityState{Status: "running", LastStarted: cycle.Format(time.RFC3339), HandledRequest: s.state.HandledRequest,
		LastScheduled: s.state.LastScheduled, NextRun: s.state.NextRun, ScannedAt: s.state.ScannedAt}
	if s.state.ScannedAt == nil {
		s.state.ScannedAt = map[string]string{}
	}
	targets, uses, err := s.inventory(ctx, cycle)
	if err != nil {
		slog.Error("varredura: inventário das imagens", "err", redact(err.Error()))
		s.state.Status, s.state.LastError = "idle", "inventory: "+redact(err.Error())
		s.saveState(ctx)
		return
	}
	for _, u := range uses {
		s.store.T.ImageWorkloads.Append(ImageWorkloadRow{TS: cycle, Digest: u.digest, Image: u.image, NamespaceID: u.namespaceID,
			WorkloadID: u.workloadID, Container: u.container, Pods: u.pods})
	}
	var todo []*scanTarget
	for _, t := range targets {
		if at := parseTime(s.state.ScannedAt[t.digest]); !force && !at.IsZero() && cycle.Sub(at) < scanRecentlyOK {
			continue
		}
		todo = append(todo, t)
	}
	batches, skipped := s.plan(todo)
	s.state.Images, s.state.Pending = len(targets), len(todo)
	slog.Info("varredura de vulnerabilidades iniciada", "images", len(targets), "to_scan", len(todo), "jobs", len(batches),
		"severities", strings.Join(c.Severities, ","))
	for _, t := range skipped {
		s.record(cycle, scanResult{target: t, status: "skipped", err: "no ready, schedulable node running the image"})
	}
	s.saveState(ctx)

	attempts := map[string]int{}
	for len(batches) > 0 && ctx.Err() == nil {
		b := batches[0]
		batches = batches[1:]
		names := make([]string, len(b.targets))
		for i, t := range b.targets {
			names[i] = t.image
			attempts[t.digest]++
		}
		s.state.Current = strings.Join(names, ", ")
		s.saveState(ctx)
		results, rest := s.runJob(ctx, cycle, b, c)
		for _, r := range results {
			if r.status == "oom" && !b.retry {
				// Uma tentativa a mais, sozinha e com o limite maior
				batches = append(batches, scanBatch{node: b.node, targets: []*scanTarget{r.target}, retry: true})
				continue
			}
			s.record(cycle, r)
		}
		var again []*scanTarget
		for _, t := range rest {
			if attempts[t.digest] < 2 {
				again = append(again, t)
			} else {
				s.record(cycle, scanResult{target: t, node: b.node, status: "error", err: "scan did not run (job failed twice)"})
			}
		}
		if len(again) > 0 {
			batches = append(batches, scanBatch{node: b.node, targets: again, retry: b.retry})
		}
		if len(batches) > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(s.cfg.ScanJobGap):
			}
		}
	}
	// Só os digests ainda em uso ficam no estado
	for d := range s.state.ScannedAt {
		if targets[d] == nil {
			delete(s.state.ScannedAt, d)
		}
	}
	s.state.Status, s.state.Current = "idle", ""
	s.state.LastFinished = s.now().UTC().Format(time.RFC3339)
	if ctx.Err() != nil {
		s.state.LastError = "cycle interrupted (agent stopping)"
	}
	slog.Info("varredura de vulnerabilidades concluída", "scanned", s.state.Scanned, "failed", s.state.Failed,
		"skipped", s.state.Skipped, "vulns", s.state.Vulns)
	s.saveState(context.WithoutCancel(ctx))
}

// record grava o resultado de um digest (image_scans e, com sucesso, vulnerabilities) e atualiza o estado.
func (s *Security) record(cycle time.Time, r scanResult) {
	ts := s.now().UTC()
	row := ImageScanRow{TS: ts, CycleTS: cycle, Digest: r.target.digest, Image: r.target.image, Node: r.node, Status: r.status}
	if r.err != "" {
		row.Error = ptr(redact(r.err))
	}
	switch r.status {
	case "ok":
		s.state.Scanned++
		s.state.ScannedAt[r.target.digest] = ts.Format(time.RFC3339)
	case "skipped":
		s.state.Skipped++
	default:
		s.state.Failed++
		s.state.LastError = fmt.Sprintf("%s: %s", r.target.image, redact(r.err))
	}
	if r.out != nil {
		row.DurationMS = r.out.DurationMS
		row.OSFamily, row.OSName = strPtr(r.out.OSFamily), strPtr(r.out.OSName)
		if r.out.OSFamily != "" {
			row.OSEOSL = ptr(r.out.OSEOSL)
		}
		rows := make([]VulnerabilityRow, 0, len(r.out.Vulns))
		for _, v := range r.out.Vulns {
			switch v.Severity {
			case "CRITICAL":
				row.Critical++
			case "HIGH":
				row.High++
			case "MEDIUM":
				row.Medium++
			case "LOW":
				row.Low++
			}
			vr := VulnerabilityRow{TS: ts, Digest: r.target.digest, VulnID: v.ID, Severity: v.Severity, Score: v.Score,
				Title: strPtr(v.Title), Description: strPtr(v.Description), URL: strPtr(v.URL), Pkg: v.Pkg,
				Installed: v.Installed, Fixed: strPtr(v.Fixed), Status: strPtr(v.Status), Target: v.Target,
				PkgPath: strPtr(v.PkgPath), Type: strPtr(v.Type)}
			if p, err := time.Parse(time.RFC3339, v.Published); err == nil {
				vr.Published = ptr(p.UTC())
			}
			rows = append(rows, vr)
		}
		row.Vulns = int64(len(rows))
		s.state.Vulns += len(rows)
		s.store.T.Vulnerabilities.Append(rows...)
	}
	s.store.T.ImageScans.Append(row)
}

// ---------------------------------------------------------------------------
// Job
// ---------------------------------------------------------------------------

func scanContainerName(i int) string { return fmt.Sprintf("scan-%d", i) }

// buildScanJob monta o Job de um lote: helper, banco do Trivy e um container de init por imagem (em sequência).
func (s *Security) buildScanJob(b scanBatch, c SecurityConfig, cycle time.Time) *batchv1.Job {
	cfg := s.cfg
	memLimit := cfg.ScanMemoryLimit
	if b.retry {
		memLimit = cfg.ScanMemoryLimitRetry
	}
	res := func(cpuReq, memReq, cpuLim, memLim string) corev1.ResourceRequirements {
		r := corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpuReq), corev1.ResourceMemory: resource.MustParse(memReq)},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse(memLim)},
		}
		if cpuLim != "" {
			r.Limits[corev1.ResourceCPU] = resource.MustParse(cpuLim)
		}
		return r
	}
	sec := func(capsAdd ...corev1.Capability) *corev1.SecurityContext {
		return &corev1.SecurityContext{
			RunAsUser: ptr(int64(0)), RunAsNonRoot: ptr(false), AllowPrivilegeEscalation: ptr(false),
			ReadOnlyRootFilesystem: ptr(true),
			Capabilities:           &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: capsAdd},
		}
	}
	mounts := []corev1.VolumeMount{{Name: "scan", MountPath: scanMount}}
	// Os certificados vêm da imagem do Trivy: a imagem varrida pode não ter (scratch) e o banco Java é baixado por ela
	env := []corev1.EnvVar{{Name: "TMPDIR", Value: scanMount + "/tmp"}, {Name: "HOME", Value: scanMount + "/home"},
		{Name: "SSL_CERT_FILE", Value: scanMount + "/ca-certificates.crt"}}
	dbArgs := ""
	if cfg.TrivyDBRepository != "" {
		dbArgs = " --db-repository " + shellQuote(cfg.TrivyDBRepository)
	}
	inits := []corev1.Container{
		{
			Name: "helper", Image: cfg.AgentImage, ImagePullPolicy: corev1.PullIfNotPresent,
			Command: []string{agentBinary, "scan-helper", "install", scanMount}, VolumeMounts: mounts,
			Resources: res("10m", "16Mi", "", "64Mi"), SecurityContext: sec(),
		},
		{
			// O banco é baixado uma vez por Job e usado por todas as imagens do lote
			Name: "trivy-db", Image: cfg.TrivyImage, ImagePullPolicy: corev1.PullIfNotPresent,
			Command: []string{"sh", "-c", "cp /usr/local/bin/trivy " + scanMount + "/trivy && cp /etc/ssl/certs/ca-certificates.crt " +
				scanMount + "/ && trivy image --download-db-only" +
				" --cache-dir " + scanMount + "/cache --no-progress --quiet" + dbArgs},
			Env: env, VolumeMounts: mounts, Resources: res(cfg.ScanCPURequest, cfg.ScanMemoryRequest, cfg.ScanCPULimit, cfg.ScanMemoryLimit),
			SecurityContext: sec(),
		},
	}
	for i, t := range b.targets {
		args := []string{scanMount + "/scan-helper", "scan-helper", "scan", t.digest, "--",
			scanMount + "/trivy", "rootfs", "/", "--scanners", "vuln", "--format", "json", "--cache-dir", scanMount + "/cache",
			"--skip-db-update", "--parallel", "1", "--skip-dirs", "/proc,/sys,/dev," + scanMount,
			"--list-all-pkgs=false", "--disable-telemetry", "--skip-version-check", "--no-progress", "--quiet",
			"--severity", strings.Join(c.Severities, ","), "--timeout", cfg.ScanImageTimeout.String(),
			"--ignorefile", scanMount + "/.trivyignore"} // vazio (criado pelo helper): nada é ignorado
		if cfg.TrivyJavaDBRepository != "" {
			args = append(args, "--java-db-repository", cfg.TrivyJavaDBRepository)
		}
		inits = append(inits, corev1.Container{
			Name: scanContainerName(i), Image: t.ref, ImagePullPolicy: corev1.PullIfNotPresent,
			Command: args[:1], Args: args[1:], Env: env, VolumeMounts: mounts,
			Resources: res(cfg.ScanCPURequest, cfg.ScanMemoryRequest, cfg.ScanCPULimit, memLimit),
			// Lê arquivos de outros usuários dentro da imagem (sem poder alterar nada: rootfs só leitura)
			SecurityContext: sec("DAC_READ_SEARCH"),
		})
	}
	deadline := int64(300 + len(b.targets)*int(cfg.ScanImageTimeout.Seconds()+60))
	labels := map[string]string{
		"app.kubernetes.io/name": scanLabelApp, "app.kubernetes.io/managed-by": "nanobot-k8s-monitoring",
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "nanobot-scan-", Namespace: cfg.PodNamespace, Labels: labels,
			Annotations: map[string]string{"nanobot.io/cycle": cycle.Format(time.RFC3339), "nanobot.io/node": b.node},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptr(int32(0)), ActiveDeadlineSeconds: &deadline, TTLSecondsAfterFinished: ptr(int32(3600)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever, AutomountServiceAccountToken: ptr(false),
					EnableServiceLinks: ptr(false), PriorityClassName: cfg.ScanPriorityClass,
					SecurityContext: &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
					// No nó onde a imagem já está (matchFields: o nome do nó, como num DaemonSet)
					Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{b.node}}},
						}}},
					}},
					// Os pods da imagem já rodam no nó: o Job tolera os mesmos taints (pools dedicados)
					Tolerations:    []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					InitContainers: inits,
					Containers: []corev1.Container{{
						Name: "done", Image: cfg.AgentImage, ImagePullPolicy: corev1.PullIfNotPresent,
						Command: []string{agentBinary, "scan-helper", "done"}, Resources: res("10m", "16Mi", "", "32Mi"), SecurityContext: sec(),
					}},
					Volumes: []corev1.Volume{{Name: "scan", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
						SizeLimit: ptr(resource.MustParse(cfg.ScanWorkdirSize)),
					}}}},
				},
			},
		},
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// runJob cria o Job do lote, espera terminar e lê o resultado de cada imagem. rest: imagens que não chegaram a rodar.
func (s *Security) runJob(ctx context.Context, cycle time.Time, b scanBatch, c SecurityConfig) (results []scanResult, rest []*scanTarget) {
	jobs := s.col.cs.BatchV1().Jobs(s.cfg.PodNamespace)
	job, err := jobs.Create(ctx, s.buildScanJob(b, c, cycle), metav1.CreateOptions{})
	if err != nil {
		for _, t := range b.targets {
			results = append(results, scanResult{target: t, node: b.node, status: "error", err: "creating the scan job: " + err.Error()})
		}
		return results, nil
	}
	defer func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		bg := metav1.DeletePropagationBackground
		if err := jobs.Delete(dctx, job.Name, metav1.DeleteOptions{PropagationPolicy: &bg}); err != nil && !apierrors.IsNotFound(err) {
			slog.Warn("varredura: Job não apagado", "job", job.Name, "err", err)
		}
	}()
	slog.Info("varredura: Job criado", "job", job.Name, "node", b.node, "images", len(b.targets), "retry", b.retry)

	pod, failure := s.waitJob(ctx, job.Name, len(b.targets))
	if pod == nil {
		for _, t := range b.targets {
			results = append(results, scanResult{target: t, node: b.node, status: "error", err: failure})
		}
		return results, nil
	}
	statuses := map[string]corev1.ContainerStatus{}
	for _, st := range pod.Status.InitContainerStatuses {
		statuses[st.Name] = st
	}
	if db := statuses["trivy-db"]; db.State.Terminated == nil || db.State.Terminated.ExitCode != 0 {
		msg := "trivy database download failed"
		if failure != "" {
			msg += ": " + failure
		}
		if tail := s.readLog(ctx, pod.Name, "trivy-db"); tail != "" {
			msg += ": " + lastLines(tail, 500)
		}
		for _, t := range b.targets {
			results = append(results, scanResult{target: t, node: b.node, status: "error", err: msg})
		}
		return results, nil
	}
	for i, t := range b.targets {
		st, ok := statuses[scanContainerName(i)]
		switch {
		case !ok || (st.State.Terminated == nil && st.State.Waiting == nil && st.State.Running == nil):
			rest = append(rest, t)
		case st.State.Terminated != nil && st.State.Terminated.Reason == "OOMKilled":
			results = append(results, scanResult{target: t, node: b.node, status: "oom", err: "scanner out of memory"})
		case st.State.Terminated != nil && st.State.Terminated.ExitCode == 0:
			out, err := decodeScanResult([]byte(s.readLog(ctx, pod.Name, scanContainerName(i))))
			switch {
			case err != nil:
				results = append(results, scanResult{target: t, node: b.node, status: "error", err: "reading the result: " + err.Error()})
			case out.Exit != 0:
				results = append(results, scanResult{target: t, node: b.node, status: "error", err: out.Error, out: nil})
			default:
				results = append(results, scanResult{target: t, node: b.node, status: "ok", out: out})
			}
		case st.State.Terminated != nil:
			results = append(results, scanResult{target: t, node: b.node, status: "error",
				err: fmt.Sprintf("scanner exited with code %d (%s)", st.State.Terminated.ExitCode, st.State.Terminated.Reason)})
		case st.State.Waiting != nil && st.State.Waiting.Reason != "PodInitializing":
			// Imagem sem cache no nó e sem credencial para baixar, imagem inválida...
			results = append(results, scanResult{target: t, node: b.node, status: "skipped",
				err: "image not available on the node: " + st.State.Waiting.Reason})
		case st.State.Running != nil:
			results = append(results, scanResult{target: t, node: b.node, status: "timeout", err: "scan timed out: " + failure})
		default:
			rest = append(rest, t)
		}
	}
	return results, rest
}

// waitJob espera o pod do Job terminar. Devolve o pod (estado final) ou nil e o motivo da falha.
// Termina antes se um container de varredura ficar preso esperando a imagem (sem cache e sem credencial).
func (s *Security) waitJob(ctx context.Context, name string, images int) (*corev1.Pod, string) {
	pods := s.col.cs.CoreV1().Pods(s.cfg.PodNamespace)
	sel := labels.Set{"job-name": name}.String()
	deadline := time.Now().Add(time.Duration(300+images*int(s.cfg.ScanImageTimeout.Seconds()+60))*time.Second + time.Minute)
	created := time.Now()
	var last *corev1.Pod
	for {
		select {
		case <-ctx.Done():
			return last, "agent stopping"
		case <-time.After(scanPollInterval):
		}
		list, err := pods.List(ctx, metav1.ListOptions{LabelSelector: sel})
		if err == nil && len(list.Items) > 0 {
			p := &list.Items[0]
			last = p
			switch p.Status.Phase {
			case corev1.PodSucceeded:
				return p, ""
			case corev1.PodFailed:
				return p, p.Status.Reason + " " + p.Status.Message
			}
			for _, st := range p.Status.InitContainerStatuses {
				if w := st.State.Waiting; w != nil && strings.HasPrefix(st.Name, "scan-") && w.Reason != "PodInitializing" &&
					w.Reason != "ContainerCreating" {
					return p, w.Reason
				}
			}
			if p.Spec.NodeName == "" && time.Since(created) > scanPendingLimit {
				return nil, "scan pod could not be scheduled on the node within " + scanPendingLimit.String()
			}
		}
		if time.Now().After(deadline) {
			if last != nil {
				return last, "deadline exceeded"
			}
			return nil, "scan job did not start"
		}
	}
}

func (s *Security) containerLog(ctx context.Context, pod, container string) string {
	raw, err := s.col.cs.CoreV1().Pods(s.cfg.PodNamespace).GetLogs(pod, &corev1.PodLogOptions{
		Container: container, LimitBytes: ptr(int64(maxScanLogBytes)),
	}).DoRaw(ctx)
	if err != nil {
		return ""
	}
	return string(raw)
}

// cleanupJobs apaga Jobs de varredura que sobraram (agente reiniciado no meio de um ciclo).
func (s *Security) cleanupJobs(ctx context.Context) {
	jobs := s.col.cs.BatchV1().Jobs(s.cfg.PodNamespace)
	list, err := jobs.List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=" + scanLabelApp})
	if err != nil {
		return
	}
	bg := metav1.DeletePropagationBackground
	for _, j := range list.Items {
		if err := jobs.Delete(ctx, j.Name, metav1.DeleteOptions{PropagationPolicy: &bg}); err == nil {
			slog.Info("varredura: Job antigo apagado", "job", j.Name)
		}
	}
	if s.state.Status == "running" {
		s.state.Status, s.state.Current, s.state.LastError = "idle", "", "cycle interrupted (agent restarted)"
	}
}
