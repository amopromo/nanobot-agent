package main

import "time"

// Tabelas gravadas no storage. Os dados fixos (cluster, namespace, workload, nó, pod) ficam só nas dimensões; os fatos
// (pod_samples, node_samples, logs) guardam os ids. Os ids são hashes estáveis (ids.go).
// O Nanobot tem as mesmas colunas: uma coluna nova precisa entrar nos dois.
//
// As dimensões são gravadas de novo a cada dia (na primeira vez que o item aparece no dia): cada dia do storage
// é completo sozinho, então a retenção apaga dias inteiros sem deixar pod sem nome.

// Os timestamps são timestamp(microsecond:local): TIMESTAMP sem fuso no DuckDB (os valores são UTC).

type ClusterRow struct {
	ID         int64     `parquet:"id"`
	Name       string    `parquet:"name"`
	K8sVersion string    `parquet:"k8s_version"`
	FirstSeen  time.Time `parquet:"first_seen,timestamp(microsecond:local)"`
}

type NamespaceRow struct {
	ID        int64     `parquet:"id"`
	ClusterID int64     `parquet:"cluster_id"`
	Name      string    `parquet:"name"`
	FirstSeen time.Time `parquet:"first_seen,timestamp(microsecond:local)"`
}

type WorkloadRow struct {
	ID          int64     `parquet:"id"`
	ClusterID   int64     `parquet:"cluster_id"`
	NamespaceID int64     `parquet:"namespace_id"`
	Kind        string    `parquet:"kind"`
	Name        string    `parquet:"name"`
	FirstSeen   time.Time `parquet:"first_seen,timestamp(microsecond:local)"`
}

type NodeRow struct {
	ID        int64     `parquet:"id"`
	ClusterID int64     `parquet:"cluster_id"`
	Name      string    `parquet:"name"`
	FirstSeen time.Time `parquet:"first_seen,timestamp(microsecond:local)"`
}

type PodRow struct {
	ID          int64     `parquet:"id"`
	ClusterID   int64     `parquet:"cluster_id"`
	NamespaceID int64     `parquet:"namespace_id"`
	WorkloadID  *int64    `parquet:"workload_id,optional"`
	Name        string    `parquet:"name"`
	UID         string    `parquet:"uid"`
	OwnerKind   *string   `parquet:"owner_kind,optional"`
	CreatedAt   time.Time `parquet:"created_at,timestamp(microsecond:local)"`
	FirstSeen   time.Time `parquet:"first_seen,timestamp(microsecond:local)"`
}

type PodSampleRow struct {
	TS                  time.Time `parquet:"ts,timestamp(microsecond:local)"`
	PodID               int64     `parquet:"pod_id"`
	WorkloadID          *int64    `parquet:"workload_id,optional"`
	NamespaceID         int64     `parquet:"namespace_id"`
	NodeID              *int64    `parquet:"node_id,optional"`
	Phase               string    `parquet:"phase"`
	Ready               bool      `parquet:"ready"`
	Restarts            int64     `parquet:"restarts"`
	Reason              *string   `parquet:"reason,optional"`
	CPUUsageM           *float64  `parquet:"cpu_usage_m,optional"`
	CPURequestM         *float64  `parquet:"cpu_request_m,optional"`
	CPULimitM           *float64  `parquet:"cpu_limit_m,optional"`
	MemUsageBytes       *int64    `parquet:"mem_usage_bytes,optional"`
	MemRequestBytes     *int64    `parquet:"mem_request_bytes,optional"`
	MemLimitBytes       *int64    `parquet:"mem_limit_bytes,optional"`
	EphemeralUsageBytes *int64    `parquet:"ephemeral_usage_bytes,optional"`
	CPUPctRequest       *float64  `parquet:"cpu_pct_request,optional"`
	CPUPctLimit         *float64  `parquet:"cpu_pct_limit,optional"`
	MemPctRequest       *float64  `parquet:"mem_pct_request,optional"`
	MemPctLimit         *float64  `parquet:"mem_pct_limit,optional"`
	// Pod Pending sem nó: a mensagem do agendador (ex.: "0/3 nodes are available: 3 Insufficient cpu."); pod despejado
	// (Evicted): a do kubelet (ex.: "The node was low on resource: memory. ...")
	Message *string `parquet:"message,optional"`
	// Último encerramento de um container do pod (o mais recente): motivo (OOMKilled, Error...), código de saída (137:
	// morto pelo kernel) e horário. Em CrashLoopBackOff, o motivo do pod (reason) esconde o OOMKilled
	LastTerminationReason *string    `parquet:"last_termination_reason,optional"`
	LastExitCode          *int64     `parquet:"last_exit_code,optional"`
	LastTerminatedAt      *time.Time `parquet:"last_terminated_at,optional,timestamp(microsecond:local)"`
}

// HPASampleRow é o estado de um HorizontalPodAutoscaler a cada coleta, ligado ao workload que ele escala.
type HPASampleRow struct {
	TS              time.Time `parquet:"ts,timestamp(microsecond:local)"`
	WorkloadID      int64     `parquet:"workload_id"`
	NamespaceID     int64     `parquet:"namespace_id"`
	Name            string    `parquet:"name"`
	MinReplicas     int64     `parquet:"min_replicas"`
	MaxReplicas     int64     `parquet:"max_replicas"`
	CurrentReplicas int64     `parquet:"current_replicas"`
	DesiredReplicas int64     `parquet:"desired_replicas"`
}

type NodeSampleRow struct {
	TS                        time.Time `parquet:"ts,timestamp(microsecond:local)"`
	NodeID                    int64     `parquet:"node_id"`
	Ready                     bool      `parquet:"ready"`
	Unschedulable             bool      `parquet:"unschedulable"`
	CPUCapacityM              float64   `parquet:"cpu_capacity_m"`
	CPUAllocatableM           float64   `parquet:"cpu_allocatable_m"`
	CPURequestM               float64   `parquet:"cpu_request_m"`
	CPULimitM                 float64   `parquet:"cpu_limit_m"`
	CPUUsageM                 *float64  `parquet:"cpu_usage_m,optional"`
	MemCapacityBytes          int64     `parquet:"mem_capacity_bytes"`
	MemAllocatableBytes       int64     `parquet:"mem_allocatable_bytes"`
	MemRequestBytes           int64     `parquet:"mem_request_bytes"`
	MemLimitBytes             int64     `parquet:"mem_limit_bytes"`
	MemUsageBytes             *int64    `parquet:"mem_usage_bytes,optional"`
	FsCapacityBytes           *int64    `parquet:"fs_capacity_bytes,optional"`
	FsUsedBytes               *int64    `parquet:"fs_used_bytes,optional"`
	EphemeralAllocatableBytes int64     `parquet:"ephemeral_allocatable_bytes"`
	EphemeralRequestBytes     int64     `parquet:"ephemeral_request_bytes"`
	PodsCount                 int64     `parquet:"pods_count"`
	PodsCapacity              int64     `parquet:"pods_capacity"`
	// Condição MemoryPressure do nó (o kubelet começa a despejar pods) e o último evento SystemOOM do kubelet (o kernel
	// do nó matou um processo por falta de memória; nil sem o evento ou sem a permissão de ler events)
	MemoryPressure *bool      `parquet:"memory_pressure,optional"`
	LastSystemOOM  *time.Time `parquet:"last_system_oom_at,optional,timestamp(microsecond:local)"`
}

type LogRow struct {
	TS          time.Time `parquet:"ts,timestamp(microsecond:local)"`
	PodID       int64     `parquet:"pod_id"`
	WorkloadID  *int64    `parquet:"workload_id,optional"`
	NamespaceID int64     `parquet:"namespace_id"`
	Container   string    `parquet:"container"`
	Message     string    `parquet:"message"`
}

// Varredura de vulnerabilidades das imagens (security.go). A varredura é por digest: uma imagem usada por vários
// workloads é varrida uma vez só, e image_workloads liga o digest aos workloads que o usavam no início do ciclo.

// ImageWorkloadRow é o inventário do ciclo: quem usa cada imagem (todas as do ciclo, varridas agora ou não).
type ImageWorkloadRow struct {
	TS          time.Time `parquet:"ts,timestamp(microsecond:local)"` // início do ciclo
	Digest      string    `parquet:"digest"`
	Image       string    `parquet:"image"` // como está no pod (repositório:tag)
	NamespaceID int64     `parquet:"namespace_id"`
	WorkloadID  *int64    `parquet:"workload_id,optional"`
	Container   string    `parquet:"container"`
	Pods        int64     `parquet:"pods"`
}

// ImageScanRow é o resultado da varredura de um digest.
type ImageScanRow struct {
	TS         time.Time `parquet:"ts,timestamp(microsecond:local)"`
	CycleTS    time.Time `parquet:"cycle_ts,timestamp(microsecond:local)"`
	Digest     string    `parquet:"digest"`
	Image      string    `parquet:"image"`
	Node       string    `parquet:"node"`
	Status     string    `parquet:"status"` // ok, error, oom, timeout, skipped
	Error      *string   `parquet:"error,optional"`
	DurationMS int64     `parquet:"duration_ms"`
	Vulns      int64     `parquet:"vulns"`
	Critical   int64     `parquet:"critical"`
	High       int64     `parquet:"high"`
	Medium     int64     `parquet:"medium"`
	Low        int64     `parquet:"low"`
	OSFamily   *string   `parquet:"os_family,optional"`
	OSName     *string   `parquet:"os_name,optional"`
	OSEOSL     *bool     `parquet:"os_eosl,optional"` // versão do SO da imagem fora de suporte (Trivy EOSL)
}

// VulnerabilityRow é uma vulnerabilidade encontrada numa varredura (ts e digest iguais aos da ImageScanRow).
type VulnerabilityRow struct {
	TS          time.Time  `parquet:"ts,timestamp(microsecond:local)"`
	Digest      string     `parquet:"digest"`
	VulnID      string     `parquet:"vuln_id"` // CVE-..., GHSA-...
	Severity    string     `parquet:"severity"`
	Score       *float64   `parquet:"score,optional"` // maior CVSS v3 entre as fontes
	Title       *string    `parquet:"title,optional"`
	Description *string    `parquet:"description,optional"`
	URL         *string    `parquet:"url,optional"`
	Pkg         string     `parquet:"pkg"`
	Installed   string     `parquet:"installed"`
	Fixed       *string    `parquet:"fixed,optional"`
	Status      *string    `parquet:"status,optional"` // fixed, affected, will_not_fix...
	Target      string     `parquet:"target"`          // o que foi analisado: SO (debian 12.5) ou o arquivo (app.jar, requirements.txt)
	PkgPath     *string    `parquet:"pkg_path,optional"`
	Type        *string    `parquet:"type,optional"` // debian, alpine, jar, pip, npm, gobinary...
	Published   *time.Time `parquet:"published,optional,timestamp(microsecond:local)"`
}

// Tables agrupa os buffers de todas as tabelas do storage.
type Tables struct {
	Clusters    *Table[ClusterRow]
	Namespaces  *Table[NamespaceRow]
	Workloads   *Table[WorkloadRow]
	Nodes       *Table[NodeRow]
	Pods        *Table[PodRow]
	PodSamples  *Table[PodSampleRow]
	NodeSamples *Table[NodeSampleRow]
	HPASamples  *Table[HPASampleRow]
	Logs        *Table[LogRow]

	ImageWorkloads  *Table[ImageWorkloadRow]
	ImageScans      *Table[ImageScanRow]
	Vulnerabilities *Table[VulnerabilityRow]
}

func newTables() *Tables {
	return &Tables{
		Clusters:    newTable("clusters", true, func(r *ClusterRow) time.Time { return r.FirstSeen }, nil),
		Namespaces:  newTable("namespaces", true, func(r *NamespaceRow) time.Time { return r.FirstSeen }, nil),
		Workloads:   newTable("workloads", true, func(r *WorkloadRow) time.Time { return r.FirstSeen }, nil),
		Nodes:       newTable("nodes", true, func(r *NodeRow) time.Time { return r.FirstSeen }, nil),
		Pods:        newTable("pods", true, func(r *PodRow) time.Time { return r.FirstSeen }, nil),
		PodSamples:  newTable("pod_samples", true, func(r *PodSampleRow) time.Time { return r.TS }, nil),
		NodeSamples: newTable("node_samples", true, func(r *NodeSampleRow) time.Time { return r.TS }, nil),
		HPASamples:  newTable("hpa_samples", true, func(r *HPASampleRow) time.Time { return r.TS }, nil),
		// Logs ficam em um arquivo por hora: juntar o dia inteiro baixaria e subiria de novo um volume grande
		Logs: newTable("logs", false, func(r *LogRow) time.Time { return r.TS }, func(r *LogRow) int { return len(r.Message) + 64 }),

		ImageWorkloads:  newTable("image_workloads", true, func(r *ImageWorkloadRow) time.Time { return r.TS }, nil),
		ImageScans:      newTable("image_scans", true, func(r *ImageScanRow) time.Time { return r.TS }, nil),
		Vulnerabilities: newTable("vulnerabilities", true, func(r *VulnerabilityRow) time.Time { return r.TS }, nil),
	}
}

func (t *Tables) all() []anyTable {
	return []anyTable{t.Clusters, t.Namespaces, t.Workloads, t.Nodes, t.Pods, t.PodSamples, t.NodeSamples, t.HPASamples, t.Logs,
		t.ImageWorkloads, t.ImageScans, t.Vulnerabilities}
}

func ptr[T any](v T) *T { return &v }

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
