package main

import "time"

// Tabelas gravadas no storage. Os dados fixos (cluster, namespace, workload, nó, pod) ficam só nas dimensões; os fatos
// (pod_samples, node_samples, logs) guardam os ids. Os ids são hashes estáveis (ids.go).
// O Nanobot (app/core/k8s_storage.py) tem as mesmas colunas: uma coluna nova precisa entrar nos dois.
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
}

type LogRow struct {
	TS          time.Time `parquet:"ts,timestamp(microsecond:local)"`
	PodID       int64     `parquet:"pod_id"`
	WorkloadID  *int64    `parquet:"workload_id,optional"`
	NamespaceID int64     `parquet:"namespace_id"`
	Container   string    `parquet:"container"`
	Message     string    `parquet:"message"`
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
	Logs        *Table[LogRow]
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
		// Logs ficam em um arquivo por hora: juntar o dia inteiro baixaria e subiria de novo um volume grande
		Logs: newTable("logs", false, func(r *LogRow) time.Time { return r.TS }, func(r *LogRow) int { return len(r.Message) + 64 }),
	}
}

func (t *Tables) all() []anyTable {
	return []anyTable{t.Clusters, t.Namespaces, t.Workloads, t.Nodes, t.Pods, t.PodSamples, t.NodeSamples, t.Logs}
}

func ptr[T any](v T) *T { return &v }

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
