package main

import (
	"hash/fnv"
	"strings"
)

// Ids estáveis (FNV-64a dos campos que identificam o item): o mesmo namespace/workload/nó/pod gera sempre
// o mesmo id, então reinícios do agente não duplicam as dimensões. Positivos para caber num BIGINT.
func stableID(kind string, parts ...string) int64 {
	h := fnv.New64a()
	h.Write([]byte(kind + "\x00" + strings.Join(parts, "\x00")))
	return int64(h.Sum64() & 0x7fffffffffffffff)
}

func clusterID(cluster string) int64 { return stableID("cluster", cluster) }

func namespaceID(cluster, ns string) int64 { return stableID("namespace", cluster, ns) }

func workloadID(cluster, ns, kind, name string) int64 {
	return stableID("workload", cluster, ns, kind, name)
}

func nodeID(cluster, node string) int64 { return stableID("node", cluster, node) }

// O uid diferencia pods recriados com o mesmo nome (StatefulSet).
func podID(cluster, uid string) int64 { return stableID("pod", cluster, uid) }
