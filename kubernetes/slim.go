package main

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Transformações dos informers: o cache guarda só os campos que a coleta e os logs usam. Num pod típico isso tira
// env, volumes, probes, imagens, anotações e managedFields; num nó, a lista de imagens (que costuma ser o maior campo).

func slimObject(obj any) (any, error) {
	switch o := obj.(type) {
	case *corev1.Pod:
		return slimPod(o), nil
	case *corev1.Node:
		return slimNode(o), nil
	}
	return obj, nil
}

func slimMeta(m metav1.ObjectMeta) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: m.Name, Namespace: m.Namespace, UID: m.UID, ResourceVersion: m.ResourceVersion,
		CreationTimestamp: m.CreationTimestamp, DeletionTimestamp: m.DeletionTimestamp, OwnerReferences: m.OwnerReferences,
	}
}

func slimMetadata(obj any) (any, error) {
	if m, ok := obj.(*metav1.PartialObjectMetadata); ok {
		return &metav1.PartialObjectMetadata{TypeMeta: m.TypeMeta, ObjectMeta: slimMeta(m.ObjectMeta)}, nil
	}
	return obj, nil
}

func slimContainers(cs []corev1.Container) []corev1.Container {
	if len(cs) == 0 {
		return nil
	}
	out := make([]corev1.Container, len(cs))
	for i, c := range cs {
		out[i] = corev1.Container{Name: c.Name, Resources: corev1.ResourceRequirements{Requests: c.Resources.Requests, Limits: c.Resources.Limits},
			RestartPolicy: c.RestartPolicy}
	}
	return out
}

func slimState(s corev1.ContainerState) corev1.ContainerState {
	var out corev1.ContainerState
	if s.Running != nil {
		out.Running = &corev1.ContainerStateRunning{StartedAt: s.Running.StartedAt}
	}
	if s.Waiting != nil {
		out.Waiting = &corev1.ContainerStateWaiting{Reason: s.Waiting.Reason}
	}
	if s.Terminated != nil {
		out.Terminated = &corev1.ContainerStateTerminated{Reason: s.Terminated.Reason, ExitCode: s.Terminated.ExitCode}
	}
	return out
}

func slimStatuses(ss []corev1.ContainerStatus) []corev1.ContainerStatus {
	if len(ss) == 0 {
		return nil
	}
	out := make([]corev1.ContainerStatus, len(ss))
	for i, s := range ss {
		out[i] = corev1.ContainerStatus{Name: s.Name, Ready: s.Ready, RestartCount: s.RestartCount,
			State: slimState(s.State), LastTerminationState: slimState(s.LastTerminationState)}
	}
	return out
}

func slimPod(p *corev1.Pod) *corev1.Pod {
	out := &corev1.Pod{
		TypeMeta:   p.TypeMeta,
		ObjectMeta: slimMeta(p.ObjectMeta),
		Spec: corev1.PodSpec{
			NodeName: p.Spec.NodeName, Overhead: p.Spec.Overhead,
			Containers: slimContainers(p.Spec.Containers), InitContainers: slimContainers(p.Spec.InitContainers),
		},
		Status: corev1.PodStatus{
			Phase: p.Status.Phase, Reason: p.Status.Reason,
			ContainerStatuses: slimStatuses(p.Status.ContainerStatuses), InitContainerStatuses: slimStatuses(p.Status.InitContainerStatuses),
		},
	}
	// Deployment com o ReplicaSet já removido: o nome do workload sai do pod-template-hash
	if h := p.Labels["pod-template-hash"]; h != "" {
		out.Labels = map[string]string{"pod-template-hash": h}
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			out.Status.Conditions = []corev1.PodCondition{{Type: c.Type, Status: c.Status}}
		}
	}
	return out
}

func slimNode(n *corev1.Node) *corev1.Node {
	out := &corev1.Node{
		TypeMeta:   n.TypeMeta,
		ObjectMeta: slimMeta(n.ObjectMeta),
		Spec:       corev1.NodeSpec{Unschedulable: n.Spec.Unschedulable},
		Status:     corev1.NodeStatus{Capacity: n.Status.Capacity, Allocatable: n.Status.Allocatable},
	}
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			out.Status.Conditions = []corev1.NodeCondition{{Type: c.Type, Status: c.Status}}
		}
	}
	return out
}
