package main

import (
	"context"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

// Eventos SystemOOM do kubelet: o kernel do nó matou um processo por falta de memória no nó (e não no limit do
// container). O watch traz só esses eventos (field selector), e o cache guarda só o nome do nó e o horário.
const systemOOMSelector = "involvedObject.kind=Node,reason=SystemOOM"

func (c *Collector) startSystemOOM(ctx context.Context) {
	opts := metav1.ListOptions{FieldSelector: systemOOMSelector, Limit: 1}
	if _, err := c.cs.CoreV1().Events("").List(ctx, opts); err != nil {
		// chart antigo (sem RBAC de events): o resto da coleta segue
		slog.Warn("eventos SystemOOM dos nós não serão coletados (sem acesso a events)", "error", redact(err.Error()))
		return
	}
	f := informers.NewSharedInformerFactoryWithOptions(c.cs, 0,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.FieldSelector = systemOOMSelector }),
		informers.WithTransform(slimEvent))
	inf := f.Core().V1().Events().Informer()
	record := func(obj any) {
		if e, ok := obj.(*corev1.Event); ok && e.Reason == "SystemOOM" && e.InvolvedObject.Kind == "Node" {
			c.recordSystemOOM(e.InvolvedObject.Name, eventTime(e))
		}
	}
	inf.AddEventHandler(cache.ResourceEventHandlerFuncs{AddFunc: record, UpdateFunc: func(_, cur any) { record(cur) }})
	f.Start(ctx.Done())
	// A lista inicial costuma ser pequena (o field selector filtra no servidor); sem sincronizar, a coleta segue e os
	// eventos chegam depois
	sync, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !cache.WaitForCacheSync(sync.Done(), inf.HasSynced) {
		slog.Warn("eventos SystemOOM dos nós ainda não sincronizaram")
	}
}

func slimEvent(obj any) (any, error) {
	e, ok := obj.(*corev1.Event)
	if !ok {
		return obj, nil
	}
	out := &corev1.Event{
		ObjectMeta:     slimMeta(e.ObjectMeta),
		InvolvedObject: corev1.ObjectReference{Kind: e.InvolvedObject.Kind, Name: e.InvolvedObject.Name},
		Reason:         e.Reason, FirstTimestamp: e.FirstTimestamp, LastTimestamp: e.LastTimestamp, EventTime: e.EventTime,
	}
	if e.Series != nil {
		out.Series = &corev1.EventSeries{LastObservedTime: e.Series.LastObservedTime}
	}
	return out, nil
}

// eventTime: a última ocorrência (eventos repetidos atualizam lastTimestamp ou series).
func eventTime(e *corev1.Event) time.Time {
	t := e.LastTimestamp.Time
	if e.Series != nil && e.Series.LastObservedTime.After(t) {
		t = e.Series.LastObservedTime.Time
	}
	if e.EventTime.After(t) {
		t = e.EventTime.Time
	}
	if t.IsZero() {
		t = e.FirstTimestamp.Time
	}
	return t.UTC()
}

func (c *Collector) recordSystemOOM(node string, at time.Time) {
	if node == "" || at.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.systemOOM == nil {
		c.systemOOM = map[string]time.Time{}
	}
	if at.After(c.systemOOM[node]) {
		c.systemOOM[node] = at
	}
}

func (c *Collector) lastSystemOOM(node string) *time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.systemOOM[node]; ok {
		return &t
	}
	return nil
}
