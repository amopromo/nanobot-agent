package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

// LogManager acompanha os logs de cada container pela API (kubectl logs -f com timestamps).
// Um stream por container; reconecta enquanto o pod existir e termina quando o pod encerrado já foi lido inteiro.
// As linhas vão direto para o buffer da tabela logs (gravado a cada flush).
type LogManager struct {
	c       *Collector
	started time.Time

	mu      sync.Mutex
	streams map[string]context.CancelFunc // uid/container
	done    map[string]bool               // containers de pods encerrados já lidos até o fim
}

func NewLogManager(c *Collector) *LogManager {
	return &LogManager{
		c:       c,
		started: time.Now(),
		streams: map[string]context.CancelFunc{},
		done:    map[string]bool{},
	}
}

func (lm *LogManager) wanted(ns string) bool {
	cfg := lm.c.cfg
	if cfg.ExcludeNS[ns] || cfg.LogExcludeNS[ns] {
		return false
	}
	return len(cfg.LogNamespaces) == 0 || cfg.LogNamespaces[ns]
}

// Run liga os streams pelos eventos do informer (pods de CronJob que duram segundos não esperam a próxima coleta).
func (lm *LogManager) Run(ctx context.Context) {
	lm.c.podInform.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { lm.onPod(ctx, obj) },
		UpdateFunc: func(_, obj any) { lm.onPod(ctx, obj) },
		DeleteFunc: func(obj any) {
			if t, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = t.Obj
			}
			if p, ok := obj.(*corev1.Pod); ok {
				lm.stopPod(string(p.UID))
			}
		},
	})
	<-ctx.Done()
}

func (lm *LogManager) onPod(ctx context.Context, obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok || !lm.wanted(pod.Namespace) || isScanPod(pod) {
		return
	}
	statuses := append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
	for _, cs := range statuses {
		// Só depois que o container subiu: antes disso a API responde "waiting to start"
		if cs.State.Running == nil && cs.State.Terminated == nil && cs.LastTerminationState.Terminated == nil {
			continue
		}
		key := string(pod.UID) + "/" + cs.Name
		lm.mu.Lock()
		_, running := lm.streams[key]
		if running || lm.done[key] {
			lm.mu.Unlock()
			continue
		}
		sctx, cancel := context.WithCancel(ctx)
		lm.streams[key] = cancel
		lm.mu.Unlock()
		go lm.stream(sctx, key, pod.Namespace, pod.Name, pod.UID, cs.Name, pod.CreationTimestamp.Time)
	}
}

func (lm *LogManager) stopPod(uid string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	for key, cancel := range lm.streams {
		if strings.HasPrefix(key, uid+"/") {
			cancel()
			delete(lm.streams, key)
		}
	}
	for key := range lm.done {
		if strings.HasPrefix(key, uid+"/") {
			delete(lm.done, key)
		}
	}
}

func (lm *LogManager) stream(ctx context.Context, key, ns, name string, uid types.UID, container string, created time.Time) {
	defer func() {
		lm.mu.Lock()
		delete(lm.streams, key)
		lm.mu.Unlock()
	}()

	// Pod que já existia quando o agente subiu: só o que vier daqui pra frente (evita reler logs já gravados)
	var last time.Time
	if created.Before(lm.started) {
		last = lm.started
	}
	for {
		pod, err := lm.c.pods.Pods(ns).Get(name)
		if err != nil || pod.UID != uid {
			return
		}
		terminal := pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed
		ref := lm.c.RegisterPod(pod, time.Now().UTC().Truncate(time.Second))

		opts := &corev1.PodLogOptions{Container: container, Follow: !terminal, Timestamps: true}
		if !last.IsZero() {
			t := metav1.NewTime(last)
			opts.SinceTime = &t
		}
		rc, err := lm.c.cs.CoreV1().Pods(ns).GetLogs(name, opts).Stream(ctx)
		if err == nil {
			last, err = lm.read(rc, ref, container, last)
			rc.Close()
		}
		if ctx.Err() != nil {
			return
		}
		if apierrors.IsNotFound(err) {
			return
		}
		if err == nil && terminal {
			lm.mu.Lock()
			lm.done[key] = true
			lm.mu.Unlock()
			return
		}
		if err != nil && !errors.Is(err, io.EOF) {
			slog.Debug("stream de log", "pod", ns+"/"+name, "container", container, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// read devolve o timestamp da última linha; linhas com timestamp <= last são repetição (o sinceTime da API é por segundo).
func (lm *LogManager) read(r io.Reader, ref podRef, container string, last time.Time) (time.Time, error) {
	// Buffer pequeno: são centenas de streams abertos; linhas maiores são montadas em partes (readLine)
	br := bufio.NewReaderSize(r, 4096)
	maxLen := lm.c.cfg.LogMaxLineBytes
	for {
		line, err := readLine(br, maxLen)
		if len(line) > 0 {
			sp := strings.IndexByte(line, ' ')
			ts, perr := time.Time{}, error(nil)
			msg := line
			if sp > 0 {
				ts, perr = time.Parse(time.RFC3339Nano, line[:sp])
				msg = line[sp+1:]
			}
			if sp <= 0 || perr != nil {
				ts, msg = time.Now(), line
			}
			ts = ts.UTC()
			if ts.After(last) {
				last = ts
				lm.c.store.T.Logs.Append(LogRow{TS: ts, PodID: ref.id, WorkloadID: ref.workloadID, NamespaceID: ref.namespaceID,
					Container: container, Message: msg})
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return last, nil
			}
			return last, err
		}
	}
}

// readLine lê uma linha inteira, guardando no máximo maxLen bytes (o resto da linha é descartado).
func readLine(br *bufio.Reader, maxLen int) (string, error) {
	var sb strings.Builder
	for {
		chunk, isPrefix, err := br.ReadLine()
		if room := maxLen - sb.Len(); room > 0 {
			if len(chunk) > room {
				chunk = chunk[:room]
			}
			sb.Write(chunk)
		}
		if err != nil || !isPrefix {
			return strings.ToValidUTF8(sb.String(), "�"), err
		}
	}
}
