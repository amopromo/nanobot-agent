// nanobot-k8s-monitoring: coleta logs, uso de CPU/memória/disco e status dos pods e nós de um cluster
// Kubernetes e grava em Parquet no storage (S3, GCS, R2), numa pasta por cluster. O Nanobot lê com o DuckDB.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	level := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(redactHandler{slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})}))
	if helper, code := runScanHelper(os.Args); helper {
		os.Exit(code)
	}
	setMemoryLimit()
	if err := run(); err != nil {
		slog.Error("agente encerrado", "err", err)
		os.Exit(1)
	}
}

// setMemoryLimit faz o GC trabalhar abaixo do limit do container (MEMORY_LIMIT_BYTES vem do resourceFieldRef do chart)
// em vez de deixar o heap dobrar até o OOM. GOMEMLIMIT, se definido, tem prioridade.
func setMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	if v, err := strconv.ParseInt(os.Getenv("MEMORY_LIMIT_BYTES"), 10, 64); err == nil && v > 0 {
		debug.SetMemoryLimit(v * 85 / 100)
	}
}

func run() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var creds *Credentials
	if cfg.Remote() {
		if creds, err = LoadCredentials(cfg.CredentialsFile); err != nil {
			return fmt.Errorf("credenciais do storage: %w", err)
		}
	}
	blob, err := NewBlob(cfg, creds)
	if err != nil {
		return err
	}
	encrypted := creds != nil && creds.EncryptionKey != ""
	if encrypted {
		if blob, err = newCryptBlob(blob, creds, filepath.Join(cfg.BufferDir, "crypt")); err != nil {
			return fmt.Errorf("credenciais do storage: %w", err)
		}
	}
	store, err := NewStore(cfg, blob)
	if err != nil {
		return err
	}
	// Storage fora do ar na subida não impede a coleta: os arquivos esperam no spool
	if err := store.Init(ctx); err != nil {
		slog.Error("leitura do storage", "err", err)
	}

	kcfg, err := kubeConfig()
	if err != nil {
		return err
	}
	kcfg.UserAgent = "nanobot-k8s-monitoring"
	mc, err := metadata.NewForConfig(kcfg)
	if err != nil {
		return err
	}
	// Protobuf: decodificar a lista inicial de pods e os eventos gasta menos CPU e memória que JSON
	pcfg := rest.CopyConfig(kcfg)
	pcfg.ContentType = "application/vnd.kubernetes.protobuf"
	pcfg.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	cs, err := kubernetes.NewForConfig(pcfg)
	if err != nil {
		return err
	}

	col := NewCollector(cfg, cs, mc, store)
	var logs *LogManager
	if cfg.LogsEnabled {
		logs = NewLogManager(col)
		go logs.Run(ctx) // registra o handler do informer antes de iniciar
	}
	if err := col.Start(ctx); err != nil {
		return err
	}
	retention := "nanobot (clean_logs.py)"
	if cfg.RetentionDays > 0 {
		retention = fmt.Sprintf("agent, %d days", cfg.RetentionDays)
	}
	slog.Info("agente iniciado", "cluster", cfg.ClusterName, "storage", cfg.ClusterPath(), "retention", retention,
		"sample_interval", cfg.SampleInterval.String(), "flush_interval", cfg.FlushInterval.String(), "reactive", cfg.Reactive,
		"logs", cfg.LogsEnabled, "security_scan", cfg.SecurityScan, "encrypted", encrypted)

	go serveHealth(cfg, col, store)
	if cfg.SecurityScan {
		go NewSecurity(cfg, col, store).Run(ctx)
	}

	sampleTick := time.NewTicker(cfg.SampleInterval)
	flushTick := time.NewTicker(cfg.FlushInterval)
	maintainTick := time.NewTicker(cfg.MaintainInterval)
	defer sampleTick.Stop()
	defer flushTick.Stop()
	defer maintainTick.Stop()
	lastSample := time.Now()
	sample := func() {
		if err := col.Sample(ctx); err != nil {
			slog.Error("coleta", "err", err)
		}
		lastSample = time.Now()
	}
	// Coleta reativa: junta a rajada de mudanças (um rollout muda vários pods) e respeita o intervalo mínimo
	var reactive <-chan time.Time
	const burst = 2 * time.Second
	maintain := func() {
		// Em paralelo: juntar uma hora de logs pode levar mais que o intervalo da coleta
		go func() {
			if err := store.Maintain(ctx); err != nil {
				slog.Error("manutenção do storage", "err", err)
			}
		}()
	}
	sample()
	maintain()
	for {
		select {
		case <-ctx.Done():
			// Grava o que ficou no buffer antes de sair (o pod tem terminationGracePeriodSeconds para isso)
			fctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			if err := store.Flush(fctx); err != nil {
				slog.Error("flush final", "err", err)
			}
			cancel()
			return nil
		case <-sampleTick.C:
			sample()
		case <-col.Changes():
			if cfg.Reactive && reactive == nil {
				reactive = time.After(max(burst, cfg.ReactiveMinGap-time.Since(lastSample)))
			}
		case <-reactive:
			reactive = nil
			if err := col.SampleReactive(ctx); err != nil {
				slog.Error("coleta reativa", "err", err)
			}
			lastSample = time.Now()
			if err := store.Flush(ctx); err != nil {
				slog.Error("flush", "err", err, "spool_files", store.SpoolFiles())
			}
		case <-flushTick.C:
			if err := store.Flush(ctx); err != nil {
				slog.Error("flush", "err", err, "spool_files", store.SpoolFiles())
			}
		case <-maintainTick.C:
			maintain()
		}
	}
}

func kubeConfig() (*rest.Config, error) {
	if c, err := rest.InClusterConfig(); err == nil {
		return c, nil
	}
	// Fora do cluster (desenvolvimento): usa o KUBECONFIG/~/.kube/config
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
}

// serveHealth responde 200 enquanto a coleta está em dia (liveness/readiness do Deployment). O flush atrasado (storage
// fora do ar) aparece na resposta mas não derruba o pod: reiniciar não resolve e os dados estão seguros no spool.
func serveHealth(cfg *Config, col *Collector, store *Store) {
	limit := 5 * cfg.SampleInterval
	started := time.Now()
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		sample, flush := col.LastSampleOK(), store.LastFlushOK()
		if (sample.IsZero() && time.Since(started) > limit) || (!sample.IsZero() && time.Since(sample) > limit) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		fmt.Fprintf(w, "last_sample=%s last_flush=%s pending_rows=%d spool_files=%d\n", sample.Format(time.RFC3339),
			flush.Format(time.RFC3339), store.Pending(), store.SpoolFiles())
	})
	if err := http.ListenAndServe(cfg.HealthAddr, nil); err != nil {
		slog.Error("health server", "err", err)
	}
}
