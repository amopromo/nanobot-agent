package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

// Config vem das variáveis de ambiente (ConfigMap do chart helm).
type Config struct {
	ClusterName        string
	StoragePath        string // s3://bucket/prefixo, gs://..., r2://... ou um diretório local (desenvolvimento)
	CredentialsFile    string // JSON do Secret com as credenciais do storage
	BufferDir          string // spool dos arquivos que ainda não subiram e área da compactação (emptyDir)
	SampleInterval     time.Duration
	FlushInterval      time.Duration
	MaintainInterval   time.Duration   // compactação dos arquivos de cada flush e retenção
	Reactive           bool            // mudança de estado de pod/HPA dispara uma coleta e um envio na hora
	ReactiveMinGap     time.Duration   // intervalo mínimo entre duas coletas (protege o storage em rajadas)
	RetentionDays      int             // dias guardados no storage (0, padrão: não apaga; a retenção é do clean_logs.py do Nanobot)
	ExcludeNS          map[string]bool // namespaces ignorados (pods, workloads e logs); entram só no total dos nós
	LogsEnabled        bool
	LogNamespaces      map[string]bool // vazio: todos
	LogExcludeNS       map[string]bool
	LogMaxLineBytes    int
	SummaryConcurrency int
	HealthAddr         string

	// Varredura de vulnerabilidades (security.go): ligada e agendada pelo Nanobot (_config/security.json); aqui só o
	// que vem do chart (imagens, limites e o namespace dos Jobs)
	SecurityScan          bool
	PodNamespace          string // namespace do agente (downward API): onde os Jobs rodam
	AgentImage            string // imagem do próprio agente (helper dos Jobs)
	TrivyImage            string
	TrivyDBRepository     string // vazio: o padrão do Trivy (mirror.gcr.io, depois ghcr.io)
	TrivyJavaDBRepository string
	ScanPriorityClass     string
	ScanCPURequest        string
	ScanCPULimit          string
	ScanMemoryRequest     string
	ScanMemoryLimit       string
	ScanMemoryLimitRetry  string // segunda tentativa de uma imagem que estourou a memória
	ScanWorkdirSize       string // emptyDir do Job: banco do Trivy (~1,5 GB) e, com .jar nas imagens, o banco Java (~1,5 GB)
	ScanImagesPerJob      int
	ScanImageTimeout      time.Duration
	ScanJobGap            time.Duration // pausa entre dois Jobs
	ScanConfigInterval    time.Duration // leitura do _config/security.json
}

// Componentes do próprio Kubernetes (coredns, kube-proxy, etcd...). EXCLUDE_NAMESPACES="" coleta todos.
const defaultExcludeNS = "kube-system,kube-public,kube-node-lease"

var clusterNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$`)

func LoadConfig() (*Config, error) {
	c := &Config{
		ClusterName:     os.Getenv("CLUSTER_NAME"),
		StoragePath:     strings.TrimRight(os.Getenv("STORAGE_PATH"), "/"),
		CredentialsFile: env("CREDENTIALS_FILE", "/etc/nanobot-k8s/credentials.json"),
		BufferDir:       env("BUFFER_DIR", "/data"),
		ExcludeNS:       csvSet(envDefault("EXCLUDE_NAMESPACES", defaultExcludeNS)),
		LogNamespaces:   csvSet(os.Getenv("LOG_NAMESPACES")),
		LogExcludeNS:    csvSet(os.Getenv("LOG_EXCLUDE_NAMESPACES")),
		HealthAddr:      env("HEALTH_ADDR", ":8080"),

		PodNamespace:          os.Getenv("POD_NAMESPACE"),
		AgentImage:            os.Getenv("AGENT_IMAGE"),
		TrivyImage:            env("TRIVY_IMAGE", "aquasec/trivy:0.75.0"),
		TrivyDBRepository:     os.Getenv("TRIVY_DB_REPOSITORY"),
		TrivyJavaDBRepository: os.Getenv("TRIVY_JAVA_DB_REPOSITORY"),
		ScanPriorityClass:     os.Getenv("SCAN_PRIORITY_CLASS"),
		ScanCPURequest:        env("SCAN_CPU_REQUEST", "50m"),
		ScanCPULimit:          env("SCAN_CPU_LIMIT", "500m"),
		ScanMemoryRequest:     env("SCAN_MEMORY_REQUEST", "128Mi"),
		ScanMemoryLimit:       env("SCAN_MEMORY_LIMIT", "384Mi"),
		ScanMemoryLimitRetry:  env("SCAN_MEMORY_LIMIT_RETRY", "768Mi"),
		ScanWorkdirSize:       env("SCAN_WORKDIR_SIZE", "4Gi"),
	}
	var err error
	if c.SampleInterval, err = envDuration("SAMPLE_INTERVAL", time.Minute); err != nil {
		return nil, err
	}
	if c.FlushInterval, err = envDuration("FLUSH_INTERVAL", time.Minute); err != nil {
		return nil, err
	}
	if c.Reactive, err = strconv.ParseBool(env("REACTIVE", "true")); err != nil {
		return nil, fmt.Errorf("REACTIVE: %w", err)
	}
	if c.ReactiveMinGap, err = envDuration("REACTIVE_MIN_INTERVAL", 10*time.Second); err != nil {
		return nil, err
	}
	if c.MaintainInterval, err = envDuration("MAINTENANCE_INTERVAL", 10*time.Minute); err != nil {
		return nil, err
	}
	if c.LogsEnabled, err = strconv.ParseBool(env("LOGS_ENABLED", "true")); err != nil {
		return nil, fmt.Errorf("LOGS_ENABLED: %w", err)
	}
	if c.LogMaxLineBytes, err = strconv.Atoi(env("LOG_MAX_LINE_BYTES", "16384")); err != nil {
		return nil, fmt.Errorf("LOG_MAX_LINE_BYTES: %w", err)
	}
	if c.RetentionDays, err = strconv.Atoi(env("RETENTION_DAYS", "0")); err != nil || c.RetentionDays < 0 {
		return nil, fmt.Errorf("RETENTION_DAYS inválido: %q", os.Getenv("RETENTION_DAYS"))
	}
	if c.SummaryConcurrency, err = strconv.Atoi(env("SUMMARY_CONCURRENCY", "8")); err != nil {
		return nil, fmt.Errorf("SUMMARY_CONCURRENCY: %w", err)
	}

	if c.SecurityScan, err = strconv.ParseBool(env("SECURITY_SCAN", "true")); err != nil {
		return nil, fmt.Errorf("SECURITY_SCAN: %w", err)
	}
	if c.ScanImagesPerJob, err = strconv.Atoi(env("SCAN_IMAGES_PER_JOB", "8")); err != nil || c.ScanImagesPerJob < 1 {
		return nil, fmt.Errorf("SCAN_IMAGES_PER_JOB inválido: %q", os.Getenv("SCAN_IMAGES_PER_JOB"))
	}
	if c.ScanImageTimeout, err = envDuration("SCAN_IMAGE_TIMEOUT", 5*time.Minute); err != nil {
		return nil, err
	}
	if c.ScanJobGap, err = envDuration("SCAN_JOB_GAP", 30*time.Second); err != nil {
		return nil, err
	}
	if c.ScanConfigInterval, err = envDuration("SCAN_CONFIG_INTERVAL", 5*time.Minute); err != nil {
		return nil, err
	}
	for _, q := range []struct{ name, v string }{{"SCAN_CPU_REQUEST", c.ScanCPURequest}, {"SCAN_CPU_LIMIT", c.ScanCPULimit},
		{"SCAN_MEMORY_REQUEST", c.ScanMemoryRequest}, {"SCAN_MEMORY_LIMIT", c.ScanMemoryLimit},
		{"SCAN_MEMORY_LIMIT_RETRY", c.ScanMemoryLimitRetry}, {"SCAN_WORKDIR_SIZE", c.ScanWorkdirSize}} {
		if _, qerr := resource.ParseQuantity(q.v); qerr != nil {
			return nil, fmt.Errorf("%s inválido: %q", q.name, q.v)
		}
	}

	if !clusterNameRe.MatchString(c.ClusterName) {
		return nil, fmt.Errorf("CLUSTER_NAME inválido ou vazio (letras, números, '.', '_' e '-'): %q", c.ClusterName)
	}
	if c.StoragePath == "" {
		return nil, fmt.Errorf("STORAGE_PATH vazio")
	}
	return c, nil
}

// Remote indica se o storage é um bucket (precisa das credenciais).
func (c *Config) Remote() bool { return strings.Contains(c.StoragePath, "://") }

// ClusterPath é a pasta deste cluster no storage: o mesmo bucket atende vários clusters.
func (c *Config) ClusterPath() string { return c.StoragePath + "/" + c.ClusterName }

// Credentials é o JSON do Secret. O mesmo formato é cadastrado no Nanobot (Admin > Kubernetes).
type Credentials struct {
	Type         string `json:"type"` // s3 (padrão, também MinIO/Ceph), gcs (chave HMAC) ou r2
	KeyID        string `json:"key_id"`
	Secret       string `json:"secret"`
	SessionToken string `json:"session_token"`
	Region       string `json:"region"`
	Endpoint     string `json:"endpoint"`
	URLStyle     string `json:"url_style"` // vhost ou path (MinIO costuma usar path)
	UseSSL       *bool  `json:"use_ssl"`
	AccountID    string `json:"account_id"` // só r2
}

func LoadCredentials(path string) (*Credentials, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("credenciais inválidas em %s: %w", path, err)
	}
	if c.Type == "" {
		c.Type = "s3"
	}
	switch c.Type {
	case "s3", "gcs", "r2":
	default:
		return nil, fmt.Errorf("type %q não suportado (s3, gcs ou r2)", c.Type)
	}
	return &c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envDefault é como env, mas a variável definida e vazia vale como vazia.
func envDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s inválido: %q", key, v)
	}
	return d, nil
}

func csvSet(v string) map[string]bool {
	set := map[string]bool{}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			set[p] = true
		}
	}
	return set
}
