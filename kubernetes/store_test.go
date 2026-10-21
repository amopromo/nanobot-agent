package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parquet-go/parquet-go"
)

// Sem variáveis, os testes gravam num diretório temporário. Com TEST_STORAGE (ex.: s3://bucket/testes) e
// TEST_CREDENTIALS (JSON das credenciais) rodam no bucket de verdade, cada teste num cluster próprio.
func testConfig(t *testing.T) (*Config, *Credentials) {
	dir := t.TempDir()
	cfg := &Config{
		ClusterName:   "test-cluster",
		StoragePath:   dir + "/bucket",
		BufferDir:     dir + "/buffer",
		FlushInterval: time.Minute,
		RetentionDays: 30,
	}
	if remote := os.Getenv("TEST_STORAGE"); remote != "" {
		cfg.StoragePath = strings.TrimRight(remote, "/")
		cfg.ClusterName = fmt.Sprintf("%s-%d", strings.ToLower(t.Name()), time.Now().UnixNano())
		creds, err := LoadCredentials(os.Getenv("TEST_CREDENTIALS"))
		if err != nil {
			t.Fatal(err)
		}
		return cfg, creds
	}
	return cfg, nil
}

func openTestStore(t *testing.T, cfg *Config, creds *Credentials) *Store {
	t.Helper()
	blob, err := NewBlob(cfg, creds)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(cfg, blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

// readTable lê as linhas que valem de uma tabela (as mesmas regras do Nanobot) e devolve também o total de arquivos.
func readTable[T any](t *testing.T, s *Store, table string) ([]T, int) {
	t.Helper()
	ctx := context.Background()
	prefix := s.prefix + table + "/"
	keys, err := s.blob.List(ctx, prefix)
	if err != nil {
		t.Fatal(err)
	}
	var rows []T
	tmp := filepath.Join(t.TempDir(), "read.parquet")
	for _, d := range groupByDay(prefix, keys) {
		for _, f := range d.effective(-1) {
			if err := s.blob.Get(ctx, f.key, tmp); err != nil {
				t.Fatal(err)
			}
			r, err := parquet.ReadFile[T](tmp)
			if err != nil {
				t.Fatalf("%s: %v", f.key, err)
			}
			rows = append(rows, r...)
		}
	}
	return rows, len(keys)
}

func logRow(ts time.Time, msg string) LogRow {
	return LogRow{TS: ts, PodID: 1, NamespaceID: 2, Container: "app", Message: msg}
}

// Flush a cada minuto, compactação da hora fechada e, na execução seguinte, remoção dos arquivos substituídos.
func TestFlushAndCompaction(t *testing.T) {
	ctx := context.Background()
	cfg, creds := testConfig(t)
	s := openTestStore(t, cfg, creds)
	start := time.Date(2026, 10, 20, 10, 50, 0, 0, time.UTC)
	for i := range 20 { // 10:50 a 11:09
		ts := start.Add(time.Duration(i) * time.Minute)
		for j := range 10 {
			s.T.Logs.Append(logRow(ts.Add(time.Duration(j)*time.Second), fmt.Sprintf("linha %d-%d", i, j)))
		}
		if err := s.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	rows, files := readTable[LogRow](t, s, "logs")
	if len(rows) != 200 || files != 20 {
		t.Fatalf("antes da compactação: %d linhas em %d arquivos, esperado 200 em 20", len(rows), files)
	}

	// 11:20: só a hora 10 fechou (closeGrace); a 11 continua com um arquivo por flush
	s.now = func() time.Time { return time.Date(2026, 10, 20, 11, 20, 0, 0, time.UTC) }
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	rows, files = readTable[LogRow](t, s, "logs")
	if len(rows) != 200 || files != 21 {
		t.Fatalf("depois da compactação: %d linhas em %d arquivos, esperado 200 em 21 (os substituídos ainda existem)", len(rows), files)
	}
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if rows, files = readTable[LogRow](t, s, "logs"); len(rows) != 200 || files != 11 {
		t.Fatalf("depois da limpeza: %d linhas em %d arquivos, esperado 200 em 11", len(rows), files)
	}

	// Linha atrasada numa hora já compactada: aparece na hora e entra na próxima compactação
	s.now = time.Now
	s.T.Logs.Append(logRow(start.Add(time.Minute+30*time.Second), "atrasada"))
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if rows, _ = readTable[LogRow](t, s, "logs"); len(rows) != 201 {
		t.Fatalf("linha atrasada: %d linhas, esperado 201", len(rows))
	}
	s.now = func() time.Time { return time.Date(2026, 10, 20, 12, 30, 0, 0, time.UTC) }
	for range 2 {
		if err := s.Maintain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if rows, files = readTable[LogRow](t, s, "logs"); len(rows) != 201 || files != 2 {
		t.Fatalf("hora 10 e 11 compactadas: %d linhas em %d arquivos, esperado 201 em 2", len(rows), files)
	}
}

// Tabelas que não são de logs: o dia fechado vira um arquivo só. Dias fora da retenção saem do storage.
func TestDailyCompactionAndRetention(t *testing.T) {
	ctx := context.Background()
	cfg, creds := testConfig(t)
	cfg.RetentionDays = 2
	s := openTestStore(t, cfg, creds)
	day := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	for d := range 3 { // 18, 19 e 20/10
		for h := 0; h < 24; h += 6 {
			ts := day.AddDate(0, 0, d).Add(time.Duration(h) * time.Hour)
			s.T.NodeSamples.Append(NodeSampleRow{TS: ts, NodeID: 1, PodsCount: int64(h)})
			s.T.Logs.Append(logRow(ts, "x"))
			if err := s.Flush(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	// 20/10 às 23h: o dia 20 ainda está aberto (4 horas compactadas); 18 e 19 fechados
	s.now = func() time.Time { return time.Date(2026, 10, 20, 23, 0, 0, 0, time.UTC) }
	for range 2 {
		if err := s.Maintain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	rows, files := readTable[NodeSampleRow](t, s, "node_samples")
	if len(rows) != 12 || files != 2+4 { // 18 e 19 em um arquivo cada; 20 ainda com um arquivo por hora
		t.Fatalf("node_samples: %d linhas em %d arquivos, esperado 12 em 6", len(rows), files)
	}
	if _, files = readTable[LogRow](t, s, "logs"); files != 12 {
		t.Fatalf("logs: %d arquivos, esperado 12 (um por hora, sem juntar o dia)", files)
	}

	// 22/10: retenção de 2 dias apaga o 18 e o 19
	s.now = func() time.Time { return time.Date(2026, 10, 22, 1, 0, 0, 0, time.UTC) }
	for range 2 {
		if err := s.Maintain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	rows, files = readTable[NodeSampleRow](t, s, "node_samples")
	if len(rows) != 4 || files != 1 {
		t.Fatalf("retenção: %d linhas em %d arquivos, esperado 4 em 1 (só o dia 20)", len(rows), files)
	}
}

type failingBlob struct {
	Blob
	fail bool
}

func (b *failingBlob) Put(ctx context.Context, key, file string) error {
	if b.fail {
		return errors.New("storage fora do ar")
	}
	return b.Blob.Put(ctx, key, file)
}

// Storage fora do ar: os arquivos esperam no spool (inclusive entre reinícios) e sobem em ordem depois.
func TestSpoolWhileStorageDown(t *testing.T) {
	ctx := context.Background()
	cfg, creds := testConfig(t)
	s := openTestStore(t, cfg, creds)
	fb := &failingBlob{Blob: s.blob, fail: true}
	s.blob = fb
	ts := time.Now().UTC()
	for i := range 3 {
		s.T.Logs.Append(logRow(ts.Add(time.Duration(i)*time.Second), "spool"))
		if err := s.Flush(ctx); err == nil {
			t.Fatal("flush deveria falhar com o storage fora do ar")
		}
	}
	if n := s.SpoolFiles(); n != 3 {
		t.Fatalf("spool: %d arquivos, esperado 3", n)
	}
	// Reinício do container: o spool (emptyDir) continua lá
	s2 := openTestStore(t, cfg, creds)
	if err := s2.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if rows, _ := readTable[LogRow](t, s2, "logs"); len(rows) != 3 || s2.SpoolFiles() != 0 {
		t.Fatalf("depois de voltar: %d linhas, %d no spool", len(rows), s2.SpoolFiles())
	}
}

// Dimensões: uma vez por dia por id.
func TestSeenResetsDaily(t *testing.T) {
	cfg, creds := testConfig(t)
	s := openTestStore(t, cfg, creds)
	d1 := time.Date(2026, 10, 20, 23, 59, 0, 0, time.UTC)
	if s.Seen("pods", 1, d1) || !s.Seen("pods", 1, d1) {
		t.Fatal("Seen deveria marcar na primeira vez")
	}
	if s.Seen("pods", 1, d1.Add(2*time.Minute)) {
		t.Fatal("no dia seguinte o pod deveria ser gravado de novo")
	}
}

func TestLayout(t *testing.T) {
	d := &dayFiles{day: "2026-10-20"}
	add := func(rel string) {
		fi, ok := parseKey(rel)
		if !ok {
			t.Fatalf("parseKey(%q) falhou", rel)
		}
		fi.key = rel
		d.files = append(d.files, fi)
	}
	add("dt=2026-10-20/hh=10/100.parquet")
	add("dt=2026-10-20/hh=10/200.parquet")
	add("dt=2026-10-20/hh=10/c200.parquet") // junta 100 e 200
	add("dt=2026-10-20/hh=10/300.parquet")  // atrasado
	add("dt=2026-10-20/hh=11/150.parquet")
	keys := func(fs []fileInfo) string {
		var out []string
		for _, f := range fs {
			out = append(out, f.key)
		}
		return strings.Join(out, " ")
	}
	if got := keys(d.effective(-1)); got != "dt=2026-10-20/hh=11/150.parquet dt=2026-10-20/hh=10/c200.parquet dt=2026-10-20/hh=10/300.parquet" {
		t.Errorf("efetivos do dia: %s", got)
	}
	add("dt=2026-10-20/c300.parquet") // o dia inteiro até 300
	add("dt=2026-10-20/hh=12/400.parquet")
	if got := keys(d.effective(-1)); got != "dt=2026-10-20/c300.parquet dt=2026-10-20/hh=12/400.parquet" {
		t.Errorf("efetivos com o dia compactado: %s", got)
	}
	for _, bad := range []string{"dt=2026-10-20/100.parquet", "dt=x/hh=10/1.parquet", "dt=2026-10-20/hh=24/1.parquet", "dt=2026-10-20/hh=10/a.parquet", "dt=2026-10-20/hh=10/1.parquet.tmp"} {
		if _, ok := parseKey(bad); ok {
			t.Errorf("parseKey(%q) deveria falhar", bad)
		}
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		`Unable to connect to Postgres at "host=db port=5432 user=k password=s3cr3t": refused`: `Unable to connect to Postgres at "host=db port=5432 user=k password=***": refused`,
		`LINE 1: CREATE SECRET (TYPE s3, KEY_ID 'AKIA', SECRET 'abc', REGION 'x')`:             `LINE 1: CREATE SECRET (TYPE s3, KEY_ID ***, SECRET ***, REGION 'x')`,
		`postgres://user:p4ss@host/db`: `postgres://user:***@host/db`,
		`the secret manager failed`:    `the secret manager failed`,
	}
	for in, want := range cases {
		if got := redact(in); got != want {
			t.Errorf("redact(%q) = %q, esperado %q", in, got, want)
		}
	}
}

// Arquivos gravados antes da coluna message (agente 0.3.x) entram na compactação junto com os novos.
func TestMergeOldPodSamples(t *testing.T) {
	type oldPodSample struct {
		TS          time.Time `parquet:"ts,timestamp(microsecond:local)"`
		PodID       int64     `parquet:"pod_id"`
		WorkloadID  *int64    `parquet:"workload_id,optional"`
		NamespaceID int64     `parquet:"namespace_id"`
		Phase       string    `parquet:"phase"`
		Ready       bool      `parquet:"ready"`
		Restarts    int64     `parquet:"restarts"`
		Reason      *string   `parquet:"reason,optional"`
		CPUUsageM   *float64  `parquet:"cpu_usage_m,optional"`
	}
	dir := t.TempDir()
	ts := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	old := filepath.Join(dir, "old.parquet")
	if err := parquet.WriteFile(old, []oldPodSample{{TS: ts, PodID: 1, NamespaceID: 9, Phase: "Running", Ready: true, CPUUsageM: ptr(12.5)}}); err != nil {
		t.Fatal(err)
	}
	cur := filepath.Join(dir, "new.parquet")
	if err := parquet.WriteFile(cur, []PodSampleRow{{TS: ts.Add(time.Minute), PodID: 2, NamespaceID: 9, Phase: "Pending",
		Reason: ptr("Unschedulable"), Message: ptr("0/1 nodes are available: 1 Insufficient memory.")}}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "merged.parquet")
	if err := newTables().PodSamples.merge(out, []string{old, cur}); err != nil {
		t.Fatal(err)
	}
	rows, err := parquet.ReadFile[PodSampleRow](out)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].PodID != 1 || rows[0].Message != nil || rows[0].CPUUsageM == nil || *rows[0].CPUUsageM != 12.5 ||
		rows[1].Message == nil || *rows[1].Reason != "Unschedulable" {
		t.Errorf("merge com o esquema antigo: %+v", rows)
	}
}
