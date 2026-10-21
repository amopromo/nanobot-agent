package main

// Armazenamento em Parquet direto no storage, numa pasta por cluster (<STORAGE_PATH>/<CLUSTER_NAME>/, layout.go).
// O agente só grava; o Nanobot lê os arquivos com o DuckDB.
//
// As linhas novas ficam num buffer em memória. A cada flush viram arquivos Parquet no spool (BUFFER_DIR/spool, um
// emptyDir) e sobem para o storage em ordem de stamp; se o storage estiver fora do ar, ficam no spool e sobem no próximo
// flush (sobrevivem a um restart do container). A manutenção junta os arquivos de cada hora (e de cada dia, nas
// tabelas que não são de logs) e apaga os dias mais antigos que a retenção.

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Uma hora (ou dia) só é compactada depois de fechada há closeGrace: o último flush dela já subiu.
const closeGrace = 5 * time.Minute

type Store struct {
	cfg      *Config
	blob     Blob
	prefix   string // chave da pasta do cluster no bucket (termina em /)
	spoolDir string
	workDir  string
	T        *Tables
	now      func() time.Time

	mu          sync.Mutex
	lastStamp   int64
	knownDay    string
	known       map[string]map[int64]bool // dimensões já gravadas hoje
	lastFlushOK time.Time

	maintaining sync.Mutex
}

func NewStore(cfg *Config, blob Blob) (*Store, error) {
	prefix := cfg.ClusterName + "/"
	if cfg.Remote() {
		_, rest, _ := strings.Cut(cfg.StoragePath, "://")
		if _, p, ok := strings.Cut(rest, "/"); ok && strings.Trim(p, "/") != "" {
			prefix = strings.Trim(p, "/") + "/" + prefix
		}
	}
	s := &Store{
		cfg:      cfg,
		blob:     blob,
		prefix:   prefix,
		spoolDir: filepath.Join(cfg.BufferDir, "spool"),
		workDir:  filepath.Join(cfg.BufferDir, "work"),
		T:        newTables(),
		now:      time.Now,
		known:    map[string]map[int64]bool{},
	}
	// Restos de uma gravação interrompida
	os.RemoveAll(s.workDir)
	filepath.WalkDir(s.spoolDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".tmp") {
			os.Remove(p)
		}
		return nil
	})
	return s, nil
}

// Init garante que os stamps novos são maiores que os do storage (relógio do nó atrasado após um restart).
func (s *Store) Init(ctx context.Context) error {
	var maxStamp int64
	for _, t := range s.T.all() {
		keys, err := s.blob.List(ctx, s.prefix+t.Name()+"/")
		if err != nil {
			return err
		}
		for _, d := range groupByDay(s.prefix+t.Name()+"/", keys) {
			for _, f := range d.files {
				maxStamp = max(maxStamp, f.stamp)
			}
		}
	}
	s.mu.Lock()
	s.lastStamp = max(s.lastStamp, maxStamp)
	s.mu.Unlock()
	return nil
}

func (s *Store) nextStamp() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastStamp = max(s.lastStamp+1, s.now().UnixNano())
	return s.lastStamp
}

// Seen marca a dimensão como gravada hoje e diz se já estava. No dia seguinte tudo é gravado de novo (schema.go).
func (s *Store) Seen(table string, id int64, now time.Time) bool {
	day := now.UTC().Format(dayLayout)
	s.mu.Lock()
	defer s.mu.Unlock()
	if day != s.knownDay {
		s.knownDay = day
		s.known = map[string]map[int64]bool{}
	}
	ids := s.known[table]
	if ids == nil {
		ids = map[int64]bool{}
		s.known[table] = ids
	}
	if ids[id] {
		return true
	}
	ids[id] = true
	return false
}

// Flush grava o buffer no spool e sobe o spool para o storage.
func (s *Store) Flush(ctx context.Context) error {
	var errs []error
	for _, t := range s.T.all() {
		if err := t.spool(s.spoolDir, s.nextStamp); err != nil {
			errs = append(errs, fmt.Errorf("spool: %w", err))
		}
	}
	if err := s.upload(ctx); err != nil {
		errs = append(errs, fmt.Errorf("upload (nova tentativa no próximo flush): %w", err))
	}
	if len(errs) == 0 {
		s.mu.Lock()
		s.lastFlushOK = time.Now()
		s.mu.Unlock()
	}
	return errors.Join(errs...)
}

type spooled struct {
	path, key string
	stamp     int64
}

func (s *Store) spooled() ([]spooled, error) {
	var out []spooled
	err := filepath.WalkDir(s.spoolDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || strings.HasSuffix(p, ".tmp") {
			return nil
		}
		rel, err := filepath.Rel(s.spoolDir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		table, inTable, _ := strings.Cut(rel, "/")
		fi, ok := parseKey(inTable)
		if !ok {
			slog.Warn("arquivo desconhecido no spool", "file", rel)
			return nil
		}
		out = append(out, spooled{path: p, key: s.prefix + table + "/" + inTable, stamp: fi.stamp})
		return nil
	})
	slices.SortFunc(out, func(a, b spooled) int { return cmp.Compare(a.stamp, b.stamp) })
	return out, err
}

// upload sobe o spool em ordem de stamp e para no primeiro erro: um arquivo ainda no spool tem stamp maior que todos
// os que já estão no storage, então a compactação (que roda em paralelo) nunca o substitui por engano.
func (s *Store) upload(ctx context.Context) error {
	files, err := s.spooled()
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := s.blob.Put(ctx, f.key, f.path); err != nil {
			return fmt.Errorf("%s: %w (%d arquivo(s) no spool)", f.key, err, len(files))
		}
		os.Remove(f.path)
	}
	return nil
}

// SpoolFiles é o total de arquivos esperando para subir.
func (s *Store) SpoolFiles() int {
	files, _ := s.spooled()
	return len(files)
}

func (s *Store) Pending() int {
	n := 0
	for _, t := range s.T.all() {
		n += t.Pending()
	}
	return n
}

func (s *Store) LastFlushOK() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastFlushOK
}

// Maintain junta os arquivos das horas (e dias) fechados e apaga os dias fora da retenção. Os arquivos substituídos
// só são apagados na execução seguinte: uma consulta do Nanobot que listou antes da compactação ainda consegue lê-los.
// Uma execução por vez; roda em paralelo com a coleta e o flush.
func (s *Store) Maintain(ctx context.Context) error {
	if !s.maintaining.TryLock() {
		return nil
	}
	defer s.maintaining.Unlock()
	now := s.now().UTC()
	cutoff := ""
	if s.cfg.RetentionDays > 0 {
		cutoff = now.AddDate(0, 0, -s.cfg.RetentionDays).Format(dayLayout)
	}
	var errs []error
	for _, t := range s.T.all() {
		if err := s.maintainTable(ctx, t, now, cutoff); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func (s *Store) maintainTable(ctx context.Context, t anyTable, now time.Time, cutoff string) error {
	tprefix := s.prefix + t.Name() + "/"
	keys, err := s.blob.List(ctx, tprefix)
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range groupByDay(tprefix, keys) {
		day, _ := time.Parse(dayLayout, d.day)
		switch {
		case cutoff != "" && d.day < cutoff:
			removed := 0
			for _, f := range d.files {
				if err := s.blob.Delete(ctx, f.key); err != nil {
					errs = append(errs, err)
					continue
				}
				removed++
			}
			slog.Info("retenção: dia apagado do storage", "table", t.Name(), "day", d.day, "files", removed)
		case t.Daily() && now.Sub(day) >= 24*time.Hour+closeGrace:
			errs = append(errs, s.compact(ctx, t, d, d.files, d.effective(-1), func(stamp int64) string {
				return s.prefix + dayFileKey(t.Name(), d.day, stamp)
			}))
		default:
			for _, h := range d.hours() {
				hour := day.Add(time.Duration(h) * time.Hour)
				if now.Sub(hour) < time.Hour+closeGrace {
					continue
				}
				var scope []fileInfo
				for _, f := range d.files {
					if f.hour == h {
						scope = append(scope, f)
					}
				}
				errs = append(errs, s.compact(ctx, t, d, scope, d.effective(h), func(stamp int64) string {
					return s.prefix + fileKey(t.Name(), hour, stamp, true)
				}))
			}
		}
	}
	return errors.Join(errs...)
}

// compact junta os arquivos efetivos do escopo (hora ou dia) num só; se já é um só, apaga os substituídos.
func (s *Store) compact(ctx context.Context, t anyTable, d *dayFiles, scope, eff []fileInfo, keyOf func(int64) string) error {
	if len(eff) == 1 {
		for _, f := range scope {
			if f.key != eff[0].key {
				if err := s.blob.Delete(ctx, f.key); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if len(eff) == 0 {
		return nil
	}
	if err := os.MkdirAll(s.workDir, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(s.workDir)
	srcs := make([]string, len(eff))
	for i, f := range eff {
		srcs[i] = filepath.Join(s.workDir, fmt.Sprintf("%d.parquet", i))
		if err := s.blob.Get(ctx, f.key, srcs[i]); err != nil {
			return err
		}
	}
	out := filepath.Join(s.workDir, "merged.parquet")
	if err := t.merge(out, srcs); err != nil {
		return err
	}
	key := keyOf(eff[len(eff)-1].stamp)
	if err := s.blob.Put(ctx, key, out); err != nil {
		return err
	}
	slog.Debug("compactação", "table", t.Name(), "day", d.day, "files", len(eff), "key", key)
	return nil
}
