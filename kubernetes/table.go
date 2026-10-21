package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/parquet-go/parquet-go"
)

const (
	rowGroupRows  = 50_000
	rowGroupBytes = 32 << 20 // logs: fecha o row group antes, para não segurar linhas longas demais em memória
)

// anyTable é o que o Store precisa de cada tabela, sem conhecer o tipo da linha.
type anyTable interface {
	Name() string
	Daily() bool
	Pending() int
	// spool grava as linhas do buffer em arquivos Parquet locais, um por hora (UTC) do timestamp das linhas
	spool(dir string, stamp func() int64) error
	// merge junta os arquivos srcs (já baixados) num só
	merge(dst string, srcs []string) error
}

type Table[T any] struct {
	name  string
	daily bool               // junta os arquivos do dia depois que ele fecha (os de hora em hora sempre são juntados)
	ts    func(*T) time.Time // partição (dia/hora) e ordem das linhas
	size  func(*T) int       // tamanho aproximado da linha (nil: só o limite de linhas)

	mu   sync.Mutex
	rows []T
}

func newTable[T any](name string, daily bool, ts func(*T) time.Time, size func(*T) int) *Table[T] {
	return &Table[T]{name: name, daily: daily, ts: ts, size: size}
}

func (t *Table[T]) Name() string { return t.name }
func (t *Table[T]) Daily() bool  { return t.daily }

func (t *Table[T]) Append(rows ...T) {
	if len(rows) == 0 {
		return
	}
	t.mu.Lock()
	t.rows = append(t.rows, rows...)
	t.mu.Unlock()
}

func (t *Table[T]) Pending() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.rows)
}

func (t *Table[T]) take() []T {
	t.mu.Lock()
	defer t.mu.Unlock()
	rows := t.rows
	t.rows = nil
	return rows
}

// putBack devolve ao buffer linhas que não foram gravadas (disco cheio, por exemplo).
func (t *Table[T]) putBack(rows []T) {
	t.mu.Lock()
	t.rows = append(rows, t.rows...)
	t.mu.Unlock()
}

func (t *Table[T]) spool(dir string, stamp func() int64) error {
	rows := t.take()
	if len(rows) == 0 {
		return nil
	}
	// Ordenadas por tempo: as estatísticas de cada row group deixam o DuckDB pular o que está fora do período
	slices.SortStableFunc(rows, func(a, b T) int { return t.ts(&a).Compare(t.ts(&b)) })
	for start := 0; start < len(rows); {
		hour := t.ts(&rows[start]).UTC().Truncate(time.Hour)
		end := start + 1
		for end < len(rows) && t.ts(&rows[end]).UTC().Truncate(time.Hour).Equal(hour) {
			end++
		}
		path := filepath.Join(dir, filepath.FromSlash(fileKey(t.name, hour, stamp(), false)))
		if err := writeAtomic(path, func(w io.Writer) error { return t.write(w, rows[start:end]) }); err != nil {
			t.putBack(rows[start:])
			return fmt.Errorf("%s: %w", t.name, err)
		}
		start = end
	}
	return nil
}

func (t *Table[T]) newWriter(w io.Writer) *parquet.GenericWriter[T] {
	return parquet.NewGenericWriter[T](w, parquet.Compression(&parquet.Zstd), parquet.MaxRowsPerRowGroup(rowGroupRows),
		parquet.CreatedBy("nanobot-k8s-monitoring", "", ""))
}

// rowGroupFull fecha o row group quando as linhas acumuladas passam de rowGroupBytes.
type rowGroupFull struct{ bytes int }

func (g *rowGroupFull) add(n int) bool {
	g.bytes += n
	if g.bytes >= rowGroupBytes {
		g.bytes = 0
		return true
	}
	return false
}

func (t *Table[T]) write(w io.Writer, rows []T) error {
	pw := t.newWriter(w)
	if t.size == nil {
		if _, err := pw.Write(rows); err != nil {
			return err
		}
		return pw.Close()
	}
	var g rowGroupFull
	for i := 0; i < len(rows); {
		j := i
		for j < len(rows) && !g.add(t.size(&rows[j])) {
			j++
		}
		j = min(j+1, len(rows))
		if _, err := pw.Write(rows[i:j]); err != nil {
			return err
		}
		if err := pw.Flush(); err != nil {
			return err
		}
		i = j
	}
	return pw.Close()
}

func (t *Table[T]) merge(dst string, srcs []string) error {
	return writeAtomic(dst, func(w io.Writer) error {
		pw := t.newWriter(w)
		buf := make([]T, 1024)
		var g rowGroupFull
		for _, src := range srcs {
			if err := t.copyRows(pw, src, buf, &g); err != nil {
				// Arquivo ilegível (não deveria acontecer: o upload é atômico) não trava a compactação da hora
				slog.Warn("arquivo ignorado na compactação", "table", t.name, "file", filepath.Base(src), "err", err)
			}
		}
		return pw.Close()
	})
}

func (t *Table[T]) copyRows(pw *parquet.GenericWriter[T], src string, buf []T, g *rowGroupFull) (err error) {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	pf, err := parquet.OpenFile(f, st.Size())
	if err != nil {
		return err
	}
	r := parquet.NewGenericReader[T](pf)
	defer r.Close()
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			if _, err := pw.Write(buf[:n]); err != nil {
				return err
			}
			if t.size != nil {
				full := false
				for i := range n {
					full = g.add(t.size(&buf[i])) || full
				}
				if full {
					if err := pw.Flush(); err != nil {
						return err
					}
				}
			}
			clear(buf[:n]) // solta as strings para o GC
		}
		if errors.Is(rerr, io.EOF) {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// writeAtomic grava em <path>.tmp e renomeia: um arquivo pela metade nunca é enviado nem lido.
func writeAtomic(path string, fn func(io.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
