package main

// Organização dos arquivos no storage (o Nanobot segue as mesmas regras):
//
//	<STORAGE_PATH>/<CLUSTER_NAME>/<tabela>/dt=AAAA-MM-DD/hh=HH/<stamp>.parquet   gravado a cada flush
//	<STORAGE_PATH>/<CLUSTER_NAME>/<tabela>/dt=AAAA-MM-DD/hh=HH/c<stamp>.parquet  a hora compactada
//	<STORAGE_PATH>/<CLUSTER_NAME>/<tabela>/dt=AAAA-MM-DD/c<stamp>.parquet        o dia compactado
//
// dt/hh vêm do timestamp das linhas (UTC). O stamp é crescente (nanossegundos de quando o arquivo foi gravado) e o
// compactado leva o maior stamp dos arquivos que juntou: ele substitui todos os arquivos do seu escopo (a hora ou o dia)
// com stamp menor ou igual. Assim, enquanto os arquivos juntados não são apagados, ou se chega um arquivo atrasado
// depois da compactação, quem lê continua vendo cada linha uma vez só.

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

const dayLayout = "2006-01-02"

type fileInfo struct {
	key       string
	day       string
	hour      int // -1: arquivo do dia
	stamp     int64
	compacted bool
}

func fileKey(table string, hour time.Time, stamp int64, compacted bool) string {
	c := ""
	if compacted {
		c = "c"
	}
	return fmt.Sprintf("%s/dt=%s/hh=%02d/%s%d.parquet", table, hour.Format(dayLayout), hour.Hour(), c, stamp)
}

func dayFileKey(table, day string, stamp int64) string {
	return fmt.Sprintf("%s/dt=%s/c%d.parquet", table, day, stamp)
}

// parseKey interpreta a chave relativa à pasta da tabela (dt=.../...). Outros arquivos são ignorados.
func parseKey(rel string) (fileInfo, bool) {
	parts := strings.Split(rel, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return fileInfo{}, false
	}
	day, ok := strings.CutPrefix(parts[0], "dt=")
	if _, err := time.Parse(dayLayout, day); !ok || err != nil {
		return fileInfo{}, false
	}
	fi := fileInfo{day: day, hour: -1}
	name := parts[len(parts)-1]
	if len(parts) == 3 {
		h, ok := strings.CutPrefix(parts[1], "hh=")
		n, err := strconv.Atoi(h)
		if !ok || err != nil || n < 0 || n > 23 {
			return fileInfo{}, false
		}
		fi.hour = n
	}
	base, ok := strings.CutSuffix(name, ".parquet")
	if !ok {
		return fileInfo{}, false
	}
	base, fi.compacted = strings.CutPrefix(base, "c")
	if fi.hour < 0 && !fi.compacted {
		return fileInfo{}, false
	}
	var err error
	if fi.stamp, err = strconv.ParseInt(base, 10, 64); err != nil {
		return fileInfo{}, false
	}
	return fi, true
}

// dayFiles são os arquivos de uma tabela num dia.
type dayFiles struct {
	day   string
	files []fileInfo
}

// groupByDay agrupa as chaves (relativas à pasta da tabela) por dia, em ordem.
func groupByDay(prefix string, keys []string) []*dayFiles {
	byDay := map[string]*dayFiles{}
	for _, k := range keys {
		fi, ok := parseKey(strings.TrimPrefix(k, prefix))
		if !ok {
			continue
		}
		fi.key = k
		d := byDay[fi.day]
		if d == nil {
			d = &dayFiles{day: fi.day}
			byDay[fi.day] = d
		}
		d.files = append(d.files, fi)
	}
	out := make([]*dayFiles, 0, len(byDay))
	for _, d := range byDay {
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b *dayFiles) int { return strings.Compare(a.day, b.day) })
	return out
}

// effective devolve os arquivos que valem (cada linha uma vez só), em ordem de stamp; o resto foi substituído.
// hour < 0: o dia inteiro; senão só a hora (sem o arquivo do dia).
func (d *dayFiles) effective(hour int) []fileInfo {
	var dayStamp int64
	for _, f := range d.files {
		if f.hour < 0 && f.stamp > dayStamp {
			dayStamp = f.stamp
		}
	}
	hourStamp := map[int]int64{}
	for _, f := range d.files {
		if f.hour >= 0 && f.compacted && f.stamp > dayStamp && f.stamp > hourStamp[f.hour] {
			hourStamp[f.hour] = f.stamp
		}
	}
	var out []fileInfo
	for _, f := range d.files {
		switch {
		case f.hour < 0:
			if hour < 0 && f.stamp == dayStamp {
				out = append(out, f)
			}
		case hour >= 0 && f.hour != hour, f.stamp <= dayStamp:
		case f.compacted && f.stamp == hourStamp[f.hour], !f.compacted && f.stamp > hourStamp[f.hour]:
			out = append(out, f)
		}
	}
	slices.SortFunc(out, func(a, b fileInfo) int { return cmp.Compare(a.stamp, b.stamp) })
	return out
}

// hours devolve as horas que têm arquivos (fora o arquivo do dia).
func (d *dayFiles) hours() []int {
	var hs []int
	for _, f := range d.files {
		if f.hour >= 0 && !slices.Contains(hs, f.hour) {
			hs = append(hs, f.hour)
		}
	}
	slices.Sort(hs)
	return hs
}
