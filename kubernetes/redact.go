package main

import (
	"context"
	"log/slog"
	"regexp"
)

// Os erros do DuckDB repetem a conexão do catálogo (password=...) e o trecho do CREATE SECRET. Os logs do agente
// também são coletados (inclusive os dele), então as senhas saem de todo log antes de serem escritas.
var (
	secretKVRe    = regexp.MustCompile(`(?i)((?:password|secret|key_id|session_token)\s*[=:]\s*)('[^']*'|"[^"]*"|[^\s'",)]+)`)
	secretSQLRe   = regexp.MustCompile(`(?i)((?:password|secret|key_id|session_token)\s+)('[^']*'|"[^"]*")`)
	urlPasswordRe = regexp.MustCompile(`(://[^:/@\s]+:)[^@\s]+@`)
)

func redact(s string) string {
	s = secretKVRe.ReplaceAllString(s, "${1}***")
	s = secretSQLRe.ReplaceAllString(s, "${1}***")
	return urlPasswordRe.ReplaceAllString(s, "${1}***@")
}

type redactHandler struct{ slog.Handler }

func (h redactHandler) Handle(ctx context.Context, r slog.Record) error {
	clean := slog.NewRecord(r.Time, r.Level, redact(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(redactAttr(a))
		return true
	})
	return h.Handler.Handle(ctx, clean)
}

func (h redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	for i := range attrs {
		attrs[i] = redactAttr(attrs[i])
	}
	return redactHandler{h.Handler.WithAttrs(attrs)}
}

func (h redactHandler) WithGroup(name string) slog.Handler {
	return redactHandler{h.Handler.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, redact(v.String()))
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			return slog.String(a.Key, redact(err.Error()))
		}
	}
	return a
}
