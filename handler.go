package unilog

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// Handler implements slog.Handler and is what auto's init() installs via
// slog.SetDefault. It is also usable directly: slog.New(unilog.NewHandler()).
type Handler struct {
	sinks     *Sinks
	minLevel  slog.Level
	baseAttrs map[string]any
	groupPfx  string
	mu        *sync.Mutex // shared across WithAttrs/WithGroup derivatives
}

func NewHandler() *Handler {
	return &Handler{
		sinks:    getSinks(),
		minLevel: parseMinLevel(),
		mu:       &sync.Mutex{},
	}
}

func parseMinLevel() slog.Level {
	v := getenvDefault("LOG_LEVEL", "INFO")
	switch strings.ToUpper(v) {
	case "OFF", "NONE":
		return slog.Level(1000)
	case "TRACE", "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR", "FATAL":
		return slog.LevelError
	}
	if n := envInt("LOG_LEVEL", -9999); n != -9999 {
		return slog.Level(n - 9) // inverse of fromSlogLevel's +9
	}
	return slog.LevelInfo
}

func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.minLevel
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	// Ambient scope (WithScope/RequestScope/WorkerScope) and a short caller
	// trace are merged in by Build() itself (via BuildOptions.Context) at
	// the lowest priority — explicit attrs collected below override them.
	attrs := map[string]any{}
	for k, v := range h.baseAttrs {
		attrs[k] = v
	}
	r.Attrs(func(a slog.Attr) bool {
		collectAttr(a, h.groupPfx, attrs)
		return true
	})

	eventName, _ := attrs["event_name"].(string)
	delete(attrs, "event_name")

	severityNumber := fromSlogLevel(r.Level)

	// Auto-expand a bare `error` value the way the community convention
	// (`slog.Error("...", "err", err)`) hands it to us — matches the pino
	// `err:` auto-serialization behavior San's earlier research settled on.
	for k, v := range attrs {
		if err, ok := v.(error); ok {
			for ek, ev := range ExceptionAttributes(err, severityNumber, "") {
				attrs[ek] = ev
			}
			delete(attrs, k)
		}
	}

	rec := Build(BuildOptions{
		SeverityNumber: severityNumber,
		Body:           r.Message,
		EventName:      eventName,
		Attributes:     attrs,
		Context:        ctx,
	})
	h.sinks.Emit(rec.JSONLine(), severityNumber)
	return nil
}

func collectAttr(a slog.Attr, prefix string, out map[string]any) {
	a.Value = a.Value.Resolve()
	key := a.Key
	if prefix != "" {
		key = prefix + "." + key
	}
	if a.Value.Kind() == slog.KindGroup {
		for _, sub := range a.Value.Group() {
			collectAttr(sub, key, out)
		}
		return
	}
	out[key] = a.Value.Any()
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := &Handler{sinks: h.sinks, minLevel: h.minLevel, groupPfx: h.groupPfx, mu: h.mu}
	nh.baseAttrs = map[string]any{}
	for k, v := range h.baseAttrs {
		nh.baseAttrs[k] = v
	}
	for _, a := range attrs {
		collectAttr(a, h.groupPfx, nh.baseAttrs)
	}
	return nh
}

func (h *Handler) WithGroup(name string) slog.Handler {
	nh := &Handler{sinks: h.sinks, minLevel: h.minLevel, mu: h.mu}
	nh.baseAttrs = h.baseAttrs
	if h.groupPfx == "" {
		nh.groupPfx = name
	} else {
		nh.groupPfx = h.groupPfx + "." + name
	}
	return nh
}

var (
	sinksOnce   sync.Once
	sinksCached *Sinks
)

func getSinks() *Sinks {
	sinksOnce.Do(func() {
		name, _ := GetResource()["service.name"].(string)
		sinksCached = NewSinks(name)
	})
	return sinksCached
}

// StdLogger returns an io.Writer that feeds this handler at the given
// severity/event_name — for redirecting anything still writing through the
// plain `log` package. Two call sites matter: auto's init() uses it at
// INFO/"log.write" as a generic net/log.SetOutput target, and a service can
// use it at WARN/"http.server.error" for http.Server.ErrorLog (broken pipes,
// TLS handshake failures, and panics net/http already recovers per-request).
func (h *Handler) StdLogger(severityNumber int, eventName string) *stdLoggerAdapter {
	return &stdLoggerAdapter{h: h, severityNumber: severityNumber, eventName: eventName}
}

type stdLoggerAdapter struct {
	h              *Handler
	severityNumber int
	eventName      string
}

func (a *stdLoggerAdapter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	rec := Build(BuildOptions{SeverityNumber: a.severityNumber, Body: msg, EventName: a.eventName})
	a.h.sinks.Emit(rec.JSONLine(), a.severityNumber)
	return len(p), nil
}
