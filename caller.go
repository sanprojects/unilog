package unilog

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// callerAttributes walks the goroutine's own call stack (still fully intact
// at this point — slog.Handle runs synchronously in the same goroutine as
// the original slog.Info/Error call) and returns code.function/filepath/
// lineno for the nearest application frame above slog/unilog's own, plus a
// short code.stacktrace chain — the Go side of the "short stacktrace on
// every line" feature. No fixed skip count is needed: every frame belonging
// to log/slog or this package is filtered out below regardless of depth,
// so it doesn't matter how many internal frames sit between the call site
// and here.
func callerAttributes(limit int) map[string]any {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(2, pcs) // 2 drops runtime.Callers + callerAttributes' own frames
	if n == 0 {
		return nil
	}
	frames := runtime.CallersFrames(pcs[:n])

	type frame struct {
		fn   string
		file string
		line int
	}
	var app []frame
	for {
		f, more := frames.Next()
		if !strings.Contains(f.Function, "log/slog") && !strings.Contains(f.Function, "sanprojects/unilog") {
			app = append(app, frame{shortFuncName(f.Function), f.File, f.Line})
			if len(app) >= limit {
				break
			}
		}
		if !more {
			break
		}
	}
	if len(app) == 0 {
		return nil
	}
	nearest := app[0]
	attrs := map[string]any{
		"code.function": nearest.fn,
		"code.filepath": nearest.file,
		"code.lineno":   nearest.line,
	}
	if len(app) > 1 {
		parts := make([]string, len(app))
		for i, f := range app {
			parts[i] = fmt.Sprintf("%s (%s:%d)", f.fn, filepath.Base(f.file), f.line)
		}
		attrs["code.stacktrace"] = strings.Join(parts, " < ")
	}
	return attrs
}

// shortFuncName trims a fully-qualified Go func name ("main.(*server).search"
// or "github.com/x/pkg.Foo.func1") down to the last path segment, matching
// the compact style the Python/Node/PHP implementations use.
func shortFuncName(full string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 {
		full = full[i+1:]
	}
	if i := strings.Index(full, "."); i >= 0 {
		full = full[i+1:]
	}
	return full
}

func callerInfoEnabled() bool {
	return getenvDefault("LOG_CALLER_INFO", "1") != "0"
}

func callerTraceFrames() int {
	return envInt("LOG_CALLER_TRACE_FRAMES", 3)
}
