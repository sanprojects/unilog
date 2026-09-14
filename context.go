package unilog

import (
	"context"
	"regexp"
)

type ctxKey struct{}

type traceCtx struct {
	traceID    string
	spanID     string
	traceFlags string
}

var traceparentRe = regexp.MustCompile(`^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)

// WithTrace attaches trace_id/span_id/trace_flags to a context.Context. This
// is the only way to get trace correlation into a log record in Go — there is
// no goroutine-local storage, so a package-global logger genuinely cannot
// reach into "whatever request is running right now" the way Python's
// contextvars or Node's AsyncLocalStorage can. Call slog.InfoContext(ctx, ...)
// (not slog.Info without a context) or the trace fields are silently absent.
func WithTrace(ctx context.Context, traceID, spanID, traceFlags string) context.Context {
	return context.WithValue(ctx, ctxKey{}, traceCtx{traceID, spanID, traceFlags})
}

func fromContext(ctx context.Context) (traceID, spanID, traceFlags string) {
	if ctx == nil {
		return "", "", ""
	}
	if tc, ok := ctx.Value(ctxKey{}).(traceCtx); ok {
		return tc.traceID, tc.spanID, tc.traceFlags
	}
	return "", "", ""
}

// ParseTraceparent parses a W3C `traceparent` header: version-traceid-spanid-flags.
func ParseTraceparent(header string) (traceID, spanID, traceFlags string, ok bool) {
	m := traceparentRe.FindStringSubmatch(header)
	if m == nil {
		return "", "", "", false
	}
	if m[2] == "00000000000000000000000000000000" || m[3] == "0000000000000000" {
		return "", "", "", false
	}
	return m[2], m[3], m[4], true
}
