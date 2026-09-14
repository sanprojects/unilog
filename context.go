package unilog

import (
	"context"
	"regexp"
)

type traceCtxKey struct{}
type scopeCtxKey struct{}

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
	return context.WithValue(ctx, traceCtxKey{}, traceCtx{traceID, spanID, traceFlags})
}

// WithScope attaches ambient attributes (request method/url, worker
// path/attrs, or anything else) to every unilog call made with this
// context or a child of it, for the rest of its lifetime. Nests: keys from
// an inner WithScope win over an outer one's; an attribute passed directly
// to a specific slog call still wins over both (call-site beats ambient) —
// see Handler.Handle, which merges scope attrs in first.
func WithScope(ctx context.Context, attrs map[string]any) context.Context {
	merged := map[string]any{}
	for k, v := range scopeFromContext(ctx) {
		merged[k] = v
	}
	for k, v := range attrs {
		merged[k] = v
	}
	return context.WithValue(ctx, scopeCtxKey{}, merged)
}

// RequestScope is WithScope pre-filled for an HTTP request:
//
//	ctx = unilog.RequestScope(ctx, r.Method, r.URL.String())
func RequestScope(ctx context.Context, method, url string) context.Context {
	return WithScope(ctx, map[string]any{"http.request.method": method, "url.full": url})
}

// WorkerScope is WithScope pre-filled for a background job:
//
//	ctx = unilog.WorkerScope(ctx, "jobs.charge_subscription", map[string]any{"account_id": 42})
func WorkerScope(ctx context.Context, path string, attrs map[string]any) context.Context {
	merged := map[string]any{"worker.path": path}
	for k, v := range attrs {
		merged[k] = v
	}
	return WithScope(ctx, merged)
}

func scopeFromContext(ctx context.Context) map[string]any {
	if ctx == nil {
		return nil
	}
	if m, ok := ctx.Value(scopeCtxKey{}).(map[string]any); ok {
		return m
	}
	return nil
}

func fromContext(ctx context.Context) (traceID, spanID, traceFlags string) {
	if ctx == nil {
		return "", "", ""
	}
	if tc, ok := ctx.Value(traceCtxKey{}).(traceCtx); ok {
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
