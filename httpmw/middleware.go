// Package httpmw provides an HTTP middleware that recovers per-request
// panics (without crashing the process — that's the difference from
// unilog.Recover, meant for main()), logs them structurally, threads an
// incoming W3C traceparent header into the request's log context, and
// attaches http.request.method/url.full to every log call made while
// handling the request (unilog.RequestScope) — so a plain
// slog.InfoContext(r.Context(), "...") inside the handler carries them
// automatically, with no logging code in the handler itself.
package httpmw

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/sanprojects/unilog"
)

// Middleware wraps next: extracts an incoming `traceparent` header into the
// request context (unilog.WithTrace), attaches the request scope
// (unilog.RequestScope), and recovers any panic from the handler — logging
// it as an ERROR record with a stack trace and returning 500, instead of
// taking the whole process down.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if tp := r.Header.Get("traceparent"); tp != "" {
			if traceID, spanID, flags, ok := unilog.ParseTraceparent(tp); ok {
				ctx = unilog.WithTrace(ctx, traceID, spanID, flags)
			}
		}
		ctx = unilog.RequestScope(ctx, r.Method, r.URL.String())
		r = r.WithContext(ctx)

		defer func() {
			if rec := recover(); rec != nil {
				stack := debug.Stack()
				err, ok := rec.(error)
				var attrs map[string]any
				if ok {
					attrs = unilog.ExceptionAttributes(err, 17, string(stack))
				} else {
					attrs = map[string]any{
						"exception.type":       "panic",
						"exception.message":    fmt.Sprint(rec),
						"exception.stacktrace": string(stack),
						"error.type":           "panic",
					}
				}
				// Context carries http.request.method/url.full (RequestScope,
				// set above) and trace_id/span_id (WithTrace) automatically —
				// no need to set them again by hand here.
				unilog.Emit(unilog.Build(unilog.BuildOptions{
					SeverityNumber: 17,
					Body:           fmt.Sprint(rec),
					EventName:      "http.server.panic_recovered",
					Attributes:     attrs,
					Context:        ctx,
				}))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
