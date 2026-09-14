// Package auto is the one-line entrypoint for Go:
//
//	import _ "github.com/sanprojects/unilog/auto"
//
// Its init() wires slog.SetDefault for the `log/slog` API, and separately
// redirects the plain `log` package (log.Printf and friends) through the
// same handler via log.SetOutput — so both logging APIs end up in the same
// format without the caller doing anything.
//
// What this does NOT give you, and cannot: Go has no goroutine-local storage
// and no global hook for an unrecovered panic. `defer unilog.Recover()` in
// main, `unilog.Go(fn)` instead of a bare `go fn()`, and unilog/httpmw for
// HTTP handlers are still your job — see the root package doc.
package auto

import (
	"log"
	"log/slog"

	"github.com/sanprojects/unilog"
)

func init() {
	h := unilog.NewHandler()
	slog.SetDefault(slog.New(h))
	log.SetFlags(0)
	log.SetOutput(h.StdLogger(9, "log.write"))
}
