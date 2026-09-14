package unilog

import (
	"fmt"
	"os"
	"runtime/debug"
)

// Recover logs a FATAL record for the panic in progress, then re-panics so
// the Go runtime still prints its own crash output and the process exits the
// way it normally would. Verified (go1.25.0): a panic in a non-main
// goroutine skips main's deferred functions entirely — there is no way to
// buffer this write, so Emit() is always synchronous.
//
//	func main() {
//	    defer unilog.Recover()
//	    ...
//	}
func Recover() {
	if r := recover(); r != nil {
		logPanic(r, debug.Stack())
		panic(r)
	}
}

// Go runs fn in a new goroutine, logging (and still propagating) any panic —
// there is no global unrecovered-panic hook in Go, so this discipline is the
// only way a goroutine's panic becomes visible in the log before the process
// dies. Bare `go func(){...}()` is invisible to unilog entirely.
func Go(fn func()) {
	go func() {
		defer Recover()
		fn()
	}()
}

// Fatal logs a FATAL record and exits(1). Unlike a panic, this does NOT run
// other deferred functions — call it only where you would have called
// log.Fatal / os.Exit(1) directly.
func Fatal(msg string, attrs map[string]any) {
	rec := Build(BuildOptions{SeverityNumber: 21, Body: msg, EventName: "process.fatal", Attributes: attrs})
	getSinks().Emit(rec.JSONLine(), 21)
	os.Exit(1)
}

func logPanic(r any, stack []byte) {
	err, ok := r.(error)
	var attrs map[string]any
	if ok {
		attrs = ExceptionAttributes(err, 21, string(stack))
	} else {
		attrs = map[string]any{
			"exception.type":       "panic",
			"exception.message":    fmt.Sprint(r),
			"exception.stacktrace": string(stack),
			"error.type":           "panic",
		}
	}
	rec := Build(BuildOptions{
		SeverityNumber: 21,
		Body:           fmt.Sprint(r),
		EventName:      "process.panic",
		Attributes:     attrs,
	})
	getSinks().Emit(rec.JSONLine(), 21)
}
