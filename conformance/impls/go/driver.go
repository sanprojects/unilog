// Conformance driver for the Go implementation. See ../../protocol.md.
//
// Go reads its LOG_* env vars into package-level vars exactly once, at
// package-init time (before main() runs) — so a case's "env" overrides only
// take effect if they're in the process environment from the start. This
// driver re-execs itself with those vars added when a case needs them,
// rather than pretending Go supports runtime reconfiguration it doesn't.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/sanprojects/unilog"
)

type caseFile struct {
	Env   map[string]string `json:"env"`
	Input struct {
		SeverityNumber int            `json:"severityNumber"`
		Body           string         `json:"body"`
		EventName      string         `json:"eventName"`
		Attributes     map[string]any `json:"attributes"`
		TraceID        string         `json:"traceId"`
		SpanID         string         `json:"spanId"`
	} `json:"input"`
}

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var c caseFile
	if err := json.Unmarshal(data, &c); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if len(c.Env) > 0 && os.Getenv("_UNILOG_CONFORMANCE_REEXEC") == "" {
		env := os.Environ()
		for k, v := range c.Env {
			env = append(env, k+"="+v)
		}
		env = append(env, "_UNILOG_CONFORMANCE_REEXEC=1")
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Env = env
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			os.Exit(1)
		}
		return
	}

	sev := c.Input.SeverityNumber
	if sev == 0 {
		sev = 9
	}
	rec := unilog.Build(unilog.BuildOptions{
		SeverityNumber: sev,
		Body:           c.Input.Body,
		EventName:      c.Input.EventName,
		Attributes:     c.Input.Attributes,
		TraceID:        c.Input.TraceID,
		SpanID:         c.Input.SpanID,
	})
	os.Stdout.Write(rec.JSONLine())
}
