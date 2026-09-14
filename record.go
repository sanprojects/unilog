package unilog

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"time"
)

// Record mirrors spec/record.schema.json. Field order here is what
// encoding/json emits for the top-level object; map keys (resource,
// attributes) are sorted alphabetically by encoding/json automatically,
// which is exactly the normative ordering spec §1.1 asks for.
type Record struct {
	Timestamp        string         `json:"timestamp"`
	SeverityText     string         `json:"severity_text"`
	SeverityNumber   int            `json:"severity_number"`
	EventName        string         `json:"event_name,omitempty"`
	Body             string         `json:"body"`
	TraceID          string         `json:"trace_id,omitempty"`
	SpanID           string         `json:"span_id,omitempty"`
	TraceFlags       string         `json:"trace_flags,omitempty"`
	Scope            string         `json:"scope,omitempty"`
	Resource         Resource       `json:"resource"`
	Attributes       map[string]any `json:"attributes,omitempty"`
	DroppedAttrCount int            `json:"dropped_attributes_count,omitempty"`
}

var eventNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

var (
	bodyLimit        = envInt("LOG_BODY_LIMIT", 8192)
	maxAttrs         = envInt("LOG_MAX_ATTRIBUTES", 128)
	maxAttrBytes     = envInt("LOG_MAX_ATTRIBUTE_BYTES", 4096)
	stacktraceMinSev = envInt("LOG_STACKTRACE_MIN_SEVERITY", 17)
	maxCauses        = envInt("LOG_EXCEPTION_MAX_CAUSES", 3)
)

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func truncateBytes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "...[truncated]"
}

var globalRedactor = newRedactor()

// BuildOptions carries everything needed to assemble one Record.
type BuildOptions struct {
	SeverityNumber int
	Body           string
	EventName      string
	Attributes     map[string]any
	TraceID        string
	SpanID         string
	TraceFlags     string
	Scope          string
}

func Build(opt BuildOptions) Record {
	sev := clampSeverity(opt.SeverityNumber)
	attrs, dropped := normalizeAttributes(opt.Attributes)

	rec := Record{
		Timestamp:        time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
		SeverityText:     severityTextFor(sev),
		SeverityNumber:   sev,
		Body:             truncateBytes(globalRedactor.RedactValuePatterns(opt.Body), bodyLimit),
		TraceID:          opt.TraceID,
		SpanID:           opt.SpanID,
		TraceFlags:       opt.TraceFlags,
		Resource:         GetResource(),
		Attributes:       attrs,
		DroppedAttrCount: dropped,
	}
	if opt.Scope != "" && len(opt.Scope) <= 255 {
		rec.Scope = opt.Scope
	}
	if opt.EventName != "" && eventNameRe.MatchString(opt.EventName) && len(opt.EventName) <= 63 {
		rec.EventName = opt.EventName
	}
	return rec
}

// Emit sends a Record through the process-wide sinks (console + syslog),
// exactly as the slog.Handler does — for callers (like httpmw) that build a
// Record directly instead of going through slog.
func Emit(r Record) {
	getSinks().Emit(r.JSONLine(), r.SeverityNumber)
}

func (r Record) JSONLine() []byte {
	b, err := json.Marshal(r)
	if err != nil {
		// Should not happen: everything under Attributes has already been
		// coerced to JSON-safe types by normalizeAttributes.
		b, _ = json.Marshal(map[string]any{
			"timestamp": r.Timestamp, "severity_text": "ERROR", "severity_number": 17,
			"body": "unilog: failed to encode log record", "resource": r.Resource,
			"attributes": map[string]string{"log.invalid": err.Error()},
		})
	}
	return append(b, '\n')
}

const reservedPrefix = "log."

func normalizeAttributes(raw map[string]any) (map[string]any, int) {
	if len(raw) == 0 {
		return nil, 0
	}
	flat := make(map[string]any, len(raw))
	for k, v := range raw {
		key := k
		if len(key) > len(reservedPrefix) && key[:len(reservedPrefix)] == reservedPrefix && key != "log.level.original" && key != "log.invalid" {
			key = "attr." + key
		}
		if globalRedactor.KeyIsSensitive(key) {
			flat[key] = "[REDACTED]"
			continue
		}
		flat[key] = flattenValue(v, 0, map[uintptr]bool{})
	}
	if len(flat) > maxAttrs {
		// Deterministic trim: sort keys, keep the first maxAttrs.
		keys := make([]string, 0, len(flat))
		for k := range flat {
			keys = append(keys, k)
		}
		sortStrings(keys)
		dropped := len(keys) - maxAttrs
		trimmed := make(map[string]any, maxAttrs)
		for _, k := range keys[:maxAttrs] {
			trimmed[k] = flat[k]
		}
		return trimmed, dropped
	}
	return flat, 0
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func flattenValue(v any, depth int, seen map[uintptr]bool) any {
	if depth > 10 {
		return "[MaxDepth]"
	}
	switch x := v.(type) {
	case nil:
		return nil
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return x
	case float32:
		if isNaNOrInf(float64(x)) {
			return nil
		}
		return x
	case float64:
		if isNaNOrInf(x) {
			return nil
		}
		return x
	case string:
		return truncateBytes(globalRedactor.RedactValuePatterns(x), maxAttrBytes)
	case []byte:
		return "base64:" + base64.StdEncoding.EncodeToString(x)
	case error:
		return truncateBytes(x.Error(), maxAttrBytes)
	case fmt.Stringer:
		return truncateBytes(x.String(), maxAttrBytes)
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		out := map[string]any{}
		iter := rv.MapRange()
		count := 0
		for iter.Next() && count < 64 {
			out[fmt.Sprint(iter.Key().Interface())] = flattenValue(iter.Value().Interface(), depth+1, seen)
			count++
		}
		return out
	case reflect.Slice, reflect.Array:
		n := rv.Len()
		if n > 64 {
			n = 64
		}
		out := make([]any, n)
		for i := 0; i < n; i++ {
			out[i] = flattenValue(rv.Index(i).Interface(), depth+1, seen)
		}
		return out
	case reflect.Ptr:
		if rv.IsNil() {
			return nil
		}
		ptr := rv.Pointer()
		if seen[ptr] {
			return "[Circular]"
		}
		seen[ptr] = true
		return flattenValue(rv.Elem().Interface(), depth+1, seen)
	}
	return truncateBytes(fmt.Sprintf("%+v", v), maxAttrBytes)
}

func isNaNOrInf(f float64) bool {
	return f != f || f > 1.7976931348623157e+308*0.999999 || f < -1.7976931348623157e+308*0.999999
}

// ExceptionAttributes converts an error (optionally with a stack trace
// captured at a panic/recover site) into exception.*/error.type attributes —
// spec §4.8. stacktrace may be empty; it's only attached when severityNumber
// is at/above LOG_STACKTRACE_MIN_SEVERITY.
func ExceptionAttributes(err error, severityNumber int, stacktrace string) map[string]any {
	if err == nil {
		return nil
	}
	attrs := map[string]any{}
	etype := fmt.Sprintf("%T", err)
	attrs["exception.type"] = etype
	attrs["exception.message"] = err.Error()
	attrs["error.type"] = etype
	if stacktrace != "" && clampSeverity(severityNumber) >= stacktraceMinSev {
		if globalRedactor.RedactStacktrace {
			stacktrace = globalRedactor.RedactValuePatterns(stacktrace)
		}
		attrs["exception.stacktrace"] = stacktrace
	}

	var causes []map[string]any
	cur := errors.Unwrap(err)
	deepestType := etype
	for i := 0; cur != nil && i < maxCauses; i++ {
		cType := fmt.Sprintf("%T", cur)
		causes = append(causes, map[string]any{"type": cType, "message": cur.Error()})
		deepestType = cType
		cur = errors.Unwrap(cur)
	}
	if len(causes) > 0 {
		attrs["exception.causes"] = causes
		attrs["error.type"] = deepestType
	}
	return attrs
}
