# Deviations from the OpenTelemetry Logs Data Model

`unilog` follows the OTel Logs data model and semantic conventions but does not depend on the
OTel SDK and does not emit OTLP wire format. Every place this format departs from the model is
listed here, with the OTel reference and how reversible the deviation is.

| # | unilog | OTel | Why | Reversible |
|---|---|---|---|---|
| V1 | Flat `snake_case` JSON | OTLP/JSON uses `camelCase` and `attributes: [{key, value: {stringValue}}]` — see [protocol/file-exporter.md](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/file-exporter.md) | Human-readable, greppable, 2-3x fewer bytes on the wire | Yes, a 1:1 transform in a collector |
| V2 | `timestamp` is RFC3339 with microseconds | `Timestamp` is `uint64` nanoseconds ([data-model.md#field-timestamp](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/logs/data-model.md)) | Readability; microsecond ordering is enough | Yes, with nanosecond precision loss |
| V3 | No `observed_timestamp` | Separate field in the model | unilog is always the source: `Timestamp == ObservedTimestamp`; a collector adds its own | Yes |
| V4 | `body` is a string only | `Body: AnyValue` | Avoids dynamic-mapping blowup in Elasticsearch/Loki when body varies in shape | Narrowing |
| V5 | `severity_text` is normalized to 6 short names | Spec says to keep "the original string representation as it is known at the source" | Enables a byte-for-byte cross-language diff in conformance; original is kept in `attributes["log.level.original"]` when it doesn't map cleanly | Yes |
| V6 | `resource` repeats on every line | OTLP batches one `Resource` per batch of records | unilog emits one JSON object per line, no batching | Yes |
| V7 | `error.type` allowed on log records | Semconv defines `error.type` for spans/metrics; for logs only `exception.*` is defined ([exceptions-logs](https://opentelemetry.io/docs/specs/semconv/exceptions/exceptions-logs/)) | Needed as a low-cardinality classifier for alerting/grouping without parsing `exception.type` | Yes, standard attribute name |
| V8 | `app.duration_ms` in milliseconds | Semconv measures duration with histograms, in seconds | `app.*` is our own namespace; milliseconds is what people actually read in a log line | Yes |
| V9 | `scope` is a plain string | `InstrumentationScope{name, version, attributes}` | No instrumenting libraries to distinguish | Narrowing |
| V10 | `event_name` is a JSON key | `EventName` is a `LogRecord` field ([data-model.md#field-eventname](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/logs/data-model.md)) | Same thing, different container | Yes |
| V11 | No `resource.service.version`, no `telemetry.sdk.*` | Both defined by semconv ([resource/README.md](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/resource/README.md)) | `telemetry.sdk.*` is constant per process (name/version are the library's own, language is implied by the record shape) — pure repetition, not information. `service.version` degraded to noise in practice: unversioned internal services report nothing meaningful (Composer's own placeholder for an unpublished package, `1.0.0+no-version-set`, was the concrete trigger) | Yes, re-add per field if a consumer ever needs it |
| V12 | `resource.command` (always) and `resource.URL` (only on a record made during a request scope) | Not in semconv at all; `resource` in the OTel model is one fixed value per emitter for its whole lifetime — `URL` varies per record, which OTel resource explicitly forbids | Operator ergonomics: `command` answers "how do I run this again" (`host> cd dir; argv`, redacted like body) without cross-referencing the unit file; `URL` answers "which request produced this line" as one glanceable string (`METHOD https://host/path?query`) instead of two attribute keys (`http.request.method`, `url.full`) scattered in `attributes` — those two keys are folded into it and dropped, not duplicated. The cost: for a request-scoped record, `resource` is no longer the cached, verbatim-shared object — it's a shallow copy with `URL` added, built fresh per record | Yes, split `URL` back into the two attributes and drop both fields |

All twelve are intentional and stable for `logspec 1.0`. A `logspec 2.0` could adopt OTLP/JSON
directly; that would be a `MAJOR` bump per `spec/record.schema.json`.
