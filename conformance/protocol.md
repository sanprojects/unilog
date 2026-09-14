# Conformance protocol

A **case** is a JSON file (`conformance/cases/*.json`) with:

```json
{
  "name": "basic_error_with_attributes",
  "env": { "LOG_REDACT": "1" },
  "input": {
    "severityNumber": 17,
    "body": "Payment charge failed",
    "eventName": "payment.charge.failed",
    "attributes": { "order_id": 42, "http.response.status_code": 502 }
  }
}
```

A **driver** (`conformance/impls/<lang>/driver.*`) is a small program that:

1. Reads the case JSON from `argv[1]` (a file path).
2. Calls the library's own `Build`/`build`/`Record::build` function directly
   with `input` translated to that language's option shape — deliberately
   bypassing console/syslog sinks, since sink routing was verified
   per-language already; this suite is about the **record shape** being
   identical across all five implementations.
3. Applies `env` as environment variables before building (redaction mode,
   limits, etc.)
4. Prints exactly one JSON line to stdout: the record's `JSONLine()`/
   `to_json_line()`/`toJsonLine()`/`toJsonLine()` output.

`run.py`:

1. For each case, runs every available driver, capturing stdout.
2. Parses each line as JSON, validates it against `spec/record.schema.json`.
3. Normalizes volatile fields before comparing (`normalize.yaml`):
   `timestamp`, `resource.host.name`, `resource.process.pid`,
   `resource.service.instance.id`, `resource.service.name`,
   `resource.service.version` (these are legitimately
   environment/language-dependent — see spec §3 — and are not part of what
   conformance checks).
4. Diffs the remaining structure across all drivers that ran; any mismatch
   fails the case and prints a unified diff.

Exit code: 0 if every case passed on every available driver, 1 otherwise.
Missing drivers (e.g. no `php` binary in `PATH`) are skipped with a warning,
not a failure — see `--require` to make a driver mandatory.
