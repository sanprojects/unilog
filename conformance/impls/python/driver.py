#!/usr/bin/env python3
"""Conformance driver for the Python implementation. See ../../protocol.md."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "python"))

case = json.load(open(sys.argv[1]))
for k, v in (case.get("env") or {}).items():
    os.environ[k] = v

from unilog import _caller, _record, _resource  # noqa: E402 (env must be set first)

opts = case["input"]

# Mirrors what unilog.auto's logging.Handler does before calling _record.build()
# — the driver itself is a manual "entry point", same as a real app's.
attributes = dict(_caller.caller_attributes()) if _caller.enabled() else {}
attributes.update(opts.get("attributes") or {})

rec = _record.build(
    severity_number=opts.get("severityNumber", 9),
    body=opts.get("body", ""),
    event_name=opts.get("eventName"),
    resource=_resource.get(),
    attributes=attributes,
    trace_id=opts.get("traceId"),
    span_id=opts.get("spanId"),
)
sys.stdout.write(_record.to_json_line(rec))
