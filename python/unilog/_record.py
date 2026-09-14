"""Record assembly — spec §1, §4. One dict in, one canonically-ordered dict out,
ready for json.dumps with sort_keys handled by our own ordering (not stdlib's)."""

from __future__ import annotations

import datetime as _dt
import os
import re
import sys
import traceback as _tb
from typing import Any

from . import _severity
from ._redact import Redactor

_TOP_ORDER = [
    "timestamp", "severity_text", "severity_number", "event_name", "body",
    "trace_id", "span_id", "trace_flags", "scope", "resource", "attributes",
    "dropped_attributes_count",
]

_BODY_LIMIT = int(os.environ.get("LOG_BODY_LIMIT", "8192"))
_MAX_ATTRS = int(os.environ.get("LOG_MAX_ATTRIBUTES", "128"))
_MAX_ATTR_BYTES = int(os.environ.get("LOG_MAX_ATTRIBUTE_BYTES", "4096"))
_STACKTRACE_MIN = int(os.environ.get("LOG_STACKTRACE_MIN_SEVERITY", "17"))
_MAX_CAUSES = int(os.environ.get("LOG_EXCEPTION_MAX_CAUSES", "3"))

_redactor = Redactor()


def now_ts() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _truncate(s: str, limit: int) -> str:
    b = s.encode("utf-8", "replace")
    if len(b) <= limit:
        return s
    return b[:limit].decode("utf-8", "ignore") + "...[truncated]"


def _flatten_value(v: Any, depth: int = 0, seen: set[int] | None = None) -> Any:
    """Attribute value coercion ladder — spec §4.3. Applied recursively but the
    *keys* stay flat (dicts collapse into dotted attribute keys by the caller)."""
    if seen is None:
        seen = set()
    if v is None or isinstance(v, (bool, int, float, str)):
        if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
            return None  # NaN/Inf forbidden in JSON — spec §1.1
        if isinstance(v, str):
            return _truncate(_redactor.redact_value_patterns(v), _MAX_ATTR_BYTES)
        return v
    if isinstance(v, (bytes, bytearray)):
        import base64

        return "base64:" + base64.b64encode(bytes(v)).decode("ascii")
    oid = id(v)
    if oid in seen:
        return "[Circular]"
    seen = seen | {oid}
    if isinstance(v, dict):
        return {str(k): _flatten_value(val, depth + 1, seen) for k, val in list(v.items())[:64]}
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_flatten_value(x, depth + 1, seen) for x in list(v)[:64]]
    if hasattr(v, "__str__"):
        try:
            return _truncate(str(v), _MAX_ATTR_BYTES)
        except Exception:
            return repr(v)
    return repr(v)


_RESERVED_PREFIXES = ("log.", "unilog.")


def normalize_attributes(raw: dict[str, Any]) -> tuple[dict[str, Any], int]:
    dropped = 0
    flat: dict[str, Any] = {}
    for k, v in raw.items():
        key = str(k)
        if key.startswith(_RESERVED_PREFIXES) and not key.startswith(("log.level.original", "log.invalid")):
            key = "attr." + key  # never silently overwrite a reserved key — spec §4.6
        if _redactor.key_is_sensitive(key):
            flat[key] = "[REDACTED]"
            continue
        flat[key] = _flatten_value(v)
    if len(flat) > _MAX_ATTRS:
        keys = sorted(flat)[:_MAX_ATTRS]
        dropped = len(flat) - _MAX_ATTRS
        flat = {k: flat[k] for k in keys}
    return flat, dropped


def exception_to_attributes(exc: BaseException, severity_number: int) -> dict[str, Any]:
    attrs: dict[str, Any] = {}
    etype = f"{type(exc).__module__}.{type(exc).__qualname__}" if type(exc).__module__ not in ("builtins",) else type(exc).__qualname__
    attrs["exception.type"] = etype
    attrs["exception.message"] = str(exc)
    if severity_number >= _STACKTRACE_MIN:
        attrs["exception.stacktrace"] = "".join(_tb.format_exception(type(exc), exc, exc.__traceback__))
        if _redactor.redact_stacktrace:
            attrs["exception.stacktrace"] = _redactor.redact_value_patterns(attrs["exception.stacktrace"])
    attrs["error.type"] = etype

    causes = []
    cur = exc.__cause__ or (exc.__context__ if not exc.__suppress_context__ else None)
    depth = 0
    deepest_type = etype
    while cur is not None and depth < _MAX_CAUSES:
        c_type = f"{type(cur).__module__}.{type(cur).__qualname__}" if type(cur).__module__ not in ("builtins",) else type(cur).__qualname__
        causes.append({"type": c_type, "message": str(cur)})
        deepest_type = c_type
        cur = cur.__cause__ or (cur.__context__ if not cur.__suppress_context__ else None)
        depth += 1
    if causes:
        attrs["exception.causes"] = causes
        attrs["error.type"] = deepest_type
    return attrs


def build(
    *,
    severity_number: int,
    body: str,
    event_name: str | None = None,
    resource: dict[str, Any],
    attributes: dict[str, Any] | None = None,
    trace_id: str | None = None,
    span_id: str | None = None,
    trace_flags: str | None = None,
    scope: str | None = None,
) -> dict[str, Any]:
    severity_number = max(1, min(24, severity_number))
    severity_text, _sv = _severity.text_and_syslog(severity_number)

    record: dict[str, Any] = {
        "timestamp": now_ts(),
        "severity_text": severity_text,
        "severity_number": severity_number,
        "body": _truncate(_redactor.redact_value_patterns(body), _BODY_LIMIT),
    }
    if event_name and re.match(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$", event_name) and len(event_name) <= 63:
        record["event_name"] = event_name
    if trace_id:
        record["trace_id"] = trace_id
    if span_id:
        record["span_id"] = span_id
    if trace_flags:
        record["trace_flags"] = trace_flags
    if scope:
        record["scope"] = scope[:255]
    record["resource"] = resource

    attrs, dropped = normalize_attributes(attributes or {})
    if attrs:
        record["attributes"] = dict(sorted(attrs.items()))
    if dropped:
        record["dropped_attributes_count"] = dropped

    return {k: record[k] for k in _TOP_ORDER if k in record}


def to_json_line(record: dict[str, Any]) -> str:
    import json

    ascii_only = os.environ.get("LOG_ASCII_ONLY", "0") == "1"
    return json.dumps(record, ensure_ascii=ascii_only, separators=(",", ":"), sort_keys=False) + "\n"
