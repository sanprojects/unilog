"""stdlib `logging` capture — the handler that turns a LogRecord into a unilog
record. See _install.py for the excepthook/faulthandler/asyncio wiring."""

from __future__ import annotations

import logging
from typing import Any, Mapping

from . import _caller, _context, _record, _resource, _severity
from ._sinks import Sinks

# Attributes every LogRecord carries natively — anything else on the record
# came from logging.error(..., extra={...}) and becomes an attribute.
_STANDARD_ATTRS = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "message",
    }
)


class Handler(logging.Handler):
    def __init__(self, sinks: Sinks) -> None:
        super().__init__()
        self._sinks = sinks

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._emit(record)
        except Exception:
            pass  # a broken sink must never crash the caller's application

    def _emit(self, record: logging.LogRecord) -> None:
        severity_number, original_level = _severity.from_python_level(record.levelno)

        body = record.getMessage()
        attrs: dict[str, Any] = {}

        # Ambient scope (request method/url, worker path/attrs — see
        # unilog.scope()/request_scope()/worker_scope()) and a short caller
        # trace both go in first, at the lowest priority: anything the call
        # site itself provides below should be able to override them.
        attrs.update(_context.current_scope_attrs())
        if _caller.enabled():
            attrs.update(_caller.caller_attributes())

        # The example from the original request:
        #   logging.error('User not found', {'id': 123})
        # stdlib special-cases a single dict in `args`: no %-formatting error,
        # and getMessage() returns the message unchanged when no placeholder
        # consumed it. That equality is exactly the signal that the dict was
        # meant as structured data, not %-format arguments.
        if isinstance(record.args, Mapping) and body == str(record.msg):
            attrs.update(record.args)

        for k, v in record.__dict__.items():
            if k not in _STANDARD_ATTRS:
                attrs[k] = v

        event_name = attrs.pop("event_name", None)

        if original_level is not None:
            attrs.setdefault("log.level.original", original_level)

        if record.exc_info:
            exc = record.exc_info[1] if isinstance(record.exc_info, tuple) else None
            if exc is not None:
                attrs.update(_record.exception_to_attributes(exc, severity_number))

        trace_id, span_id, trace_flags = _context.current()

        rec = _record.build(
            severity_number=severity_number,
            body=body,
            event_name=event_name,
            resource=_resource.get(),
            attributes=attrs,
            trace_id=trace_id,
            span_id=span_id,
            trace_flags=trace_flags,
            scope=record.name if record.name != "root" else None,
        )
        self._sinks.emit(_record.to_json_line(rec), severity_number)


def emit_raw(sinks: Sinks, *, severity_number: int, body: str, event_name: str, attributes: dict[str, Any] | None = None) -> None:
    """Used by the excepthook/unraisablehook/asyncio paths, which have no LogRecord."""
    trace_id, span_id, trace_flags = _context.current()
    attrs = dict(_context.current_scope_attrs())
    attrs.update(attributes or {})
    rec = _record.build(
        severity_number=severity_number,
        body=body,
        event_name=event_name,
        resource=_resource.get(),
        attributes=attrs,
        trace_id=trace_id,
        span_id=span_id,
        trace_flags=trace_flags,
    )
    sinks.emit(_record.to_json_line(rec), severity_number)
