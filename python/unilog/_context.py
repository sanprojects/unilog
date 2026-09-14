"""Trace context — spec §4 (trace_id/span_id) — plus generic scope attributes
(request method/url, worker path/attrs, or anything else the caller wants
attached to every log record for the duration of a request/job). contextvars
auto-propagate into asyncio tasks but NOT into threading.Thread (verified:
MISSING) — hence the explicit wrappers below."""

from __future__ import annotations

import contextlib
import contextvars
import functools
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterator, TypeVar

trace_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("unilog_trace_id", default=None)
span_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("unilog_span_id", default=None)
trace_flags_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("unilog_trace_flags", default=None)
scope_attrs_var: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar("unilog_scope_attrs", default={})

_TRACEPARENT_RE = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")

T = TypeVar("T")


def set_trace(trace_id: str | None, span_id: str | None, trace_flags: str | None = None) -> None:
    trace_id_var.set(trace_id)
    span_id_var.set(span_id)
    trace_flags_var.set(trace_flags)


def current() -> tuple[str | None, str | None, str | None]:
    return trace_id_var.get(), span_id_var.get(), trace_flags_var.get()


def current_scope_attrs() -> dict[str, Any]:
    return scope_attrs_var.get()


@contextlib.contextmanager
def scope(**attrs: Any) -> Iterator[None]:
    """Attach attributes to every unilog call made while this scope is
    active — the mechanism behind request_scope()/worker_scope() below, and
    usable directly for anything else. Nests: an inner scope's keys win over
    an outer one's on collision; an explicit attribute passed to a specific
    log call still wins over both (call-site beats ambient).

        with unilog.scope(**{"http.request.method": "POST", "url.full": url}):
            handle_request()
    """
    merged = {**scope_attrs_var.get(), **attrs}
    token = scope_attrs_var.set(merged)
    try:
        yield
    finally:
        scope_attrs_var.reset(token)


def request_scope(method: str, url: str):
    """with unilog.request_scope('POST', '/v1/payments/42'): ..."""
    return scope(**{"http.request.method": method, "url.full": url})


def worker_scope(path: str, **attrs: Any):
    """with unilog.worker_scope('jobs.charge_subscription', account_id=42): ..."""
    return scope(**{"worker.path": path, **attrs})


def parse_traceparent(header: str) -> tuple[str, str, str] | None:
    """W3C traceparent: version-traceid-spanid-flags."""
    m = _TRACEPARENT_RE.match(header.strip())
    if not m or m.group(2) == "0" * 32 or m.group(3) == "0" * 16:
        return None
    return m.group(2), m.group(3), m.group(4)


def thread(target: Callable[..., Any], *args: Any, **kwargs: Any) -> threading.Thread:
    """threading.Thread wrapper that copies the current trace/scope context in
    — contextvars do NOT cross the threading.Thread boundary on their own."""
    ctx = contextvars.copy_context()
    t = threading.Thread(target=lambda: ctx.run(target, *args, **kwargs))
    return t


def submit(executor: ThreadPoolExecutor, fn: Callable[..., T], *args: Any, **kwargs: Any):
    ctx = contextvars.copy_context()
    return executor.submit(lambda: ctx.run(functools.partial(fn, *args, **kwargs)))
