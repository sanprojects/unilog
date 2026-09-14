"""unilog — zero-config OTel-shaped structured logging.

    import unilog.auto              # one line, installs everything
    logging.error('User not found', {'id': 123})

See https://github.com/sanprojects/unilog for the format spec.
"""

from __future__ import annotations

from . import _install
from ._context import parse_traceparent, request_scope, scope, set_trace, submit, thread, worker_scope

__all__ = [
    "configure", "rearm", "disable", "set_trace", "parse_traceparent", "thread", "submit",
    "scope", "request_scope", "worker_scope",
]

__version__ = "0.1.0"


def configure(**explicit_resource: object) -> None:
    """Install (if not already) and override resource fields explicitly,
    e.g. unilog.configure(service_name='billing-api', service_version='1.8.3')."""
    from . import _resource

    _resource._cached = _resource.resolve(explicit_resource)
    _install.install()


def rearm() -> None:
    _install.rearm()


def disable() -> None:
    _install.disable()
