"""Resource resolver — spec §3. Runs once, result is cached as an already
serialized JSON fragment (the hot-path optimization the spec calls for)."""

from __future__ import annotations

import os
import socket
import sys
import uuid
from typing import Any
from urllib.parse import unquote

from ._redact import Redactor

_redactor = Redactor()


def _parse_otel_resource_attributes(raw: str) -> dict[str, str] | None:
    """key1=value1,key2=value2, percent-encoded. Whole var drops on any parse error
    (spec §3.1 point 3, matches OTel's own documented behavior)."""
    out: dict[str, str] = {}
    try:
        for pair in raw.split(","):
            pair = pair.strip()
            if not pair:
                continue
            k, _, v = pair.partition("=")
            if not _:
                raise ValueError(f"missing '=' in {pair!r}")
            out[unquote(k.strip())] = unquote(v.strip())
    except Exception:
        return None
    return out


def _package_name(dist_name: str | None) -> str | None:
    if not dist_name:
        return None
    try:
        from importlib.metadata import distribution

        return distribution(dist_name).metadata["Name"]
    except Exception:
        return None


def _executable_basename() -> str:
    argv0 = sys.argv[0] if sys.argv else ""
    base = os.path.basename(argv0) or "python"
    return base


def _command_line(host_name: str | None) -> str:
    """"how to run this again": hostname> cd <dir>; <argv, executable
    shortened to its basename>. Human-facing, not machine-parsed — spec
    deviation V12. Value-pattern redacted like body, since argv can carry a
    secret (a flag value) the way any other free-form string can."""
    try:
        cwd = os.getcwd()
    except OSError:
        cwd = "?"
    argv = list(sys.argv) or ["python"]
    argv[0] = os.path.basename(argv[0]) or "python"
    return _redactor.redact_value_patterns(f"{host_name or '?'}> cd {cwd}; {' '.join(argv)}")


def _instance_id(strategy: str, k8s: dict[str, str], host_name: str | None) -> str | None:
    if strategy == "none":
        return None
    if strategy == "host-pid":
        return f"{host_name or 'unknown'}/{os.getpid()}"
    if k8s.get("k8s.pod.name"):
        return ".".join(
            filter(None, [k8s.get("k8s.namespace.name"), k8s.get("k8s.pod.name"), k8s.get("k8s.container.name")])
        )
    return str(uuid.uuid4())


def resolve(explicit: dict[str, object] | None = None) -> dict[str, object]:
    explicit = explicit or {}
    env = os.environ

    otel_attrs = _parse_otel_resource_attributes(env.get("OTEL_RESOURCE_ATTRIBUTES", ""))
    if env.get("OTEL_RESOURCE_ATTRIBUTES") and otel_attrs is None:
        sys.stderr.write("unilog: OTEL_RESOURCE_ATTRIBUTES is malformed, ignoring it entirely\n")
        otel_attrs = {}
    otel_attrs = otel_attrs or {}

    dist_name = explicit.get("distribution_name") or env.get("LOG_DISTRIBUTION_NAME")
    pkg_name = _package_name(dist_name if isinstance(dist_name, str) else None)

    service_name = (
        explicit.get("service_name")
        or env.get("OTEL_SERVICE_NAME")
        or otel_attrs.get("service.name")
        or pkg_name
        or f"unknown_service:{_executable_basename()}"
    )
    service_namespace = explicit.get("service_namespace") or env.get("LOG_SERVICE_NAMESPACE") or otel_attrs.get("service.namespace")
    deployment_env = explicit.get("deployment_environment") or env.get("LOG_ENV") or otel_attrs.get("deployment.environment.name")

    try:
        host_name = socket.gethostname()
    except Exception:
        host_name = env.get("HOSTNAME")

    k8s: dict[str, str] = {}
    for attr, var in (
        ("k8s.namespace.name", "K8S_NAMESPACE"),
        ("k8s.pod.name", "K8S_POD_NAME"),
        ("k8s.container.name", "K8S_CONTAINER_NAME"),
        ("k8s.node.name", "K8S_NODE_NAME"),
    ):
        v = env.get(var)
        if v:
            k8s[attr] = v

    strategy = env.get("LOG_INSTANCE_ID_STRATEGY", "none")
    instance_id = _instance_id(strategy, k8s, host_name)

    resource: dict[str, object] = {"service.name": service_name}
    if service_namespace:
        resource["service.namespace"] = service_namespace
    if instance_id:
        resource["service.instance.id"] = instance_id
    if deployment_env:
        resource["deployment.environment.name"] = deployment_env
    # host.name/process.pid/service.instance.id (above) default OFF: on a
    # single-host deployment they're the same value on every record - true,
    # but not information. Opt in per field when they'd actually distinguish
    # something (multiple hosts, multiple workers on one host, ...).
    if env.get("LOG_RESOURCE_HOST") == "1" and host_name:
        resource["host.name"] = host_name
    if env.get("LOG_RESOURCE_PROCESS") == "1":
        resource["process.pid"] = os.getpid()
    if env.get("LOG_RESOURCE_COMMAND", "1") != "0":
        resource["command"] = _command_line(host_name)
    resource.update(k8s)

    # extra keys the user or OTEL_RESOURCE_ATTRIBUTES set, not in the known list
    known = set(resource) | {"service.name", "service.namespace", "deployment.environment.name"}
    for k, v in otel_attrs.items():
        if k not in known:
            resource[k] = v

    return resource


_cached: dict[str, object] | None = None
_cached_pid: int | None = None


def get(explicit: dict[str, object] | None = None) -> dict[str, object]:
    """Cached resolve(), re-resolved after fork() (spec §3.4) so php-fpm/gunicorn-style
    workers don't all report the same service.instance.id."""
    global _cached, _cached_pid
    pid = os.getpid()
    if _cached is None or _cached_pid != pid:
        _cached = resolve(explicit)
        _cached_pid = pid
    return _cached


def with_request_url(resource: dict[str, object], attrs: dict[str, Any]) -> dict[str, object]:
    """Pops http.request.method/url.full (unilog.request_scope) out of attrs
    and, if both were present, returns a resource copy with them folded into
    a single resource["URL"] — spec V12, same reasoning as resource.command.
    Leaves resource/attrs untouched (returns resource as-is) when no request
    scope is active."""
    method = attrs.get("http.request.method")
    url = attrs.get("url.full")
    if not (isinstance(method, str) and isinstance(url, str)):
        return resource
    attrs.pop("http.request.method", None)
    attrs.pop("url.full", None)
    merged = dict(resource)
    merged["URL"] = f"{method} {url}"
    return merged
