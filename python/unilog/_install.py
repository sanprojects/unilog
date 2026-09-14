"""Install orchestration — mode detection (full/sidecar/off), idempotency,
chaining to whatever was there before us, and re-arm over basicConfig(force=True)
/ dictConfig, which verified to blow our handler off the root logger."""

from __future__ import annotations

import asyncio
import logging
import logging.config
import os
import sys
import threading
import warnings

from . import _capture, _record, _resource
from ._sinks import Sinks

_MARKER = "_unilog_installed"


def _debug(msg: str) -> None:
    if os.environ.get("LOG_DEBUG") == "1":
        sys.stderr.write(f"unilog: {msg}\n")


def _detect_mode() -> str:
    forced = os.environ.get("UNILOG_MODE", "auto")
    if os.environ.get("UNILOG_DISABLE") == "1":
        return "off"
    if forced in ("full", "sidecar", "off"):
        return forced
    # auto: a non-empty root logger before we run means someone else (or a
    # framework) configured logging first — don't fight them for the handler.
    if logging.root.handlers:
        return "sidecar"
    return "full"


class _State:
    installed = False
    mode = "off"
    sinks: Sinks | None = None
    handler: Handler = None  # type: ignore[assignment]
    prev_excepthook = None
    prev_threading_excepthook = None
    prev_unraisablehook = None
    prev_new_event_loop = None
    prev_basic_config = None
    prev_dict_config = None
    prev_file_config = None


_state = _State()


def _excepthook(exc_type, exc_value, exc_tb) -> None:
    if issubclass(exc_type, KeyboardInterrupt):
        (_state.prev_excepthook or sys.__excepthook__)(exc_type, exc_value, exc_tb)
        return
    try:
        _capture.emit_raw(
            _state.sinks,
            severity_number=21,
            body=str(exc_value) or exc_type.__name__,
            event_name="process.uncaught_exception",
            attributes=_record.exception_to_attributes(exc_value, 21),
        )
    except Exception:
        pass
    (_state.prev_excepthook or sys.__excepthook__)(exc_type, exc_value, exc_tb)


def _threading_excepthook(args) -> None:
    try:
        if args.exc_type is not SystemExit:
            _capture.emit_raw(
                _state.sinks,
                severity_number=21,
                body=str(args.exc_value) or args.exc_type.__name__,
                event_name="thread.uncaught_exception",
                attributes=_record.exception_to_attributes(args.exc_value, 21) if args.exc_value else {},
            )
    except Exception:
        pass
    if _state.prev_threading_excepthook:
        _state.prev_threading_excepthook(args)


def _unraisablehook(unraisable) -> None:
    try:
        exc = unraisable.exc_value
        body = str(unraisable.err_msg or "Exception ignored")
        attrs = _record.exception_to_attributes(exc, 17) if exc is not None else {}
        if unraisable.object is not None:
            attrs["log.unraisable.object"] = repr(unraisable.object)[:200]
        _capture.emit_raw(_state.sinks, severity_number=17, body=body, event_name="python.unraisable_exception", attributes=attrs)
    except Exception:
        pass
    if _state.prev_unraisablehook:
        _state.prev_unraisablehook(unraisable)


def _asyncio_exception_handler(loop, context) -> None:
    try:
        exc = context.get("exception")
        body = context.get("message", "asyncio exception")
        attrs = _record.exception_to_attributes(exc, 17) if exc is not None else {}
        _capture.emit_raw(_state.sinks, severity_number=17, body=body, event_name="asyncio.exception", attributes=attrs)
    except Exception:
        pass
    default = getattr(loop, "_unilog_prev_handler", None)
    if default:
        default(loop, context)


def _wrap_new_event_loop(orig):
    def wrapped(*a, **kw):
        loop = orig(*a, **kw)
        try:
            prev = loop.get_exception_handler()
            loop._unilog_prev_handler = prev
            loop.set_exception_handler(_asyncio_exception_handler)
        except Exception:
            pass
        return loop

    return wrapped


def _install_root_handler() -> None:
    _state.sinks = Sinks(service_name=str(_resource.get().get("service.name", "unilog")))
    _state.handler = _capture.Handler(_state.sinks)
    level_name = os.environ.get("LOG_LEVEL", "INFO")
    try:
        level = int(level_name)
        # our 1-24 scale doesn't map 1:1 to stdlib; approximate via the table
        level = {1: 5, 5: 10, 9: 20, 13: 30, 17: 40, 21: 50}.get(level, 20)
    except ValueError:
        level = getattr(logging, level_name.upper(), logging.INFO) if level_name.upper() != "OFF" else logging.CRITICAL + 1
    logging.root.addHandler(_state.handler)
    logging.root.setLevel(level)


def _rearm_if_needed() -> None:
    if _state.mode != "full":
        return
    if _state.handler not in logging.root.handlers:
        _debug("root handler was removed (basicConfig(force=True) or dictConfig) — re-arming")
        logging.root.addHandler(_state.handler)


def _wrap_reconfig(orig, name):
    def wrapped(*a, **kw):
        result = orig(*a, **kw)
        _rearm_if_needed()
        return result

    wrapped.__name__ = name
    return wrapped


def install() -> None:
    if getattr(logging, _MARKER, False):
        return
    setattr(logging, _MARKER, True)
    _state.installed = True
    _state.mode = _detect_mode()
    if _state.mode == "off":
        return

    if _state.mode == "full":
        _install_root_handler()
    else:
        # sidecar: still need a Sinks instance for the crash hooks below
        _state.sinks = Sinks(service_name=str(_resource.get().get("service.name", "unilog")))

    # Chain, never clobber — spec §6.
    _state.prev_excepthook = sys.excepthook
    sys.excepthook = _excepthook

    _state.prev_threading_excepthook = threading.excepthook
    threading.excepthook = _threading_excepthook

    _state.prev_unraisablehook = getattr(sys, "unraisablehook", None)
    sys.unraisablehook = _unraisablehook

    _state.prev_new_event_loop = asyncio.events.new_event_loop
    asyncio.events.new_event_loop = _wrap_new_event_loop(_state.prev_new_event_loop)
    try:
        asyncio.new_event_loop = asyncio.events.new_event_loop  # keep the top-level alias in sync
    except Exception:
        pass

    logging.captureWarnings(True)

    try:
        import faulthandler

        faulthandler.enable()  # raw text, not JSON — spec §7 documented limitation
    except Exception:
        pass

    if _state.mode == "full":
        _state.prev_basic_config = logging.basicConfig
        logging.basicConfig = _wrap_reconfig(_state.prev_basic_config, "basicConfig")

        _state.prev_dict_config = logging.config.dictConfig
        logging.config.dictConfig = _wrap_reconfig(_state.prev_dict_config, "dictConfig")

        _state.prev_file_config = logging.config.fileConfig
        logging.config.fileConfig = _wrap_reconfig(_state.prev_file_config, "fileConfig")

    import atexit

    atexit.register(lambda: None)  # placeholder flush hook; sinks are unbuffered today

    _debug(f"installed, mode={_state.mode}")


def rearm() -> None:
    """Public escape hatch: call after any third-party code that might have
    reconfigured logging without going through our wrapped functions."""
    _rearm_if_needed()


def disable() -> None:
    if not _state.installed:
        return
    if _state.handler in logging.root.handlers:
        logging.root.removeHandler(_state.handler)
    if _state.prev_excepthook:
        sys.excepthook = _state.prev_excepthook
    if _state.prev_threading_excepthook:
        threading.excepthook = _state.prev_threading_excepthook
    if _state.prev_unraisablehook:
        sys.unraisablehook = _state.prev_unraisablehook
    if _state.prev_new_event_loop:
        asyncio.events.new_event_loop = _state.prev_new_event_loop
    setattr(logging, _MARKER, False)
    _state.installed = False
