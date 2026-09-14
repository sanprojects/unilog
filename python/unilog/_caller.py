"""Short caller trace — attached to every regular log call (not the full
`exception.stacktrace`, which stays reserved for actual exceptions). Mirrors
what the sanstv TSV format carried on every line (module::funcName,
filename:lineno) but as a bounded, OTel-attribute-shaped addition:
`code.function`/`code.filepath`/`code.lineno` for the immediate call site,
plus `code.stacktrace` — up to LOG_CALLER_TRACE_FRAMES (default 3) frames
above it, closest-first, skipping stdlib `logging` and unilog's own frames."""

from __future__ import annotations

import logging
import os
import traceback

_LOGGING_DIR = os.path.dirname(os.path.abspath(logging.__file__))
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))


def _is_internal(filename: str) -> bool:
    filename = os.path.abspath(filename)
    return filename.startswith(_LOGGING_DIR) or filename.startswith(_PKG_DIR)


def caller_attributes(limit: int | None = None) -> dict[str, object]:
    """Walk the real call stack (not the LogRecord's own findCaller, which
    only gives one frame) and return code.function/filepath/lineno for the
    nearest application frame, plus a short code.stacktrace chain."""
    if limit is None:
        limit = int(os.environ.get("LOG_CALLER_TRACE_FRAMES", "3"))
    frames = [f for f in traceback.extract_stack()[:-1] if not _is_internal(f.filename)]
    if not frames:
        return {}
    app_frames = frames[-limit:]
    nearest = app_frames[-1]
    attrs: dict[str, object] = {
        "code.function": nearest.name,
        "code.filepath": nearest.filename,
        "code.lineno": nearest.lineno,
    }
    if len(app_frames) > 1:
        chain = " < ".join(f"{f.name} ({os.path.basename(f.filename)}:{f.lineno})" for f in reversed(app_frames))
        attrs["code.stacktrace"] = chain
    return attrs


def enabled() -> bool:
    return os.environ.get("LOG_CALLER_INFO", "1") != "0"
