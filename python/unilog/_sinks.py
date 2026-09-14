"""console + syslog sinks — spec: routing (§2.6), syslog transport ladder,
atomicity (§4.7): exactly one write(2) per record."""

from __future__ import annotations

import os
import sys

from . import _severity

_FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
    "lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

try:
    import syslog as _native_syslog  # POSIX only
except ImportError:  # Windows
    _native_syslog = None


class Sinks:
    def __init__(self, service_name: str = "unilog") -> None:
        self.stderr_min = os.environ.get("LOG_STDERR_MIN_SEVERITY", "17")
        sinks = os.environ.get("LOG_SINK", "console+syslog")
        self.console_enabled = "console" in sinks
        self.syslog_enabled = "syslog" in sinks and _native_syslog is not None
        self._native_ok: bool | None = None
        self._warned_no_syslog = False
        self._service_name = service_name
        facility_name = os.environ.get("LOG_SYSLOG_FACILITY", "user")
        self._facility = _FACILITIES.get(facility_name, 1)
        self._pipe_atomic = os.environ.get("LOG_ATOMIC_PIPE", "auto")
        if self.syslog_enabled:
            try:
                _native_syslog.openlog(service_name, _native_syslog.LOG_PID, self._facility << 3)
                self._native_ok = True
            except Exception:
                self._native_ok = False

    def _route_stream(self, severity_number: int) -> int:
        thr = self.stderr_min
        if thr == "OFF":
            return 1  # stdout
        if thr == "0":
            return 2  # stderr
        try:
            threshold = int(thr)
        except ValueError:
            threshold = 17
        return 2 if severity_number >= threshold else 1

    def _max_bytes(self) -> int:
        default = int(os.environ.get("LOG_MAX_RECORD_BYTES", "65536"))
        if self._pipe_atomic == "0":
            return default
        if self._pipe_atomic == "1":
            return min(default, 4096)
        # auto: cap to PIPE_BUF only if stdout looks like a pipe/fifo
        try:
            import stat

            st = os.fstat(1)
            if stat.S_ISFIFO(st.st_mode):
                return min(default, 4096)
        except Exception:
            pass
        return default

    def emit(self, line: str, severity_number: int) -> None:
        if not self.console_enabled and not (self.syslog_enabled and self._native_ok):
            return
        max_bytes = self._max_bytes()
        data = line.encode("utf-8")
        if len(data) > max_bytes:
            data = data[: max_bytes - 2] + b"}\n"  # best-effort: keep it terminated

        fd = self._route_stream(severity_number)

        use_native = self.syslog_enabled and self._native_ok
        if use_native:
            try:
                priority = _severity.syslog_priority(severity_number, 0)  # facility bits already set via openlog
                _native_syslog.syslog(priority & 0x7, data.decode("utf-8", "replace"))
            except Exception:
                self._native_ok = False
                use_native = False

        if self.console_enabled:
            if not use_native and self.syslog_enabled and os.environ.get("JOURNAL_STREAM"):
                pri = _severity.syslog_priority(severity_number, self._facility)
                prefixed = f"<{pri}>".encode("ascii") + data
                self._write(fd, prefixed)
            else:
                if self.syslog_enabled and not use_native and not self._warned_no_syslog:
                    self._warned_no_syslog = True
                    self._write(2, b"unilog: no syslog transport available, continuing with console only\n")
                self._write(fd, data)

    @staticmethod
    def _write(fd: int, data: bytes) -> None:
        try:
            os.write(fd, data)
        except OSError:
            pass
