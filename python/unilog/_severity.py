"""Severity table. Mirrors spec/severity.csv 1:1 — keep the two in sync by hand
until a generator script exists (see spec/severity.csv header comment)."""

from __future__ import annotations

# number -> (text, syslog_severity 0-7)
TABLE: dict[int, tuple[str, int]] = {
    1: ("TRACE", 7), 2: ("TRACE2", 7), 3: ("TRACE3", 7), 4: ("TRACE4", 7),
    5: ("DEBUG", 7), 6: ("DEBUG2", 7), 7: ("DEBUG3", 7), 8: ("DEBUG4", 7),
    9: ("INFO", 6), 10: ("INFO2", 5), 11: ("INFO3", 5), 12: ("INFO4", 5),
    13: ("WARN", 4), 14: ("WARN2", 4), 15: ("WARN3", 4), 16: ("WARN4", 4),
    17: ("ERROR", 3), 18: ("ERROR2", 2), 19: ("ERROR3", 1), 20: ("ERROR4", 1),
    21: ("FATAL", 0), 22: ("FATAL2", 0), 23: ("FATAL3", 0), 24: ("FATAL4", 0),
}

TEXT_TO_NUMBER: dict[str, int] = {text: num for num, (text, _sv) in TABLE.items()}


def text_and_syslog(number: int) -> tuple[str, int]:
    number = max(1, min(24, number))
    return TABLE[number]


def from_python_level(level: int) -> tuple[int, str | None]:
    """Python `logging` level (0/10/20/.../50 + arbitrary custom ints) -> (severity_number, original_if_nonstandard).

    Piecewise per spec §2.3 — a straight-line formula doesn't fit stdlib's
    decade-sized bands (10=DEBUG but 25=NOTICE, a 5-wide band).
    """
    if level <= 0:
        return 9, "NOTSET"
    if level < 10:
        return 1, str(level)
    if level < 20:
        return 5, None if level == 10 else str(level)
    if level < 25:
        return 9, None if level == 20 else str(level)
    if level < 30:
        return 10, str(level)
    if level < 40:
        return 13, None if level == 30 else str(level)
    if level < 50:
        return 17, None if level == 40 else str(level)
    return 21, None if level == 50 else str(level)


def syslog_priority(number: int, facility: int) -> int:
    _text, sev = text_and_syslog(number)
    return facility * 8 + sev
