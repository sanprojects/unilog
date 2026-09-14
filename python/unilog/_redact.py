"""Redaction — spec §5. Segment matching on keys (not substring: `cardinality`
must NOT match `card`), plus a handful of value patterns with cheap prefilters."""

from __future__ import annotations

import os
import re

_DEFAULT_KEY_SEGMENTS = frozenset(
    {
        "password", "passwd", "pwd", "passphrase", "secret", "client_secret",
        "token", "access_token", "refresh_token", "id_token", "api_key", "apikey",
        "apitoken", "private_key", "secret_key", "signature", "sig", "credentials", "auth",
        "authorization", "proxy_authorization", "cookie", "set_cookie", "x_api_key",
        "x_auth_token", "x_csrf_token",
        "session", "sessionid", "sid", "jsessionid", "phpsessid", "csrf", "xsrf",
        "card", "cardnumber", "pan", "cvv", "cvc", "cvv2", "card_cvc", "expiry",
        "exp_month", "exp_year", "iban", "account_number", "routing_number",
        "ssn", "passport", "tin", "inn", "snils", "dob", "birthdate",
        "otp", "totp", "pin", "mfa_code", "recovery_code",
    }
)
_PII_KEY_SEGMENTS = frozenset({"email", "phone", "ip", "user_id", "name"})

_SEGMENT_SPLIT = re.compile(r"[._\-\s]+|(?<=[a-z0-9])(?=[A-Z])")

_VALUE_PATTERNS = [
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), "eyJ"),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{10,}"), "bearer"),
    ("pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "PRIVATE KEY"),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), None),
    ("gh_token", re.compile(r"\b(ghp_|gho_|ghu_|ghs_|glpat-)[A-Za-z0-9_-]{20,}\b"), None),
    ("dsn", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@[^\s/]+"), "://"),
    ("kv_secret", re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s,;&]{4,}"), None),
]
_PAN_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _key_segments(key: str) -> set[str]:
    return {s.lower() for s in _SEGMENT_SPLIT.split(key) if s}


class Redactor:
    def __init__(self) -> None:
        self.enabled = os.environ.get("LOG_REDACT", "1") != "0"
        self.mode = os.environ.get("LOG_REDACT_MODE", "mask")
        self.hash_key = os.environ.get("LOG_REDACT_HASH_KEY", "")
        profile = os.environ.get("LOG_REDACT_PROFILE", "default")
        self.key_segments = set(_DEFAULT_KEY_SEGMENTS)
        if profile == "pii":
            self.key_segments |= _PII_KEY_SEGMENTS
        allow = os.environ.get("LOG_REDACT_ALLOW", "")
        self.key_segments -= {s.strip().lower() for s in allow.split(",") if s.strip()}
        self.redact_stacktrace = os.environ.get("LOG_REDACT_STACKTRACE", "1") != "0"

    def key_is_sensitive(self, full_key: str) -> bool:
        if not self.enabled:
            return False
        return bool(self._key_segments_full(full_key) & self.key_segments)

    @staticmethod
    def _key_segments_full(full_key: str) -> set[str]:
        segs: set[str] = set()
        for part in full_key.split("."):
            segs |= _key_segments(part)
        return segs

    def _replace(self, _match_or_value: str) -> str:
        if self.mode == "hash" and self.hash_key:
            import hashlib
            import hmac

            digest = hmac.new(self.hash_key.encode(), _match_or_value.encode(), hashlib.sha256).hexdigest()[:16]
            return f"[REDACTED:{digest}]"
        return "[REDACTED]"

    def redact_value_patterns(self, text: str) -> str:
        if not self.enabled or not isinstance(text, str):
            return text
        for name, pattern, prefilter in _VALUE_PATTERNS:
            if prefilter and prefilter.lower() not in text.lower():
                continue
            text = pattern.sub(lambda m: self._replace(m.group(0)), text)

        def _pan_sub(m: re.Match) -> str:
            digits = re.sub(r"[ -]", "", m.group(0))
            if len(digits) < 13 or not _luhn_ok(digits):
                return m.group(0)
            return self._replace(digits)

        text = _PAN_RE.sub(_pan_sub, text)
        return text
