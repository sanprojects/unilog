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

# (name, compiled, prefilters, replace_group). A prefilter is a cheap substring
# test that skips the regex entirely; several are allowed because one string
# cannot express "AKIA or ASIA". replace_group masks only that capture group,
# so `?key=...` keeps the readable parameter name.
#
# A prefilter is matched case-SENSITIVELY unless its own regex is case-
# insensitive, which is read off re.IGNORECASE rather than carried as another
# field. It has to be: folding case made "AC" (twilio) match "ac" anywhere and
# fire on 62% of real log lines - 20.8 of the 158 microseconds per record went
# to a regex that could never match.
_VALUE_PATTERNS = [
    # Query-string parameters. `key` is ambiguous in prose ("primary key") but
    # inside ?...&key= it is a secret, so this list is wider than the key
    # segments used for attribute names.
    ("query_param", re.compile(
        r"(?i)([?&](?:key|api[_-]?key|access[_-]?key|token|access[_-]?token|auth|password"
        r"|passwd|secret|client[_-]?secret|sig|signature|session|sid)=)([^&\s\"'<>]{4,})"
    ), ("=",), 2),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), ("eyJ",), 0),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{10,}"), ("bearer",), 0),
    ("pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), ("PRIVATE KEY",), 0),
    # Vendor-issued tokens: the prefix is fixed by the vendor, so the regex is
    # exact and the prefilter is free. AWS and GitHub used to be one pattern
    # over several prefixes and therefore ran with no prefilter at all.
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), ("AKIA", "ASIA"), 0),
    ("github_token", re.compile(r"\b(ghp_|gho_|ghu_|ghs_)[A-Za-z0-9_-]{20,}\b"), ("gh",), 0),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), ("glpat-",), 0),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), ("AIza",), 0),
    ("google_oauth", re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}"), ("ya29.",), 0),
    ("openai", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b"), ("sk-",), 0),
    ("stripe", re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{16,}\b"), ("_live_", "_test_"), 0),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), ("xox",), 0),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{32,}\b"), (":AA",), 0),
    ("sendgrid", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), ("SG.",), 0),
    ("twilio_sid", re.compile(r"\bAC[0-9a-f]{32}\b"), ("AC",), 0),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), ("npm_",), 0),
    ("digitalocean_token", re.compile(r"\bdop_v1_[0-9a-f]{64}\b"), ("dop_v1_",), 0),
    ("dsn", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@[^\s/]+"), ("://",), 0),
    # Last: the vendor patterns above are precise and have already masked what
    # they recognise; this catches name=value shapes with no known form.
    ("kv_secret", re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s,;&]{4,}"), ("=", ":"), 0),
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

    # A match that already carries the mask is left alone. Without this,
    # kv_secret (broad, runs last) swallows the `token=[REDACTED]` that
    # query_param just produced and the parameter name is lost. A negative
    # lookahead would be the obvious fix and is not available: Go's RE2 has
    # none, and all four implementations have to agree byte for byte.
    def _replace(self, _match_or_value: str) -> str:
        if "[REDACTED" in _match_or_value:
            return _match_or_value
        if self.mode == "hash" and self.hash_key:
            import hashlib
            import hmac

            digest = hmac.new(self.hash_key.encode(), _match_or_value.encode(), hashlib.sha256).hexdigest()[:16]
            return f"[REDACTED:{digest}]"
        return "[REDACTED]"

    def _sub_group(self, group: int):
        """Mask one capture group in place, keeping the rest of the match - so
        `?key=AIza...` becomes `?key=[REDACTED]` rather than losing the name."""

        def sub(m: re.Match) -> str:
            whole_start = m.start(0)
            start, end = m.span(group)
            text = m.group(0)
            return text[: start - whole_start] + self._replace(m.group(group)) + text[end - whole_start :]

        return sub

    def redact_value_patterns(self, text: str) -> str:
        if not self.enabled or not isinstance(text, str):
            return text
        lower = text.lower()
        for _name, pattern, prefilters, group in _VALUE_PATTERNS:
            # Any one prefilter is enough; none present means the regex cannot
            # match, so it is never run.
            if prefilters:
                haystack = lower if pattern.flags & re.IGNORECASE else text
                if not any(p in haystack for p in prefilters):
                    continue
            before = text
            if group:
                text = pattern.sub(self._sub_group(group), text)
            else:
                text = pattern.sub(lambda m: self._replace(m.group(0)), text)
            if text is not before:
                lower = text.lower()

        def _pan_sub(m: re.Match) -> str:
            digits = re.sub(r"[ -]", "", m.group(0))
            if len(digits) < 13 or not _luhn_ok(digits):
                return m.group(0)
            return self._replace(digits)

        text = _PAN_RE.sub(_pan_sub, text)
        return text
