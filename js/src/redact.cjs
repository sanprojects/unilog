'use strict';
// Redaction — spec §5. Segment matching on keys (not substring), plus value
// patterns with cheap prefilters. Mirrors python/unilog/_redact.py and Go's
// redact.go rule for rule.

const DEFAULT_KEY_SEGMENTS = new Set([
  'password', 'passwd', 'pwd', 'passphrase', 'secret', 'client_secret',
  'token', 'access_token', 'refresh_token', 'id_token', 'api_key', 'apikey',
  'apitoken', 'private_key', 'secret_key', 'signature', 'sig', 'credentials', 'auth',
  'authorization', 'proxy_authorization', 'cookie', 'set_cookie', 'x_api_key',
  'x_auth_token', 'x_csrf_token',
  'session', 'sessionid', 'sid', 'jsessionid', 'phpsessid', 'csrf', 'xsrf',
  'card', 'cardnumber', 'pan', 'cvv', 'cvc', 'cvv2', 'card_cvc', 'expiry',
  'exp_month', 'exp_year', 'iban', 'account_number', 'routing_number',
  'ssn', 'passport', 'tin', 'inn', 'snils', 'dob', 'birthdate',
  'otp', 'totp', 'pin', 'mfa_code', 'recovery_code',
]);
const PII_KEY_SEGMENTS = new Set(['email', 'phone', 'ip', 'user_id', 'name']);

// [name, regex, prefilters, group]. A prefilter is a cheap substring test that
// skips the regex entirely; an array because one string cannot express
// "AKIA or ASIA". group masks only that capture group, so `?key=...` keeps the
// readable parameter name.
//
// A prefilter is matched case-SENSITIVELY unless its own regex carries the `i`
// flag, which is read off the regex rather than carried as another field. It
// has to be: folding case made 'AC' (twilio) match 'ac' anywhere and fire on
// 62% of real log lines.
const VALUE_PATTERNS = [
  // Query-string parameters. `key` is ambiguous in prose ("primary key") but
  // inside ?...&key= it is a secret, so this list is wider than the key
  // segments used for attribute names.
  ['query_param', /([?&](?:key|api[_-]?key|access[_-]?key|token|access[_-]?token|auth|password|passwd|secret|client[_-]?secret|sig|signature|session|sid)=)([^&\s"'<>]{4,})/gi, ['='], 2],
  ['jwt', /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g, ['eyJ'], 0],
  ['bearer', /\bbearer\s+[A-Za-z0-9._~+/=-]{10,}/gi, ['bearer'], 0],
  ['pem', /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, ['PRIVATE KEY'], 0],
  // Vendor-issued tokens: the prefix is fixed by the vendor, so the regex is
  // exact and the prefilter is free. AWS and GitHub used to be one pattern over
  // several prefixes and therefore ran with no prefilter at all.
  ['aws_access_key', /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, ['AKIA', 'ASIA'], 0],
  ['github_token', /\b(ghp_|gho_|ghu_|ghs_)[A-Za-z0-9_-]{20,}\b/g, ['gh'], 0],
  ['gitlab_token', /\bglpat-[A-Za-z0-9_-]{20,}\b/g, ['glpat-'], 0],
  ['google_api_key', /\bAIza[0-9A-Za-z_-]{35}\b/g, ['AIza'], 0],
  ['google_oauth', /\bya29\.[0-9A-Za-z_-]{20,}/g, ['ya29.'], 0],
  ['openai', /\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b/g, ['sk-'], 0],
  ['stripe', /\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{16,}\b/g, ['_live_', '_test_'], 0],
  ['slack_token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, ['xox'], 0],
  ['telegram_bot_token', /\b\d{8,10}:AA[A-Za-z0-9_-]{32,}\b/g, [':AA'], 0],
  ['sendgrid', /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g, ['SG.'], 0],
  ['twilio_sid', /\bAC[0-9a-f]{32}\b/g, ['AC'], 0],
  ['npm_token', /\bnpm_[A-Za-z0-9]{36}\b/g, ['npm_'], 0],
  ['digitalocean_token', /\bdop_v1_[0-9a-f]{64}\b/g, ['dop_v1_'], 0],
  ['dsn', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s:/@]+@[^\s/]+/g, ['://'], 0],
  // Last: the vendor patterns above are precise and have already masked what
  // they recognise; this catches name=value shapes with no known form.
  ['kv_secret', /\b(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s,;&]{4,}/gi, ['=', ':'], 0],
];
const PAN_RE = /\b(?:\d[ -]*?){13,19}\b/g;

function luhnOk(digits) {
  let total = 0;
  const parity = digits.length % 2;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(i) - 48;
    if (i % 2 === parity) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
  }
  return total % 10 === 0;
}

function keySegments(key) {
  const spaced = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2');
  return spaced.split(/[._\-\s]+/).filter(Boolean).map((s) => s.toLowerCase());
}

class Redactor {
  constructor(env = process.env) {
    this.enabled = env.LOG_REDACT !== '0';
    this.mode = env.LOG_REDACT_MODE || 'mask';
    this.hashKey = env.LOG_REDACT_HASH_KEY || '';
    this.keySegments = new Set(DEFAULT_KEY_SEGMENTS);
    if (env.LOG_REDACT_PROFILE === 'pii') {
      for (const s of PII_KEY_SEGMENTS) this.keySegments.add(s);
    }
    for (const allowed of (env.LOG_REDACT_ALLOW || '').split(',')) {
      const a = allowed.trim().toLowerCase();
      if (a) this.keySegments.delete(a);
    }
    this.redactStacktrace = env.LOG_REDACT_STACKTRACE !== '0';
  }

  keyIsSensitive(fullKey) {
    if (!this.enabled) return false;
    for (const part of fullKey.split('.')) {
      for (const seg of keySegments(part)) {
        if (this.keySegments.has(seg)) return true;
      }
    }
    return false;
  }

  _replace(match) {
    // A match that already carries the mask is left alone - see the spec's
    // replacement.no_double_mask.
    if (match.includes('[REDACTED')) return match;
    if (this.mode === 'hash' && this.hashKey) {
      const crypto = require('node:crypto');
      const digest = crypto.createHmac('sha256', this.hashKey).update(match).digest('hex').slice(0, 16);
      return `[REDACTED:${digest}]`;
    }
    return '[REDACTED]';
  }

  // Mask one capture group in place, keeping the rest of the match - so
  // `?key=AIza...` becomes `?key=[REDACTED]` rather than losing the name.
  // Uses `d` (match indices) so the group is located by position, not by
  // searching for its text inside the match.
  _replaceGroup(re, group, text) {
    const indexed = new RegExp(re.source, re.flags.includes('d') ? re.flags : re.flags + 'd');
    let out = '';
    let last = 0;
    for (const m of text.matchAll(indexed)) {
      const span = m.indices && m.indices[group];
      if (!span) continue;
      out += text.slice(last, span[0]) + this._replace(text.slice(span[0], span[1]));
      last = span[1];
    }
    return last === 0 ? text : out + text.slice(last);
  }

  redactValuePatterns(text) {
    if (!this.enabled || typeof text !== 'string') return text;
    let lower = text.toLowerCase();
    for (const [, re, prefilters, group] of VALUE_PATTERNS) {
      if (prefilters) {
        const haystack = re.flags.includes('i') ? lower : text;
        if (!prefilters.some((p) => haystack.includes(p))) continue;
      }
      const before = text;
      text = group
        ? this._replaceGroup(re, group, text)
        : text.replace(re, (m) => this._replace(m));
      if (text !== before) lower = text.toLowerCase();
    }
    text = text.replace(PAN_RE, (m) => {
      const digits = m.replace(/[ -]/g, '');
      if (digits.length < 13 || digits.length > 19 || !luhnOk(digits)) return m;
      return this._replace(digits);
    });
    return text;
  }
}

module.exports = { Redactor };
