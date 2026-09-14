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

const VALUE_PATTERNS = [
  ['jwt', /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g, 'eyj'],
  ['bearer', /\bbearer\s+[A-Za-z0-9._~+/=-]{10,}/gi, 'bearer'],
  ['pem', /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, 'private key'],
  ['aws_access_key', /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, null],
  ['gh_token', /\b(ghp_|gho_|ghu_|ghs_|glpat-)[A-Za-z0-9_-]{20,}\b/g, null],
  ['dsn', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s:/@]+@[^\s/]+/g, '://'],
  ['kv_secret', /\b(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s,;&]{4,}/gi, null],
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
    if (this.mode === 'hash' && this.hashKey) {
      const crypto = require('node:crypto');
      const digest = crypto.createHmac('sha256', this.hashKey).update(match).digest('hex').slice(0, 16);
      return `[REDACTED:${digest}]`;
    }
    return '[REDACTED]';
  }

  redactValuePatterns(text) {
    if (!this.enabled || typeof text !== 'string') return text;
    const lower = text.toLowerCase();
    for (const [, re, prefilter] of VALUE_PATTERNS) {
      if (prefilter && !lower.includes(prefilter)) continue;
      text = text.replace(re, (m) => this._replace(m));
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
