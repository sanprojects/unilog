'use strict';
// Record assembly — spec §1, §4. JS objects preserve string-key insertion
// order, so canonical ordering is just "insert in the right order" — no
// custom serializer needed for JSON.stringify to emit it byte-exact.

const severity = require('./severity.cjs');
const { Redactor } = require('./redact.cjs');
const resourceMod = require('./resource.cjs');

const BODY_LIMIT = envInt('LOG_BODY_LIMIT', 8192);
const MAX_ATTRS = envInt('LOG_MAX_ATTRIBUTES', 128);
const MAX_ATTR_BYTES = envInt('LOG_MAX_ATTRIBUTE_BYTES', 4096);
const STACKTRACE_MIN = envInt('LOG_STACKTRACE_MIN_SEVERITY', 17);
const MAX_CAUSES = envInt('LOG_EXCEPTION_MAX_CAUSES', 3);
const EVENT_NAME_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

function envInt(name, def) {
  const v = process.env[name];
  if (v === undefined) return def;
  const n = parseInt(v, 10);
  return Number.isNaN(n) ? def : n;
}

const redactor = new Redactor();

// Date#toISOString gives millisecond precision (...123Z); spec requires
// exactly 6 fractional digits (microseconds). Node has no sub-ms wall clock
// via Date, so we pad with zeros rather than fabricate precision we don't have.
function timestamp() {
  const iso = new Date().toISOString(); // 2026-09-14T14:35:42.123Z
  return iso.slice(0, -1) + '000Z';
}

function truncate(s, limit) {
  const buf = Buffer.from(s, 'utf8');
  if (buf.length <= limit) return s;
  return buf.slice(0, limit).toString('utf8') + '...[truncated]';
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Error) && !Buffer.isBuffer(v);
}

function flattenValue(v, depth, seen) {
  if (depth > 10) return '[MaxDepth]';
  if (v === null || v === undefined) return null;
  const t = typeof v;
  if (t === 'boolean' || t === 'number') {
    if (t === 'number' && !Number.isFinite(v)) return null;
    return v;
  }
  if (t === 'string') return truncate(redactor.redactValuePatterns(v), MAX_ATTR_BYTES);
  if (t === 'bigint') return v.toString();
  if (Buffer.isBuffer(v)) return 'base64:' + v.toString('base64');
  if (v instanceof Uint8Array) return 'base64:' + Buffer.from(v).toString('base64');
  if (v instanceof Error) return truncate(v.message || String(v), MAX_ATTR_BYTES);
  if (seen.has(v)) return '[Circular]';
  if (Array.isArray(v)) {
    seen.add(v);
    return v.slice(0, 64).map((x) => flattenValue(x, depth + 1, seen));
  }
  if (isPlainObject(v)) {
    seen.add(v);
    const out = {};
    let i = 0;
    for (const k of Object.keys(v)) {
      if (i++ >= 64) break;
      out[k] = flattenValue(v[k], depth + 1, seen);
    }
    return out;
  }
  try {
    return truncate(String(v), MAX_ATTR_BYTES);
  } catch {
    return '[Unserializable]';
  }
}

const RESERVED_PREFIXES = ['log.', 'unilog.'];

function normalizeAttributes(raw) {
  if (!raw || Object.keys(raw).length === 0) return [undefined, 0];
  const flat = {};
  for (const [rawKey, v] of Object.entries(raw)) {
    let key = rawKey;
    const reserved = RESERVED_PREFIXES.some((p) => key.startsWith(p));
    if (reserved && key !== 'log.level.original' && key !== 'log.invalid') key = 'attr.' + key;
    if (redactor.keyIsSensitive(key)) {
      flat[key] = '[REDACTED]';
      continue;
    }
    flat[key] = flattenValue(v, 0, new Set());
  }
  const keys = Object.keys(flat).sort();
  let dropped = 0;
  let keptKeys = keys;
  if (keys.length > MAX_ATTRS) {
    dropped = keys.length - MAX_ATTRS;
    keptKeys = keys.slice(0, MAX_ATTRS);
  }
  const ordered = {};
  for (const k of keptKeys) ordered[k] = flat[k];
  return [ordered, dropped];
}

function exceptionToAttributes(err, severityNumber) {
  if (!err) return {};
  const attrs = {};
  const etype = err.name || (err.constructor && err.constructor.name) || 'Error';
  attrs['exception.type'] = etype;
  attrs['exception.message'] = err.message !== undefined ? String(err.message) : String(err);
  attrs['error.type'] = etype;
  if (severityNumber >= STACKTRACE_MIN && err.stack) {
    let st = String(err.stack);
    if (redactor.redactStacktrace) st = redactor.redactValuePatterns(st);
    attrs['exception.stacktrace'] = st;
  }
  const causes = [];
  let cur = err.cause;
  let deepestType = etype;
  let depth = 0;
  while (cur && depth < MAX_CAUSES) {
    const cType = (cur && (cur.name || (cur.constructor && cur.constructor.name))) || 'Error';
    causes.push({ type: cType, message: cur.message !== undefined ? String(cur.message) : String(cur) });
    deepestType = cType;
    cur = cur.cause;
    depth++;
  }
  if (causes.length) {
    attrs['exception.causes'] = causes;
    attrs['error.type'] = deepestType;
  }
  return attrs;
}

function build(opts) {
  const sev = severity.clamp(opts.severityNumber);
  const [text] = severity.textAndSyslog(sev);
  const record = {
    timestamp: timestamp(),
    severity_text: text,
    severity_number: sev,
  };
  if (opts.eventName && EVENT_NAME_RE.test(opts.eventName) && opts.eventName.length <= 63) {
    record.event_name = opts.eventName;
  }
  record.body = truncate(redactor.redactValuePatterns(opts.body || ''), BODY_LIMIT);
  if (opts.traceId) record.trace_id = opts.traceId;
  if (opts.spanId) record.span_id = opts.spanId;
  if (opts.traceFlags) record.trace_flags = opts.traceFlags;
  if (opts.scope) record.scope = opts.scope.slice(0, 255);
  record.resource = opts.resource || resourceMod.get();

  const [attrs, dropped] = normalizeAttributes(opts.attributes);
  if (attrs) record.attributes = attrs;
  if (dropped) record.dropped_attributes_count = dropped;
  return record;
}

function toJsonLine(record) {
  const asciiOnly = process.env.LOG_ASCII_ONLY === '1';
  let json = JSON.stringify(record);
  if (asciiOnly) {
    json = json.replace(/[-￿]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  }
  return json + '\n';
}

module.exports = { build, toJsonLine, exceptionToAttributes, normalizeAttributes, timestamp };
