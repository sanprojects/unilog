'use strict';
// Short caller trace — attached to every regular log call. Parses
// `new Error().stack` (there's no cheaper way to walk the JS call stack)
// and skips frames inside this package's own files.

const path = require('node:path');

const SELF_DIR = __dirname;
const FRAME_RE = /^\s*at\s+(?:(.+?)\s+\()?(.+?):(\d+):(\d+)\)?\s*$/;

function isInternal(file) {
  return file.startsWith(SELF_DIR) || file.includes('node:internal') || file === '<anonymous>';
}

function enabled() {
  return process.env.LOG_CALLER_INFO !== '0';
}

function traceFrames() {
  const n = parseInt(process.env.LOG_CALLER_TRACE_FRAMES || '3', 10);
  return Number.isNaN(n) ? 3 : n;
}

/** @returns {{ 'code.function'?: string, 'code.filepath'?: string, 'code.lineno'?: number, 'code.stacktrace'?: string }} */
function callerAttributes(limit) {
  limit = limit || traceFrames();
  const lines = (new Error().stack || '').split('\n').slice(1); // drop "Error" header
  const frames = [];
  for (const line of lines) {
    const m = FRAME_RE.exec(line);
    if (!m) continue;
    const file = m[2];
    if (isInternal(file)) continue;
    frames.push({ fn: m[1] || 'anonymous', file, line: parseInt(m[3], 10) });
    if (frames.length >= limit) break;
  }
  if (frames.length === 0) return {};
  const nearest = frames[0];
  const attrs = {
    'code.function': nearest.fn,
    'code.filepath': nearest.file,
    'code.lineno': nearest.line,
  };
  if (frames.length > 1) {
    attrs['code.stacktrace'] = frames.map((f) => `${f.fn} (${path.basename(f.file)}:${f.line})`).join(' < ');
  }
  return attrs;
}

module.exports = { enabled, callerAttributes };
