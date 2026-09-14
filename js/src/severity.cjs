'use strict';
// Mirrors spec/severity.csv 1:1 — keep the two in sync by hand until a
// generator script exists.

const TABLE = {
  1: ['TRACE', 7], 2: ['TRACE2', 7], 3: ['TRACE3', 7], 4: ['TRACE4', 7],
  5: ['DEBUG', 7], 6: ['DEBUG2', 7], 7: ['DEBUG3', 7], 8: ['DEBUG4', 7],
  9: ['INFO', 6], 10: ['INFO2', 5], 11: ['INFO3', 5], 12: ['INFO4', 5],
  13: ['WARN', 4], 14: ['WARN2', 4], 15: ['WARN3', 4], 16: ['WARN4', 4],
  17: ['ERROR', 3], 18: ['ERROR2', 2], 19: ['ERROR3', 1], 20: ['ERROR4', 1],
  21: ['FATAL', 0], 22: ['FATAL2', 0], 23: ['FATAL3', 0], 24: ['FATAL4', 0],
};

function clamp(n) {
  return Math.max(1, Math.min(24, n | 0));
}

function textAndSyslog(n) {
  return TABLE[clamp(n)];
}

function syslogPriority(n, facility) {
  return facility * 8 + textAndSyslog(n)[1];
}

// console level -> our scale, spec §2.2.
const CONSOLE_SEVERITY = {
  trace: 1, debug: 5, log: 9, info: 9, warn: 13, error: 17,
};

// pino/bunyan numeric level -> our scale, spec §2.3 formula:
// sev = clamp(round(level * 0.4) - 3, 1, 24)
function fromPinoLevel(level) {
  return clamp(Math.round(level * 0.4) - 3);
}

module.exports = { TABLE, clamp, textAndSyslog, syslogPriority, CONSOLE_SEVERITY, fromPinoLevel };
