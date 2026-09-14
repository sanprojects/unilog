'use strict';
// Sidecar integration for pino: a plain synchronous destination stream, not a
// worker-thread transport (that would need pino-abstract-transport as a
// dependency — zero deps is the point). Usage:
//
//   const pino = require('pino');
//   const logger = pino({ level: 'debug' }, require('unilog/pino'));
//
// pino writes each already-serialized NDJSON line to write(); this parses it
// back out and re-emits it as a unilog record instead of patching console —
// "transport, not patch" per the design (avoids double-logging).

const capture = require('./capture.cjs');
const severity = require('./severity.cjs');

const stream = {
  write(chunk) {
    let obj;
    try {
      obj = JSON.parse(chunk);
    } catch {
      process.stderr.write(String(chunk));
      return true;
    }
    const state = capture.install();
    const sev = severity.fromPinoLevel(typeof obj.level === 'number' ? obj.level : 30);
    const { level, time, pid, hostname, msg, err, ...rest } = obj;
    const attributes = { ...rest };
    let attrs = attributes;
    if (err) {
      const e = new Error(err.message || String(err));
      e.name = err.type || 'Error';
      e.stack = err.stack;
      attrs = { ...attrs, ...require('./record.cjs').exceptionToAttributes(e, sev) };
    }
    capture.emitRecord(state.sinks, {
      severityNumber: sev,
      body: msg || '',
      attributes: attrs,
    });
    return true;
  },
};

module.exports = stream;
