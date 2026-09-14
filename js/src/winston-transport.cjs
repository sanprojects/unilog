'use strict';
// Sidecar integration for winston: a Transport subclass, not a console patch
// ("transport, not patch" — avoids double-logging when winston already owns
// console output). Usage:
//
//   const winston = require('winston');
//   const { UnilogTransport } = require('unilog/winston');
//   const logger = winston.createLogger({ transports: [new UnilogTransport()] });
//
// Requires `winston` to already be installed by the caller — this module
// does not declare it as a dependency (keeps the zero-deps default intact).

const Transport = require('winston-transport');
const capture = require('./capture.cjs');
const { exceptionToAttributes } = require('./record.cjs');

// npm log levels (winston's default) -> our scale, spec §2.2-ish mapping.
const NPM_LEVEL_TO_SEVERITY = {
  error: 17, warn: 13, info: 9, http: 9, verbose: 5, debug: 5, silly: 1,
};

class UnilogTransport extends Transport {
  log(info, callback) {
    setImmediate(() => this.emit('logged', info));
    try {
      const { level, message, stack, ...rest } = info;
      const sev = NPM_LEVEL_TO_SEVERITY[level] ?? 9;
      let attributes = rest;
      delete attributes[Symbol.for('level')];
      delete attributes[Symbol.for('message')];
      delete attributes[Symbol.for('splat')];
      if (stack) {
        const e = new Error(message);
        e.stack = stack;
        attributes = { ...attributes, ...exceptionToAttributes(e, sev) };
      }
      const state = capture.install();
      capture.emitRecord(state.sinks, { severityNumber: sev, body: String(message ?? ''), attributes });
    } catch {
      /* a broken sink must never crash the caller's application */
    }
    callback();
  }
}

module.exports = { UnilogTransport };
