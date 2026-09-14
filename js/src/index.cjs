'use strict';
// Public API: const unilog = require('unilog'); — or, for the one-line
// zero-config path, require('unilog/auto') / NODE_OPTIONS=--import unilog/auto.

const capture = require('./capture.cjs');
const resourceMod = require('./resource.cjs');
const context = require('./context.cjs');
const record = require('./record.cjs');

function configure(explicitResource) {
  if (explicitResource) resourceMod.configure(explicitResource);
  return capture.install();
}

function disable() {
  capture.disable();
}

function runWithTrace(traceId, spanId, traceFlags, fn) {
  return context.runWithTrace(traceId, spanId, traceFlags, fn);
}

function parseTraceparent(header) {
  return context.parseTraceparent(header);
}

/** Express/Connect-style middleware: (req, res, next) => void.
 * Extracts an incoming `traceparent` header into AsyncLocalStorage for the
 * rest of the request, so any unilog call downstream — however deep — picks
 * up trace_id/span_id without threading anything through function args. */
function middleware() {
  return (req, res, next) => {
    const tp = parseTraceparent(req.headers && req.headers.traceparent);
    if (tp) {
      runWithTrace(tp.traceId, tp.spanId, tp.traceFlags, next);
    } else {
      next();
    }
  };
}

/** Low-level: build+emit one record directly, bypassing console entirely.
 * Signature matches the browser build's window.unilog.log() for consistency:
 *   log(severityNumber, body, eventName, attributes) */
function log(severityNumber, body, eventName, attributes) {
  const state = capture.install();
  capture.emitRecord(state.sinks, { severityNumber, body, eventName, attributes });
}

module.exports = {
  configure,
  disable,
  runWithTrace,
  parseTraceparent,
  middleware,
  log,
  build: record.build,
  toJsonLine: record.toJsonLine,
};
