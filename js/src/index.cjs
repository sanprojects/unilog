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

/** Attach attributes to every unilog call made while `fn` runs — the
 * mechanism behind requestScope()/workerScope() below, usable directly for
 * anything else. Nests: an inner scope's keys win over an outer one's; an
 * attribute passed directly to a specific log call still wins over both.
 *
 *   unilog.scope({ 'http.request.method': 'POST', 'url.full': url }, () => handle(req)); */
function scope(attrs, fn) {
  return context.scope(attrs, fn);
}

/** unilog.requestScope('POST', '/v1/payments/42', () => handle(req)) */
function requestScope(method, url, fn) {
  return context.requestScope(method, url, fn);
}

/** unilog.workerScope('jobs.charge_subscription', { account_id: 42 }, () => run()) */
function workerScope(path, attrs, fn) {
  return context.workerScope(path, attrs, fn);
}

/** Express/Connect-style middleware: (req, res, next) => void.
 * Extracts an incoming `traceparent` header and attaches
 * http.request.method/url.full for the rest of the request — so any unilog
 * call downstream, however deep, picks these up with no logging code in the
 * route handler itself. */
function middleware() {
  return (req, res, next) => {
    const tp = parseTraceparent(req.headers && req.headers.traceparent);
    const url = req.originalUrl || req.url || '';
    context.runScope(
      {
        traceId: tp ? tp.traceId : undefined,
        spanId: tp ? tp.spanId : undefined,
        traceFlags: tp ? tp.traceFlags : undefined,
        attrs: { 'http.request.method': req.method, 'url.full': url },
      },
      next
    );
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
  scope,
  requestScope,
  workerScope,
  middleware,
  log,
  build: record.build,
  toJsonLine: record.toJsonLine,
};
