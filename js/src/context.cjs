'use strict';
// Trace context — AsyncLocalStorage, verified present in both Node and Bun —
// plus generic scope attributes (request method/url, worker path/attrs, or
// anything else) attached to every unilog call made while a scope is active.

const { AsyncLocalStorage } = require('node:async_hooks');

const als = new AsyncLocalStorage();
const TRACEPARENT_RE = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;

function current() {
  return als.getStore() || {};
}

function currentScopeAttrs() {
  return (als.getStore() || {}).attrs || {};
}

/** Merge `patch` into the current store (trace fields and/or attrs) for the
 * duration of `fn`. Nests: an inner runScope's keys win over an outer one's. */
function runScope(patch, fn) {
  const prev = als.getStore() || {};
  const next = {
    traceId: patch.traceId !== undefined ? patch.traceId : prev.traceId,
    spanId: patch.spanId !== undefined ? patch.spanId : prev.spanId,
    traceFlags: patch.traceFlags !== undefined ? patch.traceFlags : prev.traceFlags,
    attrs: { ...prev.attrs, ...patch.attrs },
  };
  return als.run(next, fn);
}

function runWithTrace(traceId, spanId, traceFlags, fn) {
  return runScope({ traceId, spanId, traceFlags }, fn);
}

/** unilog.scope({...}, fn) — attach arbitrary attributes for fn's duration. */
function scope(attrs, fn) {
  return runScope({ attrs }, fn);
}

/** unilog.requestScope('POST', '/v1/payments/42', fn) */
function requestScope(method, url, fn) {
  return runScope({ attrs: { 'http.request.method': method, 'url.full': url } }, fn);
}

/** unilog.workerScope('jobs.charge_subscription', {account_id: 42}, fn) */
function workerScope(path, attrs, fn) {
  return runScope({ attrs: { 'worker.path': path, ...attrs } }, fn);
}

function parseTraceparent(header) {
  if (!header) return null;
  const m = TRACEPARENT_RE.exec(header.trim());
  if (!m) return null;
  if (m[2] === '0'.repeat(32) || m[3] === '0'.repeat(16)) return null;
  return { traceId: m[2], spanId: m[3], traceFlags: m[4] };
}

module.exports = { als, current, currentScopeAttrs, runScope, runWithTrace, scope, requestScope, workerScope, parseTraceparent };
