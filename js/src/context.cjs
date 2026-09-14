'use strict';
// Trace context — AsyncLocalStorage, verified present in both Node and Bun.

const { AsyncLocalStorage } = require('node:async_hooks');

const als = new AsyncLocalStorage();
const TRACEPARENT_RE = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;

function current() {
  const store = als.getStore();
  if (!store) return {};
  return store;
}

function runWithTrace(traceId, spanId, traceFlags, fn) {
  return als.run({ traceId, spanId, traceFlags }, fn);
}

function parseTraceparent(header) {
  if (!header) return null;
  const m = TRACEPARENT_RE.exec(header.trim());
  if (!m) return null;
  if (m[2] === '0'.repeat(32) || m[3] === '0'.repeat(16)) return null;
  return { traceId: m[2], spanId: m[3], traceFlags: m[4] };
}

module.exports = { als, current, runWithTrace, parseTraceparent };
