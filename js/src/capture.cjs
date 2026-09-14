'use strict';
// console patch + process hooks + install orchestration.

const util = require('node:util');
const record = require('./record.cjs');
const severity = require('./severity.cjs');
const resourceMod = require('./resource.cjs');
const context = require('./context.cjs');
const { Sinks } = require('./sinks.cjs');

const INSTALL_KEY = Symbol.for('unilog.installed');

function debugLog(msg) {
  if (process.env.LOG_DEBUG === '1') process.stderr.write(`unilog: ${msg}\n`);
}

function detectMode() {
  const forced = process.env.UNILOG_MODE;
  if (process.env.UNILOG_DISABLE === '1') return 'off';
  if (forced === 'full' || forced === 'sidecar' || forced === 'off') return forced;
  // Best-effort sidecar detection: only catches pino/winston required BEFORE
  // us. Required after us is invisible here — see README limitations.
  try {
    for (const modPath of Object.keys(require.cache || {})) {
      if (/node_modules[/\\](pino|winston)[/\\]/.test(modPath)) return 'sidecar';
    }
  } catch {
    /* require.cache may not exist under bun in some modes */
  }
  return 'full';
}

function emitRecord(sinks, opts) {
  const ctx = context.current();
  const rec = record.build({
    ...opts,
    resource: resourceMod.get(),
    traceId: opts.traceId || ctx.traceId,
    spanId: opts.spanId || ctx.spanId,
    traceFlags: opts.traceFlags || ctx.traceFlags,
  });
  sinks.emit(record.toJsonLine(rec), rec.severity_number, severity.syslogPriority);
}

function errorToOpts(err, severityNumber, eventName) {
  const e = err instanceof Error ? err : new Error(typeof err === 'string' ? err : util.inspect(err));
  return {
    severityNumber,
    body: e.message || String(e),
    eventName,
    attributes: record.exceptionToAttributes(e, severityNumber),
  };
}

let state = null;

function install() {
  if (globalThis[INSTALL_KEY]) return globalThis[INSTALL_KEY];
  const mode = detectMode();
  const sinks = new Sinks();
  state = { mode, sinks, originalConsole: {}, originalWrite: {} };
  globalThis[INSTALL_KEY] = state;

  if (mode === 'off') return state;

  if (mode === 'full') {
    patchConsole(sinks);
  }

  // uncaughtExceptionMonitor: observes without changing the native crash
  // (exit code stays whatever Node would have used, verified 1).
  process.on('uncaughtExceptionMonitor', (err) => {
    try {
      emitRecord(sinks, errorToOpts(err, 21, 'process.uncaught_exception'));
    } catch {
      /* never let logging crash the crash handler */
    }
  });

  // unhandledRejection: registering a listener at all suppresses Node's own
  // crash (verified) — so we log AND explicitly exit(1) ourselves to restore
  // the pre-Node-15 default behavior instead of silently surviving.
  let exiting = false;
  process.on('unhandledRejection', (reason) => {
    try {
      emitRecord(sinks, errorToOpts(reason, 21, 'process.unhandled_rejection'));
    } finally {
      if (!exiting) {
        exiting = true;
        process.exit(1);
      }
    }
  });

  process.on('warning', (warning) => {
    try {
      emitRecord(sinks, errorToOpts(warning, 13, 'process.warning'));
    } catch {
      /* ignore */
    }
  });

  debugLog(`installed, mode=${mode}`);
  return state;
}

function patchConsole(sinks) {
  const methods = { log: 9, info: 9, debug: 5, warn: 13, error: 17, trace: 1 };
  for (const [method, sev] of Object.entries(methods)) {
    if (typeof console[method] !== 'function') continue;
    state.originalConsole[method] = console[method].bind(console);
    console[method] = (...args) => {
      try {
        const errArg = args.find((a) => a instanceof Error);
        if (errArg && (method === 'error' || method === 'warn')) {
          const rest = args.filter((a) => a !== errArg);
          const opts = errorToOpts(errArg, sev, `console.${method}`);
          if (rest.length) opts.attributes = { ...opts.attributes, extra: util.format(...rest) };
          emitRecord(sinks, opts);
        } else {
          emitRecord(sinks, { severityNumber: sev, body: util.format(...args), eventName: `console.${method}` });
        }
      } catch {
        state.originalConsole[method](...args); // sink itself broke — fall back rather than swallow output
      }
    };
  }
}

function disable() {
  if (!globalThis[INSTALL_KEY]) return;
  const s = globalThis[INSTALL_KEY];
  for (const [method, fn] of Object.entries(s.originalConsole || {})) {
    console[method] = fn;
  }
  globalThis[INSTALL_KEY] = undefined;
}

module.exports = { install, disable, emitRecord, errorToOpts, INSTALL_KEY, detectMode };
