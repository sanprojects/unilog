/*!
 * unilog browser build — plain script, no bundler required.
 *   <script src=".../unilog/js/src/browser.js"></script>
 * Exposes window.unilog. There is no stdout/stderr/syslog in a browser, so
 * this does exactly what was decided: the same JSON record shape through
 * console.*, plus window.onerror/unhandledrejection capture, plus a
 * transport hook (window.unilog.setTransport(fn)) — no built-in collector.
 */
(function (global) {
  'use strict';

  var SEVERITY = {
    1: 'TRACE', 5: 'DEBUG', 9: 'INFO', 13: 'WARN', 17: 'ERROR', 21: 'FATAL',
  };
  var CONSOLE_SEVERITY = { trace: 1, debug: 5, log: 9, info: 9, warn: 13, error: 17 };

  var config = {
    serviceName: global.__UNILOG_SERVICE_NAME__ || 'unknown_service:browser',
    environment: global.__UNILOG_ENV__ || undefined,
    redact: true,
  };
  var transport = null;
  var installed = false;
  var originalConsole = {};

  function sessionInstanceId() {
    try {
      var KEY = 'logspec.instance_id';
      var existing = sessionStorage.getItem(KEY);
      if (existing) return existing;
      var id = uuidv4();
      sessionStorage.setItem(KEY, id);
      return id;
    } catch (e) {
      return uuidv4(); // private mode / storage blocked — per-call fallback
    }
  }

  function uuidv4() {
    if (global.crypto && global.crypto.randomUUID) return global.crypto.randomUUID();
    var b = new Uint8Array(16);
    (global.crypto || {}).getRandomValues ? global.crypto.getRandomValues(b) : b.forEach(function (_, i) { b[i] = Math.floor(Math.random() * 256); });
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    var hex = Array.prototype.map.call(b, function (x) { return ('00' + x.toString(16)).slice(-2); }).join('');
    return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
  }

  var instanceId = null;
  function resource() {
    if (!instanceId) instanceId = sessionInstanceId();
    var r = {
      'service.name': config.serviceName,
      'service.instance.id': instanceId,
    };
    if (config.environment) r['deployment.environment.name'] = config.environment;
    // Every record here happens on some page, unlike a server call that may
    // or may not be inside a request — so unlike resource.URL server-side
    // (spec V12), this is unconditional, not scope-gated. No method prefix:
    // unlike a server request, there's no reliable way to know how this page
    // was reached (a link, a form POST, pushState).
    try {
      r.URL = location.href;
    } catch (e) { /* no location (unusual embedding) */ }
    return r;
  }

  // Small, self-contained subset of spec §5 — deliberately lighter than the
  // server implementations (no PAN/Luhn check: cheap enough to keep, but
  // browser payloads are usually smaller and this file ships to every user).
  var REDACT_KEYS = ['password', 'passwd', 'token', 'secret', 'authorization', 'cookie', 'api_key', 'apikey', 'card', 'cvv', 'ssn ', 'pin'];
  function keyIsSensitive(key) {
    if (!config.redact) return false;
    var lower = key.toLowerCase();
    for (var i = 0; i < REDACT_KEYS.length; i++) {
      if (lower.indexOf(REDACT_KEYS[i].trim()) !== -1) return true;
    }
    return false;
  }
  var JWT_RE = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g;
  var BEARER_RE = /\bbearer\s+[A-Za-z0-9._~+/=-]{10,}/gi;
  function redactValue(text) {
    if (!config.redact || typeof text !== 'string') return text;
    return text.replace(JWT_RE, '[REDACTED]').replace(BEARER_RE, '[REDACTED]');
  }

  function flatten(v, depth) {
    depth = depth || 0;
    if (depth > 8) return '[MaxDepth]';
    if (v === null || v === undefined) return null;
    var t = typeof v;
    if (t === 'boolean' || t === 'number') return isFinite(v) || t === 'boolean' ? v : null;
    if (t === 'string') return redactValue(v).slice(0, 4096);
    if (v instanceof Error) return v.message || String(v);
    if (Array.isArray(v)) {
      return v.slice(0, 64).map(function (x) { return flatten(x, depth + 1); });
    }
    if (t === 'object') {
      var out = {};
      var keys = Object.keys(v).slice(0, 64);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        out[k] = keyIsSensitive(k) ? '[REDACTED]' : flatten(v[k], depth + 1);
      }
      return out;
    }
    try {
      return String(v);
    } catch (e) {
      return '[Unserializable]';
    }
  }

  function normalizeAttributes(raw) {
    if (!raw) return undefined;
    var keys = Object.keys(raw).sort();
    var out = {};
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      out[k] = keyIsSensitive(k) ? '[REDACTED]' : flatten(raw[k], 0);
    }
    return keys.length ? out : undefined;
  }

  function exceptionAttributes(err) {
    if (!err) return {};
    var etype = err.name || (err.constructor && err.constructor.name) || 'Error';
    var attrs = {
      'exception.type': etype,
      'exception.message': err.message !== undefined ? String(err.message) : String(err),
      'error.type': etype,
    };
    if (err.stack) attrs['exception.stacktrace'] = redactValue(String(err.stack));
    return attrs;
  }

  function timestamp() {
    return new Date().toISOString().replace(/\.\d+Z$/, function (m) {
      return '.' + m.slice(1, 4) + '000Z';
    });
  }

  function build(severityNumber, body, eventName, attributes) {
    var rec = {
      timestamp: timestamp(),
      severity_text: SEVERITY[severityNumber] || 'INFO',
      severity_number: severityNumber,
    };
    if (eventName) rec.event_name = eventName;
    rec.body = redactValue(String(body || '')).slice(0, 8192);
    rec.resource = resource();
    var attrs = normalizeAttributes(attributes);
    if (attrs) rec.attributes = attrs;
    return rec;
  }

  function emit(severityNumber, body, eventName, attributes) {
    var rec = build(severityNumber, body, eventName, attributes);
    var line = JSON.stringify(rec);
    var method = severityNumber >= 17 ? 'error' : severityNumber >= 13 ? 'warn' : severityNumber >= 9 ? 'info' : 'debug';
    (originalConsole[method] || console[method] || console.log).call(console, line);
    if (transport) {
      try {
        transport(rec);
      } catch (e) {
        /* a broken transport must not break the page */
      }
    }
  }

  function patchConsole() {
    Object.keys(CONSOLE_SEVERITY).forEach(function (method) {
      if (typeof console[method] !== 'function') return;
      originalConsole[method] = console[method].bind(console);
      console[method] = function () {
        var args = Array.prototype.slice.call(arguments);
        var err = args.filter(function (a) { return a instanceof Error; })[0];
        var sev = CONSOLE_SEVERITY[method];
        if (err) {
          emit(sev, err.message || String(err), 'console.' + method, exceptionAttributes(err));
        } else {
          emit(sev, args.map(String).join(' '), 'console.' + method);
        }
      };
    });
  }

  function install() {
    if (installed) return;
    installed = true;
    patchConsole();

    global.addEventListener(
      'error',
      function (e) {
        if (e.error instanceof Error) {
          emit(21, e.error.message || e.message, 'window.onerror', exceptionAttributes(e.error));
        } else if (e.target && e.target !== global && e.target.tagName) {
          // Resource load failure (img/script/link) — no message/stack available.
          emit(17, 'Resource failed to load: ' + e.target.tagName.toLowerCase(), 'resource.error', {
            'url.full': e.target.src || e.target.href || '',
          });
        } else {
          emit(21, e.message || 'Script error', 'window.onerror');
        }
      },
      true // capture phase — required to see resource load failures at all
    );

    global.addEventListener('unhandledrejection', function (e) {
      var reason = e.reason;
      if (reason instanceof Error) {
        emit(21, reason.message || String(reason), 'window.unhandledrejection', exceptionAttributes(reason));
      } else {
        emit(21, 'Unhandled rejection: ' + String(reason), 'window.unhandledrejection');
      }
    });
  }

  global.unilog = {
    configure: function (opts) {
      Object.assign(config, opts || {});
    },
    setTransport: function (fn) {
      transport = fn;
    },
    install: install,
    log: function (severityNumber, body, eventName, attributes) {
      emit(severityNumber, body, eventName, attributes);
    },
  };

  install();
})(typeof window !== 'undefined' ? window : globalThis);
