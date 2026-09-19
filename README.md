# unilog

Zero-config, OTel-shaped structured logging for Python, Node.js/Bun, browser JS, PHP and Go.

Connect it in one line, keep writing the way you already write for your language, and
everything — including fatal and unhandled errors — comes out as one JSON record per line,
routed to stdout/stderr by severity and mirrored to syslog with a real priority.

```python
import unilog.auto
logging.error('User not found', {'id': 123})
```

```json
{"timestamp":"2026-09-14T14:35:42.123456Z","severity_text":"ERROR","severity_number":17,"body":"User not found","resource":{"command":"api-1> cd /srv/app; python3 app.py","service.name":"unknown_service:app.py"},"attributes":{"id":123}}
```

`resource.host.name`/`process.pid`/`service.instance.id` are off by default — on a single-host
deployment they're the same value on every record, true but not information. Opt in with
`LOG_RESOURCE_HOST=1`, `LOG_RESOURCE_PROCESS=1`, `LOG_INSTANCE_ID_STRATEGY=auto` (or `uuid`/
`host-pid`) when they'd actually distinguish something — multiple hosts, multiple workers on one.

Format spec: [spec/](spec/) · deviations from OpenTelemetry: [spec/DEVIATIONS.md](spec/DEVIATIONS.md) ·
what each runtime catches and what it can't: below.

## Install

| Language | Command |
|---|---|
| Python | `pip install "unilog @ git+ssh://git@github.com/sanprojects/unilog"` |
| Node / Bun | `npm i github:sanprojects/unilog` |
| PHP | `composer require sanprojects/unilog` (add the VCS repository, see below) |
| Go | `go get github.com/sanprojects/unilog` |
| Browser | `<script src=".../unilog/js/src/browser.js"></script>` or bundle `unilog/browser` |

PHP's composer.json needs the VCS source added once:
```json
"repositories": [{"type": "vcs", "url": "https://github.com/sanprojects/unilog"}]
```

## Connect

| Language | One line |
|---|---|
| Python | `import unilog.auto` |
| Node | `NODE_OPTIONS="--import unilog/auto" node app.js` |
| Bun | `preload = ["unilog/auto"]` in `bunfig.toml` |
| PHP | nothing — `composer.json`'s `autoload.files` wires it in automatically |
| Go | `import _ "github.com/sanprojects/unilog/auto"` |
| Browser | load `browser.js` before your app bundle |

## What "automatic" actually covers

| Runtime | Holds until... |
|---|---|
| Python | forever — stdlib `logging`, uncaught exceptions, thread exceptions, GC/`__del__` errors, asyncio task errors, `warnings.warn` |
| Node/Bun | forever — `console.*`, uncaught exceptions, unhandled rejections |
| Browser | forever — `console.*`, `window.onerror` (incl. resource loads), unhandled rejections |
| PHP | **until your framework's own bootstrap runs** (Laravel/Symfony install their own handlers later) — use the Monolog handler / PSR-3 logger inside a framework instead |
| Go | **not automatic at all** — `init()` wires `slog`/`log`, but panics in a goroutine you didn't wrap with `unilog.Go()` or `defer unilog.Recover()` are invisible to it |

Full breakdown, including what nothing can catch (SIGKILL, OOM-killer, native crashes): see
each language's `auto`/`install` module docstring.

## Every record gets a short caller trace

Not just exceptions — every regular log call carries `code.function`/`code.filepath`/
`code.lineno` for the immediate call site, plus `code.stacktrace`: up to `LOG_CALLER_TRACE_FRAMES`
(default 3) frames above it, closest first, skipping this package's own frames (and, for PHP,
well-known wrapper libraries like `psr/log`'s `LoggerTrait` and Monolog). Disable with
`LOG_CALLER_INFO=0` if the stack walk shows up in a profile.

## Request and worker scope

Attach attributes to every unilog call made for the duration of a request or a background job —
the same mechanism `trace_id`/`span_id` already use, so it survives however deep the call goes:

| Language | Request | Worker |
|---|---|---|
| Python | `with unilog.request_scope(method, url): ...` | `with unilog.worker_scope(path, **attrs): ...` |
| Go | `ctx = unilog.RequestScope(ctx, method, url)` (or `httpmw.Middleware`, done automatically) | `ctx = unilog.WorkerScope(ctx, path, attrs)` |
| Node | `unilog.requestScope(method, url, fn)` (or `unilog.middleware()`, done automatically) | `unilog.workerScope(path, attrs, fn)` |
| PHP | `Context::withRequestScope($method, $url, fn)` | `Context::withWorkerScope($path, $attrs, fn)` |

Both are thin wrappers over a generic `scope()`/`WithScope()`/`withScope()` — use that directly for
anything else. Scopes nest (inner wins on key collision); an attribute passed to a specific log
call always wins over ambient scope or caller data.

A request scope's `method`/`url` don't stay as attributes: they fold into a single
`resource.URL` (`"GET https://sanstv.ru/find_words?word=test"`) on every record made during that
request — spec deviation [V12](spec/DEVIATIONS.md). `resource.command` (`"host> cd dir; argv"`)
is unconditional, process-wide — "how do I run this again" for whoever's staring at the log line.
Both are `LOG_RESOURCE_COMMAND`/redaction-covered like every other free-form string in a record;
see [DEVIATIONS.md](spec/DEVIATIONS.md) for what that costs (`resource` is no longer always the
same cached object).

## Secrets are masked, best-effort

Every free-form string in a record — body, attribute values, stack traces — is
run through the redactor before it is written. Two independent passes:

- **by attribute name**, matched on whole segments, so `cardNumber` is masked
  and `cardinality` is not. This is the reliable half: the match is exact.
- **by value shape**, a table of regexes in `spec/redaction.default.json`. This
  half recognises known forms only.

Recognised: JWT, `Bearer`, PEM private keys, credit-card numbers (Luhn-checked),
DSNs with an inline password, `name=value` for a handful of secret-ish names,
query-string parameters, and vendor tokens — AWS, GitHub, GitLab, Google (API
key and OAuth), OpenAI, Stripe, Slack, Telegram, SendGrid, Twilio, npm,
DigitalOcean.

Query parameters keep their name: `?key=AIza...` becomes `?key=[REDACTED]`, not
a bare `[REDACTED]`, because the name is what makes the line worth reading.

**This is a safety net, not a guarantee.** A regex table cannot recognise a
home-grown token with no distinctive shape, a password in a sentence, or a
secret inside a serialised blob. Put anything sensitive in an *attribute* with
an honest name and let the name-based pass handle it — do not interpolate it
into the message text.

Measured on 359k lines of production journald and 1.56M lines of source: 506 and
3685 matches respectively, no false positives found by inspection. Redaction
costs ~159 µs per record.

## Repository layout

```
spec/         format spec — the single source of truth all 5 implementations match
conformance/  cross-language test suite
python/       pip package (import unilog.auto)
js/           npm package (Node, Bun, browser)
php/          composer package
go/           Go module (root of this repo)
examples/     one runnable demo app per language
```
