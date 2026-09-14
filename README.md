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
{"timestamp":"2026-09-14T14:35:42.123456Z","severity_text":"ERROR","severity_number":17,"body":"User not found","resource":{"service.name":"unknown_service:app.py","telemetry.sdk.name":"unilog","telemetry.sdk.version":"0.1.0","telemetry.sdk.language":"python","process.pid":4211},"attributes":{"id":123}}
```

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
