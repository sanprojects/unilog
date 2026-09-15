<?php

declare(strict_types=1);

namespace Unilog;

/**
 * Orchestrates the three PHP hooks (set_error_handler, set_exception_handler,
 * register_shutdown_function) and OOM handling. Loaded automatically via
 * composer.json's `autoload.files` — works for FPM and CLI out of the box.
 *
 * Two honest limits documented here rather than hidden:
 *  - A framework that installs its OWN error/exception handlers AFTER us
 *    (Laravel's HandleExceptions bootstrapper, Symfony's ErrorHandler) wins:
 *    set_error_handler/set_exception_handler are a stack, PHP calls only the
 *    top one. Inside a framework, use Psr3\Logger or Monolog\UnilogHandler
 *    instead of relying on the global hooks.
 *  - Workerman/Swoole fork workers from a long-lived master. Handlers
 *    themselves survive fork() (plain PHP globals, inherited via
 *    copy-on-write), but Sinks (syslog ident, cached resource/pid) should be
 *    refreshed per worker — call Installer::reinstallForWorker() from
 *    onWorkerStart, matching the pattern this package replaces.
 */
final class Installer
{
    private static bool $installed = false;
    private static ?Sinks $sinks = null;
    /** @var callable|null */
    private static $prevErrorHandler = null;
    /** @var callable|null */
    private static $prevExceptionHandler = null;
    private static ?string $oomReserve = null;

    public static function install(): void
    {
        if (self::$installed) {
            return;
        }
        self::$installed = true;

        if (getenv('UNILOG_DISABLE') === '1') {
            self::$installed = false; // stays "not installed" so a later explicit install() still works
            return;
        }

        $serviceName = (string) (Resource::get()['service.name'] ?? 'unilog');
        self::$sinks = new Sinks($serviceName);

        // Cheap defensive measure, freed as the FIRST line of the shutdown
        // handler below, against the documented risk that a shutdown
        // function has no memory left to allocate anything after a true OOM
        // fatal. Re-tested directly against this implementation on PHP
        // 8.4.13 (CLI, both a gradual leak and a single allocation far past
        // a 3M memory_limit): the shutdown handler produced full structured
        // output with or without this reserve — the engine appears to give
        // it enough headroom regardless on this version. Kept anyway: it
        // costs ~512KB and one assignment, and the failure mode it guards
        // against (silence on the one record you most need) may still be
        // real on other PHP builds/versions/SAPIs this hasn't been tested on.
        self::$oomReserve = str_repeat(' ', 512 * 1024);

        self::$prevErrorHandler = set_error_handler(self::errorHandler(...));
        self::$prevExceptionHandler = set_exception_handler(self::exceptionHandler(...));
        register_shutdown_function(self::shutdownHandler(...));

        if (self::debug()) {
            fwrite(\STDERR, "unilog: installed (pid " . (getmypid() ?: 0) . ")\n");
        }
    }

    /** Re-arm Sinks (fresh syslog handle, fresh resource/pid) after a
     * Workerman/Swoole worker fork. Handlers themselves don't need
     * reinstalling — they're inherited — but calling this is harmless. */
    public static function reinstallForWorker(): void
    {
        self::$installed = false;
        self::install();
    }

    private static function debug(): bool
    {
        return getenv('LOG_DEBUG') === '1';
    }

    private static function ignoreVendorDeprecations(): bool
    {
        return Env::flag('LOG_PHP_IGNORE_VENDOR_DEPRECATIONS');
    }

    private static function errorHandler(int $errno, string $errstr, string $errfile = '', int $errline = 0): bool
    {
        if (($errno & (\E_DEPRECATED | \E_USER_DEPRECATED)) && self::ignoreVendorDeprecations() && str_contains($errfile, '/vendor/')) {
            return true;
        }
        if (!(error_reporting() & $errno)) {
            return false; // respects @-suppression, spec note in the runtime-mechanics research
        }

        [$sev, $_label] = Severity::fromErrorConstant($errno);
        self::emit($sev, $errstr, 'php.error', [
            'code.filepath' => $errfile,
            'code.lineno' => $errline,
        ]);

        if (self::$prevErrorHandler !== null) {
            return (bool) (self::$prevErrorHandler)($errno, $errstr, $errfile, $errline);
        }
        return true;
    }

    private static function exceptionHandler(\Throwable $e): void
    {
        self::emit(21, $e->getMessage() ?: $e::class, 'process.uncaught_exception', Record::exceptionAttributes($e, 21));
        if (self::$prevExceptionHandler !== null) {
            (self::$prevExceptionHandler)($e);
        }
        // set_exception_handler() replaces PHP's own fatal-error path
        // entirely — verified: without an explicit exit here, the process
        // returns 0 instead of PHP's normal 255 for an uncaught exception,
        // silently breaking anything (including our own conformance suite)
        // that checks the exit code to detect a crash.
        exit(255);
    }

    private static function shutdownHandler(): void
    {
        self::$oomReserve = null; // free first — reclaim memory before we try to allocate anything else

        $err = error_get_last();
        if ($err === null) {
            return; // includes a plain exit()/die(): observed, but not an error
        }
        if (!($err['type'] & (\E_ERROR | \E_CORE_ERROR | \E_COMPILE_ERROR | \E_PARSE))) {
            return; // already handled by errorHandler() above
        }
        self::emit(21, $err['message'], 'process.fatal_error', [
            'code.filepath' => $err['file'],
            'code.lineno' => $err['line'],
        ]);
    }

    /** For a Throwable already caught and handled elsewhere (a framework's
     * own error page, a legacy top-level catch) — bypassing this the way the
     * sanstv reference's Kernel::fail() originally did is what leaves the
     * per-request error path invisible to syslog priority entirely. */
    public static function logThrowable(\Throwable $e, int $severityNumber = 17): void
    {
        self::emit($severityNumber, $e->getMessage() ?: $e::class, 'application.exception', Record::exceptionAttributes($e, $severityNumber));
    }

    /** @param array<string, mixed> $attributes
     * No generic caller-trace here on purpose: every caller of this method
     * (errorHandler/exceptionHandler/shutdownHandler/logThrowable) already
     * passes PHP's own, more accurate code.filepath/code.lineno for the
     * error/exception itself — a second, generic stack walk would just be
     * noise. Ambient scope (request/worker) still applies: a fatal mid-request
     * should still show which request it happened in. */
    private static function emit(int $severityNumber, string $body, string $eventName, array $attributes = []): void
    {
        if (self::$sinks === null) {
            return;
        }
        $attributes = [...Context::currentScopeAttrs(), ...$attributes];
        $resource = Resource::withRequestUrl(Resource::get(), $attributes);
        [$traceId, $spanId, $traceFlags] = Context::current();
        $record = Record::build([
            'severityNumber' => $severityNumber,
            'body' => $body,
            'eventName' => $eventName,
            'attributes' => $attributes,
            'resource' => $resource,
            'traceId' => $traceId,
            'spanId' => $spanId,
            'traceFlags' => $traceFlags,
        ]);
        self::$sinks->emit(Record::toJsonLine($record), $severityNumber);
    }

    /** Low-level: used by Psr3\Logger and the Monolog bridge. */
    public static function emitDirect(int $severityNumber, string $body, ?string $eventName, array $attributes): void
    {
        self::emit($severityNumber, $body, $eventName ?? '', $attributes);
    }
}
