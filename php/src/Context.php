<?php

declare(strict_types=1);

namespace Unilog;

/**
 * Trace context, plus generic scope attributes (request method/url, worker
 * path/attrs, or anything else) attached to every unilog call made while a
 * scope is active. A plain `static` works for Workerman-style workers (one
 * request per worker process at a time) but is a real race under Swoole,
 * where coroutines in the same worker run concurrently — so this branches on
 * whether a Swoole coroutine is actually active, per spec §4 (PHP).
 */
final class Context
{
    private static ?string $staticTraceId = null;
    private static ?string $staticSpanId = null;
    private static ?string $staticTraceFlags = null;
    /** @var array<string, mixed> */
    private static array $staticAttrs = [];

    private const TRACEPARENT_RE = '/^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/';

    public static function set(?string $traceId, ?string $spanId, ?string $traceFlags = null): void
    {
        if (self::inCoroutine()) {
            $ctx = \Swoole\Coroutine::getContext();
            $ctx['unilog.trace_id'] = $traceId;
            $ctx['unilog.span_id'] = $spanId;
            $ctx['unilog.trace_flags'] = $traceFlags;
            return;
        }
        self::$staticTraceId = $traceId;
        self::$staticSpanId = $spanId;
        self::$staticTraceFlags = $traceFlags;
    }

    /** @return array{0: ?string, 1: ?string, 2: ?string} */
    public static function current(): array
    {
        if (self::inCoroutine()) {
            [$traceId, $spanId, $traceFlags] = self::coroutineCurrent(\Swoole\Coroutine::getCid());
            return [$traceId, $spanId, $traceFlags];
        }
        return [self::$staticTraceId, self::$staticSpanId, self::$staticTraceFlags];
    }

    /** @return array<string, mixed> */
    public static function currentScopeAttrs(): array
    {
        if (self::inCoroutine()) {
            return self::coroutineScopeAttrs(\Swoole\Coroutine::getCid());
        }
        return self::$staticAttrs;
    }

    /**
     * Run $fn with $attrs merged into the current scope for its duration
     * (PHP has no `with` statement, so this is the equivalent of Python's
     * context manager / Node's runScope). Nests: an inner scope's keys win
     * over an outer one's; restores the previous scope in a finally, even
     * if $fn throws.
     *
     *   Context::withScope(['http.request.method' => 'POST', 'url.full' => $url], fn() => handle($request));
     *
     * @param array<string, mixed> $attrs
     */
    public static function withScope(array $attrs, callable $fn): mixed
    {
        [$prevTraceId, $prevSpanId, $prevTraceFlags] = self::current();
        $prevAttrs = self::currentScopeAttrs();
        self::set($prevTraceId, $prevSpanId, $prevTraceFlags);
        self::setScopeAttrs([...$prevAttrs, ...$attrs]);
        try {
            return $fn();
        } finally {
            self::setScopeAttrs($prevAttrs);
        }
    }

    /** with-style helper for an HTTP request: */
    public static function withRequestScope(string $method, string $url, callable $fn): mixed
    {
        return self::withScope(['http.request.method' => $method, 'url.full' => $url], $fn);
    }

    /** with-style helper for a background job/worker: */
    public static function withWorkerScope(string $path, array $attrs, callable $fn): mixed
    {
        return self::withScope(['worker.path' => $path, ...$attrs], $fn);
    }

    /** @param array<string, mixed> $attrs */
    private static function setScopeAttrs(array $attrs): void
    {
        if (self::inCoroutine()) {
            $ctx = \Swoole\Coroutine::getContext();
            $ctx['unilog.attrs'] = $attrs;
            return;
        }
        self::$staticAttrs = $attrs;
    }

    /**
     * Swoole's per-coroutine context does not auto-inherit from the parent —
     * walk the parent-coroutine-id chain (Coroutine::getPcid()) until a
     * context that actually set trace_id is found, or the chain ends.
     *
     * @return array{0: ?string, 1: ?string, 2: ?string}
     */
    private static function coroutineCurrent(int $cid): array
    {
        for ($i = 0; $cid > 0 && $i < 64; $i++) {
            $ctx = \Swoole\Coroutine::getContext($cid);
            if ($ctx !== null && isset($ctx['unilog.trace_id'])) {
                return [$ctx['unilog.trace_id'], $ctx['unilog.span_id'] ?? null, $ctx['unilog.trace_flags'] ?? null];
            }
            $cid = \Swoole\Coroutine::getPcid($cid) ?: 0;
        }
        return [null, null, null];
    }

    /** @return array<string, mixed> */
    private static function coroutineScopeAttrs(int $cid): array
    {
        for ($i = 0; $cid > 0 && $i < 64; $i++) {
            $ctx = \Swoole\Coroutine::getContext($cid);
            if ($ctx !== null && isset($ctx['unilog.attrs'])) {
                return $ctx['unilog.attrs'];
            }
            $cid = \Swoole\Coroutine::getPcid($cid) ?: 0;
        }
        return [];
    }

    private static function inCoroutine(): bool
    {
        return \extension_loaded('swoole') && class_exists(\Swoole\Coroutine::class) && \Swoole\Coroutine::getCid() > 0;
    }

    /** @return array{traceId: string, spanId: string, traceFlags: string}|null */
    public static function parseTraceparent(string $header): ?array
    {
        if (!preg_match(self::TRACEPARENT_RE, trim($header), $m)) {
            return null;
        }
        if ($m[2] === str_repeat('0', 32) || $m[3] === str_repeat('0', 16)) {
            return null;
        }
        return ['traceId' => $m[2], 'spanId' => $m[3], 'traceFlags' => $m[4]];
    }
}
