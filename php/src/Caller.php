<?php

declare(strict_types=1);

namespace Unilog;

/**
 * Short caller trace — attached to every regular log call (not the full
 * exception.stacktrace, which stays reserved for actual exceptions).
 * code.function/code.filepath/code.lineno for the immediate call site, plus
 * code.stacktrace — up to LOG_CALLER_TRACE_FRAMES (default 3) frames above
 * it, closest-first, skipping this package's own frames.
 */
final class Caller
{
    public static function enabled(): bool
    {
        return Env::flag('LOG_CALLER_INFO');
    }

    private static function frameLimit(): int
    {
        return Env::int('LOG_CALLER_TRACE_FRAMES', 3);
    }

    private static function isSkippedWrapper(string $file): bool
    {
        foreach (self::SKIP_SUBSTRINGS as $needle) {
            if (str_contains($file, $needle)) {
                return true;
            }
        }
        return false;
    }

    private const PACKAGE_DIR = __DIR__;

    // Well-known logging wrapper libraries whose own frames sit between the
    // user's real call site and here (psr/log's LoggerTrait delegates every
    // named level method through log(); Monolog\Logger::addRecord walks its
    // own handler stack before reaching UnilogHandler::write()) — skipped by
    // path substring so the "nearest" frame is the user's code, not a
    // wrapper's. Harmless if a project doesn't have them installed at all.
    private const SKIP_SUBSTRINGS = ['/psr/log/src/', '/monolog/monolog/src/'];

    /**
     * @return array<string, mixed>
     */
    public static function attributes(): array
    {
        $limit = self::frameLimit();
        // DEBUG_BACKTRACE_IGNORE_ARGS: argument values can contain secrets
        // (passwords, tokens) — never capture them just to compute a caller trace.
        //
        // Filtered by each frame's FILE (the location the call was made
        // FROM), not by 'function'/'class' — PHP's backtrace pairs a frame's
        // function name with the NEXT frame's file/line (frame N's function
        // is "what's currently running", frame N's file/line is "where IT
        // was called from"), which makes a name-based filter miss exactly
        // the boundary frame where Unilog's own code calls into user code.
        // File-based filtering has no such off-by-one.
        $trace = debug_backtrace(\DEBUG_BACKTRACE_IGNORE_ARGS, $limit + 16);

        $frames = [];
        foreach ($trace as $frame) {
            if (!isset($frame['file']) || str_starts_with($frame['file'], self::PACKAGE_DIR)) {
                continue;
            }
            if (self::isSkippedWrapper($frame['file'])) {
                continue;
            }
            $fn = isset($frame['class']) ? $frame['class'] . $frame['type'] . $frame['function'] : ($frame['function'] ?? '?');
            $frames[] = ['fn' => $fn, 'file' => $frame['file'], 'line' => $frame['line'] ?? 0];
            if (count($frames) >= $limit) {
                break;
            }
        }
        if ($frames === []) {
            return [];
        }
        $nearest = $frames[0];
        $attrs = [
            'code.function' => $nearest['fn'],
            'code.filepath' => $nearest['file'],
            'code.lineno' => $nearest['line'],
        ];
        if (count($frames) > 1) {
            $attrs['code.stacktrace'] = implode(' < ', array_map(
                static fn ($f) => sprintf('%s (%s:%d)', $f['fn'], basename($f['file']), $f['line']),
                $frames
            ));
        }
        return $attrs;
    }
}
