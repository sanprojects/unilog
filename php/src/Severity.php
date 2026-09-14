<?php

declare(strict_types=1);

namespace Unilog;

/**
 * Mirrors spec/severity.csv 1:1 — keep the two in sync by hand until a
 * generator script exists.
 */
final class Severity
{
    /** @var array<int, array{0: string, 1: int}> number => [text, syslogSeverity 0-7] */
    private const TABLE = [
        1 => ['TRACE', 7], 2 => ['TRACE2', 7], 3 => ['TRACE3', 7], 4 => ['TRACE4', 7],
        5 => ['DEBUG', 7], 6 => ['DEBUG2', 7], 7 => ['DEBUG3', 7], 8 => ['DEBUG4', 7],
        9 => ['INFO', 6], 10 => ['INFO2', 5], 11 => ['INFO3', 5], 12 => ['INFO4', 5],
        13 => ['WARN', 4], 14 => ['WARN2', 4], 15 => ['WARN3', 4], 16 => ['WARN4', 4],
        17 => ['ERROR', 3], 18 => ['ERROR2', 2], 19 => ['ERROR3', 1], 20 => ['ERROR4', 1],
        21 => ['FATAL', 0], 22 => ['FATAL2', 0], 23 => ['FATAL3', 0], 24 => ['FATAL4', 0],
    ];

    /** PSR-3 level name -> severity_number (spec §2.2). */
    private const PSR3_TO_NUMBER = [
        'debug' => 5, 'info' => 9, 'notice' => 10, 'warning' => 13,
        'error' => 17, 'critical' => 18, 'alert' => 19, 'emergency' => 21,
    ];

    public static function clamp(int $n): int
    {
        return max(1, min(24, $n));
    }

    public static function text(int $n): string
    {
        return self::TABLE[self::clamp($n)][0];
    }

    public static function syslogSeverity(int $n): int
    {
        return self::TABLE[self::clamp($n)][1];
    }

    public static function syslogPriority(int $n, int $facility): int
    {
        return $facility * 8 + self::syslogSeverity($n);
    }

    public static function fromPsr3(string $level): int
    {
        return self::PSR3_TO_NUMBER[strtolower($level)] ?? 9;
    }

    /**
     * PHP E_* constant -> severity_number, spec §2.4 (verified against
     * `php -r` on 8.4.13).
     *
     * @return array{0: int, 1: string}  [severityNumber, level label]
     */
    public static function fromErrorConstant(int $errno): array
    {
        return match (true) {
            (bool) ($errno & (\E_ERROR | \E_CORE_ERROR | \E_COMPILE_ERROR | \E_PARSE)) => [21, 'FATAL'],
            (bool) ($errno & (\E_USER_ERROR | \E_RECOVERABLE_ERROR)) => [17, 'ERROR'],
            (bool) ($errno & (\E_WARNING | \E_CORE_WARNING | \E_COMPILE_WARNING | \E_USER_WARNING)) => [13, 'WARN'],
            (bool) ($errno & (\E_DEPRECATED | \E_USER_DEPRECATED)) => [10, 'INFO2'],
            (bool) ($errno & (\E_NOTICE | \E_USER_NOTICE | \E_STRICT)) => [9, 'INFO'],
            default => [13, 'WARN'],
        };
    }
}
