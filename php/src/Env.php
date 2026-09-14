<?php

declare(strict_types=1);

namespace Unilog;

/**
 * getenv($name) ?: $default is broken for any env var whose valid value is
 * the string "0" — PHP's `?:` treats "0" as falsy, so `LOG_REDACT=0` (meant
 * to disable redaction) silently falls through to the default '1' instead.
 * Verified: this broke LOG_REDACT, LOG_RESOURCE_PROCESS and
 * LOG_STDERR_MIN_SEVERITY in exactly this way before this file existed.
 * Python's dict.get()/os.environ.get(), Go's os.LookupEnv and Node's `??`
 * are all presence-based already and don't have this problem — it is
 * specific to PHP's `?:`/`||` operators short-circuiting on falsy strings.
 */
final class Env
{
    public static function str(string $name, string $default): string
    {
        $v = getenv($name);
        return $v === false ? $default : $v;
    }

    public static function int(string $name, int $default): int
    {
        $v = getenv($name);
        return $v !== false && is_numeric($v) ? (int) $v : $default;
    }

    /** True unless the var is explicitly set to "0". */
    public static function flag(string $name, bool $default = true): bool
    {
        $v = getenv($name);
        if ($v === false) {
            return $default;
        }
        return $v !== '0';
    }
}
