<?php

declare(strict_types=1);

namespace Unilog;

/**
 * Record assembly — spec §1, §4. PHP arrays preserve insertion order, and
 * json_encode() respects it for associative arrays — so canonical top-level
 * ordering is just "insert fields in the right order"; resource/attributes
 * get an explicit ksort() for the normative lexicographic ordering.
 */
final class Record
{
    private static ?Redactor $redactor = null;

    private static function redactor(): Redactor
    {
        return self::$redactor ??= new Redactor();
    }

    private static function envInt(string $name, int $default): int
    {
        $v = getenv($name);
        return $v !== false && $v !== '' && is_numeric($v) ? (int) $v : $default;
    }

    private static function truncate(string $s, int $limit): string
    {
        if (strlen($s) <= $limit) {
            return $s;
        }
        return substr($s, 0, $limit) . '...[truncated]';
    }

    /**
     * @param array<string, mixed> $opts severityNumber, body, eventName?, attributes?,
     *   traceId?, spanId?, traceFlags?, scope?, resource?
     * @return array<string, mixed>
     */
    public static function build(array $opts): array
    {
        $redactor = self::redactor();
        $bodyLimit = self::envInt('LOG_BODY_LIMIT', 8192);

        $sev = Severity::clamp((int) ($opts['severityNumber'] ?? 9));

        $record = [
            'timestamp' => self::timestamp(),
            'severity_text' => Severity::text($sev),
            'severity_number' => $sev,
        ];

        $eventName = $opts['eventName'] ?? null;
        if (is_string($eventName) && preg_match('/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/', $eventName) && strlen($eventName) <= 63) {
            $record['event_name'] = $eventName;
        }

        $record['body'] = self::truncate($redactor->redactValuePatterns((string) ($opts['body'] ?? '')), $bodyLimit);

        if (!empty($opts['traceId'])) {
            $record['trace_id'] = $opts['traceId'];
        }
        if (!empty($opts['spanId'])) {
            $record['span_id'] = $opts['spanId'];
        }
        if (!empty($opts['traceFlags'])) {
            $record['trace_flags'] = $opts['traceFlags'];
        }
        if (!empty($opts['scope'])) {
            $record['scope'] = substr((string) $opts['scope'], 0, 255);
        }

        $record['resource'] = $opts['resource'] ?? Resource::get();
        ksort($record['resource']);

        [$attrs, $dropped] = self::normalizeAttributes($opts['attributes'] ?? [], $redactor);
        if ($attrs !== null) {
            ksort($attrs);
            $record['attributes'] = $attrs;
        }
        if ($dropped > 0) {
            $record['dropped_attributes_count'] = $dropped;
        }

        return $record;
    }

    private static function timestamp(): string
    {
        // microtime(true) gives float seconds; DateTime::createFromFormat('U.u')
        // is the standard way to get real microsecond precision out of PHP.
        $micro = microtime(true);
        $dt = \DateTimeImmutable::createFromFormat('U.u', sprintf('%.6F', $micro), new \DateTimeZone('UTC'));
        if ($dt === false) {
            return gmdate('Y-m-d\TH:i:s.000000\Z');
        }
        return $dt->format('Y-m-d\TH:i:s.u\Z');
    }

    /**
     * @param array<string, mixed> $raw
     * @return array{0: ?array<string, mixed>, 1: int}
     */
    private static function normalizeAttributes(array $raw, Redactor $redactor): array
    {
        if (count($raw) === 0) {
            return [null, 0];
        }
        $maxAttrs = self::envInt('LOG_MAX_ATTRIBUTES', 128);
        $flat = [];
        foreach ($raw as $rawKey => $v) {
            $key = (string) $rawKey;
            $reserved = str_starts_with($key, 'log.') || str_starts_with($key, 'unilog.');
            if ($reserved && $key !== 'log.level.original' && $key !== 'log.invalid') {
                $key = 'attr.' . $key;
            }
            if ($redactor->keyIsSensitive($key)) {
                $flat[$key] = '[REDACTED]';
                continue;
            }
            $flat[$key] = self::flattenValue($v, 0, [], $redactor);
        }
        $dropped = 0;
        if (count($flat) > $maxAttrs) {
            $keys = array_keys($flat);
            sort($keys);
            $dropped = count($keys) - $maxAttrs;
            $keys = array_slice($keys, 0, $maxAttrs);
            $flat = array_intersect_key($flat, array_flip($keys));
        }
        return [$flat, $dropped];
    }

    /**
     * @param array<int, mixed> $seenIds object spl_object_id()s already on the current path
     */
    private static function flattenValue(mixed $v, int $depth, array $seenIds, Redactor $redactor): mixed
    {
        if ($depth > 10) {
            return '[MaxDepth]';
        }
        $maxAttrBytes = self::envInt('LOG_MAX_ATTRIBUTE_BYTES', 4096);

        if ($v === null || is_bool($v) || is_int($v)) {
            return $v;
        }
        if (is_float($v)) {
            return (is_nan($v) || is_infinite($v)) ? null : $v;
        }
        if (is_string($v)) {
            return self::truncate($redactor->redactValuePatterns($v), $maxAttrBytes);
        }
        if ($v instanceof \Throwable) {
            return self::truncate($v->getMessage() ?: $v::class, $maxAttrBytes);
        }
        if (is_object($v)) {
            $id = spl_object_id($v);
            if (in_array($id, $seenIds, true)) {
                return '[Circular]';
            }
            $seenIds[] = $id;
            if (method_exists($v, '__toString')) {
                return self::truncate((string) $v, $maxAttrBytes);
            }
            if ($v instanceof \JsonSerializable) {
                return self::flattenValue($v->jsonSerialize(), $depth + 1, $seenIds, $redactor);
            }
            if ($v instanceof \Traversable) {
                $out = [];
                $i = 0;
                foreach ($v as $k => $item) {
                    if ($i++ >= 64) {
                        break;
                    }
                    $out[(string) $k] = self::flattenValue($item, $depth + 1, $seenIds, $redactor);
                }
                return $out;
            }
            // Plain object: expose public properties, same shape a JSON
            // encoder would give it by default.
            return self::flattenValue(get_object_vars($v), $depth + 1, $seenIds, $redactor);
        }
        if (is_array($v)) {
            $out = [];
            $i = 0;
            foreach ($v as $k => $item) {
                if ($i++ >= 64) {
                    break;
                }
                $out[(string) $k] = self::flattenValue($item, $depth + 1, $seenIds, $redactor);
            }
            return $out;
        }
        return self::truncate((string) $v, $maxAttrBytes);
    }

    /**
     * Throwable -> exception.* / error.type attributes, spec §4.8.
     *
     * @return array<string, mixed>
     */
    public static function exceptionAttributes(\Throwable $e, int $severityNumber): array
    {
        $redactor = self::redactor();
        $stacktraceMin = self::envInt('LOG_STACKTRACE_MIN_SEVERITY', 17);
        $maxCauses = self::envInt('LOG_EXCEPTION_MAX_CAUSES', 3);

        $etype = $e::class;
        $attrs = [
            'exception.type' => $etype,
            'exception.message' => $e->getMessage(),
            'error.type' => $etype,
        ];
        if (Severity::clamp($severityNumber) >= $stacktraceMin) {
            $trace = (string) $e;
            if ($redactor->redactStacktrace) {
                $trace = $redactor->redactValuePatterns($trace);
            }
            $attrs['exception.stacktrace'] = $trace;
        }

        $causes = [];
        $cur = $e->getPrevious();
        $deepestType = $etype;
        for ($i = 0; $cur !== null && $i < $maxCauses; $i++) {
            $cType = $cur::class;
            $causes[] = ['type' => $cType, 'message' => $cur->getMessage()];
            $deepestType = $cType;
            $cur = $cur->getPrevious();
        }
        if ($causes !== []) {
            $attrs['exception.causes'] = $causes;
            $attrs['error.type'] = $deepestType;
        }
        return $attrs;
    }

    /** @param array<string, mixed> $record */
    public static function toJsonLine(array $record): string
    {
        $asciiOnly = (getenv('LOG_ASCII_ONLY') ?: '0') === '1';
        $flags = \JSON_UNESCAPED_SLASHES | ($asciiOnly ? 0 : \JSON_UNESCAPED_UNICODE);
        $json = json_encode($record, $flags);
        if ($json === false) {
            $json = json_encode([
                'timestamp' => self::timestamp(),
                'severity_text' => 'ERROR',
                'severity_number' => 17,
                'body' => 'unilog: failed to encode log record',
                'resource' => $record['resource'] ?? ['service.name' => 'unilog'],
                'attributes' => ['log.invalid' => json_last_error_msg()],
            ], $flags);
        }
        return $json . "\n";
    }
}
