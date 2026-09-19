<?php

declare(strict_types=1);

namespace Unilog;

/**
 * Redaction — spec §5. Segment matching on keys (not substring), plus value
 * patterns with cheap prefilters. Mirrors the Python/Go/Node implementations.
 */
final class Redactor
{
    /** @var array<string, true> */
    private const DEFAULT_KEY_SEGMENTS = [
        'password' => true, 'passwd' => true, 'pwd' => true, 'passphrase' => true, 'secret' => true, 'client_secret' => true,
        'token' => true, 'access_token' => true, 'refresh_token' => true, 'id_token' => true, 'api_key' => true, 'apikey' => true,
        'apitoken' => true, 'private_key' => true, 'secret_key' => true, 'signature' => true, 'sig' => true, 'credentials' => true, 'auth' => true,
        'authorization' => true, 'proxy_authorization' => true, 'cookie' => true, 'set_cookie' => true, 'x_api_key' => true,
        'x_auth_token' => true, 'x_csrf_token' => true,
        'session' => true, 'sessionid' => true, 'sid' => true, 'jsessionid' => true, 'phpsessid' => true, 'csrf' => true, 'xsrf' => true,
        'card' => true, 'cardnumber' => true, 'pan' => true, 'cvv' => true, 'cvc' => true, 'cvv2' => true, 'card_cvc' => true, 'expiry' => true,
        'exp_month' => true, 'exp_year' => true, 'iban' => true, 'account_number' => true, 'routing_number' => true,
        'ssn' => true, 'passport' => true, 'tin' => true, 'inn' => true, 'snils' => true, 'dob' => true, 'birthdate' => true,
        'otp' => true, 'totp' => true, 'pin' => true, 'mfa_code' => true, 'recovery_code' => true,
    ];
    private const PII_KEY_SEGMENTS = ['email' => true, 'phone' => true, 'ip' => true, 'user_id' => true, 'name' => true];

    /** @var list<array{0: string, 1: string, 2: ?string}> [name, regex, prefilter] */
    // [name, regex, prefilters, group]. A prefilter is a cheap substring test
    // that skips the regex entirely; an array because one string cannot
    // express "AKIA or ASIA". group masks only that capture group, so
    // `?key=...` keeps the readable parameter name.
    //
    // A prefilter is matched case-SENSITIVELY unless its own regex carries the
    // `i` modifier, which is read off the pattern rather than carried as
    // another field. It has to be: folding case made 'AC' (twilio) match 'ac'
    // anywhere and fire on 62% of real log lines.
    private const VALUE_PATTERNS = [
        // Query-string parameters. `key` is ambiguous in prose ("primary key")
        // but inside ?...&key= it is a secret, so this list is wider than the
        // key segments used for attribute names.
        ['query_param', '/([?&](?:key|api[_-]?key|access[_-]?key|token|access[_-]?token|auth|password|passwd|secret|client[_-]?secret|sig|signature|session|sid)=)([^&\s"\'<>]{4,})/i', ['='], 2],
        ['jwt', '/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/', ['eyJ'], 0],
        ['bearer', '/\bbearer\s+[A-Za-z0-9._~+\/=-]{10,}/i', ['bearer'], 0],
        ['pem', '/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/', ['PRIVATE KEY'], 0],
        // Vendor-issued tokens: the prefix is fixed by the vendor, so the
        // regex is exact and the prefilter is free. AWS and GitHub used to be
        // one pattern over several prefixes and so ran with no prefilter.
        ['aws_access_key', '/\b(AKIA|ASIA)[A-Z0-9]{16}\b/', ['AKIA', 'ASIA'], 0],
        ['github_token', '/\b(ghp_|gho_|ghu_|ghs_)[A-Za-z0-9_-]{20,}\b/', ['gh'], 0],
        ['gitlab_token', '/\bglpat-[A-Za-z0-9_-]{20,}\b/', ['glpat-'], 0],
        ['google_api_key', '/\bAIza[0-9A-Za-z_-]{35}\b/', ['AIza'], 0],
        ['google_oauth', '/\bya29\.[0-9A-Za-z_-]{20,}/', ['ya29.'], 0],
        ['openai', '/\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b/', ['sk-'], 0],
        ['stripe', '/\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{16,}\b/', ['_live_', '_test_'], 0],
        ['slack_token', '/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/', ['xox'], 0],
        ['telegram_bot_token', '/\b\d{8,10}:AA[A-Za-z0-9_-]{32,}\b/', [':AA'], 0],
        ['sendgrid', '/\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/', ['SG.'], 0],
        ['twilio_sid', '/\bAC[0-9a-f]{32}\b/', ['AC'], 0],
        ['npm_token', '/\bnpm_[A-Za-z0-9]{36}\b/', ['npm_'], 0],
        ['digitalocean_token', '/\bdop_v1_[0-9a-f]{64}\b/', ['dop_v1_'], 0],
        ['dsn', '#\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@[^\s/]+#', ['://'], 0],
        // Last: the vendor patterns above are precise and have already masked
        // what they recognise; this catches name=value with no known form.
        ['kv_secret', '/\b(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s,;&]{4,}/i', ['=', ':'], 0],
    ];
    private const PAN_RE = '/\b(?:\d[ -]*?){13,19}\b/';

    private bool $enabled;
    private string $mode;
    private string $hashKey;
    /** @var array<string, true> */
    private array $keySegments;
    public bool $redactStacktrace;

    public function __construct()
    {
        $this->enabled = Env::flag('LOG_REDACT');
        $this->mode = Env::str('LOG_REDACT_MODE', 'mask');
        $this->hashKey = Env::str('LOG_REDACT_HASH_KEY', '');
        $this->keySegments = self::DEFAULT_KEY_SEGMENTS;
        if (getenv('LOG_REDACT_PROFILE') === 'pii') {
            $this->keySegments += self::PII_KEY_SEGMENTS;
        }
        foreach (explode(',', Env::str('LOG_REDACT_ALLOW', '')) as $allowed) {
            $allowed = strtolower(trim($allowed));
            if ($allowed !== '') {
                unset($this->keySegments[$allowed]);
            }
        }
        $this->redactStacktrace = Env::flag('LOG_REDACT_STACKTRACE');
    }

    /** @return list<string> */
    private static function keySegments(string $key): array
    {
        $spaced = preg_replace('/([a-z0-9])([A-Z])/', '$1_$2', $key) ?? $key;
        $parts = preg_split('/[._\-\s]+/', $spaced) ?: [];
        return array_map('strtolower', array_filter($parts, static fn ($s) => $s !== ''));
    }

    public function keyIsSensitive(string $fullKey): bool
    {
        if (!$this->enabled) {
            return false;
        }
        foreach (explode('.', $fullKey) as $part) {
            foreach (self::keySegments($part) as $seg) {
                if (isset($this->keySegments[$seg])) {
                    return true;
                }
            }
        }
        return false;
    }

    private function replacement(string $match): string
    {
        // A match that already carries the mask is left alone - see the spec's
        // replacement.no_double_mask. PCRE has lookahead but RE2 does not, and
        // all four implementations have to agree byte for byte.
        if (str_contains($match, '[REDACTED')) {
            return $match;
        }
        if ($this->mode === 'hash' && $this->hashKey !== '') {
            return '[REDACTED:' . substr(hash_hmac('sha256', $match, $this->hashKey), 0, 16) . ']';
        }
        return '[REDACTED]';
    }

    /** Whether the pattern carries the `i` modifier (after its closing delimiter). */
    private static function isFolded(string $regex): bool
    {
        $delimiter = $regex[0];
        $end = strrpos($regex, $delimiter);

        return $end !== false && str_contains(substr($regex, $end + 1), 'i');
    }

    /** @param list<string> $needles */
    private static function containsAny(string $haystack, array $needles, bool $fold): bool
    {
        foreach ($needles as $needle) {
            $found = $fold ? stripos($haystack, $needle) : strpos($haystack, $needle);
            if ($found !== false) {
                return true;
            }
        }

        return false;
    }

    public function redactValuePatterns(string $text): string
    {
        if (!$this->enabled || $text === '') {
            return $text;
        }
        foreach (self::VALUE_PATTERNS as [$name, $regex, $prefilters, $group]) {
            if ($prefilters !== null && !self::containsAny($text, $prefilters, self::isFolded($regex))) {
                continue;
            }
            if ($group > 0) {
                // Mask only that capture group - `?key=` stays readable. Located
                // by offset, not by searching for the group's text inside the
                // match, so the other three implementations agree byte for byte.
                $text = preg_replace_callback(
                    $regex,
                    function ($m) use ($group) {
                        [$whole, $wholeAt] = $m[0];
                        [$value, $valueAt] = $m[$group];
                        if ($valueAt < 0) {
                            return $whole;
                        }
                        $at = $valueAt - $wholeAt;

                        return substr($whole, 0, $at) . $this->replacement($value) . substr($whole, $at + strlen($value));
                    },
                    $text,
                    -1,
                    $count,
                    PREG_OFFSET_CAPTURE
                ) ?? $text;
                continue;
            }
            $text = preg_replace_callback($regex, fn ($m) => $this->replacement($m[0]), $text) ?? $text;
        }
        $text = preg_replace_callback(self::PAN_RE, function ($m) {
            $digits = str_replace([' ', '-'], '', $m[0]);
            $len = strlen($digits);
            if ($len < 13 || $len > 19 || !self::luhnOk($digits)) {
                return $m[0];
            }
            return $this->replacement($digits);
        }, $text) ?? $text;
        return $text;
    }

    private static function luhnOk(string $digits): bool
    {
        $total = 0;
        $parity = strlen($digits) % 2;
        for ($i = 0, $n = strlen($digits); $i < $n; $i++) {
            $d = (int) $digits[$i];
            if ($i % 2 === $parity) {
                $d *= 2;
                if ($d > 9) {
                    $d -= 9;
                }
            }
            $total += $d;
        }
        return $total % 10 === 0;
    }
}
