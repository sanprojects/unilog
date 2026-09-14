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
    private const VALUE_PATTERNS = [
        ['jwt', '/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/', 'eyJ'],
        ['bearer', '/\bbearer\s+[A-Za-z0-9._~+\/=-]{10,}/i', 'bearer'],
        ['pem', '/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/', 'PRIVATE KEY'],
        ['aws_access_key', '/\b(AKIA|ASIA)[A-Z0-9]{16}\b/', null],
        ['gh_token', '/\b(ghp_|gho_|ghu_|ghs_|glpat-)[A-Za-z0-9_-]{20,}\b/', null],
        ['dsn', '#\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@[^\s/]+#', '://'],
        ['kv_secret', '/\b(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s,;&]{4,}/i', null],
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
        if ($this->mode === 'hash' && $this->hashKey !== '') {
            return '[REDACTED:' . substr(hash_hmac('sha256', $match, $this->hashKey), 0, 16) . ']';
        }
        return '[REDACTED]';
    }

    public function redactValuePatterns(string $text): string
    {
        if (!$this->enabled || $text === '') {
            return $text;
        }
        foreach (self::VALUE_PATTERNS as [$name, $regex, $prefilter]) {
            if ($prefilter !== null && stripos($text, $prefilter) === false) {
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
