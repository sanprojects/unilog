<?php

declare(strict_types=1);

namespace Unilog\Psr3;

use Psr\Log\LoggerInterface;
use Psr\Log\LoggerTrait;
use Unilog\Installer;
use Unilog\Record;
use Unilog\Severity;

/**
 * PSR-3 logger backed by unilog. Requires `psr/log` (not declared as a
 * dependency here — virtually every framework already pulls it in; install
 * it explicitly if you don't: `composer require psr/log`).
 *
 * $logger->error('User not found', ['id' => 123]);
 */
final class Logger implements LoggerInterface
{
    use LoggerTrait;

    public function __construct(private readonly ?string $scope = null)
    {
    }

    // Deliberately untyped $level/$message: psr/log's own interface signature
    // has drifted across 1.x/2.x/3.x (mixed vs string|Stringer) and PHP only
    // allows an implementation to *widen* an interface's parameter types, so
    // "no type" is the one signature compatible with all three.
    public function log($level, $message, array $context = []): void
    {
        $severityNumber = Severity::fromPsr3((string) $level);
        $message = (string) $message;

        $eventName = null;
        if (isset($context['event_name']) && is_string($context['event_name'])) {
            $eventName = $context['event_name'];
            unset($context['event_name']);
        }

        $exception = $context['exception'] ?? null;
        $attributes = $context;
        if ($exception instanceof \Throwable) {
            unset($attributes['exception']);
            $attributes = array_merge($attributes, Record::exceptionAttributes($exception, $severityNumber));
        }

        $body = self::interpolate($message, $context);
        Installer::emitDirect($severityNumber, $body, $eventName ?? ($this->scope !== null ? $this->scope . '.log' : null), $attributes);
    }

    /** PSR-3 standard `{placeholder}` interpolation. */
    private static function interpolate(string $message, array $context): string
    {
        if (!str_contains($message, '{')) {
            return $message;
        }
        $replace = [];
        foreach ($context as $key => $val) {
            if (is_scalar($val) || (is_object($val) && method_exists($val, '__toString'))) {
                $replace['{' . $key . '}'] = (string) $val;
            }
        }
        return $replace === [] ? $message : strtr($message, $replace);
    }
}
