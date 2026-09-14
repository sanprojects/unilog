<?php

declare(strict_types=1);

namespace Unilog\Monolog;

use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Level;
use Monolog\LogRecord;
use Unilog\Installer;
use Unilog\Record;
use Unilog\Severity;

/**
 * Monolog handler — "transport, not patch": for a Laravel/Symfony app where
 * Monolog already owns the channel, add this handler instead of relying on
 * the global set_error_handler/set_exception_handler hooks, which the
 * framework's own bootstrap will have already overridden by the time this
 * loads. Requires `monolog/monolog` (not declared here — see composer.json's
 * suggest block).
 *
 *   $logger->pushHandler(new \Unilog\Monolog\UnilogHandler());
 */
final class UnilogHandler extends AbstractProcessingHandler
{
    // Monolog 3's own numeric levels (100-600) already line up 1:1 with
    // PSR-3 names via Level::toPsrLogLevel(), so reuse Severity::fromPsr3
    // instead of a second table.
    protected function write(LogRecord $record): void
    {
        $severityNumber = Severity::fromPsr3($record->level->toPsrLogLevel());

        $context = $record->context;
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
        if ($record->extra !== []) {
            $attributes = array_merge($attributes, $record->extra);
        }
        $attributes['log.channel'] = $record->channel;

        Installer::emitDirect($severityNumber, $record->message, $eventName, $attributes);
    }
}
