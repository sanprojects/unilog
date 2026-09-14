<?php

declare(strict_types=1);

namespace Unilog\Monolog;

use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Level;
use Monolog\LogRecord;
use Unilog\Caller;
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

        // Short caller trace, lowest priority. Caveat: by the time write() runs,
        // we're several Monolog-internal frames away from the user's original
        // $logger->error() call — our own-package filter still applies, but
        // the nearest frame it finds may be inside Monolog rather than real
        // application code. If MonoLog's own IntrospectionProcessor is
        // configured, its file/line/class/function in $record->extra is more
        // accurate and overrides this below (Monolog puts it there itself).
        $attributes = Caller::enabled() ? Caller::attributes() : [];
        $attributes = [...$attributes, ...$context];

        $exception = $context['exception'] ?? null;
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
