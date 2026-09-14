<?php

declare(strict_types=1);

// Conformance driver for the PHP implementation. See ../../protocol.md.

$case = json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR);
foreach ($case['env'] ?? [] as $k => $v) {
    putenv("{$k}={$v}");
}

require __DIR__ . '/../../../php/src/Env.php';
require __DIR__ . '/../../../php/src/Severity.php';
require __DIR__ . '/../../../php/src/Redactor.php';
require __DIR__ . '/../../../php/src/Resource.php';
require __DIR__ . '/../../../php/src/Record.php';
require __DIR__ . '/../../../php/src/Caller.php';

$opts = $case['input'];

// Mirrors what Psr3\Logger::log() does before calling Record::build() — the
// driver itself is a manual "entry point", same as a real app's.
$attributes = \Unilog\Caller::enabled() ? \Unilog\Caller::attributes() : [];
$attributes = [...$attributes, ...($opts['attributes'] ?? [])];

$record = \Unilog\Record::build([
    'severityNumber' => $opts['severityNumber'] ?? 9,
    'body' => $opts['body'] ?? '',
    'eventName' => $opts['eventName'] ?? null,
    'resource' => \Unilog\Resource::get(),
    'attributes' => $attributes,
    'traceId' => $opts['traceId'] ?? null,
    'spanId' => $opts['spanId'] ?? null,
]);
echo \Unilog\Record::toJsonLine($record);
