<?php

declare(strict_types=1);

// Conformance driver for the PHP implementation. See ../../protocol.md.

$case = json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR);
foreach ($case['env'] ?? [] as $k => $v) {
    putenv("{$k}={$v}");
}

require __DIR__ . '/../../../php/src/Severity.php';
require __DIR__ . '/../../../php/src/Redactor.php';
require __DIR__ . '/../../../php/src/Resource.php';
require __DIR__ . '/../../../php/src/Record.php';

$opts = $case['input'];
$record = \Unilog\Record::build([
    'severityNumber' => $opts['severityNumber'] ?? 9,
    'body' => $opts['body'] ?? '',
    'eventName' => $opts['eventName'] ?? null,
    'resource' => \Unilog\Resource::get(),
    'attributes' => $opts['attributes'] ?? [],
    'traceId' => $opts['traceId'] ?? null,
    'spanId' => $opts['spanId'] ?? null,
]);
echo \Unilog\Record::toJsonLine($record);
