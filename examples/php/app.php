<?php
// Run: php -n examples/php/app.php
require __DIR__ . '/../../vendor/autoload.php';

$logger = new \Unilog\Psr3\Logger();
$logger->info('Subscription updated');
$logger->error('User not found', ['id' => 123]);
throw new \RuntimeException('unhandled — watch this become a FATAL record, exit code 255');
