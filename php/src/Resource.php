<?php

declare(strict_types=1);

namespace Unilog;

/**
 * Resource resolver — spec §3. Cached, re-resolved after fork() (php-fpm
 * master forking workers, or an explicit pcntl_fork) so workers don't all
 * report the same service.instance.id.
 */
final class Resource
{
    /** @var array<string, mixed>|null */
    private static ?array $cached = null;
    private static ?int $cachedPid = null;
    /** @var array<string, string> */
    private static array $explicit = [];

    /** @param array<string, string> $overrides */
    public static function configure(array $overrides): void
    {
        self::$explicit = $overrides;
        self::$cached = null;
    }

    /** @return array<string, mixed> */
    public static function get(): array
    {
        $pid = getmypid() ?: 0;
        if (self::$cached === null || self::$cachedPid !== $pid) {
            self::$cached = self::resolve();
            self::$cachedPid = $pid;
        }
        return self::$cached;
    }

    /** @return array<string, string>|null null means "malformed, drop the whole var" */
    private static function parseOtelResourceAttributes(string $raw): ?array
    {
        $out = [];
        if ($raw === '') {
            return $out;
        }
        foreach (explode(',', $raw) as $pair) {
            $pair = trim($pair);
            if ($pair === '') {
                continue;
            }
            $eq = strpos($pair, '=');
            if ($eq === false) {
                return null;
            }
            $k = rawurldecode(trim(substr($pair, 0, $eq)));
            $v = rawurldecode(trim(substr($pair, $eq + 1)));
            $out[$k] = $v;
        }
        return $out;
    }

    private static function executableBasename(): string
    {
        $script = $_SERVER['SCRIPT_NAME'] ?? $_SERVER['SCRIPT_FILENAME'] ?? $_SERVER['argv'][0] ?? 'php';
        return basename((string) $script) ?: 'php';
    }

    private static function composerServiceName(): ?string
    {
        if (!class_exists(\Composer\InstalledVersions::class)) {
            return null;
        }
        try {
            $root = \Composer\InstalledVersions::getRootPackage();
            $name = $root['name'] ?? null;
            if ($name !== null && str_contains($name, '/')) {
                $name = substr($name, strpos($name, '/') + 1);
            }
            return $name;
        } catch (\Throwable) {
            return null;
        }
    }

    private static function uuidV4(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /** @param array<string, string> $k8s */
    private static function instanceId(string $strategy, array $k8s, ?string $hostName): ?string
    {
        if ($strategy === 'none') {
            return null;
        }
        if ($strategy === 'host-pid') {
            return ($hostName ?: 'unknown') . '/' . (getmypid() ?: 0);
        }
        if (isset($k8s['k8s.pod.name'])) {
            return implode('.', array_filter([
                $k8s['k8s.namespace.name'] ?? null,
                $k8s['k8s.pod.name'],
                $k8s['k8s.container.name'] ?? null,
            ]));
        }
        return self::uuidV4();
    }

    /** @return array<string, mixed> */
    private static function resolve(): array
    {
        $rawOtel = Env::str('OTEL_RESOURCE_ATTRIBUTES', '');
        $otelAttrs = self::parseOtelResourceAttributes($rawOtel);
        if ($rawOtel !== '' && $otelAttrs === null) {
            fwrite(\STDERR, "unilog: OTEL_RESOURCE_ATTRIBUTES is malformed, ignoring it entirely\n");
            $otelAttrs = [];
        }
        $otelAttrs ??= [];

        $pkgName = self::composerServiceName();

        $otelServiceName = getenv('OTEL_SERVICE_NAME');
        $serviceName = self::$explicit['service_name']
            ?? ($otelServiceName !== false ? $otelServiceName : null)
            ?? ($otelAttrs['service.name'] ?? null)
            ?? $pkgName
            ?? ('unknown_service:' . self::executableBasename());
        $logServiceNamespace = getenv('LOG_SERVICE_NAMESPACE');
        $serviceNamespace = self::$explicit['service_namespace'] ?? ($logServiceNamespace !== false ? $logServiceNamespace : null) ?? ($otelAttrs['service.namespace'] ?? null);
        $logEnv = getenv('LOG_ENV');
        $deploymentEnv = self::$explicit['deployment_environment'] ?? ($logEnv !== false ? $logEnv : null) ?? ($otelAttrs['deployment.environment.name'] ?? null);

        $hostNameEnv = getenv('HOSTNAME');
        $hostName = @gethostname() ?: ($hostNameEnv !== false ? $hostNameEnv : null);

        $k8s = [];
        foreach ([
            'k8s.namespace.name' => 'K8S_NAMESPACE',
            'k8s.pod.name' => 'K8S_POD_NAME',
            'k8s.container.name' => 'K8S_CONTAINER_NAME',
            'k8s.node.name' => 'K8S_NODE_NAME',
        ] as $attr => $envVar) {
            $v = getenv($envVar);
            if ($v !== false && $v !== '') {
                $k8s[$attr] = $v;
            }
        }

        $strategy = Env::str('LOG_INSTANCE_ID_STRATEGY', 'auto');

        $resource = ['service.name' => $serviceName];
        if ($serviceNamespace) {
            $resource['service.namespace'] = $serviceNamespace;
        }
        $iid = self::instanceId($strategy, $k8s, $hostName);
        if ($iid !== null) {
            $resource['service.instance.id'] = $iid;
        }
        if ($deploymentEnv) {
            $resource['deployment.environment.name'] = $deploymentEnv;
        }
        if ($hostName) {
            $resource['host.name'] = $hostName;
        }
        if (Env::flag('LOG_RESOURCE_PROCESS')) {
            $resource['process.pid'] = getmypid() ?: 0;
        }
        foreach ($k8s as $k => $v) {
            $resource[$k] = $v;
        }
        foreach ($otelAttrs as $k => $v) {
            if (!isset($resource[$k]) && !in_array($k, ['service.name', 'service.namespace', 'deployment.environment.name'], true)) {
                $resource[$k] = $v;
            }
        }
        return $resource;
    }
}
