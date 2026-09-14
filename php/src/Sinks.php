<?php

declare(strict_types=1);

namespace Unilog;

/**
 * console + syslog sinks. Atomicity (spec §4.7): one fwrite() per record,
 * capped to PIPE_BUF when stdout looks like a pipe multiple processes share
 * (php-fpm, forked workers).
 */
final class Sinks
{
    private const FACILITIES = [
        'kern' => 0, 'user' => 1, 'mail' => 2, 'daemon' => 3, 'auth' => 4, 'syslog' => 5,
        'lpr' => 6, 'news' => 7, 'uucp' => 8, 'cron' => 9, 'authpriv' => 10, 'ftp' => 11,
        'local0' => 16, 'local1' => 17, 'local2' => 18, 'local3' => 19,
        'local4' => 20, 'local5' => 21, 'local6' => 22, 'local7' => 23,
    ];

    private bool $consoleEnabled;
    private bool $syslogWanted;
    private bool $nativeOk = false;
    private int $facility;
    private bool $warnedNoSyslog = false;

    public function __construct(private readonly string $serviceName)
    {
        $sinkList = Env::str('LOG_SINK', 'console+syslog');
        $this->consoleEnabled = str_contains($sinkList, 'console');
        $this->syslogWanted = str_contains($sinkList, 'syslog') && \function_exists('openlog');
        $facilityName = Env::str('LOG_SYSLOG_FACILITY', 'user');
        $this->facility = self::FACILITIES[$facilityName] ?? 1;

        if ($this->syslogWanted) {
            $this->nativeOk = @openlog($this->serviceName, \LOG_PID, $this->facility << 3);
        }
    }

    private function routeStream(int $severityNumber)
    {
        $thr = Env::str('LOG_STDERR_MIN_SEVERITY', '17');
        if ($thr === 'OFF') {
            return \STDOUT;
        }
        if ($thr === '0') {
            return \STDERR;
        }
        $threshold = is_numeric($thr) ? (int) $thr : 17;
        return $severityNumber >= $threshold ? \STDERR : \STDOUT;
    }

    private function maxBytes(): int
    {
        $default = Env::int('LOG_MAX_RECORD_BYTES', 65536);
        $mode = Env::str('LOG_ATOMIC_PIPE', 'auto');
        if ($mode === '0') {
            return $default;
        }
        if ($mode === '1') {
            return min($default, 4096);
        }
        $stat = @fstat(\STDOUT);
        if ($stat !== false && ($stat['mode'] & 0170000) === 0010000) { // S_IFIFO
            return min($default, 4096);
        }
        return $default;
    }

    public function emit(string $line, int $severityNumber): void
    {
        if (!$this->consoleEnabled && !$this->nativeOk) {
            return;
        }
        $max = $this->maxBytes();
        if (strlen($line) > $max) {
            $line = substr($line, 0, $max - 2) . "}\n";
        }

        $usedNative = false;
        if ($this->nativeOk) {
            $priority = Severity::syslogSeverity($severityNumber); // facility already bound via openlog()
            $usedNative = @syslog($priority, rtrim($line, "\n"));
        }

        if (!$this->consoleEnabled) {
            return;
        }

        $fd = $this->routeStream($severityNumber);

        if (!$usedNative && $this->syslogWanted && getenv('JOURNAL_STREAM') !== false) {
            $pri = Severity::syslogPriority($severityNumber, $this->facility);
            @fwrite($fd, "<{$pri}>{$line}");
            return;
        }
        if ($this->syslogWanted && !$usedNative && !$this->warnedNoSyslog) {
            $this->warnedNoSyslog = true;
            @fwrite(\STDERR, "unilog: no syslog transport available, continuing with console only\n");
        }
        @fwrite($fd, $line);
    }
}
