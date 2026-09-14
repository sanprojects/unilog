'use strict';
// console + syslog sinks. Per the decision recorded in the plan: Node/Bun get
// NO native syslog client (no unix_dgram in node:dgram, no FFI) — only the
// journald <N>-prefix path, or console-only with one diagnostic line.

const fs = require('node:fs');
const severity = require('./severity.cjs');

class Sinks {
  constructor(env = process.env) {
    const sinkList = env.LOG_SINK || 'console+syslog';
    this.consoleEnabled = sinkList.includes('console');
    this.syslogWanted = sinkList.includes('syslog');
    this.journaldAvailable = this.syslogWanted && !!env.JOURNAL_STREAM;
    this.facility = FACILITIES[env.LOG_SYSLOG_FACILITY || 'user'] ?? 1;
    this.stderrMin = env.LOG_STDERR_MIN_SEVERITY ?? '17';
    this.atomicPipe = env.LOG_ATOMIC_PIPE || 'auto';
    this.maxRecordBytes = parseInt(env.LOG_MAX_RECORD_BYTES || '65536', 10);
    this._warnedNoSyslog = false;
  }

  _routeFd(severityNumber) {
    if (this.stderrMin === 'OFF') return 1;
    if (this.stderrMin === '0') return 2;
    const threshold = parseInt(this.stderrMin, 10) || 17;
    return severityNumber >= threshold ? 2 : 1;
  }

  _maxBytes() {
    if (this.atomicPipe === '0') return this.maxRecordBytes;
    if (this.atomicPipe === '1') return Math.min(this.maxRecordBytes, 4096);
    try {
      const isPipe = fs.fstatSync(1).isFIFO();
      if (isPipe) return Math.min(this.maxRecordBytes, 4096);
    } catch {
      /* ignore */
    }
    return this.maxRecordBytes;
  }

  emit(line, severityNumber) {
    if (!this.consoleEnabled) return;
    const max = this._maxBytes();
    let data = Buffer.from(line, 'utf8');
    if (data.length > max) {
      data = Buffer.concat([data.slice(0, max - 2), Buffer.from('}\n')]);
    }
    const fd = this._routeFd(severityNumber);

    if (this.journaldAvailable) {
      // systemd's own stdout/stderr "log level prefix" is NOT a real syslog
      // PRI (facility*8+severity) — it's the bare severity digit 0-7 only.
      // Verified empirically on the actual host: `<3>msg` via systemd-run
      // parses to PRIORITY=3 with the prefix stripped from MESSAGE; `<14>msg`
      // (this package's facility=user(1)<<3|severity, the real syslog PRI
      // encoding) is NOT recognized at all — falls through to journald's
      // default priority with the literal "<14>" text left in MESSAGE.
      const [, sev] = severity.textAndSyslog(severityNumber);
      const prefixed = Buffer.concat([Buffer.from(`<${sev}>`), data]);
      this._write(fd, prefixed);
      return;
    }
    if (this.syslogWanted && !this._warnedNoSyslog) {
      this._warnedNoSyslog = true;
      this._write(2, Buffer.from('unilog: no syslog transport available (Node/Bun has none built-in outside journald), continuing with console only\n'));
    }
    this._write(fd, data);
  }

  _write(fd, buf) {
    try {
      fs.writeSync(fd, buf);
    } catch {
      /* a broken pipe must never crash the app */
    }
  }
}

const FACILITIES = {
  kern: 0, user: 1, mail: 2, daemon: 3, auth: 4, syslog: 5,
  lpr: 6, news: 7, uucp: 8, cron: 9, authpriv: 10, ftp: 11,
  local0: 16, local1: 17, local2: 18, local3: 19,
  local4: 20, local5: 21, local6: 22, local7: 23,
};

module.exports = { Sinks };
