package unilog

import (
	"fmt"
	"log/syslog"
	"os"
	"strconv"
	"strings"
	"sync"
)

var facilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// Sinks is the console+syslog fan-out. One instance per process, created by
// auto's init() (or manually via NewSinks for tests).
type Sinks struct {
	mu             sync.Mutex
	consoleEnabled bool
	syslogEnabled  bool
	syslogWriter   *syslog.Writer
	facility       int
	warnedNoSyslog bool
	serviceName    string
}

func NewSinks(serviceName string) *Sinks {
	sinkList := getenvDefault("LOG_SINK", "console+syslog")
	s := &Sinks{
		consoleEnabled: strings.Contains(sinkList, "console"),
		syslogEnabled:  strings.Contains(sinkList, "syslog"),
		serviceName:    serviceName,
	}
	facName := getenvDefault("LOG_SYSLOG_FACILITY", "user")
	s.facility = facilities[facName]

	if s.syslogEnabled {
		// log/syslog's default Dial (network="") tries the local Unix socket
		// first — this is our "native API" rung of the transport ladder.
		w, err := syslog.New(syslog.Priority(s.facility<<3)|syslog.LOG_INFO, serviceName)
		if err == nil {
			s.syslogWriter = w
		}
	}
	return s
}

func (s *Sinks) routeFD(severityNumber int) *os.File {
	thr := getenvDefault("LOG_STDERR_MIN_SEVERITY", "17")
	if thr == "OFF" {
		return os.Stdout
	}
	if thr == "0" {
		return os.Stderr
	}
	threshold, err := strconv.Atoi(thr)
	if err != nil {
		threshold = 17
	}
	if severityNumber >= threshold {
		return os.Stderr
	}
	return os.Stdout
}

func (s *Sinks) maxBytes() int {
	def := envInt("LOG_MAX_RECORD_BYTES", 65536)
	mode := getenvDefault("LOG_ATOMIC_PIPE", "auto")
	if mode == "0" {
		return def
	}
	if mode == "1" {
		return min(def, 4096)
	}
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeNamedPipe != 0 {
		return min(def, 4096)
	}
	return def
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Emit writes exactly one line to console (stdout or stderr, by severity)
// and, when reachable, to syslog with a real priority — spec's sink ladder.
func (s *Sinks) Emit(line []byte, severityNumber int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.consoleEnabled && s.syslogWriter == nil {
		return
	}

	max := s.maxBytes()
	if len(line) > max {
		line = append(line[:max-2], '}', '\n')
	}

	usedNative := false
	if s.syslogWriter != nil {
		// log/syslog bakes facility+severity into a fixed w.priority at New()
		// time and only exposes per-severity methods for varying it per call
		// (Write() would always reuse the priority New() was given) — so we
		// pick the matching method instead of hand-building a <PRI> prefix,
		// which the Writer already adds internally.
		msg := string(line)
		var err error
		switch syslogSeverityFor(severityNumber) {
		case 0:
			err = s.syslogWriter.Emerg(msg)
		case 1:
			err = s.syslogWriter.Alert(msg)
		case 2:
			err = s.syslogWriter.Crit(msg)
		case 3:
			err = s.syslogWriter.Err(msg)
		case 4:
			err = s.syslogWriter.Warning(msg)
		case 5:
			err = s.syslogWriter.Notice(msg)
		case 6:
			err = s.syslogWriter.Info(msg)
		default:
			err = s.syslogWriter.Debug(msg)
		}
		if err == nil {
			usedNative = true
		} else {
			s.syslogWriter = nil
		}
	}

	if !s.consoleEnabled {
		return
	}

	f := s.routeFD(severityNumber)
	if !usedNative && s.syslogEnabled && os.Getenv("JOURNAL_STREAM") != "" {
		pri := syslogPriority(severityNumber, s.facility)
		prefixed := append([]byte(fmt.Sprintf("<%d>", pri)), line...)
		_, _ = f.Write(prefixed)
		return
	}
	if s.syslogEnabled && !usedNative && !s.warnedNoSyslog {
		s.warnedNoSyslog = true
		_, _ = os.Stderr.WriteString("unilog: no syslog transport available, continuing with console only\n")
	}
	_, _ = f.Write(line)
}
