package unilog

import "log/slog"

// severityEntry mirrors spec/severity.csv 1:1 — keep the two in sync by hand
// until a generator script exists.
type severityEntry struct {
	text        string
	syslogSev   int // 0-7
}

var severityTable = map[int]severityEntry{
	1: {"TRACE", 7}, 2: {"TRACE2", 7}, 3: {"TRACE3", 7}, 4: {"TRACE4", 7},
	5: {"DEBUG", 7}, 6: {"DEBUG2", 7}, 7: {"DEBUG3", 7}, 8: {"DEBUG4", 7},
	9: {"INFO", 6}, 10: {"INFO2", 5}, 11: {"INFO3", 5}, 12: {"INFO4", 5},
	13: {"WARN", 4}, 14: {"WARN2", 4}, 15: {"WARN3", 4}, 16: {"WARN4", 4},
	17: {"ERROR", 3}, 18: {"ERROR2", 2}, 19: {"ERROR3", 1}, 20: {"ERROR4", 1},
	21: {"FATAL", 0}, 22: {"FATAL2", 0}, 23: {"FATAL3", 0}, 24: {"FATAL4", 0},
}

func clampSeverity(n int) int {
	if n < 1 {
		return 1
	}
	if n > 24 {
		return 24
	}
	return n
}

func severityTextFor(n int) string {
	return severityTable[clampSeverity(n)].text
}

func syslogSeverityFor(n int) int {
	return severityTable[clampSeverity(n)].syslogSev
}

func syslogPriority(n int, facility int) int {
	return facility*8 + syslogSeverityFor(n)
}

// fromSlogLevel converts a slog.Level to our 1-24 scale.
// Formula verified in spec §2.3: sev = clamp(level + 9, 1, 24).
// slog.LevelDebug=-4 -> 5, LevelInfo=0 -> 9, LevelWarn=4 -> 13, LevelError=8 -> 17.
func fromSlogLevel(l slog.Level) int {
	return clampSeverity(int(l) + 9)
}
