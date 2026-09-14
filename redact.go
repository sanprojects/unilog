package unilog

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
)

var defaultKeySegments = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "passphrase": true, "secret": true, "client_secret": true,
	"token": true, "access_token": true, "refresh_token": true, "id_token": true, "api_key": true, "apikey": true,
	"apitoken": true, "private_key": true, "secret_key": true, "signature": true, "sig": true, "credentials": true, "auth": true,
	"authorization": true, "proxy_authorization": true, "cookie": true, "set_cookie": true, "x_api_key": true,
	"x_auth_token": true, "x_csrf_token": true,
	"session": true, "sessionid": true, "sid": true, "jsessionid": true, "phpsessid": true, "csrf": true, "xsrf": true,
	"card": true, "cardnumber": true, "pan": true, "cvv": true, "cvc": true, "cvv2": true, "card_cvc": true, "expiry": true,
	"exp_month": true, "exp_year": true, "iban": true, "account_number": true, "routing_number": true,
	"ssn": true, "passport": true, "tin": true, "inn": true, "snils": true, "dob": true, "birthdate": true,
	"otp": true, "totp": true, "pin": true, "mfa_code": true, "recovery_code": true,
}

var piiKeySegments = map[string]bool{"email": true, "phone": true, "ip": true, "user_id": true, "name": true}

var segmentSplit = regexp.MustCompile(`[._\-\s]+`)
var camelBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)

type valuePattern struct {
	name       string
	re         *regexp.Regexp
	prefilter  string
}

var valuePatterns = []valuePattern{
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`), "eyJ"},
	{"bearer", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{10,}`), "bearer"},
	{"pem", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), "PRIVATE KEY"},
	{"aws_access_key", regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`), ""},
	{"gh_token", regexp.MustCompile(`\b(ghp_|gho_|ghu_|ghs_|glpat-)[A-Za-z0-9_-]{20,}\b`), ""},
	{"dsn", regexp.MustCompile(`\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@[^\s/]+`), "://"},
	{"kv_secret", regexp.MustCompile(`(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s,;&]{4,}`), ""},
}

var panRe = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)

type Redactor struct {
	Enabled          bool
	Mode             string // mask | drop | hash
	HashKey          string
	KeySegments      map[string]bool
	RedactStacktrace bool
}

func newRedactor() *Redactor {
	r := &Redactor{
		Enabled:          os.Getenv("LOG_REDACT") != "0",
		Mode:             getenvDefault("LOG_REDACT_MODE", "mask"),
		HashKey:          os.Getenv("LOG_REDACT_HASH_KEY"),
		RedactStacktrace: os.Getenv("LOG_REDACT_STACKTRACE") != "0",
		KeySegments:      map[string]bool{},
	}
	for k := range defaultKeySegments {
		r.KeySegments[k] = true
	}
	if os.Getenv("LOG_REDACT_PROFILE") == "pii" {
		for k := range piiKeySegments {
			r.KeySegments[k] = true
		}
	}
	for _, allowed := range strings.Split(os.Getenv("LOG_REDACT_ALLOW"), ",") {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed != "" {
			delete(r.KeySegments, allowed)
		}
	}
	return r
}

func keySegments(key string) map[string]bool {
	// Go's regexp replacement syntax treats "$1_" as a reference to a named
	// group called "1_" (digits+underscore are valid name chars), NOT as
	// "group 1, then a literal underscore" — verified: "$1_$2" silently
	// swallowed group 1 entirely ("cardNumber" -> "carNumber"). ${1}_${2}
	// disambiguates the group boundary from the underscore.
	spaced := camelBoundary.ReplaceAllString(key, "${1}_${2}")
	segs := map[string]bool{}
	for _, s := range segmentSplit.Split(spaced, -1) {
		if s != "" {
			segs[strings.ToLower(s)] = true
		}
	}
	return segs
}

func (r *Redactor) KeyIsSensitive(fullKey string) bool {
	if !r.Enabled {
		return false
	}
	for _, part := range strings.Split(fullKey, ".") {
		for seg := range keySegments(part) {
			if r.KeySegments[seg] {
				return true
			}
		}
	}
	return false
}

func (r *Redactor) replacement(match string) string {
	if r.Mode == "hash" && r.HashKey != "" {
		mac := hmac.New(sha256.New, []byte(r.HashKey))
		mac.Write([]byte(match))
		return "[REDACTED:" + hex.EncodeToString(mac.Sum(nil))[:16] + "]"
	}
	return "[REDACTED]"
}

func (r *Redactor) RedactValuePatterns(text string) string {
	if !r.Enabled || text == "" {
		return text
	}
	lower := strings.ToLower(text)
	for _, p := range valuePatterns {
		if p.prefilter != "" && !strings.Contains(lower, strings.ToLower(p.prefilter)) {
			continue
		}
		text = p.re.ReplaceAllStringFunc(text, r.replacement)
		lower = strings.ToLower(text)
	}
	text = panRe.ReplaceAllStringFunc(text, func(m string) string {
		digits := strings.NewReplacer(" ", "", "-", "").Replace(m)
		if len(digits) < 13 || len(digits) > 19 || !luhnOK(digits) {
			return m
		}
		return r.replacement(digits)
	})
	return text
}

func luhnOK(digits string) bool {
	total := 0
	parity := len(digits) % 2
	for i, ch := range digits {
		if ch < '0' || ch > '9' {
			return false
		}
		d := int(ch - '0')
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		total += d
	}
	return total%10 == 0
}

func getenvDefault(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}
