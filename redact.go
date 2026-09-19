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

// prefilters is a cheap substring test that skips the regex entirely; a slice
// because one string cannot express "AKIA or ASIA". group masks only that
// capture group, so `?key=...` keeps the readable parameter name.
//
// A prefilter is matched case-SENSITIVELY unless the regex itself is case-
// insensitive, which is read off the pattern source rather than carried as
// another field. It has to be: folding case made "AC" (twilio) match "ac"
// anywhere and fire on 62% of real log lines.
type valuePattern struct {
	name       string
	re         *regexp.Regexp
	prefilters []string
	group      int
	fold       bool
}

var valuePatterns = []valuePattern{
	// Query-string parameters. `key` is ambiguous in prose ("primary key") but
	// inside ?...&key= it is a secret, so this list is wider than the key
	// segments used for attribute names.
	{"query_param", regexp.MustCompile(`(?i)([?&](?:key|api[_-]?key|access[_-]?key|token|access[_-]?token|auth|password|passwd|secret|client[_-]?secret|sig|signature|session|sid)=)([^&\s"'<>]{4,})`), []string{"="}, 2, true},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`), []string{"eyJ"}, 0, false},
	{"bearer", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{10,}`), []string{"bearer"}, 0, true},
	{"pem", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), []string{"PRIVATE KEY"}, 0, false},
	// Vendor-issued tokens: the prefix is fixed by the vendor, so the regex is
	// exact and the prefilter is free. AWS and GitHub used to be one pattern
	// over several prefixes and therefore ran with no prefilter at all.
	{"aws_access_key", regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`), []string{"AKIA", "ASIA"}, 0, false},
	{"github_token", regexp.MustCompile(`\b(ghp_|gho_|ghu_|ghs_)[A-Za-z0-9_-]{20,}\b`), []string{"gh"}, 0, false},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`), []string{"glpat-"}, 0, false},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), []string{"AIza"}, 0, false},
	{"google_oauth", regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}`), []string{"ya29."}, 0, false},
	{"openai", regexp.MustCompile(`\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b`), []string{"sk-"}, 0, false},
	{"stripe", regexp.MustCompile(`\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{16,}\b`), []string{"_live_", "_test_"}, 0, false},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), []string{"xox"}, 0, false},
	{"telegram_bot_token", regexp.MustCompile(`\b\d{8,10}:AA[A-Za-z0-9_-]{32,}\b`), []string{":AA"}, 0, false},
	{"sendgrid", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`), []string{"SG."}, 0, false},
	{"twilio_sid", regexp.MustCompile(`\bAC[0-9a-f]{32}\b`), []string{"AC"}, 0, false},
	{"npm_token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), []string{"npm_"}, 0, false},
	{"digitalocean_token", regexp.MustCompile(`\bdop_v1_[0-9a-f]{64}\b`), []string{"dop_v1_"}, 0, false},
	{"dsn", regexp.MustCompile(`\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@[^\s/]+`), []string{"://"}, 0, false},
	// Last: the vendor patterns above are precise and have already masked what
	// they recognise; this catches name=value shapes with no known form.
	{"kv_secret", regexp.MustCompile(`(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s,;&]{4,}`), []string{"=", ":"}, 0, true},
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
	// A match that already carries the mask is left alone - see the spec's
	// replacement.no_double_mask. RE2 has no lookahead, so this cannot be a
	// regex condition.
	if strings.Contains(match, "[REDACTED") {
		return match
	}
	if r.Mode == "hash" && r.HashKey != "" {
		mac := hmac.New(sha256.New, []byte(r.HashKey))
		mac.Write([]byte(match))
		return "[REDACTED:" + hex.EncodeToString(mac.Sum(nil))[:16] + "]"
	}
	return "[REDACTED]"
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// replaceGroup masks one capture group in place, keeping the rest of the match -
// so `?key=AIza...` becomes `?key=[REDACTED]` rather than losing the name.
func (r *Redactor) replaceGroup(re *regexp.Regexp, group int, text string) string {
	var b strings.Builder
	last := 0
	for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
		start, end := m[2*group], m[2*group+1]
		if start < 0 {
			continue
		}
		b.WriteString(text[last:start])
		b.WriteString(r.replacement(text[start:end]))
		last = end
	}
	if last == 0 {
		return text
	}
	b.WriteString(text[last:])
	return b.String()
}

func (r *Redactor) RedactValuePatterns(text string) string {
	if !r.Enabled || text == "" {
		return text
	}
	lower := strings.ToLower(text)
	for _, p := range valuePatterns {
		if len(p.prefilters) > 0 {
			haystack := text
			if p.fold {
				haystack = lower
			}
			if !containsAny(haystack, p.prefilters) {
				continue
			}
		}
		before := text
		if p.group > 0 {
			text = r.replaceGroup(p.re, p.group, text)
		} else {
			text = p.re.ReplaceAllStringFunc(text, r.replacement)
		}
		if text != before {
			lower = strings.ToLower(text)
		}
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
