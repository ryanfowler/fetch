package core

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// TerminalSafeText converts untrusted text into a representation that cannot
// inject terminal control sequences. Newlines and tabs are retained because
// they are useful diagnostic layout characters; all other C0/C1 controls and
// invalid UTF-8 are escaped.
func TerminalSafeText(s string) string {
	unsafe := firstUnsafeTerminalByte(s)
	if unsafe < 0 {
		return s
	}
	return escapeTerminalText(s, unsafe)
}

// validHyperlinkURL reports whether s can safely be placed inside an OSC 8
// hyperlink control sequence. Unlike ordinary terminal text, newlines and
// tabs are not retained here because they would become part of the control
// sequence rather than visible content.
func validHyperlinkURL(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || unicode.IsControl(r) {
			return false
		}
	}

	parsed, err := url.Parse(s)
	if err != nil {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "mailto":
		return true
	default:
		return false
	}
}

// firstUnsafeTerminalByte returns the byte offset of the first value that
// needs escaping, or -1 when s is already safe for terminal diagnostics. This
// keeps the common all-printable path allocation-free.
func firstUnsafeTerminalByte(s string) int {
	for i := 0; i < len(s); {
		if s[i] < utf8.RuneSelf {
			c := s[i]
			if c == '\n' || c == '\t' || (c >= 0x20 && c != 0x7f) {
				i++
				continue
			}
			return i
		}

		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		if (r >= 0x80 && r <= 0x9f) || unicode.IsControl(r) {
			return i
		}
		i += size
	}
	return -1
}

func escapeTerminalText(s string, firstUnsafe int) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	b.WriteString(s[:firstUnsafe])
	s = s[firstUnsafe:]

	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && size == 1 {
			writeEscapedByte(&b, s[0])
			s = s[1:]
			continue
		}
		s = s[size:]

		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || (r >= 0x7f && r <= 0x9f) || unicode.IsControl(r):
			writeEscapedRune(&b, r)
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}

func writeEscapedByte(b *strings.Builder, value byte) {
	fmt.Fprintf(b, `\x%02x`, value)
}

func writeEscapedRune(b *strings.Builder, value rune) {
	if value <= 0xff {
		fmt.Fprintf(b, `\x%02x`, value)
		return
	}
	fmt.Fprintf(b, `\u{%x}`, value)
}

const diagnosticRedactedValue = "%5BREDACTED%5D"

// RedactedURL returns a terminal-safe URL with userinfo and sensitive query
// values removed. URL userinfo and query values are authentication sources
// that must not appear in diagnostics.
func RedactedURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	copyURL := *u
	copyURL.User = nil
	if copyURL.Host == "" && copyURL.Scheme != "" {
		copyURL.Path = redactMalformedURLPath(copyURL.Path)
		copyURL.RawPath = ""
	}
	copyURL.RawQuery = RedactedQuery(copyURL.RawQuery)
	return TerminalSafeText(copyURL.String())
}

// RedactedErrorText returns a terminal-safe error message with URLs carried by
// url.Error values redacted. Transport errors commonly include the complete
// request URL in their Error string, so sanitizing only the request metadata
// is not sufficient.
func RedactedErrorText(err error) string {
	if err == nil {
		return ""
	}

	message := err.Error()
	for _, rawURL := range urlErrorURLs(err) {
		if rawURL == "" {
			continue
		}
		message = strings.ReplaceAll(message, rawURL, redactedURLString(rawURL))
	}
	return TerminalSafeText(message)
}

func redactedURLString(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err == nil {
		if malformedURLAuthority(rawURL) {
			return redactedMalformedURLString(rawURL)
		}
		return RedactedURL(u)
	}

	// url.Error can carry a URL string that is not parseable because of an
	// invalid escape in its query or path. Redact the authority and query
	// without requiring a successful URL parse in that case.
	base, query, hasQuery := strings.Cut(rawURL, "?")
	base = redactURLAuthority(base)
	redacted := base
	if !hasQuery {
		return TerminalSafeText(redacted)
	}

	query, fragment, hasFragment := strings.Cut(query, "#")
	redacted += "?" + RedactedQuery(query)
	if hasFragment {
		redacted += "#" + fragment
	}
	return TerminalSafeText(redacted)
}

func redactedMalformedURLString(rawURL string) string {
	base, query, hasQuery := strings.Cut(rawURL, "?")
	base = redactURLAuthority(base)
	redacted := base
	if !hasQuery {
		return TerminalSafeText(redacted)
	}

	query, fragment, hasFragment := strings.Cut(query, "#")
	redacted += "?" + RedactedQuery(query)
	if hasFragment {
		redacted += "#" + fragment
	}
	return TerminalSafeText(redacted)
}

func malformedURLAuthority(rawURL string) bool {
	schemeEnd := strings.IndexByte(rawURL, ':')
	if schemeEnd <= 0 {
		return false
	}
	rest := rawURL[schemeEnd+1:]
	if strings.HasPrefix(rest, "//") {
		return false
	}
	authorityStart := schemeEnd + 1
	if strings.HasPrefix(rest, "/") {
		authorityStart++
	}
	authorityEnd := len(rawURL)
	if end := strings.IndexAny(rawURL[authorityStart:], "/?#"); end >= 0 {
		authorityEnd = authorityStart + end
	}
	return strings.Contains(rawURL[authorityStart:authorityEnd], "@")
}

func redactMalformedURLPath(path string) string {
	start := 0
	if strings.HasPrefix(path, "/") {
		start++
	}
	end := len(path)
	if next := strings.IndexByte(path[start:], '/'); next >= 0 {
		end = start + next
	}
	segment := path[start:end]
	userinfoEnd := strings.LastIndexByte(segment, '@')
	if userinfoEnd < 0 {
		return path
	}
	return path[:start] + segment[userinfoEnd+1:] + path[end:]
}

// redactURLAuthority removes userinfo from a URL whose syntax is too malformed
// for net/url to parse. Transport diagnostics must not fall back to printing
// an untrusted authority verbatim because it may contain proxy credentials.
func redactURLAuthority(rawURL string) string {
	authorityStart := -1
	switch {
	case strings.HasPrefix(rawURL, "//"):
		authorityStart = 2
	default:
		schemeSeparator := strings.Index(rawURL, "://")
		if schemeSeparator >= 0 {
			authorityStart = schemeSeparator + len("://")
		} else if schemeSeparator = strings.IndexByte(rawURL, ':'); schemeSeparator >= 0 {
			authorityStart = schemeSeparator + 1
			if strings.HasPrefix(rawURL[authorityStart:], "/") {
				authorityStart++
			}
		}
	}
	if authorityStart < 0 {
		return rawURL
	}

	authorityEnd := len(rawURL)
	if end := strings.IndexAny(rawURL[authorityStart:], "/?#"); end >= 0 {
		authorityEnd = authorityStart + end
	}
	authority := rawURL[authorityStart:authorityEnd]
	if userinfoEnd := strings.LastIndexByte(authority, '@'); userinfoEnd >= 0 {
		return rawURL[:authorityStart] + authority[userinfoEnd+1:] + rawURL[authorityEnd:]
	}
	return rawURL
}

func urlErrorURLs(err error) []string {
	var urls []string
	var visit func(error)
	visit = func(current error) {
		if current == nil {
			return
		}
		switch current := current.(type) {
		case *url.Error:
			urls = append(urls, current.URL)
			visit(current.Err)
		case interface{ Unwrap() []error }:
			for _, child := range current.Unwrap() {
				visit(child)
			}
		case interface{ Unwrap() error }:
			visit(current.Unwrap())
		}
	}
	visit(err)
	return urls
}

// RedactedQuery returns a query string with values for sensitive keys
// replaced while preserving the original key spelling, ordering, duplicate
// fields, and non-sensitive encoding. The classifier intentionally errs on
// the side of hiding values when a key contains a credential-related term.
func RedactedQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	var b strings.Builder
	for i, field := range strings.Split(rawQuery, "&") {
		if i > 0 {
			b.WriteByte('&')
		}
		name, value, hasValue := strings.Cut(field, "=")
		b.WriteString(name)
		if !hasValue {
			continue
		}
		b.WriteByte('=')
		if IsSensitiveQueryKey(name) {
			b.WriteString(diagnosticRedactedValue)
		} else {
			b.WriteString(value)
		}
	}
	return b.String()
}

// IsSensitiveQueryKey reports whether a query key is likely to contain a
// credential. Matching is case-insensitive and covers compound names such as
// api_key, access_token, clientSecret, and request-signature.
func IsSensitiveQueryKey(name string) bool {
	if decoded, err := url.QueryUnescape(name); err == nil {
		name = decoded
	}
	name = strings.ToLower(name)
	for _, term := range []string{
		"key", "token", "secret", "password", "credential", "signature", "authorization", "session",
	} {
		if strings.Contains(name, term) {
			return true
		}
	}
	return false
}

// IsSensitiveHeader reports whether a header contains a credential or session
// value that must not be printed in diagnostics. In addition to the standard
// credential headers, a component-aware classifier covers user-defined names
// such as X-API-Key and X-ClientSecret without treating X-KeyboardLayout as a
// credential header merely because it contains the letters "key".
func IsSensitiveHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "cookie", "cookie2", "set-cookie",
		"www-authenticate", "proxy-authenticate", "x-amz-date",
		"x-amz-content-sha256", "x-amz-security-token", "x-amz-session-token",
		"x-client-id", "x-private-value":
		return true
	}

	var previous string
	for _, term := range diagnosticHeaderTerms(name) {
		if isDiagnosticCredentialTerm(term) {
			return true
		}
		if previous == "client" && term == "id" {
			return true
		}
		previous = term
	}
	return false
}

func isDiagnosticCredentialTerm(term string) bool {
	term = strings.ToLower(term)
	switch term {
	case "auth", "authenticate", "authentication", "authorization", "credential", "credentials",
		"token", "tokens", "key", "keys", "secret", "secrets", "password", "passwd",
		"signature", "signing", "private", "session", "sessions", "apikey", "accesskey", "authtoken", "clientid", "clientsecret", "privatekey":
		return true
	}
	for _, sensitive := range []string{
		"auth", "authenticate", "authorization", "credential", "token", "secret", "password", "passwd", "accesskey",
		"signature", "signing", "private", "session",
	} {
		if strings.Contains(term, sensitive) {
			return true
		}
	}
	return false
}

func diagnosticHeaderTerms(name string) []string {
	var terms []string
	for component := range strings.FieldsFuncSeq(name, func(r rune) bool {
		return !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}) {
		// Include the fully normalized component so compound names such as
		// X-aPiKey and X-rEqUeStSiGnAtUrE classify the same as their normally
		// cased forms. The camel-case terms below preserve component-aware
		// matching for names such as X-KeyboardLayout.
		terms = append(terms, strings.ToLower(component))
		start := 0
		for i := 1; i < len(component); i++ {
			if component[i] >= 'A' && component[i] <= 'Z' &&
				((component[i-1] >= 'a' && component[i-1] <= 'z') ||
					(i+1 < len(component) && component[i+1] >= 'a' && component[i+1] <= 'z')) {
				terms = append(terms, strings.ToLower(component[start:i]))
				start = i
			}
		}
		terms = append(terms, strings.ToLower(component[start:]))
	}
	return terms
}

// RedactHeaderValue replaces sensitive header values with a stable marker.
func RedactHeaderValue(name, value string) string {
	if strings.EqualFold(strings.TrimSpace(name), "Location") {
		_, err := url.Parse(value)
		if err != nil {
			return "[invalid redirect location]"
		}
		return redactedURLString(value)
	}
	if IsSensitiveHeader(name) {
		return "[REDACTED]"
	}
	return TerminalSafeText(value)
}

// IsBrokenPipe reports whether an output operation failed because its reader
// closed the pipe. Callers should treat this as successful early termination.
func IsBrokenPipe(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, io.ErrClosedPipe) ||
		strings.Contains(message, "broken pipe") ||
		strings.Contains(message, "pipe has been ended")
}
