package core

import (
	"errors"
	"fmt"
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

// RedactedURL returns a terminal-safe URL with userinfo removed. URL
// userinfo is an authentication source and must not appear in diagnostics.
func RedactedURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	copyURL := *u
	copyURL.User = nil
	return TerminalSafeText(copyURL.String())
}

// IsSensitiveHeader reports whether a header contains a credential or session
// value that must not be printed in diagnostics.
func IsSensitiveHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie",
		"x-amz-security-token", "x-amz-session-token":
		return true
	default:
		return false
	}
}

// RedactHeaderValue replaces sensitive header values with a stable marker.
func RedactHeaderValue(name, value string) string {
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
	return errors.Is(err, syscall.EPIPE) || strings.Contains(strings.ToLower(err.Error()), "broken pipe")
}
