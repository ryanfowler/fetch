package curl

import (
	"fmt"
	"strings"
)

// tokenize splits a shell command string into tokens, handling single quotes,
// double quotes, bash ANSI-C quotes ($'...'), backslash escaping, and line
// continuations with LF or CRLF.
func tokenize(s string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	hasContent := false

	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			if hasContent {
				tokens = append(tokens, current.String())
				current.Reset()
				hasContent = false
			}
			i++

		case '$':
			if i+1 < len(s) && s[i+1] == '"' {
				// bash $"..." is a locale-translated double-quoted string.
				// Without a translation, it is the same as "...".
				i++
				continue
			}
			if i+1 < len(s) && s[i+1] == '\'' {
				// ANSI-C quoting, which browsers use in "Copy as cURL"
				// for values with newlines or single quotes.
				decoded, next, err := decodeANSICQuoted(s, i+2)
				if err != nil {
					return nil, err
				}
				current.WriteString(decoded)
				i = next
				hasContent = true
				continue
			}
			current.WriteByte(c)
			i++
			hasContent = true

		case '\'':
			// Single-quoted string: everything is literal until closing quote.
			i++
			for i < len(s) && s[i] != '\'' {
				current.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated single quote")
			}
			i++ // skip closing quote
			hasContent = true

		case '"':
			// Double-quoted string: backslash escapes for ", \, $, `
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					next := s[i+1]
					switch next {
					case '"', '\\', '$', '`':
						current.WriteByte(next)
						i += 2
						continue
					}
				}
				current.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated double quote")
			}
			i++ // skip closing quote
			hasContent = true

		case '\\':
			if i+1 < len(s) {
				next := s[i+1]
				if next == '\n' {
					// Line continuation: skip backslash and newline.
					i += 2
				} else if next == '\r' && i+2 < len(s) && s[i+2] == '\n' {
					// Line continuation with a Windows line ending.
					i += 3
				} else {
					// Escape next character.
					current.WriteByte(next)
					i += 2
					hasContent = true
				}
			} else {
				// Trailing backslash.
				current.WriteByte(c)
				i++
				hasContent = true
			}

		default:
			current.WriteByte(c)
			i++
			hasContent = true
		}
	}

	if hasContent {
		tokens = append(tokens, current.String())
	}

	return tokens, nil
}

// decodeANSICQuoted decodes a bash $'...' string whose body starts at s[i],
// after the opening quote. It returns the decoded text and the index after
// the closing quote. As in bash, it first finds the closing quote, where a
// backslash skips the next byte, and then decodes the body.
func decodeANSICQuoted(s string, i int) (string, int, error) {
	end := i
	for end < len(s) && s[end] != '\'' {
		if s[end] == '\\' {
			end++
		}
		end++
	}
	if end >= len(s) {
		return "", 0, fmt.Errorf("unterminated $'...' quote")
	}
	decoded, err := decodeANSICBody(s[i:end])
	if err != nil {
		return "", 0, err
	}
	return decoded, end + 1, nil
}

// decodeANSICBody decodes the escapes that bash documents for $'...'.
func decodeANSICBody(body string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(body); {
		c := body[i]
		if c != '\\' || i+1 >= len(body) {
			out.WriteByte(c)
			i++
			continue
		}
		e := body[i+1]
		i += 2
		switch e {
		case 'a':
			out.WriteByte('\a')
		case 'b':
			out.WriteByte('\b')
		case 'e', 'E':
			out.WriteByte(0x1b)
		case 'f':
			out.WriteByte('\f')
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'v':
			out.WriteByte('\v')
		case '\\', '\'', '"', '?':
			out.WriteByte(e)
		case 'c':
			// \cX is the control character for X.
			if i >= len(body) {
				out.WriteString(`\c`)
				continue
			}
			x := body[i]
			i++
			switch x {
			case '?':
				out.WriteByte(0x7f)
			case '\\':
				out.WriteByte(0x1c)
				// bash reads \c\\ as one escape.
				if i < len(body) && body[i] == '\\' {
					i++
				}
			default:
				out.WriteByte(x & 0x1f)
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':
			// Up to three octal digits, including the first.
			value, n := parseDigits(body[i-1:], 8, 3)
			out.WriteByte(byte(value))
			i += n - 1
		case 'x':
			value, n := parseDigits(body[i:], 16, 2)
			if n == 0 {
				out.WriteString(`\x`)
				continue
			}
			out.WriteByte(byte(value))
			i += n
		case 'u', 'U':
			width := 4
			if e == 'U' {
				width = 8
			}
			value, n := parseDigits(body[i:], 16, width)
			if n == 0 {
				out.WriteByte('\\')
				out.WriteByte(e)
				continue
			}
			// An invalid code point, such as a surrogate, becomes U+FFFD,
			// so the result stays valid UTF-8. bash writes invalid bytes.
			out.WriteRune(rune(value))
			i += n
		default:
			// bash keeps an unknown escape as written.
			out.WriteByte('\\')
			out.WriteByte(e)
		}
	}
	decoded := out.String()
	if strings.IndexByte(decoded, 0) >= 0 {
		// bash ends the word at a NUL byte, which would drop the rest of
		// the value without a warning.
		return "", fmt.Errorf("$'...' quote contains a NUL byte, which a shell cannot pass to curl")
	}
	return decoded, nil
}

// parseDigits parses up to max digits of the given base at the start of s.
// It returns the value and the number of digits used.
func parseDigits(s string, base, max int) (uint32, int) {
	var value uint32
	n := 0
	for n < max && n < len(s) {
		d := digitValue(s[n])
		if d < 0 || d >= base {
			break
		}
		value = value*uint32(base) + uint32(d)
		n++
	}
	return value, n
}

func digitValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
