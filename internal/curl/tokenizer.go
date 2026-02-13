package curl

import (
	"fmt"
	"strings"
)

// tokenize splits a shell command string into tokens, handling single quotes,
// double quotes, backslash escaping, and line continuations.
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
