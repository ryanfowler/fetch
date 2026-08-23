package format

import (
	"errors"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFormatJSONLimitsNestingDepth(t *testing.T) {
	input := strings.Repeat("[", core.MaxFormatterNestingDepth+1) + "0" + strings.Repeat("]", core.MaxFormatterNestingDepth+1)
	p := core.TestPrinter(false)

	err := FormatJSON([]byte(input), p)
	if !errors.Is(err, core.ErrLimitExceeded) {
		t.Fatalf("FormatJSON() error = %v, want nesting limit error", err)
	}
	if got := len(p.Bytes()); got != 0 {
		t.Fatalf("FormatJSON() wrote %d bytes after nesting limit", got)
	}
}

func TestEscapeJSONString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "ascii no escape needed",
			input: "hello world",
			want:  "hello world",
		},
		{
			name:  "with backspace",
			input: "a\bb",
			want:  `a\bb`,
		},
		{
			name:  "with form feed",
			input: "a\fb",
			want:  `a\fb`,
		},
		{
			name:  "with newline",
			input: "a\nb",
			want:  `a\nb`,
		},
		{
			name:  "with carriage return",
			input: "a\rb",
			want:  `a\rb`,
		},
		{
			name:  "with tab",
			input: "a\tb",
			want:  `a\tb`,
		},
		{
			name:  "with double quote",
			input: `a"b`,
			want:  `a\"b`,
		},
		{
			name:  "with backslash",
			input: `a\b`,
			want:  `a\\b`,
		},
		{
			name:  "null character",
			input: "a\x00b",
			want:  `a\u0000b`,
		},
		{
			name:  "SOH control character",
			input: "a\x01b",
			want:  `a\u0001b`,
		},
		{
			name:  "escape character",
			input: "a\x1bb",
			want:  `a\u001bb`,
		},
		{
			name:  "unit separator",
			input: "a\x1fb",
			want:  `a\u001fb`,
		},
		{
			name:  "DEL character",
			input: "a\x7fb",
			want:  `a\u007fb`,
		},
		{
			name:  "space is not escaped",
			input: "a b",
			want:  "a b",
		},
		{
			name:  "printable ASCII not escaped",
			input: "abc123!@#",
			want:  "abc123!@#",
		},
		{
			name:  "unicode chars",
			input: "日本語",
			want:  "日本語",
		},
		{
			name:  "multiple control characters",
			input: "\x01\x02\x03",
			want:  `\u0001\u0002\u0003`,
		},
		{
			name:  "C1 control character",
			input: "\u0085",
			want:  `\u0085`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			escapeJSONString(p, tt.input)
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("escapeJSONString() = %q, want %q", got, tt.want)
			}
		})
	}
}
