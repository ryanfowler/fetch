package format

import (
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFormatJSONLine(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple object",
			input: `{"key":"value"}`,
			want:  "{ \"key\": \"value\" }\n",
		},
		{
			name:  "nested object",
			input: `{"a":{"b":"c"}}`,
			want:  "{ \"a\": { \"b\": \"c\" } }\n",
		},
		{
			name:  "array",
			input: `[1,2,3]`,
			want:  "[1, 2, 3]\n",
		},
		{
			name:  "scalar string",
			input: `"hello"`,
			want:  "\"hello\"\n",
		},
		{
			name:  "scalar number",
			input: `42`,
			want:  "42\n",
		},
		{
			name:  "boolean true",
			input: `true`,
			want:  "true\n",
		},
		{
			name:  "null",
			input: `null`,
			want:  "null\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			err := FormatJSONLine([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("FormatJSONLine() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatJSONLineInvalid(t *testing.T) {
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatJSONLine([]byte(`{invalid`), p)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFormatJSONLineTrailingData(t *testing.T) {
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatJSONLine([]byte(`{} extra`), p)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
}
