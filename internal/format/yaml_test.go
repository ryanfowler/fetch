package format

import (
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFormatYAML(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "empty input",
			input:   "",
			wantErr: false,
		},
		{
			name:    "null scalar",
			input:   "null\n",
			wantErr: false,
		},
		{
			name:    "boolean true",
			input:   "true\n",
			wantErr: false,
		},
		{
			name:    "boolean false",
			input:   "false\n",
			wantErr: false,
		},
		{
			name:    "integer",
			input:   "42\n",
			wantErr: false,
		},
		{
			name:    "float",
			input:   "3.14\n",
			wantErr: false,
		},
		{
			name:    "simple string",
			input:   "hello\n",
			wantErr: false,
		},
		{
			name:    "simple mapping",
			input:   "key: value\n",
			wantErr: false,
		},
		{
			name:    "nested mapping",
			input:   "parent:\n  child: value\n",
			wantErr: false,
		},
		{
			name:    "sequence",
			input:   "- one\n- two\n- three\n",
			wantErr: false,
		},
		{
			name:    "mapping with sequence",
			input:   "items:\n  - first\n  - second\n",
			wantErr: false,
		},
		{
			name:    "flow mapping",
			input:   "{a: 1, b: 2}\n",
			wantErr: false,
		},
		{
			name:    "flow sequence",
			input:   "[1, 2, 3]\n",
			wantErr: false,
		},
		{
			name:    "comment",
			input:   "# this is a comment\nkey: value\n",
			wantErr: false,
		},
		{
			name:    "inline comment",
			input:   "key: value # inline\n",
			wantErr: false,
		},
		{
			name:    "multi-document",
			input:   "---\na: 1\n---\nb: 2\n...\n",
			wantErr: false,
		},
		{
			name:    "anchor and alias",
			input:   "defaults: &defaults\n  color: red\nitem:\n  <<: *defaults\n",
			wantErr: false,
		},
		{
			name:    "tag",
			input:   "value: !!str 123\n",
			wantErr: false,
		},
		{
			name:    "block literal scalar",
			input:   "text: |\n  line one\n  line two\n",
			wantErr: false,
		},
		{
			name:    "block folded scalar",
			input:   "text: >\n  line one\n  line two\n",
			wantErr: false,
		},
		{
			name:    "unicode values",
			input:   "name: 日本語\n",
			wantErr: false,
		},
		{
			name:    "double quoted string",
			input:   "key: \"hello world\"\n",
			wantErr: false,
		},
		{
			name:    "single quoted string",
			input:   "key: 'hello world'\n",
			wantErr: false,
		},
		{
			name:    "complex nested",
			input:   "server:\n  host: localhost\n  port: 8080\n  features:\n    - auth\n    - logging\n",
			wantErr: false,
		},
		{
			name:    "merge key",
			input:   "base: &base\n  x: 1\nderived:\n  <<: *base\n  y: 2\n",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			err := FormatYAML([]byte(tt.input), p)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormatYAML() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormatYAMLOutput(t *testing.T) {
	input := "name: John\nage: 30\nitems:\n  - one\n  - two\n"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatYAML([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatYAML() error = %v", err)
	}

	output := string(p.Bytes())
	for _, want := range []string{"name", "John", "age", "30", "one", "two"} {
		if !strings.Contains(output, want) {
			t.Errorf("output should contain %q, got: %s", want, output)
		}
	}
}

func TestFormatYAMLPreservesStructure(t *testing.T) {
	inputs := []string{
		"key: value",
		"a: 1\nb: 2",
		"items:\n  - one\n  - two",
		"nested:\n  child:\n    value: hello",
	}

	for _, input := range inputs {
		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatYAML([]byte(input), p)
		if err != nil {
			t.Fatalf("FormatYAML(%q) error = %v", input, err)
		}

		output := string(p.Bytes())
		if output != input {
			t.Errorf("FormatYAML(%q) = %q, want original preserved", input, output)
		}
	}
}
