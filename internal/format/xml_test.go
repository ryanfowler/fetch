package format

import (
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFormatXML(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid simple xml",
			input:   "<root><child>text</child></root>",
			wantErr: false,
		},
		{
			name:    "valid nested xml",
			input:   "<a><b><c>text</c></b></a>",
			wantErr: false,
		},
		{
			name:    "valid xml with attributes",
			input:   `<root attr="value"><child id="1">text</child></root>`,
			wantErr: false,
		},
		{
			name:    "malformed xml extra closing tag at start",
			input:   "</foo><bar></bar>",
			wantErr: true, // XML decoder catches this
		},
		{
			name:    "malformed xml extra closing tag at end",
			input:   "<a></a></a>",
			wantErr: true, // XML decoder catches this
		},
		{
			name:    "malformed xml multiple extra closing tags",
			input:   "</x></y></z>",
			wantErr: true, // XML decoder catches this
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			err := FormatXML([]byte(tt.input), p)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormatXML() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormatXMLOutput(t *testing.T) {
	input := "<root><child>text</child></root>"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatXML([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatXML() error = %v", err)
	}

	output := string(p.Bytes())
	if !strings.Contains(output, "<root>") {
		t.Errorf("output should contain <root>, got: %s", output)
	}
	if !strings.Contains(output, "</root>") {
		t.Errorf("output should contain </root>, got: %s", output)
	}
	if !strings.Contains(output, "text") {
		t.Errorf("output should contain text, got: %s", output)
	}
}

func TestEscapeXMLString(t *testing.T) {
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
			name:  "with ampersand",
			input: "foo & bar",
			want:  "foo &amp; bar",
		},
		{
			name:  "with less than",
			input: "a < b",
			want:  "a &lt; b",
		},
		{
			name:  "with greater than",
			input: "a > b",
			want:  "a &gt; b",
		},
		{
			name:  "with quotes",
			input: `"quoted"`,
			want:  "&quot;quoted&quot;",
		},
		{
			name:  "with single quotes",
			input: "'quoted'",
			want:  "&apos;quoted&apos;",
		},
		{
			name:  "with tab",
			input: "a\tb",
			want:  "a&#x9;b",
		},
		{
			name:  "with newline",
			input: "a\nb",
			want:  "a&#xA;b",
		},
		{
			name:  "with carriage return",
			input: "a\rb",
			want:  "a&#xD;b",
		},
		{
			name:  "unicode chars",
			input: "日本語",
			want:  "日本語",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			escapeXMLString(p, tt.input)
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("escapeXMLString() = %q, want %q", got, tt.want)
			}
		})
	}
}
