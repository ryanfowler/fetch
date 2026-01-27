package format

import (
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFormatHTML(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid simple html",
			input:   "<html><body>text</body></html>",
			wantErr: false,
		},
		{
			name:    "valid nested html",
			input:   "<html><head><title>test</title></head><body><div>content</div></body></html>",
			wantErr: false,
		},
		{
			name:    "valid html with attributes",
			input:   `<div class="container" id="main"><p>text</p></div>`,
			wantErr: false,
		},
		{
			name:    "void elements br",
			input:   "<p>line1<br>line2</p>",
			wantErr: false,
		},
		{
			name:    "void elements img",
			input:   `<img src="test.jpg" alt="test">`,
			wantErr: false,
		},
		{
			name:    "void elements input",
			input:   `<input type="text" name="field">`,
			wantErr: false,
		},
		{
			name:    "self-closing syntax",
			input:   "<br/>",
			wantErr: false,
		},
		{
			name:    "doctype",
			input:   "<!DOCTYPE html><html></html>",
			wantErr: false,
		},
		{
			name:    "comment",
			input:   "<!-- this is a comment --><div>content</div>",
			wantErr: false,
		},
		{
			name:    "script content preservation",
			input:   `<script>var x = "<p>not html</p>";</script>`,
			wantErr: false,
		},
		{
			name:    "style content preservation",
			input:   `<style>.class { content: "<div>"; }</style>`,
			wantErr: false,
		},
		{
			name:    "pre whitespace preservation",
			input:   "<pre>  line1\n  line2</pre>",
			wantErr: false,
		},
		{
			name:    "textarea whitespace preservation",
			input:   "<textarea>  some text\n  more text</textarea>",
			wantErr: false,
		},
		{
			name:    "malformed html unclosed tag",
			input:   "<div><p>unclosed",
			wantErr: false, // HTML tokenizer handles malformed HTML gracefully
		},
		{
			name:    "malformed html mismatched tags",
			input:   "<div><span></div></span>",
			wantErr: false, // HTML tokenizer handles malformed HTML gracefully
		},
		{
			name:    "boolean attributes",
			input:   `<input type="checkbox" checked disabled>`,
			wantErr: false,
		},
		{
			name:    "multiple attributes",
			input:   `<a href="http://example.com" target="_blank" rel="noopener">link</a>`,
			wantErr: false,
		},
		{
			name:    "inline elements",
			input:   "<p>Text with <strong>bold</strong> and <em>italic</em></p>",
			wantErr: false,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			err := FormatHTML([]byte(tt.input), p)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormatHTML() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormatHTMLOutput(t *testing.T) {
	input := "<html><body><p>text</p></body></html>"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatHTML([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatHTML() error = %v", err)
	}

	output := string(p.Bytes())
	if !strings.Contains(output, "<html>") {
		t.Errorf("output should contain <html>, got: %s", output)
	}
	if !strings.Contains(output, "</html>") {
		t.Errorf("output should contain </html>, got: %s", output)
	}
	if !strings.Contains(output, "text") {
		t.Errorf("output should contain text, got: %s", output)
	}
}

func TestFormatHTMLIndentation(t *testing.T) {
	input := "<html><head><title>Test</title></head><body><div><p>content</p></div></body></html>"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatHTML([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatHTML() error = %v", err)
	}

	output := string(p.Bytes())

	// Check that block elements start on new lines with proper indentation.
	lines := strings.Split(output, "\n")
	foundIndentedDiv := false
	for _, line := range lines {
		if strings.Contains(line, "<div>") && strings.HasPrefix(line, "    ") {
			foundIndentedDiv = true
			break
		}
	}
	if !foundIndentedDiv {
		t.Errorf("expected indented <div>, got output:\n%s", output)
	}
}

func TestFormatHTMLDoctype(t *testing.T) {
	input := "<!DOCTYPE html><html><body></body></html>"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatHTML([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatHTML() error = %v", err)
	}

	output := string(p.Bytes())
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Errorf("output should contain <!DOCTYPE html>, got: %s", output)
	}
}

func TestFormatHTMLComment(t *testing.T) {
	input := "<!-- test comment --><div>content</div>"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatHTML([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatHTML() error = %v", err)
	}

	output := string(p.Bytes())
	if !strings.Contains(output, "<!-- test comment -->") {
		t.Errorf("output should contain comment, got: %s", output)
	}
}

func TestFormatHTMLVoidElements(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check string
	}{
		{
			name:  "br element",
			input: "<p>line1<br>line2</p>",
			check: "<br>",
		},
		{
			name:  "hr element",
			input: "<div><hr></div>",
			check: "<hr>",
		},
		{
			name:  "img element",
			input: `<img src="test.jpg">`,
			check: `<img src="test.jpg">`,
		},
		{
			name:  "input element",
			input: `<input type="text">`,
			check: `<input type="text">`,
		},
		{
			name:  "meta element",
			input: `<meta charset="utf-8">`,
			check: `<meta charset="utf-8">`,
		},
		{
			name:  "link element",
			input: `<link rel="stylesheet" href="style.css">`,
			check: `<link rel="stylesheet" href="style.css">`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			err := FormatHTML([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatHTML() error = %v", err)
			}

			output := string(p.Bytes())
			if !strings.Contains(output, tt.check) {
				t.Errorf("output should contain %q, got: %s", tt.check, output)
			}
			// Void elements should not have closing tags.
			tagName := strings.Split(strings.TrimPrefix(tt.check, "<"), " ")[0]
			tagName = strings.TrimSuffix(tagName, ">")
			closingTag := "</" + tagName + ">"
			if strings.Contains(output, closingTag) {
				t.Errorf("output should not contain closing tag %s for void element, got: %s", closingTag, output)
			}
		})
	}
}

func TestFormatHTMLPreservesRawText(t *testing.T) {
	input := `<script>if (x < 5 && y > 3) { alert("<test>"); }</script>`
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatHTML([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatHTML() error = %v", err)
	}

	output := string(p.Bytes())
	// The raw content should be preserved.
	if !strings.Contains(output, `if (x < 5 && y > 3)`) {
		t.Errorf("script content should be preserved, got: %s", output)
	}
}

func TestFormatHTMLPreservesPreWhitespace(t *testing.T) {
	input := "<pre>  line1\n    line2</pre>"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatHTML([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatHTML() error = %v", err)
	}

	output := string(p.Bytes())
	// The whitespace should be preserved.
	if !strings.Contains(output, "  line1") {
		t.Errorf("pre whitespace should be preserved, got: %s", output)
	}
	if !strings.Contains(output, "    line2") {
		t.Errorf("pre whitespace should be preserved, got: %s", output)
	}
}

func TestFormatHTMLPlanExample(t *testing.T) {
	input := `<!DOCTYPE html><html><head><title>Test</title></head><body><div class="container"><h1>Hello</h1><p>Text with <strong>bold</strong></p><br><img src="x.jpg"></div></body></html>`
	expected := `<!DOCTYPE html>
<html>
  <head>
    <title>Test</title>
  </head>
  <body>
    <div class="container">
      <h1>Hello</h1>
      <p>Text with <strong>bold</strong></p>
      <br>
      <img src="x.jpg">
    </div>
  </body>
</html>
`
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatHTML([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatHTML() error = %v", err)
	}

	output := string(p.Bytes())
	if output != expected {
		t.Errorf("FormatHTML() output mismatch.\nGot:\n%s\nExpected:\n%s", output, expected)
	}
}

func TestFormatHTMLEmbeddedCSS(t *testing.T) {
	t.Run("basic embedded CSS", func(t *testing.T) {
		input := `<style>body{color:red}</style>`
		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatHTML([]byte(input), p)
		if err != nil {
			t.Fatalf("FormatHTML() error = %v", err)
		}

		output := string(p.Bytes())
		// Should contain formatted CSS with body selector and color property.
		if !strings.Contains(output, "body") {
			t.Errorf("output should contain 'body', got: %s", output)
		}
		if !strings.Contains(output, "color") {
			t.Errorf("output should contain 'color', got: %s", output)
		}
		if !strings.Contains(output, "red") {
			t.Errorf("output should contain 'red', got: %s", output)
		}
	})

	t.Run("nested HTML with style", func(t *testing.T) {
		input := `<html><head><style>.a{margin:0}</style></head></html>`
		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatHTML([]byte(input), p)
		if err != nil {
			t.Fatalf("FormatHTML() error = %v", err)
		}

		output := string(p.Bytes())
		// Should contain formatted CSS.
		if !strings.Contains(output, ".a") {
			t.Errorf("output should contain '.a', got: %s", output)
		}
		if !strings.Contains(output, "margin") {
			t.Errorf("output should contain 'margin', got: %s", output)
		}
	})

	t.Run("empty style tag", func(t *testing.T) {
		input := `<style></style>`
		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatHTML([]byte(input), p)
		if err != nil {
			t.Fatalf("FormatHTML() error = %v", err)
		}

		output := string(p.Bytes())
		// Should just have the style tags.
		if !strings.Contains(output, "<style>") {
			t.Errorf("output should contain '<style>', got: %s", output)
		}
		if !strings.Contains(output, "</style>") {
			t.Errorf("output should contain '</style>', got: %s", output)
		}
	})

	t.Run("whitespace-only style", func(t *testing.T) {
		input := `<style>
   </style>`
		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatHTML([]byte(input), p)
		if err != nil {
			t.Fatalf("FormatHTML() error = %v", err)
		}

		output := string(p.Bytes())
		// Should contain style tags but no CSS content other than newlines.
		if !strings.Contains(output, "<style>") {
			t.Errorf("output should contain '<style>', got: %s", output)
		}
	})

	t.Run("script tag unchanged", func(t *testing.T) {
		input := `<script>var x = 1;</script>`
		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatHTML([]byte(input), p)
		if err != nil {
			t.Fatalf("FormatHTML() error = %v", err)
		}

		output := string(p.Bytes())
		// Script content should be preserved as-is.
		if !strings.Contains(output, "var x = 1;") {
			t.Errorf("script content should be preserved, got: %s", output)
		}
	})

	t.Run("multiple style tags", func(t *testing.T) {
		input := `<style>.a{}</style><style>.b{}</style>`
		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatHTML([]byte(input), p)
		if err != nil {
			t.Fatalf("FormatHTML() error = %v", err)
		}

		output := string(p.Bytes())
		// Both should be formatted.
		if !strings.Contains(output, ".a") {
			t.Errorf("output should contain '.a', got: %s", output)
		}
		if !strings.Contains(output, ".b") {
			t.Errorf("output should contain '.b', got: %s", output)
		}
	})

	t.Run("complex CSS in nested HTML", func(t *testing.T) {
		input := `<html><head><style>body{color:red;margin:0}.container{display:flex}</style></head></html>`
		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatHTML([]byte(input), p)
		if err != nil {
			t.Fatalf("FormatHTML() error = %v", err)
		}

		output := string(p.Bytes())
		// Should contain formatted CSS with multiple rules.
		if !strings.Contains(output, "body") {
			t.Errorf("output should contain 'body', got: %s", output)
		}
		if !strings.Contains(output, ".container") {
			t.Errorf("output should contain '.container', got: %s", output)
		}
		if !strings.Contains(output, "display") {
			t.Errorf("output should contain 'display', got: %s", output)
		}
		if !strings.Contains(output, "flex") {
			t.Errorf("output should contain 'flex', got: %s", output)
		}
	})
}

func TestEscapeHTMLAttrValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no escape needed",
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
			input: `say "hello"`,
			want:  "say &quot;hello&quot;",
		},
		{
			name:  "mixed special chars",
			input: `<script>"alert('&')"</script>`,
			want:  "&lt;script&gt;&quot;alert('&amp;')&quot;&lt;/script&gt;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			escapeHTMLAttrValue(p, tt.input)
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("escapeHTMLAttrValue() = %q, want %q", got, tt.want)
			}
		})
	}
}
