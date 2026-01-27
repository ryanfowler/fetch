package format

import (
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFormatCSS(t *testing.T) {
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
			name:    "simple rule",
			input:   "body { color: red; }",
			wantErr: false,
		},
		{
			name:    "minified CSS",
			input:   "body{color:red;margin:0}.container{display:flex}",
			wantErr: false,
		},
		{
			name:    "multiple declarations",
			input:   "div { color: red; font-size: 14px; margin: 10px; }",
			wantErr: false,
		},
		{
			name:    "class selector",
			input:   ".container { width: 100%; }",
			wantErr: false,
		},
		{
			name:    "id selector",
			input:   "#header { height: 60px; }",
			wantErr: false,
		},
		{
			name:    "descendant combinator",
			input:   "div p { color: blue; }",
			wantErr: false,
		},
		{
			name:    "child combinator",
			input:   "div > p { color: green; }",
			wantErr: false,
		},
		{
			name:    "adjacent sibling combinator",
			input:   "h1 + p { margin-top: 0; }",
			wantErr: false,
		},
		{
			name:    "general sibling combinator",
			input:   "h1 ~ p { color: gray; }",
			wantErr: false,
		},
		{
			name:    "attribute selector",
			input:   `input[type="text"] { border: 1px solid black; }`,
			wantErr: false,
		},
		{
			name:    "pseudo-class",
			input:   "a:hover { color: red; }",
			wantErr: false,
		},
		{
			name:    "pseudo-element",
			input:   "p::first-line { font-weight: bold; }",
			wantErr: false,
		},
		{
			name:    "complex selector",
			input:   "div.container > p.intro:first-child { color: blue; }",
			wantErr: false,
		},
		{
			name:    "@import",
			input:   `@import url("style.css");`,
			wantErr: false,
		},
		{
			name:    "@charset",
			input:   `@charset "UTF-8";`,
			wantErr: false,
		},
		{
			name:    "@media",
			input:   "@media screen and (min-width: 768px) { .container { width: 750px; } }",
			wantErr: false,
		},
		{
			name:    "@keyframes",
			input:   "@keyframes slide { from { left: 0; } to { left: 100px; } }",
			wantErr: false,
		},
		{
			name:    "@font-face",
			input:   `@font-face { font-family: "MyFont"; src: url("font.woff2"); }`,
			wantErr: false,
		},
		{
			name:    "comment",
			input:   "/* This is a comment */ body { color: red; }",
			wantErr: false,
		},
		{
			name:    "multiline comment",
			input:   "/* Multi\nline\ncomment */ div { margin: 0; }",
			wantErr: false,
		},
		{
			name:    "color hex",
			input:   "div { color: #ff0000; }",
			wantErr: false,
		},
		{
			name:    "color rgb",
			input:   "div { color: rgb(255, 0, 0); }",
			wantErr: false,
		},
		{
			name:    "color rgba",
			input:   "div { background: rgba(0, 0, 0, 0.5); }",
			wantErr: false,
		},
		{
			name:    "color hsl",
			input:   "div { color: hsl(120, 100%, 50%); }",
			wantErr: false,
		},
		{
			name:    "calc function",
			input:   "div { width: calc(100% - 20px); }",
			wantErr: false,
		},
		{
			name:    "var function",
			input:   "div { color: var(--main-color); }",
			wantErr: false,
		},
		{
			name:    "url function",
			input:   "div { background: url(image.png); }",
			wantErr: false,
		},
		{
			name:    "url function quoted",
			input:   `div { background: url("image.png"); }`,
			wantErr: false,
		},
		{
			name:    "dimensions",
			input:   "div { width: 100px; height: 50%; margin: 1em; padding: 2rem; }",
			wantErr: false,
		},
		{
			name:    "important",
			input:   "div { color: red !important; }",
			wantErr: false,
		},
		{
			name:    "vendor prefix",
			input:   "div { -webkit-transform: rotate(45deg); }",
			wantErr: false,
		},
		{
			name:    "custom property",
			input:   ":root { --main-color: #06c; }",
			wantErr: false,
		},
		{
			name:    "missing semicolon",
			input:   "div { color: red }",
			wantErr: false,
		},
		{
			name:    "multiple selectors",
			input:   "h1, h2, h3 { font-weight: bold; }",
			wantErr: false,
		},
		{
			name:    "nested media query",
			input:   "@media print { @page { margin: 1cm; } body { font-size: 12pt; } }",
			wantErr: false,
		},
		{
			name:    "universal selector",
			input:   "* { box-sizing: border-box; }",
			wantErr: false,
		},
		{
			name:    "not pseudo-class",
			input:   "p:not(.special) { color: gray; }",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			err := FormatCSS([]byte(tt.input), p)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormatCSS() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormatCSSOutput(t *testing.T) {
	input := "body{color:red;margin:0}.container{display:flex}"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSS([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSS() error = %v", err)
	}

	output := string(p.Bytes())
	// Check that all values are present
	for _, want := range []string{"body", "color", "red", "margin", "0", "container", "display", "flex"} {
		if !strings.Contains(output, want) {
			t.Errorf("output should contain %q, got: %s", want, output)
		}
	}
	// Check for proper formatting (braces on separate lines)
	if !strings.Contains(output, "{\n") {
		t.Errorf("output should have opening braces followed by newline, got: %s", output)
	}
	if !strings.Contains(output, "}\n") {
		t.Errorf("output should have closing braces followed by newline, got: %s", output)
	}
}

func TestFormatCSSIndentation(t *testing.T) {
	input := "body{color:red}"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSS([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSS() error = %v", err)
	}

	output := string(p.Bytes())
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")

	// Expect:
	// body {
	//   color: red;
	// }
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), output)
	}

	if !strings.HasPrefix(lines[0], "body") {
		t.Errorf("first line should start with 'body', got: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "  ") {
		t.Errorf("second line should be indented, got: %q", lines[1])
	}
	if lines[2] != "}" {
		t.Errorf("third line should be '}', got: %q", lines[2])
	}
}

func TestFormatCSSMediaQuery(t *testing.T) {
	input := "@media(min-width:768px){.container{width:750px}}"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSS([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSS() error = %v", err)
	}

	output := string(p.Bytes())
	// Should have @media at the start
	if !strings.HasPrefix(output, "@media") {
		t.Errorf("output should start with '@media', got: %s", output)
	}
	// Should contain the nested selector
	if !strings.Contains(output, ".container") {
		t.Errorf("output should contain '.container', got: %s", output)
	}
	// Should have nested indentation
	if !strings.Contains(output, "    width") {
		t.Errorf("output should have nested indentation for property, got: %s", output)
	}
}

func TestFormatCSSComment(t *testing.T) {
	input := "/* comment */ body { color: red; }"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSS([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSS() error = %v", err)
	}

	output := string(p.Bytes())
	if !strings.Contains(output, "/* comment */") {
		t.Errorf("output should preserve comment, got: %s", output)
	}
}

func TestFormatCSSEmpty(t *testing.T) {
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSS([]byte(""), p)
	if err != nil {
		t.Fatalf("FormatCSS() error = %v", err)
	}
	if len(p.Bytes()) != 0 {
		t.Errorf("expected empty output for empty input, got: %q", string(p.Bytes()))
	}
}

func TestCSSTokenizer(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantTypes []cssTokenType
	}{
		{
			name:      "empty",
			input:     "",
			wantTypes: []cssTokenType{cssTokenEOF},
		},
		{
			name:      "identifier",
			input:     "body",
			wantTypes: []cssTokenType{cssTokenIdent, cssTokenEOF},
		},
		{
			name:      "hash",
			input:     "#id",
			wantTypes: []cssTokenType{cssTokenHash, cssTokenEOF},
		},
		{
			name:      "at-keyword",
			input:     "@media",
			wantTypes: []cssTokenType{cssTokenAtKeyword, cssTokenEOF},
		},
		{
			name:      "string double quote",
			input:     `"hello"`,
			wantTypes: []cssTokenType{cssTokenString, cssTokenEOF},
		},
		{
			name:      "string single quote",
			input:     `'hello'`,
			wantTypes: []cssTokenType{cssTokenString, cssTokenEOF},
		},
		{
			name:      "number",
			input:     "123",
			wantTypes: []cssTokenType{cssTokenNumber, cssTokenEOF},
		},
		{
			name:      "dimension",
			input:     "10px",
			wantTypes: []cssTokenType{cssTokenDimension, cssTokenEOF},
		},
		{
			name:      "percentage",
			input:     "50%",
			wantTypes: []cssTokenType{cssTokenDimension, cssTokenEOF},
		},
		{
			name:      "function",
			input:     "calc(",
			wantTypes: []cssTokenType{cssTokenFunction, cssTokenEOF},
		},
		{
			name:      "comment",
			input:     "/* comment */",
			wantTypes: []cssTokenType{cssTokenComment, cssTokenEOF},
		},
		{
			name:      "delimiters",
			input:     "{}:;",
			wantTypes: []cssTokenType{cssTokenDelim, cssTokenDelim, cssTokenDelim, cssTokenDelim, cssTokenEOF},
		},
		{
			name:      "whitespace",
			input:     "  \t\n",
			wantTypes: []cssTokenType{cssTokenWhitespace, cssTokenEOF},
		},
		{
			name:      "simple rule",
			input:     "body { color: red; }",
			wantTypes: []cssTokenType{cssTokenIdent, cssTokenWhitespace, cssTokenDelim, cssTokenWhitespace, cssTokenIdent, cssTokenDelim, cssTokenWhitespace, cssTokenIdent, cssTokenDelim, cssTokenWhitespace, cssTokenDelim, cssTokenEOF},
		},
		{
			name:      "custom property",
			input:     "--main-color",
			wantTypes: []cssTokenType{cssTokenIdent, cssTokenEOF},
		},
		{
			name:      "negative number",
			input:     "-10px",
			wantTypes: []cssTokenType{cssTokenDimension, cssTokenEOF},
		},
		{
			name:      "decimal number",
			input:     "1.5em",
			wantTypes: []cssTokenType{cssTokenDimension, cssTokenEOF},
		},
		{
			name:      "vendor prefix",
			input:     "-webkit-transform",
			wantTypes: []cssTokenType{cssTokenIdent, cssTokenEOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := newCSSTokenizer([]byte(tt.input))
			var gotTypes []cssTokenType

			for {
				token := tok.next()
				gotTypes = append(gotTypes, token.typ)
				if token.typ == cssTokenEOF {
					break
				}
			}

			if len(gotTypes) != len(tt.wantTypes) {
				t.Fatalf("got %d tokens, want %d tokens\ngot: %v\nwant: %v", len(gotTypes), len(tt.wantTypes), gotTypes, tt.wantTypes)
			}

			for i, got := range gotTypes {
				if got != tt.wantTypes[i] {
					t.Errorf("token %d: got type %v, want %v", i, got, tt.wantTypes[i])
				}
			}
		})
	}
}

func TestCSSTokenizerValues(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValue string
	}{
		{
			name:      "identifier",
			input:     "body",
			wantValue: "body",
		},
		{
			name:      "hash",
			input:     "#header",
			wantValue: "#header",
		},
		{
			name:      "at-keyword",
			input:     "@media",
			wantValue: "@media",
		},
		{
			name:      "string",
			input:     `"hello world"`,
			wantValue: `"hello world"`,
		},
		{
			name:      "string with escape",
			input:     `"hello\"world"`,
			wantValue: `"hello\"world"`,
		},
		{
			name:      "dimension",
			input:     "10px",
			wantValue: "10px",
		},
		{
			name:      "comment",
			input:     "/* test */",
			wantValue: "/* test */",
		},
		{
			name:      "function",
			input:     "rgba(",
			wantValue: "rgba(",
		},
		{
			name:      "custom property",
			input:     "--color",
			wantValue: "--color",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := newCSSTokenizer([]byte(tt.input))
			token := tok.next()
			if token.value != tt.wantValue {
				t.Errorf("got value %q, want %q", token.value, tt.wantValue)
			}
		})
	}
}

func TestFormatCSSKeyframes(t *testing.T) {
	input := "@keyframes fadeIn { 0% { opacity: 0; } 100% { opacity: 1; } }"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSS([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSS() error = %v", err)
	}

	output := string(p.Bytes())
	if !strings.Contains(output, "@keyframes") {
		t.Errorf("output should contain '@keyframes', got: %s", output)
	}
	if !strings.Contains(output, "0%") {
		t.Errorf("output should contain '0%%', got: %s", output)
	}
	if !strings.Contains(output, "100%") {
		t.Errorf("output should contain '100%%', got: %s", output)
	}
	if !strings.Contains(output, "opacity") {
		t.Errorf("output should contain 'opacity', got: %s", output)
	}
}

func TestFormatCSSComplexSelector(t *testing.T) {
	input := "div.container > ul.nav li.item:hover a { color: blue; }"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSS([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSS() error = %v", err)
	}

	output := string(p.Bytes())
	for _, want := range []string{"div", ".container", ">", "ul", ".nav", "li", ".item", ":hover", "a"} {
		if !strings.Contains(output, want) {
			t.Errorf("output should contain %q, got: %s", want, output)
		}
	}
}

func TestFormatCSSFontFace(t *testing.T) {
	input := `@font-face { font-family: "Open Sans"; src: url("opensans.woff2") format("woff2"); font-weight: 400; }`
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSS([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSS() error = %v", err)
	}

	output := string(p.Bytes())
	if !strings.Contains(output, "@font-face") {
		t.Errorf("output should contain '@font-face', got: %s", output)
	}
	if !strings.Contains(output, "font-family") {
		t.Errorf("output should contain 'font-family', got: %s", output)
	}
	if !strings.Contains(output, "Open Sans") {
		t.Errorf("output should contain 'Open Sans', got: %s", output)
	}
}

func TestFormatCSSCalc(t *testing.T) {
	input := "div { width: calc(100% - 20px); height: calc(50vh + 10px); }"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSS([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSS() error = %v", err)
	}

	output := string(p.Bytes())
	if !strings.Contains(output, "calc(") {
		t.Errorf("output should contain 'calc(', got: %s", output)
	}
	if !strings.Contains(output, "100%") {
		t.Errorf("output should contain '100%%', got: %s", output)
	}
}

func TestFormatCSSBlankLinesBetweenRules(t *testing.T) {
	input := ".a{color:red}.b{color:blue}"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSS([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSS() error = %v", err)
	}

	output := string(p.Bytes())
	// Should have blank line between rules (}\n\n.)
	if !strings.Contains(output, "}\n\n.") {
		t.Errorf("output should have blank line between rules, got: %q", output)
	}
}

func TestFormatCSSTrailingNewline(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"single rule", "body{color:red}"},
		{"multiple rules", ".a{color:red}.b{color:blue}"},
		{"with media query", "@media screen{.a{color:red}}"},
		{"with import", `@import url("style.css");`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			err := FormatCSS([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatCSS() error = %v", err)
			}

			output := string(p.Bytes())
			// Should end with exactly one newline
			if !strings.HasSuffix(output, "\n") {
				t.Errorf("output should end with newline, got: %q", output)
			}
			if strings.HasSuffix(output, "\n\n") {
				t.Errorf("output should not end with double newline, got: %q", output)
			}
		})
	}
}

func TestFormatCSSCustomProperties(t *testing.T) {
	input := ":root { --primary-color: #06c; --spacing: 1rem; } .element { color: var(--primary-color); padding: var(--spacing); }"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSS([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSS() error = %v", err)
	}

	output := string(p.Bytes())
	if !strings.Contains(output, "--primary-color") {
		t.Errorf("output should contain '--primary-color', got: %s", output)
	}
	if !strings.Contains(output, "var(") {
		t.Errorf("output should contain 'var(', got: %s", output)
	}
}
