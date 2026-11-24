package format

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

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

func TestFormatCSSLimitsNestingDepth(t *testing.T) {
	input := strings.Repeat("@media all {", core.MaxFormatterNestingDepth+1) +
		strings.Repeat("}", core.MaxFormatterNestingDepth+1)
	p := core.TestPrinter(false)

	err := FormatCSS([]byte(input), p)
	if !errors.Is(err, core.ErrLimitExceeded) {
		t.Fatalf("FormatCSS() error = %v, want nesting limit error", err)
	}
	if got := len(p.Bytes()); got != 0 {
		t.Fatalf("FormatCSS() wrote %d bytes after nesting limit", got)
	}
}

func TestFormatCSSLimitsOutput(t *testing.T) {
	input := strings.Repeat("a", core.MaxFormattedBodyBytes+1) + " {}"
	p := core.TestPrinter(false)

	err := FormatCSS([]byte(input), p)
	if !errors.Is(err, core.ErrLimitExceeded) {
		t.Fatalf("FormatCSS() error = %v, want output limit error", err)
	}
	if got := len(p.Bytes()); got != 0 {
		t.Fatalf("FormatCSS() wrote %d bytes after output limit", got)
	}
}

func TestFormatCSSLimitsFunctionNestingDepth(t *testing.T) {
	input := "a { color: " + strings.Repeat("f(", core.MaxFormatterNestingDepth+1) +
		"x" + strings.Repeat(")", core.MaxFormatterNestingDepth+1) + "; }"
	p := core.TestPrinter(false)

	err := FormatCSS([]byte(input), p)
	if !errors.Is(err, core.ErrLimitExceeded) {
		t.Fatalf("FormatCSS() error = %v, want function nesting limit error", err)
	}
	if got := len(p.Bytes()); got != 0 {
		t.Fatalf("FormatCSS() wrote %d bytes after function nesting limit", got)
	}
}

func TestFormatCSSRejectsNegativeBaseIndent(t *testing.T) {
	err := FormatCSSIndented([]byte("a {}"), core.TestPrinter(false), -1)
	if err == nil {
		t.Fatal("FormatCSSIndented() error = nil, want negative base indentation error")
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

func TestFormatCSSKeepsContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "declarations in at-rule",
			input: "@font-face { font-family: Foo; src: url(a.woff); } body { color: red }",
			want:  "@font-face {\n  font-family: Foo;\n  src: url(a.woff);\n}\n\nbody {\n  color: red;\n}\n",
		},
		{
			name:  "calc operators",
			input: ".a { width: calc(100% + 2px * 3); margin: -1px; }",
			want:  ".a {\n  width: calc(100% + 2px * 3);\n  margin: -1px;\n}\n",
		},
		{
			name:  "attribute operators",
			input: `a[href^="http"], a[lang|=en], a[x$=y], a[c~=d], a[e*=f] { color: red }`,
			want:  "a[href^=\"http\"], a[lang|=en], a[x$=y], a[c~=d], a[e*=f] {\n  color: red;\n}\n",
		},
		{
			name:  "nested rule",
			input: ".a { &:hover { color: red } color: blue; }",
			want:  ".a {\n  &:hover {\n    color: red;\n  }\n  color: blue;\n}\n",
		},
		{
			name:  "media prelude",
			input: "@media screen and (min-width: 768px) { a:hover { color: red } }",
			want:  "@media screen and (min-width: 768px) {\n  a:hover {\n    color: red;\n  }\n}\n",
		},
		{
			name:  "nested parentheses in prelude",
			input: "@supports (display: grid) and (not (display: inline-grid)) { a { b: c } }",
			want:  "@supports (display: grid) and (not (display: inline-grid)) {\n  a {\n    b: c;\n  }\n}\n",
		},
		{
			name:  "page selector",
			input: "@page :first { margin: 1cm; @top-center { content: 'x' } }",
			want:  "@page :first {\n  margin: 1cm;\n  @top-center {\n    content: 'x';\n  }\n}\n",
		},
		{
			name:  "stray semicolons",
			input: ".b { color: red;; ; }",
			want:  ".b {\n  color: red;\n}\n",
		},
		{
			name:  "important",
			input: "a { color: red !important }",
			want:  "a {\n  color: red !important;\n}\n",
		}, {
			name:  "braces in unquoted url",
			input: "a { background: url(x{y}.png); color: red } p { q: r }",
			want:  "a {\n  background: url(x{y}.png);\n  color: red;\n}\n\np {\n  q: r;\n}\n",
		},
		{
			name:  "data url kept as written",
			input: "a { background: url(data:image/svg+xml;utf8,<svg>{</svg>) }",
			want:  "a {\n  background: url(data:image/svg+xml;utf8,<svg>{</svg>);\n}\n",
		},
		{
			name:  "selector function arguments",
			input: "li:nth-child(2n+1), :is(h1, h2 > b), a:not([x^=y]), b:not(.c > d) { e: f }",
			want:  "li:nth-child(2n+1), :is(h1, h2 > b), a:not([x^=y]), b:not(.c > d) {\n  e: f;\n}\n",
		},
		{
			name:  "attribute flag",
			input: `a[x=y i], a[href$=".pdf" s] { e: f }`,
			want:  "a[x=y i], a[href$=\".pdf\" s] {\n  e: f;\n}\n",
		},
		{
			name:  "at-rule without block before closing brace",
			input: "@media screen { a { @foo } b { c: d } }",
			want:  "@media screen {\n  a {\n    @foo\n  }\n  b {\n    c: d;\n  }\n}\n",
		},
		{
			name:  "custom property with braces",
			input: "a { --x: {a:b; c:d}; color: red }",
			want:  "a {\n  --x: {a:b; c:d};\n  color: red;\n}\n",
		},
		{
			name:  "stray top-level tokens",
			input: "a { b: c } } d { e: f } ;",
			want:  "a {\n  b: c;\n}\n\nd {\n  e: f;\n}\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			if err := FormatCSS([]byte(test.input), p); err != nil {
				t.Fatal(err)
			}
			if got := string(p.Bytes()); got != test.want {
				t.Fatalf("FormatCSS() =\n%s\nwant\n%s", got, test.want)
			}
		})
	}
}

func FuzzFormatCSS(f *testing.F) {
	f.Add(".a { &:hover { color: red } color: blue; }")
	f.Add("@media screen and (not (x: y)) { a:b { c: d } }")
	f.Add("@font-face { a: b; } x[y^=z] { w: calc(1 + 2) }")
	f.Add("a { ; } } { :")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			return
		}
		p := core.TestPrinter(false)
		if FormatCSS([]byte(input), p) != nil || !wellFormedCSS(input) {
			return
		}
		// Formatting is idempotent: formatted CSS is formatted again into
		// the same text. A formatter that drops or moves tokens usually
		// breaks this.
		once := string(p.Bytes())
		again := core.TestPrinter(false)
		if err := FormatCSS([]byte(once), again); err != nil {
			t.Fatalf("formatting the output failed: %v\ninput: %q\noutput: %q", err, input, once)
		}
		if twice := string(again.Bytes()); twice != once {
			t.Fatalf("formatting is not idempotent\ninput: %q\nonce:  %q\ntwice: %q", input, once, twice)
		}
	})
}

// wellFormedCSS reports whether input has terminated strings and comments,
// properly nested braces, brackets, and parentheses, and no control or
// escape characters. For such input, the formatter output must not depend
// on error recovery or on terminal escaping.
func wellFormedCSS(input string) bool {
	for _, r := range input {
		if r == '\\' || r == utf8.RuneError || (unicode.IsControl(r) && r != '\n' && r != '\t') {
			return false
		}
	}
	tok := newCSSTokenizer([]byte(input))
	var open []string
	closing := map[string]string{"}": "{", "]": "[", ")": "("}
	for {
		t := tok.next()
		switch t.typ {
		case cssTokenEOF:
			return len(open) == 0
		case cssTokenString:
			if len(t.value) < 2 || t.value[len(t.value)-1] != t.value[0] {
				return false
			}
		case cssTokenComment:
			if len(t.value) < 4 || !strings.HasSuffix(t.value, "*/") {
				return false
			}
		case cssTokenFunction:
			open = append(open, "(")
		case cssTokenURL:
			if !strings.HasSuffix(t.value, ")") {
				return false
			}
		case cssTokenDelim:
			switch t.value {
			case "{", "[", "(":
				open = append(open, t.value)
			case "}", "]", ")":
				if len(open) == 0 || open[len(open)-1] != closing[t.value] {
					return false
				}
				open = open[:len(open)-1]
			}
		}
	}
}
