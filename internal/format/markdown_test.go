package format

import (
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFormatMarkdown(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Empty / whitespace inputs
		{name: "empty input", input: "", wantErr: false},
		{name: "only whitespace", input: "   \n\n  \n", wantErr: false},
		{name: "only blank lines", input: "\n\n\n", wantErr: false},

		// ATX headings
		{name: "h1", input: "# Heading 1\n", wantErr: false},
		{name: "h2", input: "## Heading 2\n", wantErr: false},
		{name: "h3", input: "### Heading 3\n", wantErr: false},
		{name: "h4", input: "#### Heading 4\n", wantErr: false},
		{name: "h5", input: "##### Heading 5\n", wantErr: false},
		{name: "h6", input: "###### Heading 6\n", wantErr: false},
		{name: "heading no text", input: "#\n", wantErr: false},
		{name: "not a heading no space", input: "#not a heading\n", wantErr: false},
		{name: "consecutive headings", input: "# First\n## Second\n### Third\n", wantErr: false},

		// Setext headings
		{name: "setext h1", input: "Heading\n=======\n", wantErr: false},
		{name: "setext h2", input: "Heading\n-------\n", wantErr: false},

		// Fenced code blocks
		{name: "backtick fence", input: "```\ncode\n```\n", wantErr: false},
		{name: "tilde fence", input: "~~~\ncode\n~~~\n", wantErr: false},
		{name: "fence with language", input: "```go\nfmt.Println()\n```\n", wantErr: false},
		{name: "unclosed fence", input: "```\ncode\n", wantErr: false},
		{name: "nested backticks in tilde", input: "~~~\n```\ncode\n```\n~~~\n", wantErr: false},
		{name: "empty fence", input: "```\n```\n", wantErr: false},

		// Fenced code block delegation
		{name: "json code block", input: "```json\n{\"key\": \"value\"}\n```\n", wantErr: false},
		{name: "yaml code block", input: "```yaml\nkey: value\n```\n", wantErr: false},
		{name: "xml code block", input: "```xml\n<root/>\n```\n", wantErr: false},
		{name: "html code block", input: "```html\n<div>hello</div>\n```\n", wantErr: false},
		{name: "css code block", input: "```css\nbody { color: red; }\n```\n", wantErr: false},

		// Blockquotes
		{name: "blockquote single line", input: "> hello\n", wantErr: false},
		{name: "blockquote multiple lines", input: "> line1\n> line2\n", wantErr: false},
		{name: "nested blockquote", input: "> > nested\n", wantErr: false},
		{name: "blockquote with inline", input: "> **bold** in quote\n", wantErr: false},

		// Unordered lists
		{name: "dash list", input: "- item1\n- item2\n", wantErr: false},
		{name: "star list", input: "* item1\n* item2\n", wantErr: false},
		{name: "plus list", input: "+ item1\n+ item2\n", wantErr: false},
		{name: "nested list 2-space", input: "- parent\n  - child\n", wantErr: false},
		{name: "nested list 4-space", input: "- parent\n    - child\n", wantErr: false},
		{name: "list with inline", input: "- **bold** item\n", wantErr: false},

		// Ordered lists
		{name: "ordered list", input: "1. first\n2. second\n", wantErr: false},
		{name: "multi-digit ordered", input: "10. item ten\n", wantErr: false},
		{name: "nested ordered", input: "1. parent\n   1. child\n", wantErr: false},

		// Horizontal rules
		{name: "dash rule", input: "---\n", wantErr: false},
		{name: "star rule", input: "***\n", wantErr: false},
		{name: "underscore rule", input: "___\n", wantErr: false},
		{name: "long dash rule", input: "----\n", wantErr: false},
		{name: "spaced dash rule", input: "- - -\n", wantErr: false},
		{name: "spaced star rule", input: "* * *\n", wantErr: false},
		{name: "spaced underscore rule", input: "_ _ _\n", wantErr: false},

		// Inline formatting
		{name: "bold stars", input: "**bold**\n", wantErr: false},
		{name: "bold underscores", input: "__bold__\n", wantErr: false},
		{name: "italic star", input: "*italic*\n", wantErr: false},
		{name: "italic underscore", input: "_italic_\n", wantErr: false},
		{name: "bold italic", input: "***bold italic***\n", wantErr: false},
		{name: "code span", input: "`code`\n", wantErr: false},
		{name: "double backtick code", input: "`` code ``\n", wantErr: false},
		{name: "link", input: "[text](url)\n", wantErr: false},
		{name: "image", input: "![alt](url)\n", wantErr: false},
		{name: "unclosed bold", input: "**text\n", wantErr: false},
		{name: "unclosed italic", input: "*text\n", wantErr: false},
		{name: "unclosed bracket", input: "[text\n", wantErr: false},
		{name: "empty bold", input: "****\n", wantErr: false},
		{name: "markers in code span", input: "`**not bold**`\n", wantErr: false},
		{name: "link with bold text", input: "[**bold**](url)\n", wantErr: false},

		// Strikethrough
		{name: "strikethrough", input: "~~deleted~~\n", wantErr: false},

		// Tables
		{name: "simple table", input: "| A | B |\n|---|---|\n| 1 | 2 |\n", wantErr: false},

		// Autolinks
		{name: "autolink", input: "<http://example.com>\n", wantErr: false},

		// Multi-line constructs
		{name: "multi-line paragraph", input: "Hello\nworld\n", wantErr: false},
		{name: "multi-line link", input: "[link\ntext](url)\n", wantErr: false},

		// Mixed content
		{name: "mixed document", input: "# Title\n\nSome **bold** text.\n\n- item1\n- item2\n\n```\ncode\n```\n\n> quote\n", wantErr: false},

		// Front matter
		{name: "front matter simple", input: "---\ntitle: Hello\n---\n# Body\n", wantErr: false},
		{name: "front matter empty", input: "---\n---\n", wantErr: false},
		{name: "front matter only", input: "---\nkey: value\n---\n", wantErr: false},
		{name: "front matter crlf", input: "---\r\ntitle: Hi\r\n---\r\n# Body\r\n", wantErr: false},
		{name: "front matter unclosed", input: "---\ntitle: Hello\n", wantErr: false},
		{name: "front matter complex yaml", input: "---\ntags:\n  - go\n  - cli\ndate: 2024-01-01\n---\n# Post\n", wantErr: false},

		// Windows line endings
		{name: "crlf", input: "# Hello\r\n\r\nworld\r\n", wantErr: false},

		// Very long line
		{name: "long line", input: strings.Repeat("a", 10000) + "\n", wantErr: false},

		// List immediately after heading
		{name: "heading then list", input: "# Title\n- item\n", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			err := FormatMarkdown([]byte(tt.input), p)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormatMarkdown() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormatMarkdownHeadingOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "h1",
			input: "# Hello",
			want:  "# Hello\n",
		},
		{
			name:  "h2",
			input: "## World",
			want:  "## World\n",
		},
		{
			name:  "h6",
			input: "###### Deep",
			want:  "###### Deep\n",
		},
		{
			name:  "heading no text",
			input: "#",
			want:  "#\n",
		},
		{
			name:  "not a heading",
			input: "#nospace",
			want:  "#nospace\n",
		},
		{
			name:  "setext h1",
			input: "Title\n=====",
			want:  "# Title\n",
		},
		{
			name:  "setext h2",
			input: "Title\n-----",
			want:  "## Title\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			err := FormatMarkdown([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatMarkdown() error = %v", err)
			}
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatMarkdownBlockquoteOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple",
			input: "> hello",
			want:  "> hello\n",
		},
		{
			name:  "nested",
			input: "> > nested",
			want:  "> > nested\n",
		},
		{
			name:  "multi-line blockquote",
			input: "> line1\n> line2",
			want:  "> line1\n> line2\n",
		},
		{
			name:  "heading in blockquote",
			input: "> # Heading",
			want:  "> # Heading\n",
		},
		{
			name:  "heading then paragraph in blockquote",
			input: "> # Title\n>\n> text",
			want:  "> # Title\n> \n> text\n",
		},
		{
			name:  "thematic break in blockquote",
			input: "> ---",
			want:  "> ---\n",
		},
		{
			name:  "fenced code in blockquote",
			input: "> ```\n> code\n> ```",
			want:  "> ```\n> code\n> ```\n",
		},
		{
			name:  "list in blockquote",
			input: "> - a\n> - b",
			want:  "> - a\n> - b\n",
		},
		{
			name:  "nested heading in blockquote",
			input: "> > # Deep",
			want:  "> > # Deep\n",
		},
		{
			name:  "blockquote with multiple block types",
			input: "> # Title\n>\n> text\n>\n> ---",
			want:  "> # Title\n> \n> text\n> \n> ---\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			err := FormatMarkdown([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatMarkdown() error = %v", err)
			}
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatMarkdownListOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "dash list",
			input: "- item1\n- item2",
			want:  "- item1\n- item2\n",
		},
		{
			name:  "star list",
			input: "* item1\n* item2",
			want:  "* item1\n* item2\n",
		},
		{
			name:  "plus list",
			input: "+ item",
			want:  "+ item\n",
		},
		{
			name:  "nested list",
			input: "- parent\n  - child",
			want:  "- parent\n  - child\n",
		},
		{
			name:  "ordered list",
			input: "1. first\n2. second",
			want:  "1. first\n2. second\n",
		},
		{
			name:  "multi-digit ordered",
			input: "10. item",
			want:  "10. item\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			err := FormatMarkdown([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatMarkdown() error = %v", err)
			}
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatMarkdownHorizontalRuleOutput(t *testing.T) {
	// All thematic break forms normalize to "---".
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "dashes", input: "---", want: "---\n"},
		{name: "stars", input: "***", want: "---\n"},
		{name: "underscores", input: "___", want: "---\n"},
		{name: "long dashes", input: "-----", want: "---\n"},
		{name: "spaced dashes", input: "- - -", want: "---\n"},
		{name: "spaced stars", input: "* * *", want: "---\n"},
		{name: "spaced underscores", input: "_ _ _", want: "---\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			err := FormatMarkdown([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatMarkdown() error = %v", err)
			}
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatMarkdownDashDashNotRule(t *testing.T) {
	// "--" is too short to be a horizontal rule.
	p := core.TestPrinter(false)
	err := FormatMarkdown([]byte("--"), p)
	if err != nil {
		t.Fatalf("FormatMarkdown() error = %v", err)
	}
	got := string(p.Bytes())
	if got != "--\n" {
		t.Errorf("got %q, want %q", got, "--\n")
	}
}

func TestFormatMarkdownCodeBlockOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple code block",
			input: "```\nhello\n```",
			want:  "```\nhello\n```\n",
		},
		{
			name:  "tilde fence normalizes to backticks",
			input: "~~~\nhello\n~~~",
			want:  "```\nhello\n```\n",
		},
		{
			name:  "unclosed fence still closes",
			input: "```\nhello",
			want:  "```\nhello\n```\n",
		},
		{
			name:  "empty code block",
			input: "```\n```",
			want:  "```\n```\n",
		},
		{
			name:  "code with language",
			input: "```go\nfmt.Println()\n```",
			want:  "```go\nfmt.Println()\n```\n",
		},
		{
			name:  "fenced code preserves indentation",
			input: "```js\nconst r = await fetch(\n  `https://example.com`,\n  {\n    headers: {\n      Accept: \"text/markdown\",\n    },\n  },\n);\n```",
			want:  "```js\nconst r = await fetch(\n  `https://example.com`,\n  {\n    headers: {\n      Accept: \"text/markdown\",\n    },\n  },\n);\n```\n",
		},
		{
			name:  "indented code block",
			input: "text\n\n    line1\n      line2\n    line3",
			want:  "text\n\nline1\n  line2\nline3\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			err := FormatMarkdown([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatMarkdown() error = %v", err)
			}
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatMarkdownInlineOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "bold",
			input: "**bold**",
			want:  "bold\n",
		},
		{
			name:  "italic",
			input: "*italic*",
			want:  "italic\n",
		},
		{
			name:  "code span",
			input: "`code`",
			want:  "code\n",
		},
		{
			name:  "link",
			input: "[text](url)",
			want:  "[text](url)\n",
		},
		{
			name:  "image",
			input: "![alt](url)",
			want:  "![alt](url)\n",
		},
		{
			name:  "markers in code span",
			input: "`**not bold**`",
			want:  "**not bold**\n",
		},
		{
			name:  "bold italic",
			input: "***text***",
			want:  "text\n",
		},
		{
			name:  "unclosed bold passthrough",
			input: "**text",
			want:  "**text\n",
		},
		{
			name:  "inline mixed",
			input: "Hello **world** and *foo*",
			want:  "Hello world and foo\n",
		},
		{
			name:  "double backtick code span",
			input: "`` code ``",
			want:  "code\n",
		},
		{
			name:  "multi-line code span preserves indentation",
			input: "``\nconst r = await fetch(\n  `https://example.com`,\n  {\n    headers: {\n      Accept: \"text/markdown\",\n    },\n  },\n);\n``",
			want:  "const r = await fetch(\n  `https://example.com`,\n  {\n    headers: {\n      Accept: \"text/markdown\",\n    },\n  },\n);\n",
		},
		{
			name:  "utf8 plain text",
			input: "café résumé naïve",
			want:  "café résumé naïve\n",
		},
		{
			name:  "utf8 with bold",
			input: "**café**",
			want:  "café\n",
		},
		{
			name:  "utf8 cjk characters",
			input: "Hello 世界",
			want:  "Hello 世界\n",
		},
		{
			name:  "utf8 emoji",
			input: "Hello 👋🌍",
			want:  "Hello 👋🌍\n",
		},
		{
			name:  "strikethrough",
			input: "~~deleted~~",
			want:  "deleted\n",
		},
		{
			name:  "autolink",
			input: "<http://example.com>",
			want:  "<http://example.com>\n",
		},
		{
			name:  "nested emphasis",
			input: "**bold and *italic***",
			want:  "bold and italic\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			err := FormatMarkdown([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatMarkdown() error = %v", err)
			}
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatMarkdownColor(t *testing.T) {
	tests := []struct {
		name  string
		input string
		seqs  []string
	}{
		{
			name:  "heading uses bold blue",
			input: "# Title",
			seqs:  []string{"\x1b[1m", "\x1b[34m"},
		},
		{
			name:  "bold text uses bold",
			input: "**bold**",
			seqs:  []string{"\x1b[1m"},
		},
		{
			name:  "italic text uses italic",
			input: "*italic*",
			seqs:  []string{"\x1b[3m"},
		},
		{
			name:  "code span uses cyan",
			input: "`code`",
			seqs:  []string{"\x1b[36m"},
		},
		{
			name:  "link url uses cyan",
			input: "[text](http://example.com)",
			seqs:  []string{"\x1b[36m"},
		},
		{
			name:  "link text uses underline and brackets use dim",
			input: "[text](url)",
			seqs:  []string{"\x1b[4m", "\x1b[2m"},
		},
		{
			name:  "horizontal rule uses dim",
			input: "---",
			seqs:  []string{"\x1b[2m"},
		},
		{
			name:  "blockquote marker uses dim",
			input: "> text",
			seqs:  []string{"\x1b[2m"},
		},
		{
			name:  "list marker uses blue",
			input: "- item",
			seqs:  []string{"\x1b[34m"},
		},
		{
			name:  "ordered list marker uses blue",
			input: "1. item",
			seqs:  []string{"\x1b[34m"},
		},
		{
			name:  "strikethrough uses dim",
			input: "~~deleted~~",
			seqs:  []string{"\x1b[2m"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(true)
			err := FormatMarkdown([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatMarkdown() error = %v", err)
			}
			output := string(p.Bytes())
			for _, seq := range tt.seqs {
				if !strings.Contains(output, seq) {
					t.Errorf("output should contain ANSI sequence %q, got: %q", seq, output)
				}
			}
		})
	}
}

func TestFormatMarkdownCodeBlockDelegation(t *testing.T) {
	// JSON code block should produce formatted JSON output (indented).
	input := "```json\n{\"a\":1}\n```"
	p := core.TestPrinter(false)
	err := FormatMarkdown([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatMarkdown() error = %v", err)
	}
	output := string(p.Bytes())
	// The JSON formatter should indent the output.
	if !strings.Contains(output, "  ") {
		t.Errorf("expected JSON delegation to produce indented output, got: %q", output)
	}
	if !strings.Contains(output, "\"a\"") {
		t.Errorf("expected output to contain key \"a\", got: %q", output)
	}
}

func TestFormatMarkdownWindowsLineEndings(t *testing.T) {
	input := "# Hello\r\n\r\nworld\r\n"
	p := core.TestPrinter(false)
	err := FormatMarkdown([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatMarkdown() error = %v", err)
	}
	output := string(p.Bytes())
	if strings.Contains(output, "\r") {
		t.Errorf("output should not contain \\r, got: %q", output)
	}
	if !strings.Contains(output, "# Hello") {
		t.Errorf("output should contain '# Hello', got: %q", output)
	}
}

func TestFormatMarkdownMixedDocument(t *testing.T) {
	input := `# Title

Some **bold** and *italic* text.

- item 1
- item 2

1. ordered
2. list

> a blockquote

` + "```" + `
code block
` + "```" + `

---
`
	p := core.TestPrinter(false)
	err := FormatMarkdown([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatMarkdown() error = %v", err)
	}
	output := string(p.Bytes())
	for _, want := range []string{"# Title", "bold", "italic", "- item 1", "1. ordered", ">", "code block", "---"} {
		if !strings.Contains(output, want) {
			t.Errorf("output should contain %q, got: %q", want, output)
		}
	}
}

func TestFormatMarkdownEmptyInput(t *testing.T) {
	p := core.TestPrinter(false)
	err := FormatMarkdown([]byte(""), p)
	if err != nil {
		t.Fatalf("FormatMarkdown() error = %v", err)
	}
	if len(p.Bytes()) != 0 {
		t.Errorf("expected empty output for empty input, got: %q", string(p.Bytes()))
	}
}

func TestFormatMarkdownImageInline(t *testing.T) {
	input := "See ![logo](http://example.com/logo.png) here"
	p := core.TestPrinter(false)
	err := FormatMarkdown([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatMarkdown() error = %v", err)
	}
	output := string(p.Bytes())
	if !strings.Contains(output, "logo") {
		t.Errorf("expected output to contain 'logo', got: %q", output)
	}
	if !strings.Contains(output, "http://example.com/logo.png") {
		t.Errorf("expected output to contain URL, got: %q", output)
	}
}

func TestFormatMarkdownTable(t *testing.T) {
	input := "| Name | Age |\n|------|-----|\n| Alice | 30 |\n| Bob | 25 |\n"
	p := core.TestPrinter(false)
	err := FormatMarkdown([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatMarkdown() error = %v", err)
	}
	output := string(p.Bytes())
	if !strings.Contains(output, "Alice") {
		t.Errorf("expected output to contain 'Alice', got: %q", output)
	}
	if !strings.Contains(output, "Bob") {
		t.Errorf("expected output to contain 'Bob', got: %q", output)
	}
	if !strings.Contains(output, "|") {
		t.Errorf("expected output to contain '|', got: %q", output)
	}
}

func TestFormatMarkdownMultiLineLink(t *testing.T) {
	// A link split across lines should still be parsed.
	input := "[click\nhere](http://example.com)"
	p := core.TestPrinter(false)
	err := FormatMarkdown([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatMarkdown() error = %v", err)
	}
	output := string(p.Bytes())
	if !strings.Contains(output, "http://example.com") {
		t.Errorf("expected output to contain URL, got: %q", output)
	}
}

func TestFormatMarkdownNestedBlockquote(t *testing.T) {
	input := "> > deeply nested"
	p := core.TestPrinter(false)
	err := FormatMarkdown([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatMarkdown() error = %v", err)
	}
	output := string(p.Bytes())
	if !strings.Contains(output, ">") {
		t.Errorf("expected output to contain blockquote markers, got: %q", output)
	}
	if !strings.Contains(output, "deeply nested") {
		t.Errorf("expected output to contain text, got: %q", output)
	}
}

func TestFormatMarkdownBlockSpacing(t *testing.T) {
	// Every block-level element should be separated by a blank line from the
	// following block when both are present.
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "list then paragraph",
			input: "- a\n- b\n\nparagraph\n",
			want:  "- a\n- b\n\nparagraph\n",
		},
		{
			name:  "thematic break then paragraph",
			input: "---\n\nparagraph\n",
			want:  "---\n\nparagraph\n",
		},
		{
			name:  "html block then paragraph",
			input: "<div>hi</div>\n\nparagraph\n",
			want:  "<div>hi</div>\n\nparagraph\n",
		},
		{
			name:  "table then paragraph",
			input: "| A |\n|---|\n| 1 |\n\nparagraph\n",
			want:  "| A   |\n|---|\n| 1   |\n\nparagraph\n",
		},
		{
			name:  "blockquote then paragraph",
			input: "> quote\n\nparagraph\n",
			want:  "> quote\n\nparagraph\n",
		},
		{
			name:  "heading then paragraph",
			input: "# Title\n\nparagraph\n",
			want:  "# Title\n\nparagraph\n",
		},
		{
			name:  "fenced code then paragraph",
			input: "```\ncode\n```\n\nparagraph\n",
			want:  "```\ncode\n```\n\nparagraph\n",
		},
		{
			name:  "invalid json fence preserves prior output",
			input: "# Title\n\n```json\nnot json\n```\n\ntail\n",
			want:  "# Title\n\n```json\nnot json\n```\n\ntail\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			err := FormatMarkdown([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatMarkdown() error = %v", err)
			}
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractFrontMatter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantFM   string // empty means nil
		wantRest string
	}{
		{
			name:     "simple",
			input:    "---\ntitle: Hello\n---\nbody\n",
			wantFM:   "---\ntitle: Hello\n---\n",
			wantRest: "body\n",
		},
		{
			name:     "no front matter",
			input:    "# Heading\n",
			wantFM:   "",
			wantRest: "# Heading\n",
		},
		{
			name:     "standalone dash rule",
			input:    "---\n",
			wantFM:   "",
			wantRest: "---\n",
		},
		{
			name:     "unclosed",
			input:    "---\ntitle: Hello\nbody\n",
			wantFM:   "",
			wantRest: "---\ntitle: Hello\nbody\n",
		},
		{
			name:     "empty front matter",
			input:    "---\n---\n",
			wantFM:   "---\n---\n",
			wantRest: "",
		},
		{
			name:     "front matter only",
			input:    "---\nkey: val\n---\n",
			wantFM:   "---\nkey: val\n---\n",
			wantRest: "",
		},
		{
			name:     "crlf",
			input:    "---\r\ntitle: Hi\r\n---\r\nbody\r\n",
			wantFM:   "---\r\ntitle: Hi\r\n---\r\n",
			wantRest: "body\r\n",
		},
		{
			name:     "leading space not front matter",
			input:    " ---\ntitle: x\n---\n",
			wantFM:   "",
			wantRest: " ---\ntitle: x\n---\n",
		},
		{
			name:     "complex yaml",
			input:    "---\ntags:\n  - go\n  - cli\ndate: 2024-01-01\n---\n# Post\n",
			wantFM:   "---\ntags:\n  - go\n  - cli\ndate: 2024-01-01\n---\n",
			wantRest: "# Post\n",
		},
		{
			name:     "closing without newline",
			input:    "---\nkey: val\n---",
			wantFM:   "---\nkey: val\n---",
			wantRest: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm, rest := extractFrontMatter([]byte(tt.input))
			gotFM := string(fm)
			gotRest := string(rest)
			if tt.wantFM == "" {
				if fm != nil {
					t.Errorf("expected nil front matter, got %q", gotFM)
				}
			} else if gotFM != tt.wantFM {
				t.Errorf("front matter: got %q, want %q", gotFM, tt.wantFM)
			}
			if gotRest != tt.wantRest {
				t.Errorf("rest: got %q, want %q", gotRest, tt.wantRest)
			}
		})
	}
}

func TestFormatMarkdownFrontMatter(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "front matter with body",
			input: "---\ntitle: Hello\n---\n# Heading\n",
			want:  "---\ntitle: Hello\n---\n\n# Heading\n",
		},
		{
			name:  "front matter only",
			input: "---\nkey: value\n---\n",
			want:  "---\nkey: value\n---",
		},
		{
			name:  "empty front matter",
			input: "---\n---\nbody\n",
			want:  "---\n---\n\nbody\n",
		},
		{
			name:  "no front matter passthrough",
			input: "# Heading\n",
			want:  "# Heading\n",
		},
		{
			name:  "unclosed treated as markdown",
			input: "---\ntitle: Hello\n",
			want:  "---\n\ntitle: Hello\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			err := FormatMarkdown([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatMarkdown() error = %v", err)
			}
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatMarkdownFrontMatterColor(t *testing.T) {
	tests := []struct {
		name  string
		input string
		seqs  []string
	}{
		{
			name:  "dim delimiters and blue keys",
			input: "---\ntitle: Hello\n---\n",
			seqs:  []string{"\x1b[2m", "\x1b[34m"},
		},
		{
			name:  "front matter with heading body",
			input: "---\nkey: val\n---\n# Title\n",
			seqs:  []string{"\x1b[2m", "\x1b[34m", "\x1b[1m"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(true)
			err := FormatMarkdown([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("FormatMarkdown() error = %v", err)
			}
			output := string(p.Bytes())
			for _, seq := range tt.seqs {
				if !strings.Contains(output, seq) {
					t.Errorf("output should contain ANSI sequence %q, got: %q", seq, output)
				}
			}
		})
	}
}
