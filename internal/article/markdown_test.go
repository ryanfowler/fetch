package article

import (
	"errors"
	"strings"
	"testing"

	html "golang.org/x/net/html"
)

func parseDocument(t *testing.T, source string) *html.Node {
	t.Helper()
	document, err := html.Parse(strings.NewReader(source))
	if err != nil {
		t.Fatalf("parse HTML: %v", err)
	}
	return document
}

func TestConvertSupportsCommonArticleElements(t *testing.T) {
	document := parseDocument(t, `<!doctype html><html><body>
	<nav>Do not include this navigation</nav>
	<h1> A &amp; Heading </h1>
	<p>Text with <strong>strong</strong>, <em>emphasis</em>, <del>removed</del>, <code>x &lt; y</code>, <a href="https://example.test/a_(b)">a link</a>, and <img src="https://example.test/image.png" alt="an image">.<br>Next line.</p>
	<blockquote><p>A quote.</p><p>Second paragraph.</p></blockquote>
	<hr>
	<ul><li>one<ul><li>nested</li></ul></li><li>two</li></ul>
	<ol start="3"><li>three</li><li>four</li></ol>
	<pre><code class="language-go">func main() {
	println("ok")
}</code></pre>
	<script>alert("not content")</script><p hidden>also not content</p>
</body></html>`)

	got, err := Convert(document)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	want := "# A & Heading\n\nText with **strong**, *emphasis*, ~~removed~~, `x < y`, [a link](https://example.test/a_\\(b\\)), and ![an image](https://example.test/image.png).  \nNext line.\n\n> A quote.\n>\n> Second paragraph.\n\n---\n\n- one\n  - nested\n- two\n\n3. three\n4. four\n\n```go\nfunc main() {\n\tprintln(\"ok\")\n}\n```\n"
	if got != want {
		t.Fatalf("Convert() = %q, want %q", got, want)
	}
	if strings.Contains(got, "navigation") || strings.Contains(got, "alert") || strings.Contains(got, "also not") {
		t.Fatalf("omitted content was rendered: %q", got)
	}
}

func TestConvertTablesAndIrregularFallback(t *testing.T) {
	document := parseDocument(t, `<main>
	<table><caption>People</caption><thead><tr><th>Name</th><th>Role</th></tr></thead><tbody><tr><td>Alice</td><td>Writer</td></tr><tr><td>Bob</td><td><strong>Editor</strong></td></tr></tbody></table>
	<table><tr><td>A</td><td>B</td></tr><tr><td>Only one cell</td></tr></table>
</main>`)
	got, err := Convert(document)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	want := "People\n\n| Name | Role |\n| --- | --- |\n| Alice | Writer |\n| Bob | **Editor** |\n\n- A; B\n- Only one cell\n"
	if got != want {
		t.Fatalf("Convert() = %q, want %q", got, want)
	}
}

func TestConvertPreUsesLongerFence(t *testing.T) {
	document := parseDocument(t, "<pre>before ``` and ```` after</pre>")
	got, err := Convert(document)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	want := "`````\nbefore ``` and ```` after\n`````\n"
	if got != want {
		t.Fatalf("Convert() = %q, want %q", got, want)
	}
}

func TestConvertBoundsDepthAndCycles(t *testing.T) {
	root := &html.Node{Type: html.DocumentNode}
	current := root
	for i := 0; i < MaxMarkdownDepth+20; i++ {
		child := &html.Node{Type: html.ElementNode, Data: "div"}
		current.AppendChild(child)
		current = child
	}
	current.AppendChild(&html.Node{Type: html.TextNode, Data: "deep"})
	// A malformed manually-built tree can contain a cycle. The renderer must
	// treat it as an omitted descendant rather than recurse forever.
	current.AppendChild(root)
	got, err := Convert(root)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if strings.Contains(got, "deep") {
		t.Fatalf("depth limit was not applied: %q", got)
	}
}

func TestConvertRejectsNilAndBoundsGrowth(t *testing.T) {
	if _, err := Convert(nil); !errors.Is(err, ErrNilNode) {
		t.Fatalf("Convert(nil) error = %v, want ErrNilNode", err)
	}
	document := &html.Node{Type: html.DocumentNode}
	document.AppendChild(&html.Node{Type: html.ElementNode, Data: "p", FirstChild: &html.Node{Type: html.TextNode, Data: strings.Repeat("*", maxMarkdownBytes)}})
	if _, err := Convert(document); !errors.Is(err, ErrMarkdownTooLarge) {
		t.Fatalf("oversized Convert() error = %v, want ErrMarkdownTooLarge", err)
	}
}

func TestConvertEscapesMarkdownStructure(t *testing.T) {
	document := parseDocument(t, `<main><p>- list-like
1. ordered
![not an image] a|b</p></main>`)
	got, err := Convert(document)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	want := "\\- list-like 1\\. ordered \\!\\[not an image\\] a\\|b\n"
	if got != want {
		t.Fatalf("Convert() = %q, want %q", got, want)
	}
}

func TestConvertOmitsHiddenNodes(t *testing.T) {
	document := parseDocument(t, `<html><head><title>Page title</title><meta name="description" content="metadata"></head><body><main><p>visible</p><p aria-hidden="true">hidden</p><p style="display: none">hidden</p><p style="visibility:hidden">hidden</p><template>hidden</template></main></body></html>`)
	got, err := Convert(document)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if got != "visible\n" {
		t.Fatalf("Convert() = %q, want visible only", got)
	}
}

func TestConvertPreservesEmphasisWhitespaceAndEscapesURLs(t *testing.T) {
	document := parseDocument(t, `<main><p><em> spaced text </em> <strong> strong </strong> <del> deleted </del> <a href="https://example.test/a b&#10;c">link</a></p><pre><code class="language-foo`+"`"+`bar">code</code></pre></main>`)
	got, err := Convert(document)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	want := "*spaced text* **strong** ~~deleted~~ [link](https://example.test/a%20b%0Ac)\n\n```\ncode\n```\n"
	if got != want {
		t.Fatalf("Convert() = %q, want %q", got, want)
	}
}

func TestConvertUnknownBlockWrapperKeepsBoundaries(t *testing.T) {
	document := parseDocument(t, `<main><custom-element><p>one</p><p>two</p></custom-element><p>tail</p></main>`)
	got, err := Convert(document)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if got != "one\n\ntwo\n\ntail\n" {
		t.Fatalf("Convert() = %q, want block separation", got)
	}
}

func TestConvertInlineBoundariesEntitiesAndCodeSpans(t *testing.T) {
	document := parseDocument(t, `<main><p>Hello <em>world</em> again</p><p>&amp;copy; <code>a
b</code></p></main>`)
	got, err := Convert(document)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	want := "Hello *world* again\n\n\\&copy; `a b`\n"
	if got != want {
		t.Fatalf("Convert() = %q, want %q", got, want)
	}
}

func TestConvertInlineRootsAndTableCellPipes(t *testing.T) {
	link := &html.Node{Type: html.ElementNode, Data: "a", Attr: []html.Attribute{{Key: "href", Val: "https://example.test"}}}
	link.AppendChild(&html.Node{Type: html.TextNode, Data: "link"})
	got, err := Convert(link)
	if err != nil || got != "[link](https://example.test)\n" {
		t.Fatalf("Convert(link) = %q, %v", got, err)
	}
	document := parseDocument(t, `<table><tr><th>Value</th></tr><tr><td><code>a|b</code></td></tr></table>`)
	got, err = Convert(document)
	if err != nil {
		t.Fatalf("Convert(table) error = %v", err)
	}
	want := "| Value |\n| --- |\n| `a\\|b` |\n"
	if got != want {
		t.Fatalf("Convert(table) = %q, want %q", got, want)
	}
}

func TestConvertGuardsSiblingCycles(t *testing.T) {
	root := &html.Node{Type: html.DocumentNode}
	paragraph := &html.Node{Type: html.ElementNode, Data: "p"}
	text := &html.Node{Type: html.TextNode, Data: "safe"}
	paragraph.FirstChild = text
	text.NextSibling = text
	root.FirstChild = paragraph
	paragraph.NextSibling = paragraph
	got, err := Convert(root)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if got != "safe\n" {
		t.Fatalf("Convert() = %q, want safe output", got)
	}
}

func TestConvertBoundsDeepInlineCopies(t *testing.T) {
	root := &html.Node{Type: html.DocumentNode}
	current := root
	for i := 0; i < MaxMarkdownDepth/2; i++ {
		child := &html.Node{Type: html.ElementNode, Data: "strong"}
		current.AppendChild(child)
		current = child
	}
	current.AppendChild(&html.Node{Type: html.TextNode, Data: strings.Repeat("x", 1<<20)})
	if _, err := Convert(root); !errors.Is(err, ErrMarkdownTooLarge) {
		t.Fatalf("deep inline Convert() error = %v, want ErrMarkdownTooLarge", err)
	}
}

func FuzzConvertMalformedDOM(f *testing.F) {
	f.Add("<main><p>text</p></main>")
	f.Add("<table><tr><td>a|b</td></tr></table>")
	f.Fuzz(func(t *testing.T, source string) {
		document, err := html.Parse(strings.NewReader(source))
		if err == nil {
			output, convertErr := Convert(document)
			if convertErr == nil && len(output) > maxMarkdownBytes {
				t.Fatalf("output length %d exceeds %d", len(output), maxMarkdownBytes)
			}
		}

		// Also exercise manually-built malformed graphs. The same node is
		// reachable through both a child and a sibling cycle.
		root := &html.Node{Type: html.DocumentNode}
		paragraph := &html.Node{Type: html.ElementNode, Data: "p"}
		shared := &html.Node{Type: html.TextNode, Data: source}
		root.FirstChild = paragraph
		paragraph.FirstChild = shared
		paragraph.NextSibling = paragraph
		shared.NextSibling = shared
		output, convertErr := Convert(root)
		if convertErr == nil && len(output) > maxMarkdownBytes {
			t.Fatalf("malformed output length %d exceeds %d", len(output), maxMarkdownBytes)
		}
	})
}
