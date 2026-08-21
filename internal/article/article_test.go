package article

import (
	"errors"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/readability"
)

func TestReadLimitedAcceptsExactLimitAndRejectsOverflow(t *testing.T) {
	exact := strings.NewReader(strings.Repeat("x", int(core.MaxArticleBodyBytes)))
	body, err := ReadLimited(exact)
	if err != nil || int64(len(body)) != core.MaxArticleBodyBytes {
		t.Fatalf("ReadLimited(exact) length=%d, err=%v; want exact limit", len(body), err)
	}

	over := strings.NewReader(strings.Repeat("x", int(core.MaxArticleBodyBytes)+1))
	if _, err := ReadLimited(over); !errors.Is(err, core.ErrLimitExceeded) {
		t.Fatalf("ReadLimited(over) error=%v, want limit error", err)
	}
}

func TestRenderExtractsReadableHTMLWithMetadata(t *testing.T) {
	source := []byte(`<!doctype html>
<html lang="en" dir="ltr"><head>
<title>An &quot;Article&quot;</title>
<meta property="og:site_name" content="Example News">
<meta name="author" content="Jane Smith">
<meta name="description" content="A useful summary">
</head><body><nav>Navigation</nav><article><h1>An Article</h1><p>This is a sufficiently substantial article paragraph with readable content for extraction. It contains enough prose to be selected as the primary document content.</p><p><a href="relative">Related reading</a></p></article></body></html>`)

	got, err := Render(source, "text/html; charset=utf-8", "https://example.com/posts/one")
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	output := string(got)
	for _, want := range []string{
		"title: \"An ",
		"byline: \"Jane Smith\"",
		"site_name: \"Example News\"",
		"lang: \"en\"",
		"length: ",
		"url: \"https://example.com/posts/one\"",
		"primary document content",
		"https://example.com/posts/relative",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("article output does not contain %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "Navigation") || !strings.HasSuffix(output, "\n") || strings.HasSuffix(output, "\n\n") {
		t.Fatalf("article output has invalid content or termination:\n%q", output)
	}
}

func TestRenderAddsURLFrontmatterToMarkdownWithoutChangingBody(t *testing.T) {
	body := []byte("# Existing Markdown\n\nBody with *formatting*.\n")
	got, err := Render(body, "text/markdown", "https://example.com/readme.md")
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	want := "---\nurl: \"https://example.com/readme.md\"\n---\n\n" + string(body)
	if string(got) != want {
		t.Fatalf("Render() = %q, want %q", got, want)
	}

	withoutNewline := []byte("# No trailing newline")
	got, err = Render(withoutNewline, "text/x-markdown", "https://example.com/readme.md")
	if err != nil {
		t.Fatalf("Render() without trailing newline error = %v", err)
	}
	want = "---\nurl: \"https://example.com/readme.md\"\n---\n\n" + string(withoutNewline)
	if string(got) != want {
		t.Fatalf("Render() changed Markdown body = %q, want %q", got, want)
	}
}

func TestRenderSniffsGenericHTMLAndRejectsOtherTypes(t *testing.T) {
	source := []byte(`<html><body><article><p>This is enough readable content to make the article extractor accept this page as an article.</p></article></body></html>`)
	if _, err := Render(source, "application/octet-stream", "https://example.com"); err != nil {
		t.Fatalf("generic HTML Render() error = %v", err)
	}
	if _, err := Render([]byte(`{"value":1}`), "application/json", "https://example.com"); !errors.Is(err, ErrUnsupportedContentType) {
		t.Fatalf("JSON Render() error = %v, want unsupported content type", err)
	}
}

func TestRenderReportsNoReadableContent(t *testing.T) {
	_, err := Render([]byte(`<html><head><title>Only a title</title></head><body></body></html>`), "text/html", "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "readable article") || !strings.Contains(err.Error(), "JavaScript-rendered") {
		t.Fatalf("Render() error = %v, want readable-content and JavaScript guidance", err)
	}
	if !errors.Is(err, readability.ErrNoContent) {
		t.Fatalf("Render() error = %v, want readability.ErrNoContent", err)
	}
}

func TestRenderQuotesFrontmatterValues(t *testing.T) {
	body := []byte(`<html><head><title>ignored?</title></head><body><article><h1>Title</h1><p>This paragraph contains enough readable text to make extraction deterministic and useful.</p></article></body></html>`)
	got, err := Render(body, "text/html", "https://example.com/?a=1&b=2")
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if !strings.Contains(string(got), `url: "https://example.com/?a=1&b=2"`) {
		t.Fatalf("URL was not JSON-quoted: %q", got)
	}
}
