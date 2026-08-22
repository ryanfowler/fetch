package article

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/readability"
)

// ErrUnsupportedContentType identifies a response that article mode cannot
// extract. Article mode accepts HTML/XHTML and Markdown responses.
var ErrUnsupportedContentType = errors.New("article mode requires HTML or Markdown content")

// ReadLimited reads at most the configured decoded article-body limit. It
// does not retain a sentinel byte when the input is exactly at the limit.
func ReadLimited(source io.Reader) ([]byte, error) {
	buffer := core.NewBoundedBuffer(core.MaxArticleBodyBytes, "article body")
	if _, err := io.Copy(buffer, io.LimitReader(source, core.MaxArticleBodyBytes)); err != nil {
		return nil, err
	}

	var extra [1]byte
	n, err := io.ReadFull(source, extra[:])
	if n > 0 {
		return nil, core.LimitError{Subsystem: "article body", Limit: core.MaxArticleBodyBytes}
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// Render extracts readable HTML or adds article frontmatter to Markdown.
// pageURL is the final response URL. The returned bytes are uncolored and are
// suitable for files, pipes, and terminal presentation.
func Render(source []byte, contentType, pageURL string) ([]byte, error) {
	mediaType := normalizedMediaType(contentType)
	switch {
	case mediaType == "text/markdown" || mediaType == "text/x-markdown":
		return addURLFrontmatter(source, pageURL), nil
	case mediaType == "text/html" || mediaType == "application/xhtml+xml":
		return extractHTML(source, pageURL)
	case mediaType == "" || isGenericMediaType(mediaType):
		// A missing or generic type may still be an HTML page. Do not sniff
		// specific non-HTML types, because article mode must not silently
		// reinterpret JSON, XML, or binary protocol responses.
		if looksLikeHTML(source) {
			return extractHTML(source, pageURL)
		}
	default:
		// Fall through to the same stable error for all unsupported types.
	}
	if mediaType == "" {
		mediaType = "unknown"
	}
	return nil, fmt.Errorf("%w (received %s)", ErrUnsupportedContentType, mediaType)
}

func extractHTML(source []byte, pageURL string) ([]byte, error) {
	parsed, err := readability.Parse(bytes.NewReader(source), pageURL,
		readability.WithMaxElemsToParse(core.MaxReadabilityElements))
	if err != nil {
		if errors.Is(err, readability.ErrNoContent) {
			return nil, fmt.Errorf("failed to extract readable article: no readable content (JavaScript-rendered content is not executed): %w", err)
		}
		return nil, fmt.Errorf("failed to extract readable article: %w", err)
	}
	if parsed == nil || parsed.Node == nil {
		return nil, errors.New("failed to extract readable article: no readable content (JavaScript-rendered content is not executed)")
	}

	markdown, err := Convert(parsed.Node)
	if err != nil {
		return nil, fmt.Errorf("failed to convert readable article to Markdown: %w", err)
	}
	return renderDocument(parsed, pageURL, markdown), nil
}

func addURLFrontmatter(markdown []byte, pageURL string) []byte {
	var out strings.Builder
	out.Grow(len(markdown) + len(pageURL) + 32)
	out.WriteString("---\n")
	pushString(&out, "url", pageURL)
	out.WriteString("---\n\n")
	out.Write(markdown)
	return []byte(out.String())
}

func renderDocument(parsed *readability.Article, pageURL, markdown string) []byte {
	var out strings.Builder
	out.Grow(len(markdown) + 256)
	out.WriteString("---\n")
	// Readability supplies length for every extracted article. Optional
	// metadata is omitted when the source did not provide it.
	pushOptionalString(&out, "title", parsed.Title)
	pushOptionalString(&out, "byline", parsed.Byline)
	pushOptionalString(&out, "site_name", parsed.SiteName)
	pushOptionalString(&out, "published_time", parsed.PublishedTime)
	pushOptionalString(&out, "lang", parsed.Lang)
	pushOptionalString(&out, "dir", parsed.Dir)
	fmt.Fprintf(&out, "length: %d\n", parsed.Length)
	pushOptionalString(&out, "excerpt", parsed.Excerpt)
	pushString(&out, "url", pageURL)
	out.WriteString("---\n\n")
	out.WriteString(strings.TrimSpace(markdown))
	out.WriteByte('\n')
	return []byte(out.String())
}

func pushOptionalString(out *strings.Builder, key, value string) {
	if value != "" {
		pushString(out, key, value)
	}
}

func pushString(out *strings.Builder, key, value string) {
	// JSON string quoting produces a scalar that is also valid YAML and safely
	// handles quotes, newlines, and control characters.
	fmt.Fprintf(out, "%s: %s\n", key, quoteYAMLString(value))
}

func quoteYAMLString(value string) string {
	// Keep this helper local so frontmatter has one escaping rule for all
	// metadata fields. JSON string quoting is valid and safe as a YAML scalar.
	// encoding/json/v2 does not escape HTML characters by default, so URLs
	// retain readable '&' and '<' characters.
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func normalizedMediaType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	}
	return strings.ToLower(mediaType)
}

func isGenericMediaType(mediaType string) bool {
	switch mediaType {
	case "application/octet-stream", "binary/octet-stream", "text/plain":
		return true
	default:
		return false
	}
}

func looksLikeHTML(source []byte) bool {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(source, []byte{0xef, 0xbb, 0xbf}))
	if len(trimmed) == 0 || trimmed[0] != '<' {
		return false
	}
	trimmed = trimmed[1:]
	if hasPrefixFold(trimmed, []byte("!doctype")) {
		rest := bytes.TrimSpace(trimmed[len("!doctype"):])
		return hasPrefixFold(rest, []byte("html")) && hasTagDelimiter(rest[len("html"):])
	}

	for _, tag := range []string{
		"html", "head", "body", "article", "main", "p", "div", "section",
		"header", "footer", "nav", "h1", "h2", "h3", "h4", "h5", "h6",
	} {
		if hasPrefixFold(trimmed, []byte(tag)) && hasTagDelimiter(trimmed[len(tag):]) {
			return true
		}
	}
	return false
}

func hasPrefixFold(value, prefix []byte) bool {
	return len(value) >= len(prefix) && bytes.EqualFold(value[:len(prefix)], prefix)
}

func hasTagDelimiter(value []byte) bool {
	return len(value) == 0 || value[0] == '>' || value[0] == '/' || value[0] == ' ' || value[0] == '\t' || value[0] == '\r' || value[0] == '\n'
}
