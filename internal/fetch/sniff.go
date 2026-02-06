package fetch

import (
	"bytes"
	"net/http"
	"strings"
)

var (
	prefixXMLDecl = []byte("?xml")
	prefixDoctype = []byte("!doctype")
	prefixHTML    = []byte("html")

	htmlTags = [][]byte{
		[]byte("html"), []byte("head"), []byte("body"), []byte("div"),
		[]byte("span"), []byte("p"), []byte("a"),
		[]byte("table"), []byte("tr"), []byte("td"), []byte("th"),
		[]byte("ul"), []byte("ol"), []byte("li"),
		[]byte("form"), []byte("input"), []byte("button"),
		[]byte("script"), []byte("style"), []byte("link"),
		[]byte("meta"), []byte("title"), []byte("section"), []byte("article"),
		[]byte("nav"), []byte("header"), []byte("footer"), []byte("main"),
		[]byte("aside"), []byte("h1"), []byte("h2"), []byte("h3"),
		[]byte("h4"), []byte("h5"), []byte("h6"),
		[]byte("img"), []byte("br"), []byte("hr"),
		[]byte("pre"), []byte("code"), []byte("blockquote"),
	}
)

// sniffContentType attempts to detect the content type of the provided bytes
// by examining the leading bytes of the body. It is used as a fallback when
// no Content-Type header is present in the HTTP response.
func sniffContentType(buf []byte) ContentType {
	b := trimBOMAndSpace(buf)
	if len(b) == 0 {
		return TypeUnknown
	}

	switch b[0] {
	case '{', '[':
		return TypeJSON
	case '<':
		return sniffMarkup(b)
	case '-':
		if len(b) >= 3 && b[1] == '-' && b[2] == '-' {
			return TypeYAML
		}
	}

	// Use net/http.DetectContentType for image detection.
	ct := http.DetectContentType(buf)
	if strings.HasPrefix(ct, "image/") {
		return TypeImage
	}

	return TypeUnknown
}

// sniffMarkup determines whether markup bytes starting with '<' are HTML or XML.
func sniffMarkup(b []byte) ContentType {
	// Skip the leading '<'.
	rest := b[1:]

	// <?xml declaration.
	if bytes.HasPrefix(rest, prefixXMLDecl) {
		return TypeXML
	}

	// CDATA section or comment → XML.
	if len(rest) > 0 && (rest[0] == '!' || rest[0] == '?') {
		if hasPrefixFold(rest, prefixDoctype) {
			// Check if it's an HTML doctype.
			after := bytes.TrimSpace(rest[len(prefixDoctype):])
			if hasPrefixFold(after, prefixHTML) {
				return TypeHTML
			}
			return TypeXML
		}
		// <!-- comment or <![CDATA[ → XML.
		return TypeXML
	}

	// Starts with a letter → could be an element tag.
	if len(rest) > 0 && isLetter(rest[0]) {
		return sniffTag(rest)
	}

	return TypeUnknown
}

// sniffTag examines a tag name (the bytes after '<') and returns TypeHTML if
// it matches a known HTML element, otherwise TypeXML.
func sniffTag(b []byte) ContentType {
	if isHTMLTag(b) {
		return TypeHTML
	}
	return TypeXML
}

// isHTMLTag checks whether b (starting right after '<') begins with a known
// HTML tag name followed by a delimiter (space, '>', '/', or end of input).
func isHTMLTag(b []byte) bool {
	for _, tag := range htmlTags {
		if !hasPrefixFold(b, tag) {
			continue
		}
		// Must be followed by a delimiter or end of input.
		if len(b) == len(tag) {
			return true
		}
		c := b[len(tag)]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '>' || c == '/' {
			return true
		}
	}
	return false
}

// hasPrefixFold checks whether b starts with the given prefix,
// comparing ASCII letters case-insensitively.
func hasPrefixFold(b, prefix []byte) bool {
	return len(b) >= len(prefix) && bytes.EqualFold(b[:len(prefix)], prefix)
}

// isLetter returns true if c is an ASCII letter.
func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// trimBOMAndSpace trims a leading UTF-8 BOM and any whitespace from b.
func trimBOMAndSpace(b []byte) []byte {
	// UTF-8 BOM: 0xEF, 0xBB, 0xBF.
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	return bytes.TrimSpace(b)
}
