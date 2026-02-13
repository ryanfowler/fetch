package format

import (
	"bytes"
	"mime"
	"net/http"
	"strings"
)

// ContentType represents a recognized response content type.
type ContentType int

const (
	TypeUnknown ContentType = iota
	TypeCSS
	TypeCSV
	TypeGRPC
	TypeHTML
	TypeImage
	TypeJSON
	TypeMsgPack
	TypeNDJSON
	TypeProtobuf
	TypeSSE
	TypeXML
	TypeYAML
)

// GetContentType parses the Content-Type header and returns the detected
// ContentType and charset. Returns TypeUnknown if the type is not recognized.
func GetContentType(headers http.Header) (ContentType, string) {
	contentType := headers.Get("Content-Type")
	if contentType == "" {
		return TypeUnknown, ""
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return TypeUnknown, ""
	}
	charset := params["charset"]

	if typ, subtype, ok := strings.Cut(mediaType, "/"); ok {
		switch typ {
		case "image":
			return TypeImage, charset
		case "application":
			switch subtype {
			case "csv":
				return TypeCSV, charset
			case "grpc", "grpc+proto":
				return TypeGRPC, charset
			case "json":
				return TypeJSON, charset
			case "msgpack", "x-msgpack", "vnd.msgpack":
				return TypeMsgPack, charset
			case "x-ndjson", "ndjson", "x-jsonl", "jsonl", "x-jsonlines":
				return TypeNDJSON, charset
			case "protobuf", "x-protobuf", "x-google-protobuf", "vnd.google.protobuf":
				return TypeProtobuf, charset
			case "xml":
				return TypeXML, charset
			case "yaml", "x-yaml":
				return TypeYAML, charset
			}
			if strings.HasSuffix(subtype, "+json") || strings.HasSuffix(subtype, "-json") {
				return TypeJSON, charset
			}
			if strings.HasSuffix(subtype, "+proto") {
				return TypeProtobuf, charset
			}
			if strings.HasSuffix(subtype, "+xml") {
				return TypeXML, charset
			}
			if strings.HasSuffix(subtype, "+yaml") {
				return TypeYAML, charset
			}
		case "text":
			switch subtype {
			case "css":
				return TypeCSS, charset
			case "csv":
				return TypeCSV, charset
			case "html":
				return TypeHTML, charset
			case "event-stream":
				return TypeSSE, charset
			case "xml":
				return TypeXML, charset
			case "yaml", "x-yaml":
				return TypeYAML, charset
			}
		}
	}

	return TypeUnknown, charset
}

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

// SniffContentType attempts to detect the content type of the provided bytes
// by examining the leading bytes of the body. It is used as a fallback when
// no Content-Type header is present in the HTTP response.
func SniffContentType(buf []byte) ContentType {
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
