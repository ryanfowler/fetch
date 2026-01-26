package format

import (
	"bytes"
	"io"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"

	"golang.org/x/net/html"
)

// voidElements are HTML5 elements that have no closing tag.
var voidElements = map[string]bool{
	"area":   true,
	"base":   true,
	"br":     true,
	"col":    true,
	"embed":  true,
	"hr":     true,
	"img":    true,
	"input":  true,
	"link":   true,
	"meta":   true,
	"param":  true,
	"source": true,
	"track":  true,
	"wbr":    true,
}

// blockElements are elements that should start on their own line and indent children.
var blockElements = map[string]bool{
	"html":       true,
	"head":       true,
	"body":       true,
	"title":      true,
	"meta":       true,
	"link":       true,
	"base":       true,
	"div":        true,
	"p":          true,
	"h1":         true,
	"h2":         true,
	"h3":         true,
	"h4":         true,
	"h5":         true,
	"h6":         true,
	"ul":         true,
	"ol":         true,
	"li":         true,
	"table":      true,
	"thead":      true,
	"tbody":      true,
	"tfoot":      true,
	"tr":         true,
	"td":         true,
	"th":         true,
	"form":       true,
	"fieldset":   true,
	"section":    true,
	"article":    true,
	"nav":        true,
	"aside":      true,
	"header":     true,
	"footer":     true,
	"main":       true,
	"figure":     true,
	"figcaption": true,
	"blockquote": true,
	"pre":        true,
	"address":    true,
	"details":    true,
	"summary":    true,
	"dialog":     true,
	"script":     true,
	"style":      true,
	"noscript":   true,
	"template":   true,
	"canvas":     true,
	"video":      true,
	"audio":      true,
	"iframe":     true,
	"object":     true,
	"select":     true,
	"option":     true,
	"optgroup":   true,
	"datalist":   true,
	"textarea":   true,
	"dl":         true,
	"dt":         true,
	"dd":         true,
	// Void elements that should be on their own line.
	"hr":     true,
	"br":     true,
	"img":    true,
	"input":  true,
	"area":   true,
	"col":    true,
	"embed":  true,
	"source": true,
	"track":  true,
	"wbr":    true,
}

// rawTextElements contain content that should not be parsed as HTML.
var rawTextElements = map[string]bool{
	"script": true,
	"style":  true,
}

// preserveWhitespaceElements should not have indentation added to their content.
var preserveWhitespaceElements = map[string]bool{
	"pre":      true,
	"textarea": true,
}

// htmlStackEntry tracks information about an open element.
type htmlStackEntry struct {
	tagName       string
	isBlock       bool
	hasBlockChild bool // true if a block-level child has been output
}

// FormatHTML formats the provided HTML to the Printer.
func FormatHTML(buf []byte, w *core.Printer) error {
	tokenizer := html.NewTokenizer(bytes.NewReader(buf))

	var stack []htmlStackEntry

	for {
		tt := tokenizer.Next()

		switch tt {
		case html.ErrorToken:
			err := tokenizer.Err()
			if err == io.EOF {
				return nil
			}
			return err

		case html.DoctypeToken:
			// Doctype is always at the start, no need for preceding newline.
			w.WriteString("<!")
			writeHTMLDoctype(w, tokenizer.Token())
			w.WriteString(">\n")

		case html.StartTagToken:
			tagName, hasAttr := tokenizer.TagName()
			tagNameStr := string(tagName)
			tagNameLower := strings.ToLower(tagNameStr)

			isBlock := blockElements[tagNameLower]
			isVoid := voidElements[tagNameLower]

			// Mark parent as having a block child if this is a block element.
			if isBlock && len(stack) > 0 {
				if !stack[len(stack)-1].hasBlockChild {
					w.WriteString("\n")
				}
				stack[len(stack)-1].hasBlockChild = true
				writeIndent(w, len(stack))
			}

			w.WriteString("<")
			writeHTMLTagName(w, tagNameStr)
			if hasAttr {
				writeHTMLAttributes(w, tokenizer)
			}
			w.WriteString(">")

			if !isVoid {
				stack = append(stack, htmlStackEntry{
					tagName:       tagNameLower,
					isBlock:       isBlock,
					hasBlockChild: false,
				})
			} else if isBlock {
				w.WriteString("\n")
			}

		case html.EndTagToken:
			tagName, _ := tokenizer.TagName()
			tagNameStr := string(tagName)
			tagNameLower := strings.ToLower(tagNameStr)

			// Skip end tags for void elements.
			if voidElements[tagNameLower] {
				continue
			}

			// Find and pop the matching tag from the stack.
			var entry htmlStackEntry
			found := false
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].tagName == tagNameLower {
					entry = stack[i]
					stack = stack[:i]
					found = true
					break
				}
			}

			if entry.isBlock && entry.hasBlockChild {
				writeIndent(w, len(stack))
			}

			w.WriteString("</")
			writeHTMLTagName(w, tagNameStr)
			w.WriteString(">")

			if found && entry.isBlock {
				w.WriteString("\n")
			}

		case html.SelfClosingTagToken:
			tagName, hasAttr := tokenizer.TagName()
			tagNameStr := string(tagName)
			tagNameLower := strings.ToLower(tagNameStr)

			isBlock := blockElements[tagNameLower]

			// Mark parent as having a block child if this is a block element.
			if isBlock && len(stack) > 0 {
				if !stack[len(stack)-1].hasBlockChild {
					w.WriteString("\n")
				}
				stack[len(stack)-1].hasBlockChild = true
				writeIndent(w, len(stack))
			}

			w.WriteString("<")
			writeHTMLTagName(w, tagNameStr)
			if hasAttr {
				writeHTMLAttributes(w, tokenizer)
			}
			w.WriteString(">")

			if isBlock {
				w.WriteString("\n")
			}

		case html.TextToken:
			text := tokenizer.Text()

			// Check if we're inside a raw text or whitespace-preserving element.
			inRawText := false
			inPreserveWS := false
			if len(stack) > 0 {
				currentTag := stack[len(stack)-1].tagName
				inRawText = rawTextElements[currentTag]
				inPreserveWS = preserveWhitespaceElements[currentTag]
			}

			if inRawText || inPreserveWS {
				// Preserve content exactly.
				w.Set(core.Green)
				w.Write(text)
				w.Reset()
			} else {
				// Skip text that is only whitespace (formatting whitespace in source).
				// For text with content, normalize by trimming leading/trailing whitespace
				// but preserve space between inline elements.
				trimmed := bytes.TrimSpace(text)
				if len(trimmed) > 0 {
					// Check if original text had leading/trailing spaces that should
					// be preserved for inline element separation.
					hasLeadingSpace := len(text) > 0 && (text[0] == ' ' || text[0] == '\t' || text[0] == '\n' || text[0] == '\r')
					hasTrailingSpace := len(text) > 0 && (text[len(text)-1] == ' ' || text[len(text)-1] == '\t' || text[len(text)-1] == '\n' || text[len(text)-1] == '\r')

					if hasLeadingSpace {
						w.WriteString(" ")
					}
					writeHTMLText(w, trimmed)
					if hasTrailingSpace {
						w.WriteString(" ")
					}
				}
			}

		case html.CommentToken:
			// Comments are treated like block elements.
			if len(stack) > 0 {
				if !stack[len(stack)-1].hasBlockChild {
					w.WriteString("\n")
				}
				stack[len(stack)-1].hasBlockChild = true
				writeIndent(w, len(stack))
			}
			w.WriteString("<!--")
			writeHTMLComment(w, tokenizer.Token().Data)
			w.WriteString("-->\n")
		}
	}
}

func writeHTMLTagName(p *core.Printer, s string) {
	p.Set(core.Bold)
	p.Set(core.Blue)
	p.WriteString(s)
	p.Reset()
}

func writeHTMLAttrName(p *core.Printer, s string) {
	p.Set(core.Cyan)
	p.WriteString(s)
	p.Reset()
}

func writeHTMLAttrVal(p *core.Printer, s string) {
	p.Set(core.Green)
	escapeHTMLAttrValue(p, s)
	p.Reset()
}

func writeHTMLText(p *core.Printer, t []byte) {
	p.Set(core.Green)
	p.Write(t)
	p.Reset()
}

func writeHTMLDoctype(p *core.Printer, t html.Token) {
	p.Set(core.Cyan)
	p.WriteString("DOCTYPE ")
	p.WriteString(t.Data)
	p.Reset()
}

func writeHTMLComment(p *core.Printer, s string) {
	p.Set(core.Dim)
	p.WriteString(s)
	p.Reset()
}

func writeHTMLAttributes(w *core.Printer, tokenizer *html.Tokenizer) {
	for {
		key, val, more := tokenizer.TagAttr()
		if len(key) == 0 && !more {
			break
		}
		if len(key) > 0 {
			w.WriteString(" ")
			writeHTMLAttrName(w, string(key))
			if len(val) > 0 {
				w.WriteString("=\"")
				writeHTMLAttrVal(w, string(val))
				w.WriteString("\"")
			}
		}
		if !more {
			break
		}
	}
}

// escapeHTMLAttrValue escapes special characters in HTML attribute values.
func escapeHTMLAttrValue(p *core.Printer, s string) {
	var last int
	for i := 0; i < len(s); i++ {
		var esc string
		switch s[i] {
		case '"':
			esc = "&quot;"
		case '&':
			esc = "&amp;"
		case '<':
			esc = "&lt;"
		case '>':
			esc = "&gt;"
		default:
			continue
		}
		p.WriteString(s[last:i])
		p.WriteString(esc)
		last = i + 1
	}
	p.WriteString(s[last:])
}
