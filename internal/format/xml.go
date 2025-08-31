package format

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
)

// FormatXML formats the provided XML to the Printer.
func FormatXML(buf []byte, w *core.Printer) error {
	dec := xml.NewDecoder(bytes.NewReader(buf))

	var stack []bool
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) > 0 && !stack[len(stack)-1] {
				w.WriteString("\n")
			}
			writeIndent(w, len(stack))
			w.WriteString("<")
			writeXMLTagName(w, t.Name.Local)
			if len(t.Attr) > 0 {
				w.WriteString(" ")
				for i, attr := range t.Attr {
					if i > 0 {
						w.WriteString(" ")
					}
					writeXMLAttrName(w, attr.Name.Local)
					w.WriteString("=\"")
					writeXMLAttrVal(w, attr.Value)
					w.WriteString("\"")
				}
			}
			w.WriteString(">")

			if len(stack) > 0 {
				stack[len(stack)-1] = true
			}
			stack = append(stack, false)
		case xml.EndElement:
			last := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			if last {
				writeIndent(w, len(stack))
			}

			w.WriteString("</")
			writeXMLTagName(w, t.Name.Local)
			w.WriteString(">\n")
		case xml.CharData:
			text := bytes.TrimSpace(t)
			if len(text) > 0 {
				writeXMLText(w, text)
			}
		case xml.Comment:
			writeIndent(w, len(stack))
			w.WriteString("<!--")
			writeXMLComment(w, t)
			w.WriteString("-->\n")
		case xml.ProcInst:
			writeIndent(w, len(stack))
			w.WriteString("<?")
			writeXMLTagName(w, t.Target)
			writeXMLProcInst(w, t.Inst)
			w.WriteString("?>\n")
		case xml.Directive:
			writeIndent(w, len(stack))
			w.WriteString("<!")
			writeXMLDirective(w, t)
			w.WriteString(">\n")
		}
	}
}

func writeXMLTagName(p *core.Printer, s string) {
	p.Set(core.Bold)
	p.Set(core.Blue)
	escapeXMLString(p, s)
	p.Reset()
}

func writeXMLAttrName(p *core.Printer, s string) {
	p.Set(core.Cyan)
	escapeXMLString(p, s)
	p.Reset()
}

func writeXMLAttrVal(p *core.Printer, s string) {
	p.Set(core.Green)
	escapeXMLString(p, s)
	p.Reset()
}

func writeXMLText(p *core.Printer, t []byte) {
	p.Set(core.Green)
	escapeXMLString(p, string(t))
	p.Reset()
}

func writeXMLDirective(p *core.Printer, b []byte) {
	p.Set(core.Cyan)
	p.Write(b)
	p.Reset()
}

func writeXMLComment(p *core.Printer, b []byte) {
	p.Set(core.Dim)
	p.Write(b)
	p.Reset()
}

var equalChar = []byte("=")
var quoteChar = []byte("\"")

func writeXMLProcInst(p *core.Printer, inst []byte) {
	// This isn't perfect, but should work in most cases. This will break
	// when a field contains whitespace.
	for pair := range bytes.FieldsSeq(inst) {
		p.WriteString(" ")

		key, val, ok := bytes.Cut(pair, equalChar)
		p.Set(core.Cyan)
		p.Write(key)
		p.Reset()
		if !ok {
			continue
		}

		p.WriteString("=")
		val, ok = bytes.CutPrefix(val, quoteChar)
		if ok {
			p.Write(quoteChar)
			val, ok = bytes.CutSuffix(val, quoteChar)
			if ok {
				p.Set(core.Green)
				p.Write(val)
				p.Reset()
				p.Write(quoteChar)
				continue
			}
		}
		p.Set(core.Cyan)
		p.Write(val)
		p.Reset()
	}
}

// Mostly taken from the Go encoding/xml package in the standard library:
// https://cs.opensource.google/go/go/+/refs/tags/go1.24.0:src/encoding/xml/xml.go;l=1964-1999
func escapeXMLString(p *core.Printer, s string) {
	var esc string
	var last int
	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		i += width
		switch r {
		case '"':
			esc = "&quot;"
		case '\'':
			esc = "&apos;"
		case '&':
			esc = "&amp;"
		case '<':
			esc = "&lt;"
		case '>':
			esc = "&gt;"
		case '\t':
			esc = "&#x9;"
		case '\n':
			esc = "&#xA;"
		case '\r':
			esc = "&#xD;"
		default:
			if !isInCharacterRange(r) || (r == 0xFFFD && width == 1) {
				esc = "\uFFFD"
				break
			}
			continue
		}
		p.WriteString(s[last : i-width])
		p.WriteString(esc)
		last = i
	}
	p.WriteString(s[last:])
}

// Decide whether the given rune is in the XML Character Range, per
// the Char production of https://www.xml.com/axml/testaxml.htm,
// Section 2.2 Characters.
func isInCharacterRange(r rune) (inrange bool) {
	return r == 0x09 ||
		r == 0x0A ||
		r == 0x0D ||
		r >= 0x20 && r <= 0xD7FF ||
		r >= 0xE000 && r <= 0xFFFD ||
		r >= 0x10000 && r <= 0x10FFFF
}
