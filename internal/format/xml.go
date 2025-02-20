package format

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/printer"
)

func FormatXML(r io.Reader, w *printer.Printer) error {
	dec := xml.NewDecoder(r)

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
				for _, attr := range t.Attr {
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

func writeXMLTagName(p *printer.Printer, s string) {
	p.Set(printer.Bold)
	p.Set(printer.Blue)
	escapeXMLString(p, s)
	p.Reset()
}

func writeXMLAttrName(p *printer.Printer, s string) {
	p.Set(printer.Cyan)
	escapeXMLString(p, s)
	p.Reset()
}

func writeXMLAttrVal(p *printer.Printer, s string) {
	p.Set(printer.Green)
	escapeXMLString(p, s)
	p.Reset()
}

func writeXMLText(p *printer.Printer, t []byte) {
	p.Set(printer.Green)
	escapeXMLString(p, string(t))
	p.Reset()
}

func writeXMLDirective(p *printer.Printer, b []byte) {
	p.Set(printer.Cyan)
	p.Write(b)
	p.Reset()
}

func writeXMLComment(p *printer.Printer, b []byte) {
	p.Set(printer.Dim)
	p.Write(b)
	p.Reset()
}

var equalChar = []byte("=")
var quoteChar = []byte("\"")

func writeXMLProcInst(p *printer.Printer, inst []byte) {
	// This isn't perfect, but should work in most cases.
	for pair := range bytes.FieldsSeq(inst) {
		p.WriteString(" ")

		key, val, ok := bytes.Cut(pair, equalChar)
		p.Set(printer.Cyan)
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
				p.Set(printer.Green)
				p.Write(val)
				p.Reset()
				p.Write(quoteChar)
				continue
			}
		}
		p.Set(printer.Cyan)
		p.Write(val)
		p.Reset()
	}
}

// Mostly taken from the Go encoding/xml package in the standard library:
// https://cs.opensource.google/go/go/+/refs/tags/go1.24.0:src/encoding/xml/xml.go;l=1964-1999
func escapeXMLString(p *printer.Printer, s string) {
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
