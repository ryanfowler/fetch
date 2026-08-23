package format

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"

	"github.com/ryanfowler/fetch/internal/core"
)

// FormatJSON formats the provided raw JSON data to the Printer.
func FormatJSON(buf []byte, p *core.Printer) error {
	err := formatJSON(bytes.NewReader(buf), p)
	if err != nil {
		p.Discard()
	}
	return err
}

func formatJSON(r io.Reader, p *core.Printer) error {
	dec := jsontext.NewDecoder(r)
	if err := formatJSONValue(dec, p, 0); err != nil {
		return err
	}

	// Ensure that there are no more tokens left.
	tok, err := dec.ReadToken()
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("unexpected token: %v", tok)
	}

	p.WriteString("\n")
	return p.Err()
}

func formatJSONValue(dec *jsontext.Decoder, p *core.Printer, indent int) error {
	if err := p.Err(); err != nil {
		return err
	}
	token, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if err := formatJSONValueToken(dec, p, indent, token); err != nil {
		return err
	}
	return p.Err()
}

func formatJSONValueToken(dec *jsontext.Decoder, p *core.Printer, indent int, token jsontext.Token) error {
	if indent > core.MaxFormatterNestingDepth {
		return core.LimitError{Subsystem: "JSON nesting depth", Limit: core.MaxFormatterNestingDepth}
	}

	switch token.Kind() {
	case jsontext.KindBeginObject:
		return formatJSONObject(dec, p, indent)
	case jsontext.KindBeginArray:
		return formatJSONArray(dec, p, indent)
	case jsontext.KindEndObject, jsontext.KindEndArray:
		return fmt.Errorf("unexpected token: %q", token.String())
	case jsontext.KindTrue, jsontext.KindFalse, jsontext.KindNull, jsontext.KindNumber:
		p.WriteString(token.String())
	case jsontext.KindString:
		writeJSONString(p, token.String())
	default:
		return fmt.Errorf("unexpected token: %q", token.String())
	}
	return p.Err()
}

func formatJSONObject(dec *jsontext.Decoder, p *core.Printer, indent int) error {
	p.WriteString("{")
	if err := p.Err(); err != nil {
		return err
	}

	var hasFields bool
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return err
		}

		switch tok.Kind() {
		case jsontext.KindEndObject:
			if hasFields {
				p.WriteString("\n")
				writeIndent(p, indent)
			}
			p.WriteString("}")
			return p.Err()
		case jsontext.KindString:
			if hasFields {
				p.WriteString(",")
			}
			p.WriteString("\n")
			writeIndent(p, indent+1)
			hasFields = true
			writeJSONKey(p, tok.String())

			if err := formatJSONValue(dec, p, indent+1); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected token: %q", tok.String())
		}
	}
}

func formatJSONArray(dec *jsontext.Decoder, p *core.Printer, indent int) error {
	p.WriteString("[")
	if err := p.Err(); err != nil {
		return err
	}

	var hasFields bool
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return err
		}

		if tok.Kind() == jsontext.KindEndArray {
			if hasFields {
				p.WriteString("\n")
				writeIndent(p, indent)
			}
			p.WriteString("]")
			return p.Err()
		}

		if hasFields {
			p.WriteString(",")
		}
		p.WriteString("\n")
		writeIndent(p, indent+1)
		hasFields = true

		if err := formatJSONValueToken(dec, p, indent+1, tok); err != nil {
			return err
		}
	}
}

func writeJSONKey(p *core.Printer, s string) {
	p.WriteString("\"")
	p.Set(core.Blue)
	p.Set(core.Bold)
	escapeJSONString(p, s)
	p.Reset()
	p.WriteString("\": ")
}

func writeJSONString(p *core.Printer, s string) {
	p.WriteString("\"")
	p.Set(core.Green)
	escapeJSONString(p, s)
	p.Reset()
	p.WriteString("\"")
}

func escapeJSONString(p *core.Printer, s string) {
	for _, c := range s {
		switch c {
		case '\b':
			p.WriteString(`\b`)
		case '\f':
			p.WriteString(`\f`)
		case '\n':
			p.WriteString(`\n`)
		case '\r':
			p.WriteString(`\r`)
		case '\t':
			p.WriteString(`\t`)
		case '"':
			p.WriteString(`\"`)
		case '\\':
			p.WriteString(`\\`)
		default:
			if c < 0x20 || (c >= 0x7f && c <= 0x9f) {
				fmt.Fprintf(p, "\\u%04x", c)
			} else {
				p.WriteRune(c)
			}
		}
	}
}
