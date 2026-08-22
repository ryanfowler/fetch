package format

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"

	"github.com/ryanfowler/fetch/internal/core"
)

// FormatJSONLine formats the provided raw JSON data as a single compact line
// to the Printer.
func FormatJSONLine(buf []byte, p *core.Printer) error {
	dec := jsontext.NewDecoder(bytes.NewReader(buf))
	err := formatNDJSONValue(dec, p)
	if err != nil {
		p.Discard()
		return err
	}
	tok, err := dec.ReadToken()
	if !errors.Is(err, io.EOF) {
		p.Discard()
		return fmt.Errorf("unexpected token: %v", tok)
	}
	p.WriteString("\n")
	return nil
}

// FormatNDJSON streams newline-delimited JSON to the Printer, flushing after
// each record. It uses explicit line boundaries so a partial record never
// causes the decoder to retain an unbounded stream prefix.
func FormatNDJSON(r io.Reader, p *core.Printer) error {
	lines := newLineReader(r)
	lineNumber := 0
	for {
		line, ok, err := lines.next()
		if err != nil {
			p.Discard()
			return formatStreamingError("NDJSON", lineNumber+1, err)
		}
		if !ok {
			return nil
		}
		lineNumber++
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		if err := FormatJSONLine(line, p); err != nil {
			p.Discard()
			return formatStreamingError("NDJSON", lineNumber, err)
		}
		if err := p.Flush(); err != nil {
			p.Discard()
			return err
		}
	}
}

func formatNDJSONValue(dec *jsontext.Decoder, p *core.Printer) error {
	token, err := dec.ReadToken()
	if err != nil {
		return err
	}
	return formatNDJSONValueToken(dec, p, token)
}

func formatNDJSONValueToken(dec *jsontext.Decoder, p *core.Printer, token jsontext.Token) error {
	switch token.Kind() {
	case jsontext.KindBeginObject:
		return formatNDJSONObject(dec, p)
	case jsontext.KindBeginArray:
		return formatNDJSONArray(dec, p)
	case jsontext.KindEndObject, jsontext.KindEndArray:
		return fmt.Errorf("unexpected token: %q", token.String())
	case jsontext.KindTrue, jsontext.KindFalse, jsontext.KindNull, jsontext.KindNumber:
		p.WriteString(token.String())
	case jsontext.KindString:
		writeJSONString(p, token.String())
	default:
		return fmt.Errorf("unexpected token: %q", token.String())
	}
	return nil
}

func formatNDJSONObject(dec *jsontext.Decoder, p *core.Printer) error {
	p.WriteString("{")

	var hasFields bool
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return err
		}

		switch tok.Kind() {
		case jsontext.KindEndObject:
			if hasFields {
				p.WriteString(" ")
			}
			p.WriteString("}")
			return nil
		case jsontext.KindString:
			if hasFields {
				p.WriteString(",")
			}
			p.WriteString(" ")
			hasFields = true
			writeJSONKey(p, tok.String())

			if err := formatNDJSONValue(dec, p); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected token: %q", tok.String())
		}
	}
}

func formatNDJSONArray(dec *jsontext.Decoder, p *core.Printer) error {
	p.WriteString("[")

	var hasFields bool
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return err
		}

		if tok.Kind() == jsontext.KindEndArray {
			p.WriteString("]")
			return nil
		}

		if hasFields {
			p.WriteString(", ")
		}
		hasFields = true

		if err := formatNDJSONValueToken(dec, p, tok); err != nil {
			return err
		}
	}
}
