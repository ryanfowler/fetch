package format

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/ryanfowler/fetch/internal/core"
)

// FormatJSONLine formats the provided raw JSON data as a single compact line
// to the Printer.
func FormatJSONLine(buf []byte, p *core.Printer) error {
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.UseNumber()
	err := formatNDJSONValue(dec, p)
	if err != nil {
		p.Discard()
		return err
	}
	tok, err := dec.Token()
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

func formatNDJSONValue(dec *json.Decoder, p *core.Printer) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}

	return formatNDJSONValueToken(dec, p, token)
}

func formatNDJSONValueToken(dec *json.Decoder, p *core.Printer, token any) error {
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			return formatNDJSONObject(dec, p)
		case '[':
			return formatNDJSONArray(dec, p)
		case ']', '}':
			return fmt.Errorf("unexpected token: %q", t)
		}
		p.WriteString(string(t))
	case bool:
		p.WriteString(strconv.FormatBool(t))
	case string:
		writeJSONString(p, t)
	case json.Number:
		p.WriteString(string(t))
	case nil:
		p.WriteString("null")
	}

	return nil
}

func formatNDJSONObject(dec *json.Decoder, p *core.Printer) error {
	p.WriteString("{")

	var hasFields bool
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}

		switch t := tok.(type) {
		case json.Delim:
			if t != '}' {
				return fmt.Errorf("unexpected token: %q", string(t))
			}
			if hasFields {
				p.WriteString(" ")
			}
			p.WriteString("}")
			return nil
		case string:
			if hasFields {
				p.WriteString(",")
			}
			p.WriteString(" ")
			hasFields = true
			writeJSONKey(p, t)

			err = formatNDJSONValue(dec, p)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected token: %q", t)
		}
	}
}

func formatNDJSONArray(dec *json.Decoder, p *core.Printer) error {
	p.WriteString("[")

	var hasFields bool
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}

		if t, ok := tok.(json.Delim); ok && t == ']' {
			p.WriteString("]")
			return nil
		}

		if hasFields {
			p.WriteString(", ")
		}
		hasFields = true

		err = formatNDJSONValueToken(dec, p, tok)
		if err != nil {
			return err
		}
	}
}
