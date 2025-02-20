package format

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/ryanfowler/fetch/internal/printer"
)

func FormatJSON(r io.Reader, p *printer.Printer) error {
	dec := json.NewDecoder(r)
	err := formatJSONValue(dec, p, 0)
	if errors.Is(err, io.EOF) {
		p.WriteString("\n")
		return nil
	}
	if err != nil {
		return err
	}
	if dec.More() {
		return io.ErrUnexpectedEOF
	}
	p.WriteString("\n")
	return nil
}

func formatJSONValue(dec *json.Decoder, p *printer.Printer, indent int) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}

	return formatJSONValueToken(dec, p, indent, token)
}

func formatJSONValueToken(dec *json.Decoder, p *printer.Printer, indent int, token any) error {
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			return formatJSONObject(dec, p, indent)
		case '[':
			return formatJSONArray(dec, p, indent)
		case ']', '}':
			return fmt.Errorf("unexpected token: %q", t)
		}
		p.WriteString(string(t))
	case bool:
		p.WriteString(strconv.FormatBool(t))
	case string:
		writeJSONString(p, t)
	case float64:
		p.WriteString(strconv.FormatFloat(t, 'f', -1, 64))
	case json.Number:
		p.WriteString(string(t))
	case nil:
		p.WriteString("null")
	}

	return nil
}

func formatJSONObject(dec *json.Decoder, p *printer.Printer, indent int) error {
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
				p.WriteString("\n")
				writeIndent(p, indent)
			}
			p.WriteString("}")
			return nil
		case string:
			if hasFields {
				p.WriteString(",")
			}
			p.WriteString("\n")
			writeIndent(p, indent+1)
			hasFields = true
			writeJSONKey(p, t)

			err = formatJSONValue(dec, p, indent+1)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected token: %q", t)
		}
	}
}

func formatJSONArray(dec *json.Decoder, p *printer.Printer, indent int) error {
	p.WriteString("[")

	var hasFields bool
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}

		if t, ok := tok.(json.Delim); ok && t == ']' {
			if hasFields {
				p.WriteString("\n")
				writeIndent(p, indent)
			}
			p.WriteString("]")
			return nil
		}

		if hasFields {
			p.WriteString(",")
		}
		p.WriteString("\n")
		writeIndent(p, indent+1)
		hasFields = true

		err = formatJSONValueToken(dec, p, indent+1, tok)
		if err != nil {
			return err
		}
	}
}

func writeJSONKey(p *printer.Printer, s string) {
	p.WriteString("\"")
	p.Set(printer.Blue)
	p.Set(printer.Bold)
	escapeJSONString(p, s)
	p.Reset()
	p.WriteString("\": ")
}

func writeJSONString(p *printer.Printer, s string) {
	p.WriteString("\"")
	p.Set(printer.Green)
	escapeJSONString(p, s)
	p.Reset()
	p.WriteString("\"")
}

func escapeJSONString(p *printer.Printer, s string) {
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
			p.WriteRune(c)
		}
	}
}
