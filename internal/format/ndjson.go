package format

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/ryanfowler/fetch/internal/printer"
)

func FormatNDJSON(r io.Reader, p *printer.Printer) error {
	dec := json.NewDecoder(r)
	for dec.More() {
		err := formatNDJSONValue(dec, p)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		p.WriteString("\n")
		p.Flush()
	}
	return nil
}

func formatNDJSONValue(dec *json.Decoder, p *printer.Printer) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}

	return formatNDJSONValueToken(dec, p, token)
}

func formatNDJSONValueToken(dec *json.Decoder, p *printer.Printer, token any) error {
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
	case float64:
		p.WriteString(strconv.FormatFloat(t, 'f', -1, 64))
	case json.Number:
		p.WriteString(string(t))
	case nil:
		p.WriteString("null")
	}

	return nil
}

func formatNDJSONObject(dec *json.Decoder, p *printer.Printer) error {
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

func formatNDJSONArray(dec *json.Decoder, p *printer.Printer) error {
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
