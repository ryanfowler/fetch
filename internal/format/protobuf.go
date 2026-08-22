package format

import (
	"fmt"
	"io"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
	fetchproto "github.com/ryanfowler/fetch/internal/proto"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// FormatProtobuf formats the provided raw protobuf data to the Printer.
func FormatProtobuf(buf []byte, p *core.Printer) error {
	// Format into a private printer first. Besides preventing partial output on
	// malformed input, this gives the schema-less formatter one bounded output
	// surface before it is appended to the caller's printer.
	out := p.NewWriter(io.Discard)
	bounded := &boundedProtobufPrinter{p: out, max: core.MaxFormattedBodyBytes}
	state := protobufFormatState{}
	err := formatProtobuf(buf, bounded, 0, 0, &state)
	if err == nil {
		err = bounded.err
	}
	if err != nil {
		p.Discard()
		return err
	}
	_, _ = p.Write(out.Bytes())
	return nil
}

// FormatProtobufWithSchema formats protobuf data as JSON using the provided schema.
func FormatProtobufWithSchema(buf []byte, schema *fetchproto.Schema, typeName string, p *core.Printer) error {
	md, err := schema.FindMessage(typeName)
	if err != nil {
		return err
	}

	return FormatProtobufWithDescriptor(buf, md, p)
}

// FormatProtobufWithDescriptor formats protobuf data as JSON using a message descriptor.
func FormatProtobufWithDescriptor(buf []byte, md protoreflect.MessageDescriptor, p *core.Printer) error {
	msg := dynamicpb.NewMessage(md)
	if err := proto.Unmarshal(buf, msg); err != nil {
		return err
	}

	// Marshal to JSON.
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}

	jsonBytes, err := opts.Marshal(msg)
	if err != nil {
		return err
	}

	// Format the JSON with syntax highlighting.
	return FormatJSON(jsonBytes, p)
}

type protobufFormatState struct {
	fields int
}

// protobufOutput is the small part of Printer used by the schema-less
// formatter. Keeping this interface also lets the existing formatting helpers
// remain directly testable with a normal Printer.
type protobufOutput interface {
	Set(core.Sequence)
	Reset()
	WriteString(string) (int, error)
	WriteRune(rune) (int, error)
}

// boundedProtobufPrinter prevents a descriptor-less message from expanding
// the output buffer without limit. Printer itself intentionally has no size
// policy, so the formatter applies one at its deepest write boundary.
type boundedProtobufPrinter struct {
	p   *core.Printer
	max int64
	err error
}

func (w *boundedProtobufPrinter) reserve(n int) bool {
	if w.err != nil {
		return false
	}
	if n < 0 || int64(len(w.p.Bytes())) > w.max-int64(n) {
		w.err = core.LimitError{Subsystem: "schema-less protobuf output", Limit: w.max}
		return false
	}
	return true
}

func (w *boundedProtobufPrinter) Set(s core.Sequence) {
	if w.reserve(len(string(s)) + 3) {
		w.p.Set(s)
	}
}

func (w *boundedProtobufPrinter) Reset() { w.Set(core.Sequence("0")) }

func (w *boundedProtobufPrinter) WriteString(s string) (int, error) {
	if !w.reserve(len(s)) {
		return 0, w.err
	}
	return w.p.WriteString(s)
}

func (w *boundedProtobufPrinter) WriteRune(r rune) (int, error) {
	n := utf8.RuneLen(r)
	if n < 0 {
		n = 3
	}
	if !w.reserve(n) {
		return 0, w.err
	}
	return w.p.WriteRune(r)
}

func formatProtobuf(buf []byte, p protobufOutput, indent, depth int, state *protobufFormatState) error {
	for len(buf) > 0 {
		state.fields++
		if state.fields > core.MaxSchemaLessProtobufFields {
			return core.LimitError{Subsystem: "schema-less protobuf fields", Limit: core.MaxSchemaLessProtobufFields}
		}
		num, wtype, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return protowire.ParseError(n)
		}
		buf = buf[n:]

		writeIndent(p, indent)
		writeFieldNumber(p, num)

		switch wtype {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(buf)
			if n < 0 {
				return protowire.ParseError(n)
			}
			buf = buf[n:]
			writeWireType(p, "varint")
			p.WriteString(" ")
			p.WriteString(strconv.FormatUint(v, 10))
			p.WriteString("\n")

		case protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(buf)
			if n < 0 {
				return protowire.ParseError(n)
			}
			buf = buf[n:]
			writeWireType(p, "fixed64")
			p.WriteString(" ")
			p.WriteString(fmt.Sprintf("0x%016x", v))
			p.WriteString("\n")

		case protowire.Fixed32Type:
			v, n := protowire.ConsumeFixed32(buf)
			if n < 0 {
				return protowire.ParseError(n)
			}
			buf = buf[n:]
			writeWireType(p, "fixed32")
			p.WriteString(" ")
			p.WriteString(fmt.Sprintf("0x%08x", v))
			p.WriteString("\n")

		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return protowire.ParseError(n)
			}
			buf = buf[n:]

			// Try to parse as nested message.
			if depth < core.MaxNestingDepth && isValidProtobuf(v) {
				writeWireType(p, "message")
				p.WriteString(" {\n")
				err := formatProtobuf(v, p, indent+1, depth+1, state)
				if err != nil {
					return err
				}
				writeIndent(p, indent)
				p.WriteString("}\n")
			} else if isPrintableBytes(v) {
				writeWireType(p, "bytes")
				p.WriteString(" ")
				writeProtobufString(p, string(v))
				p.WriteString("\n")
			} else {
				writeWireType(p, "bytes")
				p.WriteString(" ")
				writeProtobufBytes(p, v)
				p.WriteString("\n")
			}

		case protowire.StartGroupType, protowire.EndGroupType:
			// Groups are deprecated; skip them.
			return fmt.Errorf("deprecated group wire type")

		default:
			return fmt.Errorf("unknown wire type: %d", wtype)
		}
	}
	return nil
}

// isValidProtobuf checks if the bytes can be parsed as a valid protobuf message.
func isValidProtobuf(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}

	for len(buf) > 0 {
		num, wtype, n := protowire.ConsumeTag(buf)
		if n < 0 || num == 0 {
			return false
		}
		buf = buf[n:]

		switch wtype {
		case protowire.VarintType:
			_, n = protowire.ConsumeVarint(buf)
		case protowire.Fixed64Type:
			_, n = protowire.ConsumeFixed64(buf)
		case protowire.Fixed32Type:
			_, n = protowire.ConsumeFixed32(buf)
		case protowire.BytesType:
			_, n = protowire.ConsumeBytes(buf)
		case protowire.StartGroupType, protowire.EndGroupType:
			return false
		default:
			return false
		}
		if n < 0 {
			return false
		}
		buf = buf[n:]
	}
	return true
}

// isPrintableBytes returns true if the bytes are printable UTF-8 text.
func isPrintableBytes(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func writeFieldNumber(p protobufOutput, num protowire.Number) {
	p.Set(core.Blue)
	p.Set(core.Bold)
	p.WriteString(strconv.FormatInt(int64(num), 10))
	p.Reset()
	p.WriteString(":")
}

func writeWireType(p protobufOutput, wtype string) {
	p.WriteString(" ")
	p.Set(core.Dim)
	p.WriteString("(")
	p.WriteString(wtype)
	p.WriteString(")")
	p.Reset()
}

func writeProtobufString(p protobufOutput, s string) {
	p.WriteString("\"")
	p.Set(core.Green)
	for _, c := range s {
		switch c {
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
			if c < 0x20 || c == 0x7f {
				p.WriteString(fmt.Sprintf("\\u%04x", c))
			} else {
				p.WriteRune(c)
			}
		}
	}
	p.Reset()
	p.WriteString("\"")
}

func writeProtobufBytes(p protobufOutput, b []byte) {
	p.Set(core.Yellow)
	p.WriteString("<")
	for i, byt := range b {
		if i > 0 {
			p.WriteString(" ")
		}
		p.WriteString(fmt.Sprintf("%02x", byt))
	}
	p.WriteString(">")
	p.Reset()
}
