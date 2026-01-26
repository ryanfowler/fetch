package format

import (
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestFormatProtobuf(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantErr  bool
		contains []string
	}{
		{
			name:     "varint field",
			input:    appendVarint(nil, 1, 123),
			wantErr:  false,
			contains: []string{"1:", "(varint)", "123"},
		},
		{
			name:     "fixed64 field",
			input:    appendFixed64(nil, 2, 0x123456789abcdef0),
			wantErr:  false,
			contains: []string{"2:", "(fixed64)", "0x123456789abcdef0"},
		},
		{
			name:     "fixed32 field",
			input:    appendFixed32(nil, 3, 0x12345678),
			wantErr:  false,
			contains: []string{"3:", "(fixed32)", "0x12345678"},
		},
		{
			name:     "string field",
			input:    appendBytes(nil, 4, []byte("hello world")),
			wantErr:  false,
			contains: []string{"4:", "(bytes)", `"hello world"`},
		},
		{
			name:     "binary bytes field",
			input:    appendBytes(nil, 5, []byte{0x00, 0xff, 0x80}),
			wantErr:  false,
			contains: []string{"5:", "(bytes)", "<00 ff 80>"},
		},
		{
			name: "multiple fields",
			input: func() []byte {
				b := appendVarint(nil, 1, 42)
				b = appendBytes(b, 2, []byte("test"))
				return b
			}(),
			wantErr:  false,
			contains: []string{"1:", "42", "2:", `"test"`},
		},
		{
			name: "nested message",
			input: func() []byte {
				inner := appendVarint(nil, 1, 456)
				return appendBytes(nil, 3, inner)
			}(),
			wantErr:  false,
			contains: []string{"3:", "(message)", "{", "1:", "456", "}"},
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: false,
		},
		{
			name:    "invalid tag",
			input:   []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01},
			wantErr: true,
		},
		{
			name:    "truncated varint",
			input:   []byte{0x08, 0x80}, // field 1, varint, but varint is incomplete
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			err := FormatProtobuf(tt.input, p)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormatProtobuf() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			output := string(p.Bytes())
			for _, want := range tt.contains {
				if !strings.Contains(output, want) {
					t.Errorf("output should contain %q, got: %s", want, output)
				}
			}
		})
	}
}

func TestFormatProtobufNested(t *testing.T) {
	// Create a deeply nested message: field 1 contains field 2 contains field 3 with varint
	innermost := appendVarint(nil, 3, 789)
	middle := appendBytes(nil, 2, innermost)
	outer := appendBytes(nil, 1, middle)

	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatProtobuf(outer, p)
	if err != nil {
		t.Fatalf("FormatProtobuf() error = %v", err)
	}

	output := string(p.Bytes())

	// Check for proper nesting structure
	if !strings.Contains(output, "1:") {
		t.Error("output should contain field 1")
	}
	if !strings.Contains(output, "2:") {
		t.Error("output should contain field 2")
	}
	if !strings.Contains(output, "3:") {
		t.Error("output should contain field 3")
	}
	if !strings.Contains(output, "789") {
		t.Error("output should contain value 789")
	}
	if strings.Count(output, "{") != 2 || strings.Count(output, "}") != 2 {
		t.Errorf("output should have 2 nested messages, got: %s", output)
	}
}

func TestFormatProtobufAllWireTypes(t *testing.T) {
	// Build a message with all supported wire types
	b := appendVarint(nil, 1, 100)
	b = appendFixed64(b, 2, 200)
	b = appendFixed32(b, 3, 300)
	b = appendBytes(b, 4, []byte("string"))

	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatProtobuf(b, p)
	if err != nil {
		t.Fatalf("FormatProtobuf() error = %v", err)
	}

	output := string(p.Bytes())
	if !strings.Contains(output, "(varint)") {
		t.Error("output should contain varint wire type")
	}
	if !strings.Contains(output, "(fixed64)") {
		t.Error("output should contain fixed64 wire type")
	}
	if !strings.Contains(output, "(fixed32)") {
		t.Error("output should contain fixed32 wire type")
	}
	if !strings.Contains(output, "(bytes)") {
		t.Error("output should contain bytes wire type")
	}
}

func TestIsValidProtobuf(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "empty",
			input: []byte{},
			want:  false,
		},
		{
			name:  "valid varint",
			input: appendVarint(nil, 1, 123),
			want:  true,
		},
		{
			name:  "valid multiple fields",
			input: appendBytes(appendVarint(nil, 1, 1), 2, []byte("test")),
			want:  true,
		},
		{
			name:  "invalid tag",
			input: []byte{0x00}, // field number 0 is invalid
			want:  false,
		},
		{
			name:  "truncated",
			input: []byte{0x08}, // field 1, varint, but no value
			want:  false,
		},
		{
			name:  "random bytes",
			input: []byte{0xff, 0xff, 0xff},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidProtobuf(tt.input)
			if got != tt.want {
				t.Errorf("isValidProtobuf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPrintableBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "ascii text",
			input: []byte("hello world"),
			want:  true,
		},
		{
			name:  "unicode text",
			input: []byte("hello 世界"),
			want:  true,
		},
		{
			name:  "with newline",
			input: []byte("hello\nworld"),
			want:  true,
		},
		{
			name:  "with tab",
			input: []byte("hello\tworld"),
			want:  true,
		},
		{
			name:  "binary data",
			input: []byte{0x00, 0x01, 0x02},
			want:  false,
		},
		{
			name:  "invalid utf8",
			input: []byte{0xff, 0xfe},
			want:  false,
		},
		{
			name:  "empty",
			input: []byte{},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrintableBytes(tt.input)
			if got != tt.want {
				t.Errorf("isPrintableBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteProtobufString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple string",
			input: "hello",
			want:  `"hello"`,
		},
		{
			name:  "with newline",
			input: "hello\nworld",
			want:  `"hello\nworld"`,
		},
		{
			name:  "with tab",
			input: "hello\tworld",
			want:  `"hello\tworld"`,
		},
		{
			name:  "with quotes",
			input: `say "hello"`,
			want:  `"say \"hello\""`,
		},
		{
			name:  "with backslash",
			input: `path\to\file`,
			want:  `"path\\to\\file"`,
		},
		{
			name:  "with carriage return",
			input: "hello\rworld",
			want:  `"hello\rworld"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			writeProtobufString(p, tt.input)
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("writeProtobufString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteProtobufBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "single byte",
			input: []byte{0xab},
			want:  "<ab>",
		},
		{
			name:  "multiple bytes",
			input: []byte{0x00, 0xff, 0x80},
			want:  "<00 ff 80>",
		},
		{
			name:  "empty",
			input: []byte{},
			want:  "<>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			writeProtobufBytes(p, tt.input)
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("writeProtobufBytes() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Helper functions to build protobuf test data

func appendVarint(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.VarintType)
	b = protowire.AppendVarint(b, v)
	return b
}

func appendFixed64(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.Fixed64Type)
	b = protowire.AppendFixed64(b, v)
	return b
}

func appendFixed32(b []byte, num protowire.Number, v uint32) []byte {
	b = protowire.AppendTag(b, num, protowire.Fixed32Type)
	b = protowire.AppendFixed32(b, v)
	return b
}

func appendBytes(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	b = protowire.AppendBytes(b, v)
	return b
}
