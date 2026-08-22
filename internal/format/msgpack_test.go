package format

import (
	"bytes"
	"encoding/json/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/tinylib/msgp/msgp"
)

func TestFormatMsgPack(t *testing.T) {
	v := map[string]string{
		"key1": "val1",
		"key2": "val2",
	}

	var buf bytes.Buffer
	w := msgp.NewWriter(&buf)
	w.WriteIntf(v)
	if err := w.Flush(); err != nil {
		t.Fatalf("unable to encode msgpack map: %s", err.Error())
	}

	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatMsgPack(buf.Bytes(), p)
	if err != nil {
		t.Fatalf("unable to format msgpack data: %s", err.Error())
	}

	var out map[string]string
	err = json.Unmarshal(p.Bytes(), &out)
	if err != nil {
		t.Fatalf("unable to unmarshal json output: %s", err.Error())
	}

	if !reflect.DeepEqual(v, out) {
		t.Fatalf("unexpected output: %+v", out)
	}
}

func TestFormatMsgPackHardenedInput(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr string
		want    string
	}{
		{
			name:  "empty string key",
			input: []byte{0x81, 0xa0, 0x01},
			want:  `"": 1`,
		},
		{
			name:  "binary value is base64",
			input: []byte{0xc4, 0x02, 0x00, 0xff},
			want:  `"AP8="`,
		},
		{
			name:  "float32 keeps float32 precision",
			input: []byte{0xca, 0x3f, 0x8c, 0xcc, 0xcd},
			want:  "1.1",
		},
		{
			name:  "binary key with utf8 contents",
			input: []byte{0x81, 0xc4, 0x03, 'b', 'i', 'n', 0x01},
			want:  `"Ymlu": 1`,
		},
		{
			name:    "invalid string utf8",
			input:   []byte{0xa1, 0xe0},
			wantErr: "invalid UTF-8 in MessagePack str",
		},
		{
			name:  "arbitrary binary key is base64",
			input: []byte{0x81, 0xc4, 0x01, 0xe0, 0x01},
			want:  `"4A==": 1`,
		},
		{
			name:    "unsupported map key",
			input:   []byte{0x81, 0xc0, 0x01},
			wantErr: "unsupported MessagePack map key type",
		},
		{
			name:    "duplicate converted map keys",
			input:   []byte{0x82, 0xa1, '1', 0x01, 0x01, 0x02},
			wantErr: "duplicate MessagePack map key after JSON conversion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			err := FormatMsgPack(tt.input, p)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("FormatMsgPack() error = %v", err)
				}
				if !strings.Contains(string(p.Bytes()), tt.want) {
					t.Fatalf("output does not contain %q: %s", tt.want, p.Bytes())
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("FormatMsgPack() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestFormatMsgPackRejectsDeepNesting(t *testing.T) {
	input := []byte{0x00}
	for i := 0; i <= core.MaxNestingDepth; i++ {
		input = append([]byte{0x91}, input...)
	}
	p := core.TestPrinter(false)
	if err := FormatMsgPack(input, p); err == nil || !strings.Contains(err.Error(), "MessagePack nesting too deep") {
		t.Fatalf("FormatMsgPack() error = %v, want nesting error", err)
	}
}
