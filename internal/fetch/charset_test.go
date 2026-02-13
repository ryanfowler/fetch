package fetch

import (
	"io"
	"strings"
	"testing"
)

func TestCharsetDecoder(t *testing.T) {
	tests := []struct {
		charset string
		wantNil bool
	}{
		{"", true},
		{"utf-8", true},
		{"UTF-8", true},
		{"utf8", true},
		{"us-ascii", true},
		{"ascii", true},
		{"US-ASCII", true},
		{"ASCII", true},
		{"iso-8859-1", false},
		{"ISO-8859-1", false},
		{"windows-1252", false},
		{"shift_jis", false},
		{"euc-kr", false},
		{"not-a-real-charset", true},
	}
	for _, tt := range tests {
		t.Run(tt.charset, func(t *testing.T) {
			dec := charsetDecoder(tt.charset)
			if (dec == nil) != tt.wantNil {
				t.Errorf("charsetDecoder(%q) nil=%v, want nil=%v", tt.charset, dec == nil, tt.wantNil)
			}
		})
	}
}

func TestTranscodeBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		charset string
		want    string
	}{
		{
			name:    "latin1 cafe",
			input:   []byte{0x63, 0x61, 0x66, 0xe9},
			charset: "iso-8859-1",
			want:    "caf\u00e9",
		},
		{
			name:    "windows-1252 curly quotes",
			input:   []byte{0x93, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x94},
			charset: "windows-1252",
			want:    "\u201chello\u201d",
		},
		{
			name:    "empty charset returns unchanged",
			input:   []byte("hello"),
			charset: "",
			want:    "hello",
		},
		{
			name:    "utf-8 charset returns unchanged",
			input:   []byte("hello"),
			charset: "utf-8",
			want:    "hello",
		},
		{
			name:    "unknown charset returns unchanged",
			input:   []byte("hello"),
			charset: "not-a-real-charset",
			want:    "hello",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := transcodeBytes(tt.input, tt.charset)
			if string(got) != tt.want {
				t.Errorf("transcodeBytes(%v, %q) = %q, want %q", tt.input, tt.charset, got, tt.want)
			}
		})
	}
}

func TestTranscodeReader(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		charset string
		want    string
	}{
		{
			name:    "latin1 cafe",
			input:   []byte{0x63, 0x61, 0x66, 0xe9},
			charset: "iso-8859-1",
			want:    "caf\u00e9",
		},
		{
			name:    "empty charset passes through",
			input:   []byte("hello"),
			charset: "",
			want:    "hello",
		},
		{
			name:    "utf-8 charset passes through",
			input:   []byte("hello"),
			charset: "utf-8",
			want:    "hello",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := transcodeReader(strings.NewReader(string(tt.input)), tt.charset)
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("transcodeReader result = %q, want %q", got, tt.want)
			}
		})
	}
}
