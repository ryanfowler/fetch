package format

import (
	"io"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFormatNDJSONHandlesChunkBoundariesAndCRLF(t *testing.T) {
	p := core.TestPrinter(false)
	input := &chunkReader{chunks: [][]byte{
		[]byte(`{"id":`), []byte(`1}`), []byte("\r"), []byte("\n"),
		[]byte(`{"id":2}`), []byte("\n"),
	}}

	if err := FormatNDJSON(input, p); err != nil {
		t.Fatalf("FormatNDJSON() error = %v", err)
	}
	want := "{ \"id\": 1 }\n{ \"id\": 2 }\n"
	if got := string(p.Bytes()); got != want {
		t.Fatalf("FormatNDJSON() = %q, want %q", got, want)
	}
}

func TestFormatNDJSONRejectsAnOversizedRecord(t *testing.T) {
	p := core.TestPrinter(false)
	input := strings.NewReader(strings.Repeat("x", int(maxStreamingRecordBytes+1)))
	if err := FormatNDJSON(input, p); err == nil {
		t.Fatal("FormatNDJSON() accepted an oversized record")
	}
}

func TestFormatJSONLine(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple object",
			input: `{"key":"value"}`,
			want:  "{ \"key\": \"value\" }\n",
		},
		{
			name:  "nested object",
			input: `{"a":{"b":"c"}}`,
			want:  "{ \"a\": { \"b\": \"c\" } }\n",
		},
		{
			name:  "array",
			input: `[1,2,3]`,
			want:  "[1, 2, 3]\n",
		},
		{
			name:  "scalar string",
			input: `"hello"`,
			want:  "\"hello\"\n",
		},
		{
			name:  "scalar number",
			input: `42`,
			want:  "42\n",
		},
		{
			name:  "boolean true",
			input: `true`,
			want:  "true\n",
		},
		{
			name:  "null",
			input: `null`,
			want:  "null\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			err := FormatJSONLine([]byte(tt.input), p)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := string(p.Bytes())
			if got != tt.want {
				t.Errorf("FormatJSONLine() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatJSONLineInvalid(t *testing.T) {
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatJSONLine([]byte(`{invalid`), p)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFormatJSONLineTrailingData(t *testing.T) {
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatJSONLine([]byte(`{} extra`), p)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
}

type chunkReader struct {
	chunks [][]byte
	index  int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.index == len(r.chunks) {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[r.index])
	if n == len(r.chunks[r.index]) {
		r.index++
	}
	return n, nil
}
