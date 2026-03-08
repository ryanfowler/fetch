package ws

import (
	"bytes"
	"testing"
	"time"
)

func TestExtractCursorRow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     []byte
		wantRow   int
		wantRest  []byte
		wantFound bool
	}{
		{
			name:      "plain dsr response",
			input:     []byte("\x1b[12;34R"),
			wantRow:   12,
			wantRest:  nil,
			wantFound: true,
		},
		{
			name:      "bytes before and after dsr are preserved",
			input:     []byte("abc\x1b[7;9Rxyz"),
			wantRow:   7,
			wantRest:  []byte("abcxyz"),
			wantFound: true,
		},
		{
			name:      "non-dsr bytes are left untouched",
			input:     []byte("hello"),
			wantRow:   0,
			wantRest:  []byte("hello"),
			wantFound: false,
		},
		{
			name:      "incomplete dsr stays buffered",
			input:     []byte("\x1b[12;"),
			wantRow:   0,
			wantRest:  []byte("\x1b[12;"),
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row, rest, ok := extractCursorRow(tt.input)
			if row != tt.wantRow {
				t.Fatalf("row = %d, want %d", row, tt.wantRow)
			}
			if ok != tt.wantFound {
				t.Fatalf("ok = %v, want %v", ok, tt.wantFound)
			}
			if !bytes.Equal(rest, tt.wantRest) {
				t.Fatalf("rest = %q, want %q", rest, tt.wantRest)
			}
		})
	}
}

func TestDetectCursorRow(t *testing.T) {
	t.Parallel()

	t.Run("returns parsed row and preserves user input", func(t *testing.T) {
		inputCh := make(chan []byte, 2)
		inputCh <- []byte("x")
		inputCh <- []byte("\x1b[23;45Ry")
		close(inputCh)

		row, pending := detectCursorRow(inputCh)
		if row != 23 {
			t.Fatalf("row = %d, want 23", row)
		}
		if !bytes.Equal(pending, []byte("xy")) {
			t.Fatalf("pending = %q, want %q", pending, []byte("xy"))
		}
	})

	t.Run("closed input falls back to row 1", func(t *testing.T) {
		inputCh := make(chan []byte)
		close(inputCh)

		row, pending := detectCursorRow(inputCh)
		if row != 1 {
			t.Fatalf("row = %d, want 1", row)
		}
		if len(pending) != 0 {
			t.Fatalf("pending = %q, want empty", pending)
		}
	})

	t.Run("timeout preserves buffered bytes", func(t *testing.T) {
		inputCh := make(chan []byte, 1)
		inputCh <- []byte("typed")

		row, pending := detectCursorRowWithTimeout(inputCh, 10*time.Millisecond)
		if row != 1 {
			t.Fatalf("row = %d, want 1", row)
		}
		if !bytes.Equal(pending, []byte("typed")) {
			t.Fatalf("pending = %q, want %q", pending, []byte("typed"))
		}
	})
}
