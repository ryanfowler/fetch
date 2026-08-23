package fetch

import (
	"bytes"
	"io"
	"testing"
)

type fixedChunkReader struct {
	chunks [][]byte
	index  int
}

func (r *fixedChunkReader) Read(p []byte) (int, error) {
	if r.index >= len(r.chunks) {
		return 0, io.EOF
	}
	chunk := r.chunks[r.index]
	r.index++
	copy(p, chunk)
	return len(chunk), nil
}

func TestTerminalSafeReaderEscapesControls(t *testing.T) {
	reader := newTerminalSafeReader(bytes.NewReader([]byte("ok\x1b]0;pwned\x07")))
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if want := `ok\x1b]0;pwned\x07`; string(got) != want {
		t.Fatalf("safe reader output = %q, want %q", got, want)
	}
}

func TestTerminalSafeReaderPreservesSplitUTF8(t *testing.T) {
	reader := newTerminalSafeReader(&fixedChunkReader{chunks: [][]byte{
		[]byte("caf\xc3"),
		[]byte("\xa9 and \xc2"),
		[]byte("\x85"),
	}})
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if want := "café and \\x85"; string(got) != want {
		t.Fatalf("safe reader output = %q, want %q", got, want)
	}
}

func TestBinaryGuardPreservesSplitUTF8(t *testing.T) {
	input := &fixedChunkReader{chunks: [][]byte{
		[]byte("caf\xc3"),
		[]byte("\xa9 au lait"),
	}}
	guard := newBinaryGuardReader(input, false, nil)
	got, err := io.ReadAll(guard)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "café au lait" {
		t.Fatalf("guard output = %q, want valid split UTF-8 text", got)
	}
	if guard.Triggered() {
		t.Fatal("valid split UTF-8 triggered the binary guard")
	}
}

func TestBinaryGuardRejectsBinaryAfterText(t *testing.T) {
	input := &fixedChunkReader{chunks: [][]byte{
		[]byte("safe text"),
		[]byte("\x00unsafe"),
		[]byte(" and the rest"),
	}}
	guard := newBinaryGuardReader(input, true, nil)
	got, err := io.ReadAll(guard)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "safe text" {
		t.Fatalf("guard output = %q, want only the safe prefix", got)
	}
	if !guard.Triggered() {
		t.Fatal("binary data did not trigger the guard")
	}
}

func TestBinaryGuardDoesNotReadPastBinaryWhenDrainDisabled(t *testing.T) {
	input := &fixedChunkReader{chunks: [][]byte{[]byte("text"), []byte("\x00more")}}
	guard := newBinaryGuardReader(input, false, nil)
	got, err := io.ReadAll(guard)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("text")) {
		t.Fatalf("guard output = %q, want text prefix", got)
	}
	if !guard.Triggered() {
		t.Fatal("binary data did not trigger the guard")
	}
}

func TestPrintableBytesAllowsIncompleteTrailingRune(t *testing.T) {
	if !printableBytes([]byte("caf\xc3")) {
		t.Fatal("incomplete trailing UTF-8 rune was rejected")
	}
	if printableBytes([]byte{0xff}) {
		t.Fatal("invalid UTF-8 was accepted as printable")
	}
}

func TestBinaryGuardRejectsTruncatedUTF8AtEOF(t *testing.T) {
	guard := newBinaryGuardReader(bytes.NewReader([]byte("text\xc3")), false, nil)
	got, err := io.ReadAll(guard)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "text" {
		t.Fatalf("guard output = %q, want truncated rune omitted", got)
	}
	if !guard.Triggered() {
		t.Fatal("truncated UTF-8 did not trigger the binary guard")
	}
}
