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

func TestTerminalSafeReaderPreservesSafeText(t *testing.T) {
	input := []byte("ordinary text with UTF-8: café\n")
	reader := newTerminalSafeReader(bytes.NewReader(input))
	got, err := readWithBuffer(reader, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("safe reader output = %q, want %q", got, input)
	}
}

func TestTerminalSafeReaderHandlesSmallOutputBuffers(t *testing.T) {
	input := []byte("prefix\x1b[2Jmiddle\x00suffix\n")
	reader := newTerminalSafeReader(bytes.NewReader(input))
	got, err := readWithBuffer(reader, 3)
	if err != nil {
		t.Fatal(err)
	}
	if want := `prefix\x1b[2Jmiddle\x00suffix
`; string(got) != want {
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

func readWithBuffer(reader io.Reader, size int) ([]byte, error) {
	var output bytes.Buffer
	buf := make([]byte, size)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			_, _ = output.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				return output.Bytes(), nil
			}
			return output.Bytes(), err
		}
		if n == 0 {
			return output.Bytes(), io.ErrNoProgress
		}
	}
}

func BenchmarkTerminalSafeReader(b *testing.B) {
	safeText := bytes.Repeat([]byte("ordinary text with UTF-8: café\n"), 128)
	controls := bytes.Repeat([]byte("line\x1b[2J\x07\x00\n"), 128)
	splitUTF8 := make([][]byte, 0, 256)
	for i := 0; i < cap(splitUTF8)/2; i++ {
		splitUTF8 = append(splitUTF8, []byte("caf\xc3"), []byte("\xa9 and text\n"))
	}
	splitUTF8Bytes := 0
	for _, chunk := range splitUTF8 {
		splitUTF8Bytes += len(chunk)
	}

	cases := []struct {
		name  string
		bytes int
		new   func() io.Reader
	}{
		{name: "SafeText", bytes: len(safeText), new: func() io.Reader {
			return bytes.NewReader(safeText)
		}},
		{name: "Controls", bytes: len(controls), new: func() io.Reader {
			return bytes.NewReader(controls)
		}},
		{name: "SplitUTF8", bytes: splitUTF8Bytes, new: func() io.Reader {
			return &fixedChunkReader{chunks: splitUTF8}
		}},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			buf := make([]byte, 32*1024)
			b.SetBytes(int64(tc.bytes))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				consumeBenchmarkReader(b, newTerminalSafeReader(tc.new()), buf)
			}
		})
	}
}

func BenchmarkBinaryGuardReader(b *testing.B) {
	safeText := bytes.Repeat([]byte("ordinary text with UTF-8: café\n"), 128)
	binaryData := append(bytes.Repeat([]byte("ordinary text "), 4096), 0)
	cases := []struct {
		name  string
		bytes int
		data  []byte
	}{
		{name: "SafeText", bytes: len(safeText), data: safeText},
		{name: "BinaryDetection", bytes: len(binaryData), data: binaryData},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			buf := make([]byte, 32*1024)
			b.SetBytes(int64(tc.bytes))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				consumeBenchmarkReader(b, newBinaryGuardReader(bytes.NewReader(tc.data), false, nil), buf)
			}
		})
	}
}

func BenchmarkTerminalSafeReaderLongStream(b *testing.B) {
	data := bytes.Repeat([]byte("long-lived stream with UTF-8: café\n"), 1<<15)
	buf := make([]byte, 32*1024)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		consumeBenchmarkReader(b, newTerminalSafeReader(bytes.NewReader(data)), buf)
	}
}

func consumeBenchmarkReader(b *testing.B, reader io.Reader, buf []byte) {
	b.Helper()
	for {
		n, err := reader.Read(buf)
		if err != nil {
			if err != io.EOF {
				b.Fatal(err)
			}
			return
		}
		if n == 0 {
			b.Fatal("reader returned no data without an error")
		}
	}
}
