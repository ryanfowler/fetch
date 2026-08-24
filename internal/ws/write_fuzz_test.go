package ws

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func FuzzReadBoundedLine(f *testing.F) {
	f.Add([]byte("hello\n"))
	f.Add([]byte("hello\r\n"))
	f.Add([]byte("line without a terminator"))
	// This crosses bufio's production reader buffer and exercises the
	// ErrBufferFull continuation path.
	f.Add(bytes.Repeat([]byte{'x'}, websocketStdinBufferSize+1))
	const maxLineBytes = core.MaxWebSocketPipedTextLine
	// The production-limit overflow is covered by the focused unit test in
	// ws_test.go; keep fuzz inputs bounded so scheduled smoke runs remain short.

	f.Fuzz(func(t *testing.T, input []byte) {
		const maxGeneratedFuzzInput = 64 << 10
		if len(input) > maxGeneratedFuzzInput {
			input = input[:maxGeneratedFuzzInput]
		}
		line, ok, err := readBoundedLine(bufio.NewReaderSize(bytes.NewReader(input), websocketStdinBufferSize), core.MaxWebSocketPipedTextLine)
		if err == nil && ok && int64(len(line)) > maxLineBytes {
			t.Fatalf("readBoundedLine returned %d bytes, want at most %d", len(line), maxLineBytes)
		}
	})
}
