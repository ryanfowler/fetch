package format

import (
	"bytes"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/grpc"
)

func TestFormatGRPCStream(t *testing.T) {
	t.Run("single frame", func(t *testing.T) {
		protoData := appendVarint(nil, 1, 42)
		protoData = appendBytes(protoData, 2, []byte("hello"))
		framed := grpc.Frame(protoData, false)

		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatGRPCStream(bytes.NewReader(framed), nil, p)
		if err != nil {
			t.Fatalf("FormatGRPCStream() error = %v", err)
		}
	})

	t.Run("multiple frames", func(t *testing.T) {
		frame1 := grpc.Frame(appendVarint(nil, 1, 100), false)
		frame2 := grpc.Frame(appendVarint(nil, 1, 200), false)
		frame3 := grpc.Frame(appendVarint(nil, 1, 300), false)

		var buf bytes.Buffer
		buf.Write(frame1)
		buf.Write(frame2)
		buf.Write(frame3)

		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatGRPCStream(&buf, nil, p)
		if err != nil {
			t.Fatalf("FormatGRPCStream() error = %v", err)
		}
	})

	t.Run("empty stream", func(t *testing.T) {
		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatGRPCStream(bytes.NewReader(nil), nil, p)
		if err != nil {
			t.Fatalf("FormatGRPCStream() error = %v", err)
		}
	})

	t.Run("empty message frame", func(t *testing.T) {
		framed := grpc.Frame(nil, false)

		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatGRPCStream(bytes.NewReader(framed), nil, p)
		if err != nil {
			t.Fatalf("FormatGRPCStream() error = %v", err)
		}
	})

	t.Run("error mid-stream", func(t *testing.T) {
		// First frame is valid, then stream is truncated mid-header.
		frame1 := grpc.Frame(appendVarint(nil, 1, 42), false)
		truncated := append(frame1, 0x00, 0x00) // partial header

		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatGRPCStream(bytes.NewReader(truncated), nil, p)
		if err == nil {
			t.Error("expected error for truncated stream")
		}
	})

	t.Run("multiple frames with multi-field messages", func(t *testing.T) {
		msg1 := appendVarint(nil, 1, 10)
		msg1 = appendBytes(msg1, 2, []byte("first"))

		msg2 := appendVarint(nil, 1, 20)
		msg2 = appendBytes(msg2, 2, []byte("second"))

		var buf bytes.Buffer
		buf.Write(grpc.Frame(msg1, false))
		buf.Write(grpc.Frame(msg2, false))

		p := core.NewHandle(core.ColorOff).Stderr()
		err := FormatGRPCStream(&buf, nil, p)
		if err != nil {
			t.Fatalf("FormatGRPCStream() error = %v", err)
		}
	})
}
