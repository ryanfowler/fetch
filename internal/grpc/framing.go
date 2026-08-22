package grpc

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

// Frame wraps a valid message in gRPC length-prefixed format.
// Format: [compressed:1][length:4][data]. It returns nil when data cannot
// be represented by a strict gRPC frame; callers that need the reason should
// use FrameChecked.
func Frame(data []byte, compressed bool) []byte {
	if int64(len(data)) > MaxMessageSize || uint64(len(data)) > uint64(^uint32(0)) {
		return nil
	}
	buf := make([]byte, 5+len(data))
	if compressed {
		buf[0] = 1
	} else {
		buf[0] = 0
	}
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(data)))
	copy(buf[5:], data)
	return buf
}

// MaxMessageSize is the maximum encoded or decoded gRPC message size.
const MaxMessageSize int64 = core.MaxGRPCMessageBytes

// maxMessageSize is retained as a local compatibility name for package tests.
const maxMessageSize = MaxMessageSize

// FrameChecked wraps a message in gRPC length-prefixed format and rejects
// messages that cannot be represented by the wire format or exceed the
// configured message limit.
func FrameChecked(data []byte, compressed bool) ([]byte, error) {
	if int64(len(data)) > MaxMessageSize {
		return nil, fmt.Errorf("gRPC message too large: %d bytes", len(data))
	}
	if uint64(len(data)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("gRPC message length overflows the frame header: %d bytes", len(data))
	}
	return Frame(data, compressed), nil
}

// DecodeMessage decompresses one gRPC message when its compressed flag is set.
// Decompression is bounded so a small compressed payload cannot expand beyond
// the gRPC message limit.
func DecodeMessage(data []byte, compressed bool, encoding string) ([]byte, error) {
	return DecodeMessageLimited(data, compressed, encoding, MaxMessageSize)
}

// DecodeMessageLimited is DecodeMessage with a caller-supplied decoded-size
// limit. Reflection uses this to enforce its aggregate limit before retaining
// another decompressed response.
func DecodeMessageLimited(data []byte, compressed bool, encoding string, max int64) ([]byte, error) {
	if max < 0 {
		return nil, fmt.Errorf("gRPC message exceeds invalid limit: %d bytes", max)
	}
	if !compressed {
		if int64(len(data)) > max {
			return nil, fmt.Errorf("gRPC message too large: %d bytes", len(data))
		}
		return data, nil
	}

	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("invalid gzip gRPC message: %w", err)
		}
		decoded, readErr := core.ReadAllLimited(reader, max, "decompressed gRPC message")
		closeErr := reader.Close()
		if readErr != nil {
			return nil, fmt.Errorf("invalid gzip gRPC message: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("invalid gzip gRPC message: %w", closeErr)
		}
		return decoded, nil
	case "":
		return nil, fmt.Errorf("compressed gRPC message has no grpc-encoding")
	default:
		return nil, fmt.Errorf("unsupported gRPC message encoding: %s", encoding)
	}
}

// ReadFrameHeader reads and validates the five-byte gRPC frame header.
// It returns io.EOF when the reader has no more data. The payload is not read,
// which lets callers enforce an aggregate limit before allocating it.
func ReadFrameHeader(r io.Reader) (uint32, bool, error) {
	var header [5]byte
	_, err := io.ReadFull(r, header[:])
	if err != nil {
		if err == io.EOF {
			return 0, false, io.EOF
		}
		if err == io.ErrUnexpectedEOF {
			return 0, false, fmt.Errorf("failed to read gRPC frame header: incomplete header")
		}
		return 0, false, err
	}

	switch header[0] {
	case 0, 1:
	default:
		return 0, false, fmt.Errorf("invalid gRPC compressed flag: %d", header[0])
	}
	return binary.BigEndian.Uint32(header[1:5]), header[0] == 1, nil
}

// ReadFrameBody reads a frame payload after ReadFrameHeader. max is checked
// before allocation so callers can enforce an operation-wide limit without
// briefly allocating an over-limit message.
func ReadFrameBody(r io.Reader, length uint32, max int64) ([]byte, error) {
	if max < 0 || uint64(length) > uint64(max) {
		return nil, fmt.Errorf("gRPC message too large: %d bytes", length)
	}
	data := make([]byte, int(length))
	if length == 0 {
		return data, nil
	}
	_, err := io.ReadFull(r, data)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("failed to read gRPC message: incomplete data")
		}
		return nil, err
	}
	return data, nil
}

// ReadFrame reads a single gRPC length-prefixed frame from the reader.
// Returns the message data, whether it was compressed, and any error.
// Returns io.EOF when the reader has no more data.
func ReadFrame(r io.Reader) ([]byte, bool, error) {
	length, compressed, err := ReadFrameHeader(r)
	if err != nil {
		return nil, false, err
	}
	data, err := ReadFrameBody(r, length, maxMessageSize)
	if err != nil {
		return nil, false, err
	}
	return data, compressed, nil
}

// Unframe extracts a gRPC length-prefixed message from the data.
// Returns the message data and whether it was compressed.
func Unframe(data []byte) ([]byte, bool, error) {
	if len(data) < 5 {
		return nil, false, fmt.Errorf("failed to read gRPC frame header: insufficient data")
	}

	switch data[0] {
	case 0:
		// uncompressed
	case 1:
		// compressed
	default:
		return nil, false, fmt.Errorf("invalid gRPC compressed flag: %d", data[0])
	}
	compressed := data[0] == 1
	length := binary.BigEndian.Uint32(data[1:5])

	if uint64(length) > uint64(maxMessageSize) {
		return nil, false, fmt.Errorf("gRPC message too large: %d bytes", length)
	}

	if len(data) < 5+int(length) {
		return nil, false, fmt.Errorf("failed to read gRPC message: insufficient data")
	}

	return data[5 : 5+length], compressed, nil
}
