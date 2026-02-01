package grpc

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame wraps message in gRPC length-prefixed format.
// Format: [compressed:1][length:4][data]
func Frame(data []byte, compressed bool) []byte {
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

// maxMessageSize is the maximum allowed gRPC message size.
const maxMessageSize = 64 * 1024 * 1024 // 64MB

// ReadFrame reads a single gRPC length-prefixed frame from the reader.
// Returns the message data, whether it was compressed, and any error.
// Returns io.EOF when the reader has no more data.
func ReadFrame(r io.Reader) ([]byte, bool, error) {
	var header [5]byte
	_, err := io.ReadFull(r, header[:])
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, false, fmt.Errorf("failed to read gRPC frame header: incomplete header")
		}
		return nil, false, err
	}

	compressed := header[0] != 0
	length := binary.BigEndian.Uint32(header[1:5])

	if length > maxMessageSize {
		return nil, false, fmt.Errorf("gRPC message too large: %d bytes", length)
	}

	data := make([]byte, length)
	if length > 0 {
		_, err = io.ReadFull(r, data)
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				return nil, false, fmt.Errorf("failed to read gRPC message: incomplete data")
			}
			return nil, false, err
		}
	}

	return data, compressed, nil
}

// Unframe extracts a gRPC length-prefixed message from the data.
// Returns the message data and whether it was compressed.
func Unframe(data []byte) ([]byte, bool, error) {
	if len(data) < 5 {
		return nil, false, fmt.Errorf("failed to read gRPC frame header: insufficient data")
	}

	compressed := data[0] != 0
	length := binary.BigEndian.Uint32(data[1:5])

	if length > maxMessageSize {
		return nil, false, fmt.Errorf("gRPC message too large: %d bytes", length)
	}

	if len(data) < 5+int(length) {
		return nil, false, fmt.Errorf("failed to read gRPC message: insufficient data")
	}

	return data[5 : 5+length], compressed, nil
}
