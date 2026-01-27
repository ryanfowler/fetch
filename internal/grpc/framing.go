package grpc

import (
	"encoding/binary"
	"fmt"
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

// Unframe extracts a gRPC length-prefixed message from the data.
// Returns the message data and whether it was compressed.
func Unframe(data []byte) ([]byte, bool, error) {
	if len(data) < 5 {
		return nil, false, fmt.Errorf("failed to read gRPC frame header: insufficient data")
	}

	compressed := data[0] != 0
	length := binary.BigEndian.Uint32(data[1:5])

	// Sanity check on length.
	const maxMessageSize = 64 * 1024 * 1024 // 64MB
	if length > maxMessageSize {
		return nil, false, fmt.Errorf("gRPC message too large: %d bytes", length)
	}

	if len(data) < 5+int(length) {
		return nil, false, fmt.Errorf("failed to read gRPC message: insufficient data")
	}

	return data[5 : 5+length], compressed, nil
}
