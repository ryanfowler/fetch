package format

import (
	"errors"
	"io"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/grpc"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// FormatGRPCStream formats a gRPC response stream by reading and formatting
// each length-prefixed frame as it arrives. This handles both unary (single
// frame) and server-streaming (multiple frames) responses.
func FormatGRPCStream(r io.Reader, md protoreflect.MessageDescriptor, p *core.Printer) error {
	var written bool
	for {
		data, compressed, err := grpc.ReadFrame(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			p.Discard()
			return err
		}
		if compressed {
			p.Discard()
			return errors.New("compressed gRPC messages are not supported")
		}

		if written {
			p.WriteString("\n")
		} else {
			written = true
		}

		if md != nil {
			err = FormatProtobufWithDescriptor(data, md, p)
		} else {
			err = FormatProtobuf(data, p)
		}
		if err != nil {
			// If formatting fails, return the error.
			p.Discard()
			return err
		}

		p.Flush()
	}
}
