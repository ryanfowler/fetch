package format

import (
	"errors"
	"io"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/grpc"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// FormatGRPCStream formats an uncompressed gRPC response stream by reading
// and formatting each length-prefixed frame as it arrives. It is retained for
// callers that do not have response metadata; compressed frames are rejected
// with an actionable missing-encoding error.
func FormatGRPCStream(r io.Reader, md protoreflect.MessageDescriptor, p *core.Printer) error {
	return FormatGRPCStreamWithEncoding(r, md, p, "")
}

// FormatGRPCStreamWithEncoding formats a gRPC response stream incrementally.
// The grpc-encoding value applies to frames whose compressed flag is set.
func FormatGRPCStreamWithEncoding(r io.Reader, md protoreflect.MessageDescriptor, p *core.Printer, encoding string) error {
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
		data, err = grpc.DecodeMessage(data, compressed, encoding)
		if err != nil {
			p.Discard()
			return err
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

		if err := p.Flush(); err != nil {
			p.Discard()
			return err
		}
	}
}
