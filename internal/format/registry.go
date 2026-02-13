package format

import (
	"io"

	"github.com/ryanfowler/fetch/internal/core"
)

// BufferedFormatter formats buffered bytes to the Printer.
type BufferedFormatter func(buf []byte, p *core.Printer) error

// StreamingFormatter formats a stream to the Printer.
type StreamingFormatter func(r io.Reader, p *core.Printer) error

var (
	bufferedFormatters  map[ContentType]BufferedFormatter
	streamingFormatters map[ContentType]StreamingFormatter
)

func init() {
	bufferedFormatters = map[ContentType]BufferedFormatter{
		TypeCSS:      FormatCSS,
		TypeCSV:      FormatCSV,
		TypeHTML:     FormatHTML,
		TypeJSON:     FormatJSON,
		TypeMsgPack:  FormatMsgPack,
		TypeProtobuf: FormatProtobuf,
		TypeXML:      FormatXML,
		TypeYAML:     FormatYAML,
	}
	streamingFormatters = map[ContentType]StreamingFormatter{
		TypeNDJSON: FormatNDJSON,
		TypeSSE:    FormatEventStream,
	}
}

// GetBuffered returns the buffered formatter for the given content type, or nil.
func GetBuffered(ct ContentType) BufferedFormatter {
	return bufferedFormatters[ct]
}

// GetStreaming returns the streaming formatter for the given content type, or nil.
func GetStreaming(ct ContentType) StreamingFormatter {
	return streamingFormatters[ct]
}
