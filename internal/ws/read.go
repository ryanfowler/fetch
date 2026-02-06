package ws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/format"

	"github.com/coder/websocket"
)

// readLoop reads messages from the WebSocket and writes them to stdout.
func readLoop(ctx context.Context, cfg Config) error {
	for {
		typ, data, err := cfg.Conn.Read(ctx)
		if err != nil {
			return handleReadErr(err)
		}

		switch typ {
		case websocket.MessageText:
			writeTextMessage(data, cfg.Stdout, cfg.Format)
		case websocket.MessageBinary:
			writeBinaryIndicator(cfg.Stderr, len(data))
		}
	}
}

// writeTextMessage writes a text message to stdout, attempting JSON
// formatting if applicable.
func writeTextMessage(data []byte, p *core.Printer, f core.Format) {
	if shouldFormat(f) && json.Valid(data) && format.FormatJSONLine(data, p) == nil {
		p.Flush()
		return
	}

	p.Write(data)
	p.WriteString("\n")
	p.Flush()
}

// shouldFormat returns true if formatting is enabled.
func shouldFormat(f core.Format) bool {
	if f == core.FormatOff {
		return false
	}
	if f == core.FormatOn {
		return true
	}
	return core.IsStdoutTerm
}

// writeBinaryIndicator writes a binary message indicator to stderr.
func writeBinaryIndicator(p *core.Printer, n int) {
	p.Set(core.Dim)
	fmt.Fprintf(p, "[binary %d bytes]", n)
	p.Reset()
	p.WriteString("\n")
	p.Flush()
}

// handleReadErr handles the error from reading a WebSocket message. Normal
// closure is expected and returns nil.
func handleReadErr(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	var closeErr websocket.CloseError
	if errors.As(err, &closeErr) {
		if closeErr.Code == websocket.StatusNormalClosure {
			return nil
		}
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	// "use of closed network connection" occurs when we initiate the
	// close from the write side.
	if isClosedConnErr(err) {
		return nil
	}
	return err
}

// isClosedConnErr returns true if the error indicates a closed connection.
func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}
