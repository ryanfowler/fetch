package ws

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/format"

	"github.com/coder/websocket"
)

// readLoop reads messages from the WebSocket and writes them to stdout. The
// connection library performs the protocol-level read limit check before it
// returns a message, so this loop never queues an oversized payload.
func readLoop(ctx context.Context, cfg Config) error {
	for {
		typ, data, err := cfg.Conn.Read(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				// A raw EOF is not a WebSocket close handshake. Keep it
				// distinct from the normal CloseError path.
				return fmt.Errorf("abnormal WebSocket closure: %w", err)
			}
			return handleReadErr(err)
		}

		var writeErr error
		switch typ {
		case websocket.MessageText:
			writeErr = writeTextMessage(data, cfg.Stdout, cfg.Format)
		case websocket.MessageBinary:
			writeErr = writeBinaryMessage(data, cfg)
		}
		if writeErr != nil {
			if core.IsBrokenPipe(writeErr) {
				return nil
			}
			return writeErr
		}
	}
}

// writeTextMessage writes a text message to stdout, attempting JSON
// formatting if applicable.
func writeTextMessage(data []byte, p *core.Printer, f core.Format) error {
	if core.IsStdoutTerm {
		data = []byte(core.TerminalSafeText(string(data)))
	}
	if shouldFormat(f) && jsontext.Value(data).IsValid() && format.FormatJSONLine(data, p) == nil {
		return p.Flush()
	}

	if _, err := p.Write(data); err != nil {
		return err
	}
	if _, err := p.WriteString("\n"); err != nil {
		return err
	}
	return p.Flush()
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

// writeBinaryMessage keeps binary payloads byte-exact when stdout is not a
// terminal. Raw binary must never be written to a terminal, where it could
// contain control sequences or corrupt the user's session.
func writeBinaryMessage(data []byte, cfg Config) error {
	return writeBinaryMessageForTerminal(data, cfg, core.IsStdoutTerm)
}

func writeBinaryMessageForTerminal(data []byte, cfg Config, stdoutTerminal bool) error {
	if !stdoutTerminal {
		if _, err := cfg.Stdout.Write(data); err != nil {
			return err
		}
		return cfg.Stdout.Flush()
	}
	return writeBinaryIndicator(cfg.Stderr, len(data))
}

// writeBinaryIndicator writes a binary message indicator to stderr.
func writeBinaryIndicator(p *core.Printer, n int) error {
	p.Set(core.Dim)
	if _, err := fmt.Fprintf(p, "[binary %d bytes]", n); err != nil {
		return err
	}
	p.Reset()
	if _, err := p.WriteString("\n"); err != nil {
		return err
	}
	return p.Flush()
}

// handleReadErr handles the error from reading a WebSocket message. Normal
// closure is expected and returns nil. A raw EOF is intentionally retained as
// nil here for compatibility with callers that classify a completed reader;
// readLoop classifies a network EOF as abnormal before calling this helper.
func handleReadErr(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("WebSocket read timed out: %w", err)
	}
	if closeErr, ok := errors.AsType[websocket.CloseError](err); ok {
		switch closeErr.Code {
		case websocket.StatusNormalClosure, websocket.StatusGoingAway:
			return nil
		default:
			return fmt.Errorf("WebSocket closed abnormally: %w", closeErr)
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
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}
