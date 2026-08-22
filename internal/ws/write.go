package ws

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/ryanfowler/fetch/internal/core"
)

const websocketStdinBufferSize = 32 * 1024

// writeLoop reads piped stdin and sends one WebSocket message for each text
// line, or bounded binary chunks in binary mode. It does NOT call conn.Close;
// the caller owns connection cleanup.
func writeLoop(ctx context.Context, cfg Config) error {
	if cfg.Stdin == nil {
		return nil
	}
	if cfg.MessageMode == core.WSMessageBinary {
		return writeBinaryLoop(ctx, cfg)
	}
	return writeTextLoop(ctx, cfg)
}

func writeTextLoop(ctx context.Context, cfg Config) error {
	reader := bufio.NewReaderSize(cfg.Stdin, websocketStdinBufferSize)
	for {
		line, ok, err := readBoundedLine(reader, core.MaxWebSocketPipedTextLine)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if !utf8.Valid(line) {
			return errors.New("piped WebSocket text message is not valid UTF-8")
		}
		if err := writeMessage(ctx, cfg.Conn, websocket.MessageText, line); err != nil {
			return err
		}
	}
}

// readBoundedLine returns a line without its LF or CRLF terminator. Empty
// lines are valid messages. It bounds the raw line slightly above the payload
// limit so a CRLF terminator does not consume message capacity.
func readBoundedLine(reader *bufio.Reader, max int64) ([]byte, bool, error) {
	var line []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(part) > 0 {
			if int64(len(line))+int64(len(part)) > max+2 {
				return nil, false, core.LimitError{Subsystem: "WebSocket stdin line", Limit: max}
			}
			line = append(line, part...)
		}

		switch err {
		case nil:
			line = trimLineEnding(line)
			if int64(len(line)) > max {
				return nil, false, core.LimitError{Subsystem: "WebSocket stdin line", Limit: max}
			}
			return line, true, nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			if len(line) == 0 {
				return nil, false, nil
			}
			if int64(len(line)) > max {
				return nil, false, core.LimitError{Subsystem: "WebSocket stdin line", Limit: max}
			}
			return line, true, nil
		default:
			return nil, false, fmt.Errorf("read WebSocket stdin: %w", err)
		}
	}
}

func writeBinaryLoop(ctx context.Context, cfg Config) error {
	buf := make([]byte, websocketStdinBufferSize)
	for {
		n, err := cfg.Stdin.Read(buf)
		if n > 0 {
			if writeErr := writeMessage(ctx, cfg.Conn, websocket.MessageBinary, buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read WebSocket stdin: %w", err)
		}
	}
}

func writeMessage(ctx context.Context, conn *websocket.Conn, typ websocket.MessageType, data []byte) error {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if err := conn.Write(ctx, typ, data); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("write WebSocket message: %w", err)
	}
	return nil
}

func trimLineEnding(line []byte) []byte {
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
	}
	return line
}
