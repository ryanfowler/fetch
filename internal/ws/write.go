package ws

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/coder/websocket"
)

// writeLoop reads lines from stdin and sends them as text messages over the
// WebSocket connection. It does NOT call conn.Close — the caller handles
// connection cleanup.
func writeLoop(ctx context.Context, cfg Config) error {
	reader := bufio.NewReader(cfg.Stdin)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = trimLineEnding(line)
			if len(line) > 0 {
				if err := ctx.Err(); err != nil {
					return nil
				}

				err := cfg.Conn.Write(ctx, websocket.MessageText, line)
				if err != nil {
					return nil
				}
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return fmt.Errorf("read WebSocket stdin: %w", readErr)
		}
	}
}

func trimLineEnding(line []byte) []byte {
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return line
}
