package ws

import (
	"bufio"
	"context"

	"github.com/coder/websocket"
)

// writeLoop reads lines from stdin and sends them as text messages over the
// WebSocket connection. It does NOT call conn.Close — the caller handles
// connection cleanup.
func writeLoop(ctx context.Context, cfg Config) {
	scanner := bufio.NewScanner(cfg.Stdin)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		if err := ctx.Err(); err != nil {
			return
		}

		err := cfg.Conn.Write(ctx, websocket.MessageText, line)
		if err != nil {
			return
		}
	}
}
