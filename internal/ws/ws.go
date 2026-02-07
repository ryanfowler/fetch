package ws

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/coder/websocket"
)

// Config holds the configuration for a WebSocket session.
type Config struct {
	Conn       *websocket.Conn
	Stdin      io.Reader
	Stderr     *core.Printer
	Stdout     *core.Printer
	Format     core.Format
	Verbosity  core.Verbosity
	InitialMsg []byte
}

// Run starts the bidirectional WebSocket message loop.
//
// When stdin is nil (no pipe, just -d), it sends any initial message, then
// reads from the server until close or Ctrl+C.
//
// When stdin is provided (piped input), it sends lines concurrently while
// reading responses.
func Run(ctx context.Context, cfg Config) error {
	// Send initial message from -d / -j flag.
	if len(cfg.InitialMsg) > 0 {
		err := cfg.Conn.Write(ctx, websocket.MessageText, cfg.InitialMsg)
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}

	if cfg.Stdin != nil {
		return runBidirectional(ctx, cfg)
	}

	// No stdin: just read messages from the server until it closes or
	// the context is cancelled (Ctrl+C).
	return readLoop(ctx, cfg)
}

// runBidirectional handles the case where we have both stdin and server
// messages. It reads stdin in a separate goroutine and processes server
// messages in the main goroutine.
func runBidirectional(ctx context.Context, cfg Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Write stdin lines in a background goroutine.
	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		writeLoop(ctx, cfg)
	}()

	// Read server messages in a separate goroutine. This allows us to
	// detect when stdin is done and start a graceful shutdown.
	readDone := make(chan error, 1)
	go func() {
		readDone <- readLoop(ctx, cfg)
	}()

	// Wait for either stdin EOF or server close.
	select {
	case err := <-readDone:
		// Cancel and return immediately — writeLoop may be blocked
		// reading from stdin and cannot be interrupted.
		cancel()
		return err
	case <-stdinDone:
		// Piped stdin EOF. Give the server a short window to send
		// remaining messages (e.g. echo responses), then shut down.
		drainCtx, drainCancel := context.WithTimeout(ctx, 2*time.Second)
		defer drainCancel()

		select {
		case err := <-readDone:
			return err
		case <-drainCtx.Done():
			cancel()
			return nil
		}
	}
}
