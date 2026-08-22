package ws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/coder/websocket"
)

// Config holds the configuration for a WebSocket session.
type Config struct {
	Conn          *websocket.Conn
	Stdin         io.Reader
	Stderr        *core.Printer
	Stdout        *core.Printer
	Format        core.Format
	Verbosity     core.Verbosity
	InitialMsg    []byte
	InitialMsgSet bool
	InitialReader io.Reader
	MessageMode   core.WSMessageMode
	IsInteractive bool
}

// Run starts the bidirectional WebSocket message loop.
//
// When stdin is nil (no pipe, just -d), it sends any initial message, then
// reads from the server until close or Ctrl+C.
//
// When stdin is provided (piped input), it sends messages concurrently while
// reading responses. EOF performs a WebSocket close handshake instead of
// cancelling the receive side, so delayed peer responses are not discarded.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Conn == nil {
		return errors.New("WebSocket connection is nil")
	}

	// SetReadLimit makes coder/websocket reject a message after reading only
	// one byte beyond the limit. Configure it before the first Read: Read
	// otherwise allocates the complete message.
	cfg.Conn.SetReadLimit(core.MaxWebSocketMessageBytes)

	if cfg.IsInteractive {
		return runInteractive(ctx, cfg)
	}

	if err := sendInitialMessage(ctx, &cfg); err != nil {
		return err
	}

	if cfg.Stdin == nil {
		return readLoop(ctx, cfg)
	}
	return runBidirectional(ctx, cfg)
}

func sendInitialMessage(ctx context.Context, cfg *Config) error {
	if !cfg.InitialMsgSet && len(cfg.InitialMsg) == 0 && cfg.InitialReader == nil {
		return nil
	}

	if cfg.InitialReader != nil {
		data, err := core.ReadAllLimited(cfg.InitialReader, core.MaxWebSocketMessageBytes, "WebSocket initial message")
		if closer, ok := cfg.InitialReader.(io.Closer); ok {
			_ = closer.Close()
		}
		if err != nil {
			return err
		}
		cfg.InitialMsg = data
		cfg.InitialReader = nil
		cfg.InitialMsgSet = true
	}

	typ, err := initialMessageType(cfg.MessageMode, cfg.InitialMsg)
	if err != nil {
		return err
	}
	if err := cfg.Conn.Write(ctx, typ, cfg.InitialMsg); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("write initial WebSocket message: %w", err)
	}
	return nil
}

func initialMessageType(mode core.WSMessageMode, data []byte) (websocket.MessageType, error) {
	switch mode {
	case core.WSMessageText:
		if !utf8.Valid(data) {
			return 0, errors.New("initial WebSocket message is not valid UTF-8")
		}
		return websocket.MessageText, nil
	case core.WSMessageBinary:
		return websocket.MessageBinary, nil
	default:
		if utf8.Valid(data) {
			return websocket.MessageText, nil
		}
		return websocket.MessageBinary, nil
	}
}

// runBidirectional owns both directions after the handshake. There is one
// reader and one writer, as required by coder/websocket. The close operation
// is allowed to coordinate with the reader; this lets the reader print data
// that arrived just before the peer's close frame.
func runBidirectional(ctx context.Context, cfg Config) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// A context cancellation must unblock both network operations and a
	// closable stdin source. An arbitrary Reader cannot be interrupted, so it
	// is deliberately not retained in an additional goroutine after return.
	stopCancellation := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeInput(cfg.Stdin)
			_ = cfg.Conn.CloseNow()
		case <-stopCancellation:
		}
	}()
	defer close(stopCancellation)

	writeDone := make(chan error, 1)
	go func() { writeDone <- writeLoop(sessionCtx, cfg) }()

	readDone := make(chan error, 1)
	go func() { readDone <- readLoop(sessionCtx, cfg) }()

	for {
		select {
		case <-ctx.Done():
			closeInput(cfg.Stdin)
			cancel()
			_ = cfg.Conn.CloseNow()
			return contextTerminationError(ctx)
		case err := <-readDone:
			closeInput(cfg.Stdin)
			cancel()
			_ = cfg.Conn.CloseNow()
			return err

		case err := <-writeDone:
			if err != nil {
				closeInput(cfg.Stdin)
				cancel()
				_ = cfg.Conn.CloseNow()
				return err
			}

			// EOF is a local, orderly shutdown. Conn.Close writes and flushes
			// the normal close frame, then waits for the peer response with the
			// library's finite close-handshake deadline. The reader remains
			// active while this happens, so peer data already in flight is not
			// needlessly dropped.
			closeDone := startNormalClose(cfg.Conn)

			for {
				select {
				case err := <-readDone:
					if err != nil {
						cancel()
						return err
					}
					// A peer close can finish the reader before Conn.Close's
					// bookkeeping returns. Give that operation a short chance
					// to finish so it does not outlive this session.
					select {
					case closeErr := <-closeDone:
						cancel()
						return normalizeCloseError(closeErr)
					case <-time.After(time.Second):
						cancel()
						return nil
					}
				case closeErr := <-closeDone:
					cancel()
					return normalizeCloseError(closeErr)
				case <-ctx.Done():
					closeInput(cfg.Stdin)
					cancel()
					_ = cfg.Conn.CloseNow()
					return contextTerminationError(ctx)
				}
			}
		}
	}
}

func closeInput(input io.Reader) {
	if closer, ok := input.(io.Closer); ok {
		_ = closer.Close()
	}
}

func contextTerminationError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("WebSocket connection timed out: %w", ctx.Err())
	}
	return nil
}

func normalizeCloseError(err error) error {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	var closeErr websocket.CloseError
	if errors.As(err, &closeErr) && (closeErr.Code == websocket.StatusNormalClosure || closeErr.Code == websocket.StatusGoingAway) {
		return nil
	}
	return err
}
