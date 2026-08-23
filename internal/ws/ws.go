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
	Conn *websocket.Conn
	// Stdin must be interruptible while Run is active. Run closes a Stdin
	// that implements io.Closer when cancellation or the peer ends the
	// session. A non-closable reader must otherwise arrange for its Read to
	// return independently; Run joins the writer before returning and cannot
	// complete cancellation until that Read returns.
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

	writeDone := make(chan error, 1)
	go func() { writeDone <- writeLoop(sessionCtx, cfg) }()

	readDone := make(chan error, 1)
	go func() { readDone <- readLoop(sessionCtx, cfg) }()

	for {
		select {
		case <-ctx.Done():
			stopAndJoinWriter(cfg, cancel, writeDone)
			return contextTerminationError(ctx)
		case err := <-readDone:
			stopAndJoinWriter(cfg, cancel, writeDone)
			if ctx.Err() != nil {
				return contextTerminationError(ctx)
			}
			return err

		case err := <-writeDone:
			if err != nil {
				closeInput(cfg.Stdin)
				cancel()
				_ = cfg.Conn.CloseNow()
				if ctx.Err() != nil {
					return contextTerminationError(ctx)
				}
				return err
			}

			// Drain messages sent before EOF before starting the close
			// handshake. coder/websocket documents that Conn.Close discards
			// data frames received during its handshake. A ping gives the
			// peer a protocol-level chance to flush earlier responses, and
			// the reader remains active for the bounded drain interval after
			// the pong. If the peer does not answer the ping, use the close
			// handshake as the fallback.
			drainDeadline := time.Now().Add(time.Second)
			drainCtx, cancelDrain := context.WithDeadline(ctx, drainDeadline)
			// A failed ping does not mean that in-flight data is absent. The
			// reader still gets the remainder of the same bounded drain window.
			_ = cfg.Conn.Ping(drainCtx)
			cancelDrain()
			if remaining := time.Until(drainDeadline); remaining > 0 {
				drainTimer := time.NewTimer(remaining)
				select {
				case err := <-readDone:
					drainTimer.Stop()
					cancel()
					_ = cfg.Conn.CloseNow()
					if ctx.Err() != nil {
						return contextTerminationError(ctx)
					}
					return err
				case <-ctx.Done():
					if !drainTimer.Stop() {
						<-drainTimer.C
					}
					cancel()
					_ = cfg.Conn.CloseNow()
					return contextTerminationError(ctx)
				case <-drainTimer.C:
				}
			}
			if ctx.Err() != nil {
				cancel()
				_ = cfg.Conn.CloseNow()
				return contextTerminationError(ctx)
			}

			// Conn.Close writes and flushes the normal close frame, then waits
			// for the peer response with the library's finite close-handshake
			// deadline. The reader remains active while this happens.
			closeDone := startNormalClose(cfg.Conn)

			for {
				select {
				case err := <-readDone:
					if ctx.Err() != nil {
						cancel()
						return contextTerminationError(ctx)
					}
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
					case <-ctx.Done():
						// Conn.Close has no cancellation mechanism and owns the
						// connection once started. Wait for it instead of calling
						// CloseNow concurrently, which would block on the same close.
						cancel()
						<-closeDone
						return contextTerminationError(ctx)
					}
				case closeErr := <-closeDone:
					// Close may finish before the reader has processed frames
					// that were already in flight. Keep the reader alive briefly
					// so local EOF cannot discard those messages.
					select {
					case readErr := <-readDone:
						cancel()
						if ctx.Err() != nil {
							return contextTerminationError(ctx)
						}
						if readErr != nil {
							return readErr
						}
						return normalizeCloseError(closeErr)
					case <-time.After(time.Second):
						cancel()
						return normalizeCloseError(closeErr)
					case <-ctx.Done():
						cancel()
						return contextTerminationError(ctx)
					}
				case <-ctx.Done():
					closeInput(cfg.Stdin)
					// Conn.Close has no cancellation mechanism and owns the
					// connection once started. Wait for it instead of calling
					// CloseNow concurrently, which would block on the same close.
					cancel()
					<-closeDone
					return contextTerminationError(ctx)
				}
			}
		}
	}
}

// stopAndJoinWriter interrupts the network and input sides, then waits for
// writeLoop. Waiting is required because writeLoop owns the only read from
// Stdin and must not outlive the WebSocket session. For a non-closable Stdin,
// this wait lasts until its Read implementation returns.
func stopAndJoinWriter(cfg Config, cancel context.CancelFunc, writeDone <-chan error) {
	closeInput(cfg.Stdin)
	cancel()
	_ = cfg.Conn.CloseNow()
	<-writeDone
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
