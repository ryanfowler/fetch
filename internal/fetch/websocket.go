package fetch

import (
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/ws"

	"github.com/coder/websocket"
)

// handleWebSocket performs a WebSocket upgrade and runs the bidirectional
// message loop.
func handleWebSocket(ctx context.Context, r *Request, c *client.Client, req *http.Request) (int, error) {
	// WebSocket requires GET for the upgrade handshake.
	if req.Method != "GET" {
		p := r.PrinterHandle.Stderr()
		core.WriteWarningMsg(p, "WebSocket requires GET; ignoring method "+req.Method)
		p.Flush()
	}

	// Extract Sec-WebSocket-Protocol for DialOptions.Subprotocols.
	var subprotocols []string
	if proto := req.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		for p := range strings.SplitSeq(proto, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				subprotocols = append(subprotocols, p)
			}
		}
		req.Header.Del("Sec-WebSocket-Protocol")
	}

	// Print request metadata / dry-run.
	if r.Verbosity >= core.VExtraVerbose || r.DryRun {
		errPrinter := r.PrinterHandle.Stderr()
		printRequestMetadata(errPrinter, req, r.HTTP, r.Verbosity)
		errPrinter.Flush()
		if r.DryRun {
			return 0, nil
		}
	}

	// Apply timeout to the handshake only.
	dialCtx := ctx
	if r.Timeout > 0 {
		var cancelDial context.CancelFunc
		dialCtx, cancelDial = context.WithTimeout(ctx, r.Timeout)
		defer cancelDial()
	}

	// Attach debug trace for -vvv.
	if r.Verbosity >= core.VDebug {
		trace := newDebugTrace(r.PrinterHandle.Stderr())
		dialCtx = httptrace.WithClientTrace(dialCtx, trace)
	}

	opts := &websocket.DialOptions{
		HTTPClient:   c.HTTPClient(),
		HTTPHeader:   req.Header,
		Subprotocols: subprotocols,
	}

	conn, resp, err := websocket.Dial(dialCtx, req.URL.String(), opts)
	if err != nil {
		return 1, err
	}
	defer conn.CloseNow()
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Print response metadata.
	if r.Verbosity >= core.VNormal && resp != nil {
		p := r.PrinterHandle.Stderr()
		printResponseMetadata(p, r.Verbosity, resp)
		p.Flush()
	}

	// Prepare the initial message from -d or -j flags.
	var initialMsg []byte
	if req.Body != nil {
		initialMsg, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return 1, err
		}
	}

	// Determine stdin: use it for the write loop only if it's a pipe or
	// file. When stdin is a terminal or /dev/null, pass nil so we run in
	// read-only mode.
	var stdin io.Reader
	if info, err := os.Stdin.Stat(); err == nil {
		if info.Size() > 0 || info.Mode()&os.ModeNamedPipe != 0 {
			stdin = os.Stdin
		}
	}

	cfg := ws.Config{
		Conn:       conn,
		Stdin:      stdin,
		Stderr:     r.PrinterHandle.Stderr(),
		Stdout:     r.PrinterHandle.Stdout(),
		Format:     r.Format,
		Verbosity:  r.Verbosity,
		InitialMsg: initialMsg,
	}

	err = ws.Run(ctx, cfg)
	if err != nil {
		return 1, err
	}
	return 0, nil
}
