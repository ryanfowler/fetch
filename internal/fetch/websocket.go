package fetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"

	"github.com/ryanfowler/fetch/internal/body"
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
		core.WriteWarningMsgIf(p, "WebSocket requires GET; ignoring method "+req.Method, r.Verbosity == core.VSilent)
		req.Method = "GET"
	}

	// Timing waterfall is not supported for persistent WebSocket connections.
	if r.Timing {
		p := r.PrinterHandle.Stderr()
		core.WriteWarningMsgIf(p, "--timing is not supported for WebSocket connections", r.Verbosity == core.VSilent)
	}

	// Prepare the initial message from -d or -j flags. It is sent after the
	// handshake and is not part of the signed WebSocket upgrade request.
	var initialMsg []byte
	var initialReader io.Reader
	var initialMsgSet bool
	var dryRunBody *body.Body
	if source, ok := body.SourceFromContext(req.Context()); ok {
		initialMsgSet = true
		if r.DryRun {
			dryRunBody = source
		}
	}
	if req.Body != nil {
		if !r.DryRun {
			// Keep the body unopened until after the WebSocket handshake. This
			// is important for -d @- and other one-shot sources: connecting
			// must not wait for stdin or consume it before the peer accepts.
			initialReader = req.Body
		}
		req.Body = http.NoBody
		req.GetBody = nil
		req.ContentLength = 0
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

	if r.DryRun {
		// Client.Do normally applies cookies immediately before transport. The
		// WebSocket dialer does the same later, so apply them only to this
		// diagnostic request to show the effective redacted handshake.
		req = c.ApplyJarCookies(req)
	}
	if err := signWebSocketHandshake(r, req); err != nil {
		return 1, err
	}

	// Print request metadata / dry-run.
	if r.Verbosity >= core.VExtraVerbose || r.DryRun {
		errPrinter := r.PrinterHandle.Stderr()
		printRequestMetadataWithURL(errPrinter, req, r.HTTP, r.Verbosity, r.DryRun)
		if r.Verbosity >= core.VDebug {
			printProxyMetadata(errPrinter, r.Proxy, req.URL)
		}
		errPrinter.Flush()
		if r.DryRun {
			errPrinter.WriteString("WebSocket message mode: ")
			errPrinter.WriteString(r.WSMessageMode.String())
			errPrinter.WriteString("\n")
			errPrinter.Flush()
			if dryRunBody != nil {
				if r.Verbosity < core.VExtraVerbose {
					errPrinter.WriteString("\n")
					errPrinter.Flush()
				}
				if err := printDryRunBodyPreview(errPrinter, dryRunBody, r.Verbosity == core.VSilent); err != nil {
					return 1, err
				}
			}
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

	if err := c.ValidateTransport(req); err != nil {
		return 1, err
	}

	// Attach debug trace for -vvv.
	if r.Verbosity >= core.VDebug {
		trace, _ := newDebugTrace(r.PrinterHandle.Stderr())
		dialCtx = httptrace.WithClientTrace(dialCtx, trace)
	}

	opts := &websocket.DialOptions{
		HTTPClient:   c.HTTPClient(),
		HTTPHeader:   req.Header,
		Host:         req.Host,
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

	// Detect interactive mode: default to TUI only when all three FDs are terminals.
	interactive := core.IsStdinTerm && core.IsStdoutTerm && core.IsStderrTerm
	switch r.WSInteractive {
	case core.WSInteractiveOn:
		if !interactive {
			return 1, errors.New("--ws-interactive on requires stdin, stdout, and stderr to be terminals")
		}
	case core.WSInteractiveOff:
		interactive = false
	}

	// Determine stdin: use it for the write loop only if it's a pipe or
	// file. When stdin is a terminal or /dev/null, pass nil so we run in
	// read-only mode (unless interactive).
	var stdin io.Reader
	if !interactive {
		if info, err := os.Stdin.Stat(); err == nil {
			if info.Size() > 0 || info.Mode()&os.ModeNamedPipe != 0 {
				stdin = os.Stdin
			}
		}
	}

	cfg := ws.Config{
		Conn:          conn,
		Stdin:         stdin,
		Stderr:        r.PrinterHandle.Stderr(),
		Stdout:        r.PrinterHandle.Stdout(),
		Format:        r.Format,
		Verbosity:     r.Verbosity,
		InitialMsg:    initialMsg,
		InitialMsgSet: initialMsgSet,
		InitialReader: initialReader,
		MessageMode:   r.WSMessageMode,
		IsInteractive: interactive,
	}

	err = ws.Run(ctx, cfg)
	if err != nil {
		return 1, err
	}
	return 0, nil
}

func signWebSocketHandshake(r *Request, req *http.Request) error {
	if r.AWSSigv4 == nil {
		return nil
	}
	if req.Body == nil || req.Body == http.NoBody {
		return signAWSRequest(r, req)
	}

	body := req.Body
	getBody := req.GetBody
	contentLength := req.ContentLength
	req.Body = http.NoBody
	req.GetBody = nil
	req.ContentLength = 0
	err := signAWSRequest(r, req)
	req.Body = body
	req.GetBody = getBody
	req.ContentLength = contentLength
	return err
}
