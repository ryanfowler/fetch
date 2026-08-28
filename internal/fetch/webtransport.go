package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/webtransport-go"
	"github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/wt"
)

func handleWebTransport(ctx context.Context, r *Request, c *client.Client, req *http.Request) (int, error) {
	if r.MethodExplicit && req.Method != http.MethodConnect {
		p := r.PrinterHandle.Stderr()
		core.WriteWarningMsgIf(p, "WebTransport requires CONNECT; ignoring method "+req.Method, r.Verbosity == core.VSilent)
		req.Method = http.MethodConnect
	}
	p := r.PrinterHandle.Stderr()
	if r.Timing {
		core.WriteWarningMsgIf(p, "--timing is not supported for WebTransport connections", r.Verbosity == core.VSilent)
	}
	if r.Pager != core.PagerUnknown || r.NoPager {
		core.WriteWarningMsgIf(p, "pager does not apply to WebTransport output", r.Verbosity == core.VSilent)
	}
	if r.Image != core.ImageUnknown {
		core.WriteWarningMsgIf(p, "image rendering does not apply to WebTransport output", r.Verbosity == core.VSilent)
	}

	protocols := append([]string(nil), r.WTProtocols...)
	if len(protocols) > 0 {
		value, err := marshalWTProtocols(protocols)
		if err != nil {
			return 1, err
		}
		req.Header.Set("WT-Available-Protocols", value)
	}
	// A CONNECT body is never sent. Preserve it as deferred application input.
	var initialReader io.Reader
	var initialSet bool
	var preview *body.Body
	initialOwned := false
	if source, ok := body.SourceFromContext(req.Context()); ok {
		initialSet = true
		if r.DryRun {
			preview = source
		}
	}
	if req.Body != nil && req.Body != http.NoBody {
		if !r.DryRun {
			initialReader = req.Body
			initialOwned = true
		}
		req.Body = http.NoBody
		req.GetBody = nil
		req.ContentLength = 0
	}
	defer func() {
		if initialOwned {
			if closer, ok := initialReader.(io.Closer); ok {
				_ = closer.Close()
			}
		}
	}()
	// Transport.Dial is not an http.Client request, so apply the active jar
	// explicitly. Do this once, before signing, just like net/http.
	req = c.ApplyJarCookies(req)
	if err := signAWSRequest(r, req); err != nil {
		return 1, err
	}
	// This check is network-free and also catches environment and system
	// proxies. It must run before dry-run output and before the QUIC dial.
	if err := c.ValidateTransport(req); err != nil {
		return 1, err
	}

	if r.Verbosity >= core.VExtraVerbose || r.DryRun {
		p := r.PrinterHandle.Stderr()
		printRequestMetadataWithURL(p, req, core.HTTP3, r.Verbosity, r.DryRun)
		if r.Verbosity >= core.VDebug {
			printProxyMetadata(p, r.Proxy, req.URL)
			printResolverMetadata(p, c)
		}
		p.WriteString("webtransport mode: ")
		p.WriteString(r.WTMode.String())
		p.WriteString("\n")
		if len(protocols) > 0 {
			p.WriteString("webtransport protocols: ")
			p.WriteString(core.TerminalSafeText(strings.Join(protocols, ", ")))
			p.WriteString("\n")
		}
		p.Flush()
		if r.DryRun {
			if preview != nil {
				if err := printDryRunBodyPreview(p, preview, r.Verbosity == core.VSilent); err != nil {
					_ = preview.Close()
					return 1, err
				}
				_ = preview.Close()
			}
			return 0, nil
		}
	}
	dialCtx := ctx
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	if r.Verbosity >= core.VDebug {
		trace, _ := newDebugTrace(r.PrinterHandle.Stderr())
		dialCtx = httptrace.WithClientTrace(dialCtx, trace)
	}
	t, err := c.NewWebTransport(protocols)
	if err != nil {
		return 1, err
	}
	resp, session, err := t.Dial(dialCtx, req.URL.String(), req.Header)
	if resp != nil {
		c.SetResponseCookies(req.URL, resp)
	}
	if r.Verbosity >= core.VNormal && resp != nil {
		p := r.PrinterHandle.Stderr()
		printResponseMetadata(p, r.Verbosity, resp)
		if r.Verbosity >= core.VVerbose {
			if selected := resp.Header.Get("WT-Protocol"); selected != "" {
				p.WriteString("webtransport protocol: ")
				p.WriteString(core.TerminalSafeText(selected))
				p.WriteString("\n")
			}
		}
		p.Flush()
	}
	if err != nil {
		return 1, webtransportHandshakeError(resp, err)
	}
	if session == nil {
		return 1, errors.New("WebTransport handshake succeeded without a session")
	}
	defer session.CloseWithError(0, "")
	state := session.SessionState()
	if r.Verbosity >= core.VVerbose && state.ApplicationProtocol != "" {
		p := r.PrinterHandle.Stderr()
		p.WriteString("webtransport protocol: ")
		p.WriteString(core.TerminalSafeText(state.ApplicationProtocol))
		p.WriteString("\n")
		p.Flush()
	}

	stdin := io.Reader(nil)
	if initialReader == nil || isReplayableInitial(req) {
		if info, statErr := os.Stdin.Stat(); statErr == nil && (info.Size() > 0 || info.Mode()&os.ModeNamedPipe != 0) {
			stdin = os.Stdin
		}
	}
	initialOwned = false
	stdout := &flushPrinterWriter{printer: r.PrinterHandle.Stdout()}
	return wtStatus(wt.Run(ctx, wt.Config{Session: webTransportSession{session}, Stdin: stdin, Stdout: stdout, Mode: r.WTMode, DatagramMode: r.WTDgramMode, InitialPayloadSet: initialSet && initialReader == nil, InitialPayload: nil, InitialReader: initialReader, TerminalOutput: core.IsStdoutTerm && r.WTMode == core.WTStream}))
}

type flushPrinterWriter struct{ printer *core.Printer }

func (w *flushPrinterWriter) Write(p []byte) (int, error) {
	n, err := w.printer.Write(p)
	if err != nil {
		return n, err
	}
	if err = w.printer.Flush(); err != nil {
		return n, err
	}
	return n, nil
}

func isReplayableInitial(req *http.Request) bool {
	source, ok := body.SourceFromContext(req.Context())
	return ok && source.Replayable()
}

func wtStatus(err error) (int, error) {
	if err != nil {
		return 1, err
	}
	return 0, nil
}

func marshalWTProtocols(protocols []string) (string, error) {
	list := make(httpsfv.List, 0, len(protocols))
	for _, protocol := range protocols {
		list = append(list, httpsfv.NewItem(protocol))
	}
	value, err := httpsfv.Marshal(list)
	if err != nil {
		return "", fmt.Errorf("invalid WebTransport application protocol: %w", err)
	}
	return value, nil
}

type webTransportSession struct{ session *webtransport.Session }

func (s webTransportSession) OpenStream(ctx context.Context) (io.ReadWriteCloser, error) {
	return s.session.OpenStreamSync(ctx)
}
func (s webTransportSession) SendDatagram(data []byte) error { return s.session.SendDatagram(data) }
func (s webTransportSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.session.ReceiveDatagram(ctx)
}
func (s webTransportSession) Close() error { return s.session.CloseWithError(0, "") }

func webtransportHandshakeError(resp *http.Response, err error) error {
	message := "WebTransport handshake failed"
	if resp != nil {
		message += " with " + core.TerminalSafeText(resp.Status)
	}
	if err != nil {
		message += ": " + core.RedactedErrorText(err)
	}
	if resp == nil || resp.Body == nil {
		return errors.New(message)
	}
	const limit = 1024
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	_ = resp.Body.Close()
	if len(data) > limit {
		data = data[:limit]
	}
	if len(data) > 0 {
		message += fmt.Sprintf(": response excerpt %q", core.TerminalSafeText(string(data)))
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		message += ": " + core.TerminalSafeText(readErr.Error())
	}
	return errors.New(message)
}
