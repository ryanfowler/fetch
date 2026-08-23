package fetch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/article"
	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/format"
	"github.com/ryanfowler/fetch/internal/har"
	"github.com/ryanfowler/fetch/internal/image"
	"github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/pager"
	iproto "github.com/ryanfowler/fetch/internal/proto"
	"github.com/ryanfowler/fetch/internal/resolver"
	"github.com/ryanfowler/fetch/internal/session"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// maxBodyBytes is retained as a local compatibility name for existing fetch
// code and tests; the limit itself is centralized in core.
const maxBodyBytes = core.MaxFormattedBodyBytes

func setReplayableBody(req *http.Request, data []byte) {
	body.Attach(req, body.NewBytes(data, req.Header.Get("Content-Type")))
}

type Request struct {
	AWSSigv4         *aws.Config
	Basic            *core.KeyVal[string]
	Bearer           string
	CACerts          []*x509.Certificate
	ClientCert       *tls.Certificate
	Clobber          bool
	ConnectTimeout   time.Duration
	ContentType      string
	Compression      core.CompressionMode
	Copy             bool
	Data             io.Reader
	Digest           *core.KeyVal[string]
	Discard          bool
	ResolverEndpoint *resolver.Endpoint
	DNSServer        *url.URL
	DryRun           bool
	ECH              core.ECHMode
	Edit             bool
	Form             []core.KeyVal[string]
	Format           core.Format
	GRPC             bool
	GRPCDescribe     string
	GRPCList         bool
	HAR              string
	Headers          []core.KeyVal[string]
	HTTP             core.HTTPVersion
	IgnoreStatus     bool
	Image            core.ImageSetting
	Insecure         bool
	NoEncode         bool
	NoPager          bool
	Pager            core.PagerMode
	Method           string
	Multipart        *multipart.Multipart
	Output           string
	PrinterHandle    *core.Handle
	ProtoDesc        string
	ProtoFiles       []string
	ProtoImports     []string
	Proxy            *url.URL
	QueryParams      []core.KeyVal[string]
	Range            []string
	Article          bool
	Redirects        *int
	RemoteHeaderName bool
	RemoteName       bool
	Retry            int
	RetryDelay       time.Duration
	Session          string
	Timeout          time.Duration
	Timing           bool
	TLSMax           uint16
	TLSMin           uint16
	UnixSocket       string
	URL              *url.URL
	Verbosity        core.Verbosity
	WS               bool
	WSInteractive    core.WSInteractiveMode
	WSMessageMode    core.WSMessageMode
	SchemelessURL    bool

	// responseDescriptor is set internally after proto setup for response formatting.
	responseDescriptor protoreflect.MessageDescriptor

	// harRecorder is reserved before the request starts and records the final
	// response exchange. It remains private so callers only provide a path.
	harRecorder *har.Recorder
}

func (r *Request) HasGRPCDiscovery() bool {
	return r.GRPCList || r.GRPCDescribe != ""
}

func (r *Request) HasGRPCMode() bool {
	return r.GRPC || r.HasGRPCDiscovery()
}

func (r *Request) HasLocalProtoSchema() bool {
	return len(r.ProtoFiles) > 0 || r.ProtoDesc != ""
}

func Fetch(ctx context.Context, r *Request) int {
	code, err := fetch(ctx, r)
	if signalCode, ok := core.SignalExitCode(context.Cause(ctx)); ok {
		return signalCode
	}
	if err == nil {
		return code
	}
	if core.IsBrokenPipe(err) {
		return 0
	}

	p := r.PrinterHandle.Stderr()
	core.WriteErrorMsgNoFlush(p, err)
	if plaintextHint := schemelessPlaintextHint(r, err); plaintextHint != "" {
		core.WriteWarningMsgIf(p, "If this is a plaintext service, use "+plaintextHint+".", r.Verbosity == core.VSilent)
	}

	if isCertificateErr(err) {
		p.WriteString("\n")
		printInsecureMsg(p)
	}

	p.Flush()
	return 1
}

func fetch(ctx context.Context, r *Request) (int, error) {
	if r.HAR != "" {
		if r.WS || r.GRPCList || r.GRPCDescribe != "" || r.DryRun {
			return 0, errors.New("--har cannot be used with WebSocket, gRPC discovery, or --dry-run")
		}
		if r.Output != "" && r.Output != "-" {
			harPath, err := filepath.Abs(r.HAR)
			if err != nil {
				return 0, err
			}
			outputPath, err := filepath.Abs(r.Output)
			if err != nil {
				return 0, err
			}
			if sameDestinationPath(harPath, outputPath) {
				return 0, errors.New("--har path cannot be the same as the response output path")
			}
		}
		recorder, err := har.New(r.HAR, r.Clobber)
		if err != nil {
			return 0, err
		}
		r.harRecorder = recorder
		defer func() {
			_ = recorder.Close()
			r.harRecorder = nil
		}()
	}

	if r.GRPC {
		applyGRPCDefaults(r)
	}
	// ECH discovery can be confidential only when the resolver transport is
	// authenticated. Emit this diagnostic once here, before retries and
	// redirects, rather than from each connection attempt.
	if r.Verbosity >= core.VDebug && client.ECHDiscoveryNeedsWarning(r.ECH, r.URL, r.ResolverEndpoint, r.Insecure, r.Proxy) {
		core.WriteWarningMsgIf(r.PrinterHandle.Stderr(), "ECH discovery is using a DNS resolver whose transport is not authenticated; the resolver can observe or alter the HTTPS record", r.Verbosity == core.VSilent)
	}

	// 1. Create the HTTP client.
	c := newClient(r)
	defer c.Close()

	// 2. Load session before reflection so cookies apply to discovery requests.
	// Reflection is part of the normal gRPC request flow and must use the same
	// cookie, TLS, proxy, DNS, and authentication policy as the final call.
	var sess *session.Session
	if r.Session != "" {
		var loadErr error
		if r.DryRun {
			sess, loadErr = session.LoadReadOnly(r.Session)
		} else {
			sess, loadErr = session.Load(r.Session)
		}
		if loadErr != nil {
			if sess == nil {
				return 0, loadErr
			}
			// Session file was corrupted; warn and start fresh.
			p := r.PrinterHandle.Stderr()
			msg := fmt.Sprintf("session '%s' is corrupted, starting fresh: %s", r.Session, loadErr.Error())
			core.WriteWarningMsgIf(p, msg, r.Verbosity == core.VSilent)
		}
		c.SetJar(sess.Jar())
		defer saveSession(r, sess)
	}

	// 3. Resolve any proto schema and configure gRPC descriptors.
	var schema *iproto.Schema
	var requestDesc protoreflect.MessageDescriptor
	var isClientStreaming, isServerStreaming bool
	if r.GRPC {
		var err error
		// Local descriptors are useful during dry-run because they let us show
		// the same framed/converted request that a real call would send. A
		// schema-less dry-run must not perform reflection network I/O; binary
		// input can still be framed, while JSON input is rejected below because
		// its conversion is impossible without a descriptor.
		schema, err = resolveCallSchema(ctx, r, c)
		if err != nil {
			return 0, err
		}
		requestDesc, r.responseDescriptor, isClientStreaming, isServerStreaming, err = setupGRPC(r, schema)
		if err != nil {
			// Reflection is advisory for a binary schema-less call. A
			// descriptor set that does not contain the requested method must
			// not prevent the raw framed request from being sent. JSON input
			// still requires a usable descriptor for conversion.
			if requiresGRPCSchema(r) {
				return 0, err
			}
			schema = nil
			requestDesc = nil
			r.responseDescriptor = nil
			isClientStreaming, isServerStreaming = false, false
		}
		if r.harRecorder != nil && (schema == nil || requestDesc == nil || isClientStreaming || isServerStreaming) {
			return 0, errors.New("--har for gRPC requires a positively identified unary method")
		}
	}

	headers := r.Headers
	if r.GRPC {
		headers = grpcHeaders(r.Headers)
	}
	req, err := c.NewRequest(ctx, client.RequestConfig{
		Article:     r.Article,
		Basic:       r.Basic,
		Bearer:      r.Bearer,
		Compression: r.Compression,
		ContentType: r.ContentType,
		Data:        r.Data,
		Form:        r.Form,
		Headers:     headers,
		HTTP:        r.HTTP,
		Method:      r.Method,
		Multipart:   r.Multipart,
		NoEncode:    r.NoEncode,
		QueryParams: r.QueryParams,
		Range:       r.Range,
		URL:         r.URL,
	})
	if err != nil {
		return 0, err
	}
	defer func() {
		if req.Body != nil {
			req.Body.Close()
		}
	}()

	// 4. WebSocket: branch to handleWebSocket before edit/gRPC/retry. The
	// session save is deferred above, so handshake cookie changes persist even
	// when the message loop or a later validation step fails.
	if r.WS {
		return handleWebSocket(ctx, r, c, req)
	}

	// 5. Edit step (user edits request body).
	if r.Edit {
		err = editRequestBody(req)
		if err != nil {
			return 0, err
		}
	}

	// 6. Convert and frame gRPC request AFTER edit. Protocol conversion is
	// the one dry-run path that may consume a one-shot source: without reading
	// it there is no way to show the effective protobuf frame. The shared
	// materialization cap guarantees that this happens once and remains
	// bounded. Raw binary dry-runs materialize only when framing requires a
	// lengthless source.
	if r.GRPC {
		if isClientStreaming && requestDesc != nil {
			if r.DryRun {
				// A replayable file can be converted directly through the
				// streaming factory. Materialize only a one-shot source so the
				// preview can open the converted stream without consuming it
				// twice.
				if err := materializeGRPCDryRunBody(req); err != nil {
					return 0, err
				}
			}
			// Client/bidi streaming JSON: convert multiple objects to separate
			// gRPC frames while preserving backpressure.
			if req.Body != nil && req.Body != http.NoBody {
				setStreamingGRPCBody(req, requestDesc)
			} else {
				// Empty client stream: no frames, just close immediately.
				req.Body = http.NoBody
				req.GetBody = nil
			}
		} else {
			// Unary / server-streaming: convert JSON with the descriptor, then
			// frame one protobuf message.
			if requestDesc != nil && requiresGRPCSchema(r) && req.Body != nil && req.Body != http.NoBody {
				converted, err := convertJSONToProtobuf(req.Body, requestDesc)
				if err != nil {
					return 0, err
				}
				setReplayableBody(req, converted)
			}
			if r.DryRun {
				source, _ := body.SourceFromContext(req.Context())
				framed, err := dryRunGRPCBody(source)
				if err != nil {
					return 0, err
				}
				body.Attach(req, framed)
			} else {
				framed, err := frameGRPCRequest(req.Body)
				if err != nil {
					return 0, err
				}
				setReplayableBody(req, framed)
			}
		}
	}

	if err := signAWSRequest(r, req); err != nil {
		return 0, err
	}
	if r.DryRun {
		// Client.Do normally lets net/http add jar cookies immediately before
		// transport. Dry-run prints earlier, so apply the jar here to expose the
		// effective, redacted Cookie header without writing session state.
		req = c.ApplyJarCookies(req)
	}
	if r.harRecorder != nil {
		req = req.WithContext(client.WithRequestObserver(req.Context(), r.harRecorder.ObserveRequest))
	}

	// 7. Print request metadata / dry-run.
	if r.Verbosity >= core.VExtraVerbose || r.DryRun {
		errPrinter := r.PrinterHandle.Stderr()
		printRequestMetadataWithURL(errPrinter, req, r.HTTP, r.Verbosity, r.DryRun)
		if r.Verbosity >= core.VDebug {
			printProxyMetadata(errPrinter, r.Proxy, req.URL)
		}

		if r.DryRun {
			if req.Body == nil || req.Body == http.NoBody {
				errPrinter.Flush()
				return 0, nil
			}

			if r.Verbosity < core.VExtraVerbose {
				errPrinter.WriteString("\n")
			}
			errPrinter.Flush()

			source, ok := body.SourceFromContext(req.Context())
			if !ok {
				return 0, errors.New("request body preview is unavailable")
			}
			if err := printDryRunBodyPreview(errPrinter, source, r.Verbosity == core.VSilent); err != nil {
				return 0, err
			}
			return 0, nil
		}

		// Trailing "> \n" already written by printRequestMetadata.
		errPrinter.Flush()
	}

	// 8. Make request (with optional retries and per-attempt timeout).
	code, err := retryableRequest(ctx, r, c, req)

	return code, err
}

func printDryRunBodyPreview(p *core.Printer, source *body.Body, silent bool) error {
	// A preview of a replayable source can be retained and replayed by the
	// body abstraction. A one-shot source, such as stdin, must not be read
	// during dry-run: doing so can block forever and would consume bytes a
	// real request would otherwise receive.
	if !source.Replayable() {
		core.WriteWarningMsgIf(p, "request body preview is unavailable for a one-shot source", silent)
		return nil
	}
	preview, err := source.Preview(core.MaxDryRunBodyPreview)
	if err != nil {
		return err
	}
	printable, _, err := isPrintable(bytes.NewReader(preview.Data))
	if err != nil {
		return err
	}
	if printable {
		if _, err = p.WriteString(core.TerminalSafeText(string(preview.Data))); err != nil {
			return err
		}
		if preview.Truncated {
			if len(preview.Data) > 0 && preview.Data[len(preview.Data)-1] != '\n' {
				p.WriteString("\n")
			}
			core.WriteWarningMsgIf(p, "request body preview truncated at 1024 bytes", silent)
		}
		return p.Flush()
	}

	core.WriteWarningMsgIf(p, "the request body appears to be binary", silent)
	if preview.Truncated {
		core.WriteWarningMsgIf(p, "request body preview truncated at 1024 bytes", silent)
	}
	return nil
}

func saveSession(r *Request, sess *session.Session) {
	if r.DryRun || sess == nil {
		return
	}
	if saveErr := sess.Save(); saveErr != nil {
		p := r.PrinterHandle.Stderr()
		msg := fmt.Sprintf("unable to save session '%s': %s", sess.Name, saveErr.Error())
		core.WriteWarningMsgIf(p, msg, r.Verbosity == core.VSilent)
	}
}

func signAWSRequest(r *Request, req *http.Request) error {
	if r.AWSSigv4 == nil {
		return nil
	}
	// SigV4 normally hashes a replayable body or materializes a one-shot body.
	// A dry-run must not consume stdin merely to print redacted authorization
	// metadata, so use the standard unsigned-payload marker for that diagnostic
	// case. No request is sent from dry-run, and replayable sources still use
	// their exact payload hash.
	if r.DryRun {
		if source, ok := body.SourceFromContext(req.Context()); ok && !source.Replayable() && req.Body != nil && req.Body != http.NoBody && req.Header.Get("X-Amz-Content-Sha256") == "" {
			req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		}
	}
	if err := aws.Sign(req, *r.AWSSigv4, time.Now().UTC()); err != nil {
		return err
	}
	client.MarkCredentialHeaders(req,
		"Authorization", "X-Amz-Date", "X-Amz-Content-Sha256",
		"X-Amz-Security-Token", "X-Amz-Session-Token")
	return nil
}

func processResponse(ctx context.Context, r *Request, resp *http.Response, hadRedirects, hadRetries bool, metrics *connectionMetrics) (exitCode int, retErr error) {
	if !r.IgnoreStatus {
		exitCode = getExitCodeForStatus(resp.StatusCode)
	}

	if r.Verbosity >= core.VNormal {
		p := r.PrinterHandle.Stderr()
		// Add blank line to separate retry/redirect output from response metadata.
		// At VDebug, the TTFB trace callback already writes a trailing "* \n".
		if (hadRetries && r.Verbosity < core.VDebug) || (hadRedirects && r.Verbosity == core.VVerbose) {
			if r.Verbosity >= core.VExtraVerbose {
				p.WriteInfoPrefix()
			}
			p.WriteString("\n")
		}
		printResponseMetadata(p, r.Verbosity, resp)
		p.Flush()
	}

	// Wrap response body to measure body download time. HAR needs this timing
	// even when --timing was not requested.
	var bodyTimer *timedReader
	if (r.Timing || r.harRecorder != nil) && metrics != nil {
		bodyTimer = newTimedReader(resp.Body)
		resp.Body = bodyTimer
	}
	// Install one response pipeline before any output mode can consume the
	// body. This allows clipboard/HAR/progress observers to share one read.
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	responseStream := body.NewStream(resp.Body)
	var harResponse *har.ResponseCapture
	if r.harRecorder != nil {
		harResponse = r.harRecorder.CaptureResponse(resp)
		responseStream.AddTee(harResponse)
	}
	resp.Body = responseStream
	// Every consumer below can block on a body read. Tie the original response
	// stream to the request context so cancellation closes it promptly, even
	// when a formatter, file writer, or discard path owns the read loop.
	var exchangeCompleted time.Time
	responseContext := ctx
	if resp.Request != nil {
		responseContext = resp.Request.Context()
	}
	stopBodyClose := closeReaderOnContext(responseContext, resp.Body)
	defer stopBodyClose()
	if r.harRecorder != nil {
		defer func() {
			timings := har.Timings{TransferSize: -1}
			if metrics != nil {
				t := metrics.snapshot()
				timings.DNS = t.dnsDur
				timings.Connect = t.tcpDur
				timings.TLS = t.tlsDur
				timings.Wait = t.ttfbDur
				timings.RemoteIP = t.remoteIP
				timings.DNSKnown = !t.dnsStart.IsZero()
				timings.ConnectKnown = !t.tcpStart.IsZero()
				timings.TLSKnown = !t.tlsStart.IsZero()
				timings.WaitKnown = !t.ttfbStart.IsZero()
			}
			if bodyTimer != nil {
				timings.Receive = bodyTimer.wallTime()
				timings.ReceiveKnown = !bodyTimer.firstRead.IsZero()
			}
			if wireSize := client.WireContentLength(resp); wireSize >= 0 {
				timings.TransferSize = wireSize
				timings.TransferKnown = true
			} else if progress, ok := resp.Body.(interface{ ProgressBytes() (int64, bool) }); ok {
				if wireSize, valid := progress.ProgressBytes(); valid {
					timings.TransferSize = wireSize
					timings.TransferKnown = true
				}
			}
			if !timings.TransferKnown && len(resp.Header.Values("Content-Encoding")) == 0 && harResponse != nil {
				timings.TransferSize = harResponse.Size()
				timings.TransferKnown = true
			}
			if retErr != nil {
				return
			}
			if bodyTimer != nil && !bodyTimer.lastRead.IsZero() {
				timings.CompletedAt = bodyTimer.lastRead
			} else if !exchangeCompleted.IsZero() {
				timings.CompletedAt = exchangeCompleted
			}
			if harErr := r.harRecorder.Finalize(resp, harResponse, timings); harErr != nil && retErr == nil {
				exitCode = 0
				retErr = harErr
			}
		}()
	}

	if r.Discard {
		_, err := io.Copy(io.Discard, resp.Body)
		if err != nil {
			return 0, err
		}
		if r.Timing && bodyTimer != nil {
			p := r.PrinterHandle.Stderr()
			renderWaterfall(p, metrics, bodyTimer)
			p.Flush()
		}
		if r.GRPC {
			exitCode = checkGRPCStatus(r, resp, exitCode)
		}
		exchangeCompleted = time.Now()
		return exitCode, nil
	}

	// If --copy is requested, wrap the response body to capture raw bytes.
	cc := newClipboardCopier(r, resp)

	body, err := formatResponse(ctx, r, resp, cc)
	if err != nil {
		return 0, err
	}

	if body == nil {
		// HEAD, discard-to-file, and formatters that consume the body have
		// completed the response by this point. Body reads take precedence
		// below when a timed source recorded a more precise completion time.
		exchangeCompleted = time.Now()
	}
	if body != nil {
		p := r.PrinterHandle.Stderr()
		// Explicit raw formatting is an opt-in terminal bypass, just like
		// -o -. Pipes are already safe because they are not terminals.
		forceRaw := r.Output == "-" || r.Format == core.FormatOff
		contentType := resp.Header.Get("Content-Type")
		err = streamToStdoutWithPagerContent(ctx, body, p, forceRaw, r.NoPager, cc != nil || r.harRecorder != nil, r.Verbosity == core.VSilent, r.Pager, contentType)
		if err != nil {
			return 0, err
		}
	}

	if bodyTimer == nil || bodyTimer.lastRead.IsZero() {
		exchangeCompleted = time.Now()
	}

	// Copy captured bytes to clipboard.
	cc.finish(r.PrinterHandle.Stderr())

	// Render timing waterfall after body is fully consumed.
	if r.Timing && bodyTimer != nil {
		p := r.PrinterHandle.Stderr()
		renderWaterfall(p, metrics, bodyTimer)
		p.Flush()
	}

	// Check gRPC trailer status after the body has been fully consumed.
	if r.GRPC {
		exitCode = checkGRPCStatus(r, resp, exitCode)
	}

	return exitCode, nil
}

func formatWithBoundedOutput(p *core.Printer, subsystem string, fn func(*core.Printer) error) ([]byte, error) {
	out := p.NewBoundedWriter(io.Discard, maxBodyBytes, subsystem)
	if err := fn(out); err != nil {
		return nil, err
	}
	if err := out.Err(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func formatResponse(ctx context.Context, r *Request, resp *http.Response, cc *clipboardCopier) (io.Reader, error) {
	// Avoid trying to format the response for HEAD requests.
	if resp.Request != nil && resp.Request.Method == "HEAD" {
		return nil, nil
	}

	if r.Article {
		return formatArticleResponse(r, resp, cc)
	}

	output, outputWarning, err := getOutputValueDetails(r, resp)
	if err != nil {
		return nil, err
	}
	if outputWarning != "" {
		core.WriteWarningMsgIf(r.PrinterHandle.Stderr(), outputWarning, r.Verbosity == core.VSilent)
	}
	if err := rejectHAROutputPath(r, output); err != nil {
		return nil, err
	}

	// An explicit stdout output path is a raw byte route. Do this before image
	// decoding so users can download an image to a pipe without invoking a
	// renderer or an external adapter.
	if r.Output == "-" {
		return resp.Body, nil
	}

	if output != "" && r.Output != "-" {
		size := client.WireContentLength(resp)
		p := r.PrinterHandle.Stderr()
		return nil, writeOutputToFile(output, resp.Body, size, p, r.Verbosity, r.Clobber)
	}

	if r.Format == core.FormatOff || (!core.IsStdoutTerm && r.Format != core.FormatOn) {
		return resp.Body, nil
	}

	p := r.PrinterHandle.Stdout()
	contentType, charset := format.GetContentType(resp.Header)

	// gRPC streaming needs the response descriptor — handle inline, but keep
	// the formatted stream pageable and backpressure-aware.
	if contentType == format.TypeGRPC {
		grpcEncoding := resp.Header.Get("grpc-encoding")
		reader := newFormattedStream(resp.Body, p, func(input io.Reader, output *core.Printer) error {
			return format.FormatGRPCStreamWithEncoding(input, r.responseDescriptor, output, grpcEncoding)
		}, resp.Body)
		return reader, nil
	}

	// Dispatch registered streaming formatters (NDJSON, SSE) through a pipe.
	// The formatter can flush each event while the downstream pager still
	// controls backpressure and process lifetime; no complete response is
	// buffered merely to make it pageable.
	if fn := format.GetStreaming(contentType); fn != nil {
		return newFormattedStream(transcodeReader(resp.Body, charset), p, fn, resp.Body), nil
	}

	// If image rendering is disabled, return the reader immediately.
	if contentType == format.TypeImage && r.Image == core.ImageOff {
		return resp.Body, nil
	}

	// An unknown content type only needs a bounded prefix for sniffing. If it
	// is not a formatter, return that prefix immediately and keep the rest of
	// the response streaming instead of buffering a formatting-sized body.
	var prefix []byte
	if contentType == format.TypeUnknown {
		prefix, err = io.ReadAll(io.LimitReader(resp.Body, 1024))
		if err != nil {
			return nil, err
		}
		contentType = format.SniffContentType(prefix)
		if contentType == format.TypeUnknown || (contentType == format.TypeImage && r.Image == core.ImageOff) {
			return newUntrustedResponseReader(newReaderWithCloser(io.MultiReader(bytes.NewReader(prefix), resp.Body), resp.Body)), nil
		}
	}

	formatInput := io.Reader(resp.Body)
	if len(prefix) > 0 {
		formatInput = io.MultiReader(bytes.NewReader(prefix), resp.Body)
	}
	buf, err := io.ReadAll(io.LimitReader(formatInput, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > maxBodyBytes {
		// We've read past the in-memory formatting limit, skip formatting.
		return newUntrustedResponseReader(newReaderWithCloser(io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body)), nil
	}

	// Transcode non-UTF-8 text to UTF-8, skipping binary formats.
	switch contentType {
	case format.TypeImage, format.TypeMsgPack, format.TypeProtobuf:
	default:
		buf = transcodeBytes(buf, charset)
	}

	// Special cases that need extra context beyond ([]byte, *Printer).
	if contentType == format.TypeImage {
		return nil, image.RenderWithMode(ctx, buf, r.Image)
	}
	if contentType == format.TypeProtobuf && r.responseDescriptor != nil {
		if formatted, err := formatWithBoundedOutput(p, "formatted response", func(out *core.Printer) error {
			return format.FormatProtobufWithDescriptor(buf, r.responseDescriptor, out)
		}); err == nil {
			buf = formatted
		} else {
			return newUntrustedResponseReader(bytes.NewReader(buf)), nil
		}
		return bytes.NewReader(buf), nil
	}

	// Dispatch registered buffered formatters through a bounded private printer.
	// This keeps the output limit at the response boundary instead of requiring
	// every formatter to implement the same buffering policy.
	formattedResponse := false
	if fn := format.GetBuffered(contentType); fn != nil {
		if formatted, err := formatWithBoundedOutput(p, "formatted response", func(out *core.Printer) error {
			return fn(buf, out)
		}); err == nil {
			buf = formatted
			formattedResponse = true
		} else {
			return newUntrustedResponseReader(bytes.NewReader(buf)), nil
		}
	}

	if formattedResponse {
		return bytes.NewReader(buf), nil
	}
	return newUntrustedResponseReader(bytes.NewReader(buf)), nil
}

func rejectHAROutputPath(r *Request, output string) error {
	if r == nil || r.harRecorder == nil || output == "" || output == "-" {
		return nil
	}
	harPath, err := filepath.Abs(r.HAR)
	if err != nil {
		return err
	}
	outputPath, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if sameDestinationPath(harPath, outputPath) {
		return errors.New("--har path cannot be the same as the response output path")
	}
	return nil
}

func sameDestinationPath(first, second string) bool {
	canonical := func(path string) string {
		abs, err := filepath.Abs(path)
		if err != nil {
			return filepath.Clean(path)
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		dir, name := filepath.Dir(abs), filepath.Base(abs)
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			dir = resolved
		}
		return filepath.Clean(filepath.Join(dir, name))
	}
	first, second = canonical(first), canonical(second)
	if first == second {
		return true
	}
	return strings.EqualFold(first, second) && os.PathSeparator == '\\'
}

func formatArticleResponse(r *Request, resp *http.Response, cc *clipboardCopier) (io.Reader, error) {
	_, charset := format.GetContentType(resp.Header)
	original := resp.Body
	decoded, err := article.ReadLimited(transcodeReader(original, charset))
	closeErr := original.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}

	pageURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		pageURL = resp.Request.URL.String()
	} else if r.URL != nil {
		pageURL = r.URL.String()
	}
	markdown, err := article.Render(decoded, resp.Header.Get("Content-Type"), pageURL)
	if err != nil {
		return nil, err
	}

	// Article extraction is a presentation transformation. Replace the
	// consumed response with the uncolored Markdown so output files and pipes
	// receive the exact article document, independent of terminal settings.
	resp.Body = io.NopCloser(bytes.NewReader(markdown))
	resp.ContentLength = int64(len(markdown))
	cc.setBytes(markdown)

	output, outputWarning, err := getOutputValueDetails(r, resp)
	if err != nil {
		return nil, err
	}
	if outputWarning != "" {
		core.WriteWarningMsgIf(r.PrinterHandle.Stderr(), outputWarning, r.Verbosity == core.VSilent)
	}
	if err := rejectHAROutputPath(r, output); err != nil {
		return nil, err
	}
	if output != "" && r.Output != "-" {
		size := int64(len(markdown))
		p := r.PrinterHandle.Stderr()
		return nil, writeOutputToFile(output, resp.Body, size, p, r.Verbosity, r.Clobber)
	}

	// Pipes and explicit raw output must not receive terminal formatting.
	if r.Output == "-" || r.Format == core.FormatOff || !core.IsStdoutTerm {
		return resp.Body, nil
	}

	p := r.PrinterHandle.Stdout()
	if err := format.FormatMarkdown(markdown, p); err != nil {
		return nil, err
	}
	return bytes.NewReader(p.Bytes()), nil
}

func newFormattedStream(source io.Reader, p *core.Printer, formatter format.StreamingFormatter, closers ...io.Closer) io.ReadCloser {
	reader, writer := io.Pipe()
	streamPrinter := p.NewWriter(writer)
	go func() {
		err := formatter(source, streamPrinter)
		if err != nil {
			_ = writer.CloseWithError(err)
			return
		}
		_ = writer.Close()
	}()
	return newReaderWithCloser(reader, append([]io.Closer{reader}, closers...)...)
}

func streamToStdout(r io.Reader, p *core.Printer, forceOutput, noPager, drainSuppressedBinary bool) error {
	return streamToStdoutWithPagerContent(context.Background(), r, p, forceOutput, noPager, drainSuppressedBinary, false, core.PagerUnknown, "")
}

func streamToStdoutWithPagerContent(ctx context.Context, r io.Reader, p *core.Printer, forceOutput, noPager, drainSuppressedBinary, silent bool, pagerMode core.PagerMode, contentType string) error {
	if noPager || forceOutput || isImageContentType(contentType) {
		// Raw output must remain byte-oriented, and image protocol bytes must
		// never be fed to a text pager. This also makes --output - an explicit
		// pager bypass, matching its raw-output contract.
		pagerMode = core.PagerOff
	}
	imageOutput := isImageContentType(contentType)

	// Buffered formatting fallbacks are still untrusted response data. Escape
	// terminal controls before sending them to a terminal, but leave explicit
	// raw output and formatted ANSI output unchanged.
	sanitizeTerminal := false
	if _, ok := r.(interface{ untrustedResponse() }); ok && core.IsStdoutTerm && !forceOutput && !imageOutput {
		sanitizeTerminal = true
	}

	// A terminal must not receive a response chunk until that chunk has
	// passed the binary classifier. The guard continues checking later chunks,
	// so a binary response cannot hide behind an initial text prefix.
	if core.IsStdoutTerm && !forceOutput {
		guard := newBinaryGuardReader(r, drainSuppressedBinary, nil)
		stopClosing := closeReaderOnContext(ctx, guard)
		first := make([]byte, 64*1024)
		n, err := guard.Read(first)
		if n == 0 && guard.Triggered() {
			stopClosing()
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			printBinaryWarningContentType(p, silent, contentType)
			return nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			stopClosing()
			return err
		}
		if n == 0 {
			stopClosing()
			return nil
		}

		r = newReaderWithCloser(io.MultiReader(bytes.NewReader(first[:n]), guard), guard)
		if sanitizeTerminal {
			r = newTerminalSafeReader(r)
		}
		err = pager.StreamContext(ctx, r, pagerMode, core.IsStdoutTerm, imageOutput, os.Stdout)
		stopClosing()
		if err != nil {
			return err
		}
		if guard.Triggered() {
			printBinaryWarningAfterBody(p, silent, contentType)
		}
		return nil
	}

	stopClosing := closeReaderOnContext(ctx, r)
	err := pager.StreamContext(ctx, r, pagerMode, core.IsStdoutTerm, imageOutput, os.Stdout)
	stopClosing()
	return err
}

func isImageContentType(contentType string) bool {
	contentType, _, _ = strings.Cut(strings.ToLower(contentType), ";")
	return strings.HasPrefix(strings.TrimSpace(contentType), "image/")
}

func getExitCodeForStatus(status int) int {
	switch {
	case status >= 200 && status < 400:
		return 0
	case status >= 400 && status < 500:
		return 4
	case status >= 500 && status < 600:
		return 5
	default:
		return 6
	}
}

func getHeaders(headers http.Header) []core.KeyVal[string] {
	// Keep one entry per value. Joining duplicate headers with commas changes
	// the request metadata for headers whose values are not comma-list syntax.
	// Stable sorting keeps the supplied value order within a name while
	// retaining deterministic alphabetical header-name output.
	out := make([]core.KeyVal[string], 0, len(headers))
	for k, values := range headers {
		name := strings.ToLower(k)
		for _, value := range values {
			if name == "location" {
				value = redactedRedirectLocation(value)
			}
			out = append(out, core.KeyVal[string]{
				Key: name,
				Val: core.RedactHeaderValue(name, value),
			})
		}
	}
	slices.SortStableFunc(out, func(a, b core.KeyVal[string]) int {
		return strings.Compare(a.Key, b.Key)
	})
	return out
}

func addHeader(headers []core.KeyVal[string], h core.KeyVal[string]) []core.KeyVal[string] {
	i, _ := slices.BinarySearchFunc(headers, h, func(a, b core.KeyVal[string]) int {
		return strings.Compare(a.Key, b.Key)
	})
	return slices.Insert(headers, i, h)
}

// schemelessPlaintextHint returns an HTTP alternative for a failed
// schemeless HTTPS connection when the failure is not a certificate or timeout
// error.
func schemelessPlaintextHint(r *Request, err error) string {
	if r == nil || !r.SchemelessURL || r.URL == nil || r.URL.Scheme != "https" || isCertificateErr(err) {
		return ""
	}
	var recordErr tls.RecordHeaderError
	if !errors.As(err, &recordErr) {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ""
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) || urlErr == nil {
		return ""
	}

	hintURL := *r.URL
	hintURL.Scheme = "http"
	return core.RedactedURL(&hintURL)
}

// isCertificateErr returns true if the error has to do with TLS cert validation.
func isCertificateErr(err error) bool {
	urlErr, ok := errors.AsType[*url.Error](err)
	if !ok {
		return false
	}

	if _, ok := errors.AsType[x509.CertificateInvalidError](urlErr.Err); ok {
		return true
	}

	if _, ok := errors.AsType[x509.HostnameError](urlErr.Err); ok {
		return true
	}

	if _, ok := errors.AsType[x509.UnknownAuthorityError](urlErr.Err); ok {
		return true
	}

	return false
}

func printInsecureMsg(p *core.Printer) {
	p.WriteString("If you absolutely trust the server, try '")
	p.Set(core.Bold)
	p.WriteString("--insecure")
	p.Reset()
	p.WriteString("'.\n")
}
