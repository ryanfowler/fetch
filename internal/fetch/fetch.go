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
	"slices"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/format"
	"github.com/ryanfowler/fetch/internal/image"
	"github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/pager"
	iproto "github.com/ryanfowler/fetch/internal/proto"
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
	DNSServer        *url.URL
	DryRun           bool
	Edit             bool
	Form             []core.KeyVal[string]
	Format           core.Format
	GRPC             bool
	GRPCDescribe     string
	GRPCList         bool
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
	SchemelessURL    bool

	// responseDescriptor is set internally after proto setup for response formatting.
	responseDescriptor protoreflect.MessageDescriptor
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
	if r.GRPC {
		applyGRPCDefaults(r)
	}

	// 1. Create the HTTP client.
	c := newClient(r)
	defer c.Close()

	// 2. Resolve any proto schema and configure gRPC descriptors.
	var schema *iproto.Schema
	var requestDesc protoreflect.MessageDescriptor
	var isClientStreaming bool
	if r.GRPC {
		var err error
		schema, err = resolveCallSchema(ctx, r, c)
		if err != nil {
			return 0, err
		}
		requestDesc, r.responseDescriptor, isClientStreaming, err = setupGRPC(r, schema)
		if err != nil {
			return 0, err
		}
	}

	// 3. Load session and set cookie jar, if configured.
	var sess *session.Session
	if r.Session != "" {
		var loadErr error
		sess, loadErr = session.Load(r.Session)
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

	// 4. WebSocket: branch to handleWebSocket before edit/gRPC/retry.
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

	// 6. Convert and frame gRPC request AFTER edit.
	if r.GRPC {
		if isClientStreaming && requestDesc != nil {
			// Client/bidi streaming: stream multiple JSON objects as gRPC frames.
			if req.Body != nil && req.Body != http.NoBody {
				setStreamingGRPCBody(req, requestDesc)
			} else {
				// Empty client stream: no frames, just close immediately.
				req.Body = http.NoBody
				req.GetBody = nil
			}
		} else {
			// Unary / server-streaming: existing single-message path.
			if requestDesc != nil && req.Body != nil && req.Body != http.NoBody {
				converted, err := convertJSONToProtobuf(req.Body, requestDesc)
				if err != nil {
					return 0, err
				}
				setReplayableBody(req, converted)
			}
			framed, err := frameGRPCRequest(req.Body)
			if err != nil {
				return 0, err
			}
			setReplayableBody(req, framed)
		}
	}

	if err := signAWSRequest(r, req); err != nil {
		return 0, err
	}

	// 7. Print request metadata / dry-run.
	if r.Verbosity >= core.VExtraVerbose || r.DryRun {
		errPrinter := r.PrinterHandle.Stderr()
		printRequestMetadataWithURL(errPrinter, req, r.HTTP, r.Verbosity, r.DryRun)

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
			preview, err := source.Preview(core.MaxDryRunBodyPreview)
			if err != nil {
				return 0, err
			}
			printable, _, err := isPrintable(bytes.NewReader(preview.Data))
			if err != nil {
				return 0, err
			}
			if printable {
				if _, err = os.Stderr.Write(preview.Data); err != nil {
					return 0, err
				}
				if preview.Truncated {
					core.WriteWarningMsgIf(errPrinter, "request body preview truncated at 1024 bytes", r.Verbosity == core.VSilent)
				}
				return 0, nil
			}

			msg := "the request body appears to be binary"
			core.WriteWarningMsgIf(errPrinter, msg, r.Verbosity == core.VSilent)
			return 0, nil
		}

		// Trailing "> \n" already written by printRequestMetadata.
		errPrinter.Flush()
	}

	// 8. Make request (with optional retries and per-attempt timeout).
	code, err := retryableRequest(ctx, r, c, req)

	// Save session cookies after request completes.
	if sess != nil {
		if saveErr := sess.Save(); saveErr != nil {
			p := r.PrinterHandle.Stderr()
			msg := fmt.Sprintf("unable to save session '%s': %s", sess.Name, saveErr.Error())
			core.WriteWarningMsgIf(p, msg, r.Verbosity == core.VSilent)
		}
	}

	return code, err
}

func signAWSRequest(r *Request, req *http.Request) error {
	if r.AWSSigv4 == nil {
		return nil
	}
	return aws.Sign(req, *r.AWSSigv4, time.Now().UTC())
}

func processResponse(ctx context.Context, r *Request, resp *http.Response, hadRedirects, hadRetries bool, metrics *connectionMetrics) (int, error) {
	var exitCode int
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

	// Wrap response body to measure body download time for --timing.
	var bodyTimer *timedReader
	if r.Timing && metrics != nil {
		bodyTimer = newTimedReader(resp.Body)
		resp.Body = bodyTimer
	}
	// Install one response pipeline before any output mode can consume the
	// body. This allows clipboard/HAR/progress observers to share one read.
	resp.Body = body.NewStream(resp.Body)
	// Every consumer below can block on a body read. Tie the original response
	// stream to the request context so cancellation closes it promptly, even
	// when a formatter, file writer, or discard path owns the read loop.
	responseContext := ctx
	if resp.Request != nil {
		responseContext = resp.Request.Context()
	}
	stopBodyClose := closeReaderOnContext(responseContext, resp.Body)
	defer stopBodyClose()

	if r.Discard {
		_, err := io.Copy(io.Discard, resp.Body)
		if err != nil {
			return 0, err
		}
		if bodyTimer != nil {
			p := r.PrinterHandle.Stderr()
			renderWaterfall(p, metrics, bodyTimer)
			p.Flush()
		}
		if r.GRPC {
			exitCode = checkGRPCStatus(r, resp, exitCode)
		}
		return exitCode, nil
	}

	// If --copy is requested, wrap the response body to capture raw bytes.
	cc := newClipboardCopier(r, resp)

	body, err := formatResponse(ctx, r, resp)
	if err != nil {
		return 0, err
	}

	if body != nil {
		p := r.PrinterHandle.Stderr()
		// Explicit raw formatting is an opt-in terminal bypass, just like
		// -o -. Pipes are already safe because they are not terminals.
		forceRaw := r.Output == "-" || r.Format == core.FormatOff
		contentType := resp.Header.Get("Content-Type")
		err = streamToStdoutWithPagerContent(ctx, body, p, forceRaw, r.NoPager, cc != nil, r.Verbosity == core.VSilent, r.Pager, contentType)
		if err != nil {
			return 0, err
		}
	}

	// Copy captured bytes to clipboard.
	cc.finish(r.PrinterHandle.Stderr())

	// Render timing waterfall after body is fully consumed.
	if bodyTimer != nil {
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

func formatResponse(ctx context.Context, r *Request, resp *http.Response) (io.Reader, error) {
	// Avoid trying to format the response for HEAD requests.
	if resp.Request.Method == "HEAD" {
		return nil, nil
	}

	output, err := getOutputValue(r, resp)
	if err != nil {
		return nil, err
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
		reader := newFormattedStream(resp.Body, p, func(input io.Reader, output *core.Printer) error {
			return format.FormatGRPCStream(input, r.responseDescriptor, output)
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
			return newReaderWithCloser(io.MultiReader(bytes.NewReader(prefix), resp.Body), resp.Body), nil
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
		return newReaderWithCloser(io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body), nil
	}

	// Transcode non-UTF-8 text to UTF-8, skipping binary formats.
	switch contentType {
	case format.TypeImage, format.TypeMsgPack, format.TypeProtobuf:
	default:
		buf = transcodeBytes(buf, charset)
	}

	// Special cases that need extra context beyond ([]byte, *Printer).
	if contentType == format.TypeImage {
		return nil, image.Render(ctx, buf, r.Image == core.ImageNative)
	}
	if contentType == format.TypeProtobuf && r.responseDescriptor != nil {
		if format.FormatProtobufWithDescriptor(buf, r.responseDescriptor, p) == nil {
			buf = p.Bytes()
		}
		return bytes.NewReader(buf), nil
	}

	// Dispatch registered buffered formatters.
	if fn := format.GetBuffered(contentType); fn != nil {
		if fn(buf, p) == nil {
			buf = p.Bytes()
		}
	}

	return bytes.NewReader(buf), nil
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
	out := make([]core.KeyVal[string], 0, len(headers))
	for k, v := range headers {
		k = strings.ToLower(k)
		value := core.RedactHeaderValue(k, strings.Join(v, ","))
		out = append(out, core.KeyVal[string]{Key: k, Val: value})
	}
	slices.SortFunc(out, func(a, b core.KeyVal[string]) int {
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
