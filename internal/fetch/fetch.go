package fetch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/format"
	"github.com/ryanfowler/fetch/internal/image"
	"github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/proto"
	"github.com/ryanfowler/fetch/internal/session"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// maxBodyBytes is the maximum number of bytes read into memory for
// formatting a response body or copying it to the clipboard.
const maxBodyBytes = 1 << 20 // 1MiB

type Request struct {
	AWSSigv4         *aws.Config
	Basic            *core.KeyVal[string]
	Bearer           string
	CACerts          []*x509.Certificate
	ClientCert       *tls.Certificate
	Clobber          bool
	ConnectTimeout   time.Duration
	ContentType      string
	Copy             bool
	Data             io.Reader
	Discard          bool
	DNSServer        *url.URL
	DryRun           bool
	Edit             bool
	Form             []core.KeyVal[string]
	Format           core.Format
	GRPC             bool
	Headers          []core.KeyVal[string]
	HTTP             core.HTTPVersion
	IgnoreStatus     bool
	Image            core.ImageSetting
	Insecure         bool
	NoEncode         bool
	NoPager          bool
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
	Redirects        *int
	RemoteHeaderName bool
	RemoteName       bool
	Retry            int
	RetryDelay       time.Duration
	Session          string
	Timeout          time.Duration
	Timing           bool
	TLS              uint16
	UnixSocket       string
	URL              *url.URL
	Verbosity        core.Verbosity
	WS               bool

	// responseDescriptor is set internally after proto setup for response formatting.
	responseDescriptor protoreflect.MessageDescriptor
}

func Fetch(ctx context.Context, r *Request) int {
	code, err := fetch(ctx, r)
	if err == nil {
		return code
	}

	p := r.PrinterHandle.Stderr()
	core.WriteErrorMsgNoFlush(p, err)

	if isCertificateErr(err) {
		p.WriteString("\n")
		printInsecureMsg(p)
	}

	p.Flush()
	return 1
}

func fetch(ctx context.Context, r *Request) (int, error) {
	// 1. Load proto schema if configured.
	var schema *proto.Schema
	if len(r.ProtoFiles) > 0 || r.ProtoDesc != "" {
		var err error
		schema, err = loadProtoSchema(r)
		if err != nil {
			return 0, err
		}
	}

	// 2. Setup gRPC (adds headers, sets HTTP version, finds descriptors).
	var requestDesc protoreflect.MessageDescriptor
	var isClientStreaming bool
	if r.GRPC {
		var err error
		requestDesc, r.responseDescriptor, isClientStreaming, err = setupGRPC(r, schema)
		if err != nil {
			return 0, err
		}
	}

	// 3. Create HTTP client and request.
	c := client.NewClient(client.ClientConfig{
		CACerts:        r.CACerts,
		ClientCert:     r.ClientCert,
		ConnectTimeout: r.ConnectTimeout,
		DNSServer:      r.DNSServer,
		HTTP:           r.HTTP,
		Insecure:       r.Insecure,
		Proxy:          r.Proxy,
		Redirects:      r.Redirects,
		TLS:            r.TLS,
		UnixSocket:     r.UnixSocket,
	})
	defer c.Close()

	// Load session and set cookie jar, if configured.
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
			core.WriteWarningMsg(p, msg)
		}
		c.SetJar(sess.Jar())
	}

	req, err := c.NewRequest(ctx, client.RequestConfig{
		AWSSigV4:    r.AWSSigv4,
		Basic:       r.Basic,
		Bearer:      r.Bearer,
		ContentType: r.ContentType,
		Data:        r.Data,
		Form:        r.Form,
		Headers:     r.Headers,
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
				req.Body = streamGRPCRequest(req.Body, requestDesc)
				req.ContentLength = -1 // Unknown length; use chunked encoding.
			} else {
				// Empty client stream: no frames, just close immediately.
				req.Body = http.NoBody
			}
		} else {
			// Unary / server-streaming: existing single-message path.
			if requestDesc != nil && req.Body != nil && req.Body != http.NoBody {
				converted, err := convertJSONToProtobuf(req.Body, requestDesc)
				if err != nil {
					return 0, err
				}
				req.Body = io.NopCloser(converted)
			}
			framed, err := frameGRPCRequest(req.Body)
			if err != nil {
				return 0, err
			}
			req.Body = io.NopCloser(framed)
		}
	}

	// 7. Print request metadata / dry-run.
	if r.Verbosity >= core.VExtraVerbose || r.DryRun {
		errPrinter := r.PrinterHandle.Stderr()
		printRequestMetadata(errPrinter, req, r.HTTP, r.Verbosity)

		if r.DryRun {
			if req.Body == nil || req.Body == http.NoBody {
				errPrinter.Flush()
				return 0, nil
			}

			if r.Verbosity < core.VExtraVerbose {
				errPrinter.WriteString("\n")
			}
			errPrinter.Flush()

			ok, rdr, err := isPrintable(req.Body)
			if err != nil {
				return 0, err
			}
			if ok {
				_, err = io.Copy(os.Stderr, rdr)
				return 0, err
			}

			msg := "the request body appears to be binary"
			core.WriteWarningMsg(errPrinter, msg)
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
			core.WriteWarningMsg(p, msg)
		}
	}

	return code, err
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
		err = streamToStdout(body, p, r.Output == "-", r.NoPager)
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
		size := resp.ContentLength
		p := r.PrinterHandle.Stderr()
		return nil, writeOutputToFile(output, resp.Body, size, p, r.Verbosity)
	}

	if r.Format == core.FormatOff || (!core.IsStdoutTerm && r.Format != core.FormatOn) {
		return resp.Body, nil
	}

	p := r.PrinterHandle.Stdout()
	contentType, charset := format.GetContentType(resp.Header)

	// gRPC streaming needs the response descriptor — handle inline.
	if contentType == format.TypeGRPC {
		return nil, format.FormatGRPCStream(resp.Body, r.responseDescriptor, p)
	}

	// Dispatch registered streaming formatters (NDJSON, SSE).
	if fn := format.GetStreaming(contentType); fn != nil {
		return nil, fn(transcodeReader(resp.Body, charset), p)
	}

	// If image rendering is disabled, return the reader immediately.
	if contentType == format.TypeImage && r.Image == core.ImageOff {
		return resp.Body, nil
	}

	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	if len(buf) >= maxBodyBytes {
		// We've reached the limit of bytes read into memory, skip formatting.
		return io.MultiReader(bytes.NewReader(buf), resp.Body), nil
	}

	// If the Content-Type is unknown, attempt to sniff the body.
	if contentType == format.TypeUnknown {
		contentType = format.SniffContentType(buf)
		if contentType == format.TypeUnknown {
			return bytes.NewReader(buf), nil
		}
		if contentType == format.TypeImage && r.Image == core.ImageOff {
			return bytes.NewReader(buf), nil
		}
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

func streamToStdout(r io.Reader, p *core.Printer, forceOutput, noPager bool) error {
	// Check output to see if it's likely safe to print to stdout.
	if core.IsStdoutTerm && !forceOutput {
		var ok bool
		var err error
		ok, r, err = isPrintable(r)
		if err != nil {
			return err
		}
		if !ok {
			printBinaryWarning(p)
			return nil
		}
	}

	// Optionally stream output to a pager.
	if !noPager && core.IsStdoutTerm {
		path, err := exec.LookPath("less")
		if err == nil {
			return streamToPager(r, path)
		}
	}

	_, err := io.Copy(os.Stdout, r)
	return err
}

func streamToPager(r io.Reader, path string) error {
	cmd := exec.Command(path, "-FIRX")
	cmd.Stdin = r
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
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
		out = append(out, core.KeyVal[string]{Key: k, Val: strings.Join(v, ",")})
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
