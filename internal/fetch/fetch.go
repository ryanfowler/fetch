package fetch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptrace"
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
	fetchgrpc "github.com/ryanfowler/fetch/internal/grpc"
	"github.com/ryanfowler/fetch/internal/image"
	"github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/proto"
	"github.com/ryanfowler/fetch/internal/session"

	"google.golang.org/protobuf/reflect/protoreflect"
)

type ContentType int

const (
	TypeUnknown ContentType = iota
	TypeCSS
	TypeCSV
	TypeGRPC
	TypeHTML
	TypeImage
	TypeJSON
	TypeMsgPack
	TypeNDJSON
	TypeProtobuf
	TypeSSE
	TypeXML
)

type Request struct {
	AWSSigv4         *aws.Config
	Basic            *core.KeyVal[string]
	Bearer           string
	CACerts          []*x509.Certificate
	ClientCert       *tls.Certificate
	Clobber          bool
	ContentType      string
	Data             io.Reader
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
	Session          string
	Timeout          time.Duration
	TLS              uint16
	UnixSocket       string
	URL              *url.URL
	Verbosity        core.Verbosity

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

func fetch(ctx context.Context, r *Request) (retCode int, retErr error) {
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
	if r.GRPC {
		var err error
		requestDesc, r.responseDescriptor, err = setupGRPC(r, schema)
		if err != nil {
			return 0, err
		}
	}

	// 3. Create HTTP client and request.
	c := client.NewClient(client.ClientConfig{
		CACerts:    r.CACerts,
		ClientCert: r.ClientCert,
		DNSServer:  r.DNSServer,
		HTTP:       r.HTTP,
		Insecure:   r.Insecure,
		Proxy:      r.Proxy,
		Redirects:  r.Redirects,
		TLS:        r.TLS,
		UnixSocket: r.UnixSocket,
	})

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

	// 4. Edit step (user edits request body).
	if r.Edit {
		err = editRequestBody(req)
		if err != nil {
			return 0, err
		}
	}

	// 5. Convert JSON to protobuf AFTER edit.
	if requestDesc != nil && req.Body != nil && req.Body != http.NoBody {
		// Read the body and convert.
		converted, err := convertJSONToProtobuf(req.Body, requestDesc)
		if err != nil {
			return 0, err
		}
		req.Body = io.NopCloser(converted)
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/protobuf")
		}
	}

	// 6. Frame gRPC request AFTER conversion.
	// gRPC requires framing even for empty messages.
	if r.GRPC {
		framed, err := frameGRPCRequest(req.Body)
		if err != nil {
			return 0, err
		}
		req.Body = io.NopCloser(framed)
	}

	// 7. Print request metadata / dry-run.
	if r.Verbosity >= core.VExtraVerbose || r.DryRun {
		errPrinter := r.PrinterHandle.Stderr()
		printRequestMetadata(errPrinter, req, r.HTTP)

		if r.DryRun {
			if req.Body == nil || req.Body == http.NoBody {
				errPrinter.Flush()
				return 0, nil
			}

			errPrinter.WriteString("\n")
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

		errPrinter.WriteString("\n")
		errPrinter.Flush()
	}

	// Wrap the request body with upload progress tracking.
	// Only show progress for file uploads (-d @file) and multipart (-F),
	// not for inline data (-d 'hello') or form data (-f).
	if r.Verbosity > core.VSilent && req.Body != nil && req.Body != http.NoBody {
		_, isFileData := r.Data.(*os.File)
		if isFileData || r.Multipart != nil {
			p := r.PrinterHandle.Stderr()
			origBody := req.Body
			if core.IsStderrTerm {
				if req.ContentLength > 0 {
					pb := newUploadProgressBar(origBody, p, req.ContentLength)
					defer func() { pb.Close(retErr) }()
					req.Body = &uploadReadCloser{Reader: pb, closer: origBody}
				} else {
					ps := newUploadProgressSpinner(origBody, p)
					defer func() { ps.Close(retErr) }()
					req.Body = &uploadReadCloser{Reader: ps, closer: origBody}
				}
			} else {
				ps := newUploadProgressStatic(origBody, p)
				defer func() { ps.Close(retErr) }()
				req.Body = &uploadReadCloser{Reader: ps, closer: origBody}
			}
		}
	}

	if r.Timeout > 0 {
		var cancel context.CancelFunc
		cause := core.ErrRequestTimedOut{Timeout: r.Timeout}
		ctx, cancel = context.WithTimeoutCause(req.Context(), r.Timeout, cause)
		defer cancel()
		req = req.WithContext(ctx)
	}

	// 8. Make request.
	code, err := makeRequest(ctx, r, c, req)

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

func makeRequest(ctx context.Context, r *Request, c *client.Client, req *http.Request) (int, error) {
	// Track if any redirects were printed.
	var hadRedirects bool

	// Set up redirect callback at -v and higher.
	if r.Verbosity >= core.VVerbose {
		p := r.PrinterHandle.Stderr()
		ctx = client.WithRedirectCallback(req.Context(), func(hop client.RedirectHop) {
			hadRedirects = true
			printRedirectHop(p, r.Verbosity, hop, r.HTTP)
		})
		req = req.WithContext(ctx)
	}

	if r.Verbosity >= core.LDebug {
		trace := newDebugTrace(r.PrinterHandle.Stderr())
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	}

	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var exitCode int
	if !r.IgnoreStatus {
		exitCode = getExitCodeForStatus(resp.StatusCode)
	}

	if r.Verbosity >= core.VNormal {
		p := r.PrinterHandle.Stderr()
		// Add blank line after redirect summaries at -v level.
		if hadRedirects && r.Verbosity == core.VVerbose {
			p.WriteString("\n")
		}
		printResponseMetadata(p, r.Verbosity, resp)
		p.Flush()
	}

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
	contentType := getContentType(resp.Header)
	switch contentType {
	case TypeUnknown:
		return resp.Body, nil
	case TypeNDJSON:
		// NOTE: This bypasses the isPrintable check for binary data.
		return nil, format.FormatNDJSON(resp.Body, p)
	case TypeSSE:
		// NOTE: This bypasses the isPrintable check for binary data.
		return nil, format.FormatEventStream(resp.Body, p)
	}

	// If image rendering is disabled, return the reader immediately.
	if contentType == TypeImage && r.Image == core.ImageOff {
		return resp.Body, nil
	}

	const bytesLimit = 1 << 24 // 16MB
	buf, err := io.ReadAll(io.LimitReader(resp.Body, bytesLimit))
	if err != nil {
		return nil, err
	}
	if len(buf) >= bytesLimit {
		// We've reached the limit of bytes read into memory, skip formatting.
		return io.MultiReader(bytes.NewReader(buf), resp.Body), nil
	}

	switch contentType {
	case TypeCSS:
		if format.FormatCSS(buf, p) == nil {
			buf = p.Bytes()
		}
	case TypeCSV:
		if format.FormatCSV(buf, p) == nil {
			buf = p.Bytes()
		}
	case TypeHTML:
		if format.FormatHTML(buf, p) == nil {
			buf = p.Bytes()
		}
	case TypeImage:
		return nil, image.Render(ctx, buf, r.Image == core.ImageNative)
	case TypeJSON:
		if format.FormatJSON(buf, p) == nil {
			buf = p.Bytes()
		}
	case TypeMsgPack:
		if format.FormatMsgPack(buf, p) == nil {
			buf = p.Bytes()
		}
	case TypeGRPC:
		// Unframe gRPC response before processing.
		unframedBuf, _, err := fetchgrpc.Unframe(buf)
		if err != nil {
			// If unframing fails, try to process as raw protobuf.
			unframedBuf = buf
		}
		if r.responseDescriptor != nil {
			err = format.FormatProtobufWithDescriptor(unframedBuf, r.responseDescriptor, p)
		} else {
			err = format.FormatProtobuf(unframedBuf, p)
		}
		if err == nil {
			buf = p.Bytes()
		}
	case TypeProtobuf:
		var err error
		if r.responseDescriptor != nil {
			err = format.FormatProtobufWithDescriptor(buf, r.responseDescriptor, p)
		} else {
			err = format.FormatProtobuf(buf, p)
		}
		if err == nil {
			buf = p.Bytes()
		}
	case TypeXML:
		if format.FormatXML(buf, p) == nil {
			buf = p.Bytes()
		}
	}

	return bytes.NewReader(buf), nil
}

func getContentType(headers http.Header) ContentType {
	contentType := headers.Get("Content-Type")
	if contentType == "" {
		return TypeUnknown
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return TypeUnknown
	}

	if typ, subtype, ok := strings.Cut(mediaType, "/"); ok {
		switch typ {
		case "image":
			return TypeImage
		case "application":
			switch subtype {
			case "csv":
				return TypeCSV
			case "grpc", "grpc+proto":
				return TypeGRPC
			case "json":
				return TypeJSON
			case "msgpack", "x-msgpack", "vnd.msgpack":
				return TypeMsgPack
			case "x-ndjson", "ndjson", "x-jsonl", "jsonl", "x-jsonlines":
				return TypeNDJSON
			case "protobuf", "x-protobuf", "x-google-protobuf", "vnd.google.protobuf":
				return TypeProtobuf
			case "xml":
				return TypeXML
			}
			if strings.HasSuffix(subtype, "+json") || strings.HasSuffix(subtype, "-json") {
				return TypeJSON
			}
			if strings.HasSuffix(subtype, "+proto") {
				return TypeProtobuf
			}
			if strings.HasSuffix(subtype, "+xml") {
				return TypeXML
			}
		case "text":
			switch subtype {
			case "css":
				return TypeCSS
			case "csv":
				return TypeCSV
			case "html":
				return TypeHTML
			case "event-stream":
				return TypeSSE
			case "xml":
				return TypeXML
			}
		}
	}

	return TypeUnknown
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
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		var certInvalidErr x509.CertificateInvalidError
		if errors.As(urlErr.Err, &certInvalidErr) {
			return true
		}

		var hostErr x509.HostnameError
		if errors.As(urlErr.Err, &hostErr) {
			return true
		}

		var unknownErr x509.UnknownAuthorityError
		if errors.As(urlErr.Err, &unknownErr) {
			return true
		}
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
