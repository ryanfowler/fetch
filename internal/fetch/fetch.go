package fetch

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"mime"
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
)

type ContentType int

const (
	TypeUnknown ContentType = iota
	TypeImage
	TypeJSON
	TypeNDJSON
	TypeSSE
	TypeXML
)

type Request struct {
	AWSSigv4      *aws.Config
	Basic         *core.KeyVal
	Bearer        string
	Data          io.Reader
	DNSServer     *url.URL
	DryRun        bool
	Edit          bool
	Form          []core.KeyVal
	Format        core.Format
	Headers       []core.KeyVal
	HTTP          core.HTTPVersion
	IgnoreStatus  bool
	Image         core.ImageSetting
	Insecure      bool
	JSON          io.Reader
	NoEncode      bool
	NoPager       bool
	Method        string
	Multipart     *multipart.Multipart
	Output        string
	OutputDir     bool
	PrinterHandle *core.Handle
	Proxy         *url.URL
	QueryParams   []core.KeyVal
	Range         []string
	Redirects     *int
	Timeout       time.Duration
	TLS           uint16
	URL           *url.URL
	Verbosity     core.Verbosity
	XML           io.Reader
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
	c := client.NewClient(client.ClientConfig{
		DNSServer: r.DNSServer,
		HTTP:      r.HTTP,
		Insecure:  r.Insecure,
		Proxy:     r.Proxy,
		Redirects: r.Redirects,
		TLS:       r.TLS,
	})
	req, err := c.NewRequest(ctx, client.RequestConfig{
		AWSSigV4:    r.AWSSigv4,
		Basic:       r.Basic,
		Bearer:      r.Bearer,
		Data:        r.Data,
		Form:        r.Form,
		Headers:     r.Headers,
		HTTP:        r.HTTP,
		JSON:        r.JSON,
		Method:      r.Method,
		Multipart:   r.Multipart,
		NoEncode:    r.NoEncode,
		QueryParams: r.QueryParams,
		Range:       r.Range,
		URL:         r.URL,
		XML:         r.XML,
	})
	if err != nil {
		return 0, err
	}
	defer func() {
		if req.Body != nil {
			req.Body.Close()
		}
	}()

	// Open an editor to modify the request body, if necessary.
	if r.Edit {
		err = editRequestBody(req)
		if err != nil {
			return 0, err
		}
	}

	if r.Verbosity >= core.VExtraVerbose || r.DryRun {
		errPrinter := r.PrinterHandle.Stderr()
		printRequestMetadata(errPrinter, req)

		if r.DryRun {
			if req.Body == nil || req.Body == http.NoBody {
				errPrinter.Flush()
				return 0, nil
			}

			errPrinter.WriteString("\n")
			errPrinter.Flush()

			_, err = io.Copy(os.Stderr, req.Body)
			return 0, err
		}

		errPrinter.WriteString("\n")
		errPrinter.Flush()
	}

	if r.Timeout > 0 {
		var cancel context.CancelFunc
		cause := core.ErrRequestTimedOut{Timeout: r.Timeout}
		ctx, cancel = context.WithTimeoutCause(req.Context(), r.Timeout, cause)
		defer cancel()
		req = req.WithContext(ctx)
	}

	return makeRequest(ctx, r, c, req)
}

func makeRequest(ctx context.Context, r *Request, c *client.Client, req *http.Request) (int, error) {
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
	output, err := getOutputValue(r, resp.Header)
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
	case TypeImage:
		return nil, image.Render(ctx, buf, r.Image == core.ImageNative)
	case TypeJSON:
		if format.FormatJSON(buf, p) == nil {
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
			case "json":
				return TypeJSON
			case "x-ndjson", "ndjson", "x-jsonl", "jsonl", "x-jsonlines":
				return TypeNDJSON
			case "xml":
				return TypeXML
			}
		case "text":
			switch subtype {
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

func getHeaders(headers http.Header) []core.KeyVal {
	out := make([]core.KeyVal, 0, len(headers))
	for k, v := range headers {
		k = strings.ToLower(k)
		out = append(out, core.KeyVal{Key: k, Val: strings.Join(v, ",")})
	}
	slices.SortFunc(out, func(a, b core.KeyVal) int {
		return strings.Compare(a.Key, b.Key)
	})
	return out
}

func addHeader(headers []core.KeyVal, h core.KeyVal) []core.KeyVal {
	i, _ := slices.BinarySearchFunc(headers, h, func(a, b core.KeyVal) int {
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
