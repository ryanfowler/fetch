package fetch

import (
	"bytes"
	"context"
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
	"github.com/ryanfowler/fetch/internal/printer"
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
	DNSServer     string
	DryRun        bool
	Edit          bool
	Format        core.Format
	HTTP          core.HTTPVersion
	IgnoreStatus  bool
	Insecure      bool
	NoEncode      bool
	NoPager       bool
	Output        string
	PrinterHandle *printer.Handle
	TLS           uint16
	Verbosity     core.Verbosity

	Method      string
	URL         *url.URL
	Body        io.Reader
	Form        []core.KeyVal
	Multipart   *multipart.Multipart
	Headers     []core.KeyVal
	QueryParams []core.KeyVal
	AWSSigv4    *aws.Config
	Basic       *core.KeyVal
	Bearer      string
	JSON        bool
	XML         bool
	Proxy       *url.URL
	Timeout     time.Duration
}

func Fetch(ctx context.Context, r *Request) int {
	code, err := fetch(ctx, r)
	if err == nil {
		return code
	}
	if e := context.Cause(ctx); e != nil {
		err = e
	}

	p := r.PrinterHandle.Stderr()
	p.Set(printer.Red)
	p.Set(printer.Bold)
	p.WriteString("error")
	p.Reset()
	p.WriteString(": ")
	p.WriteString(err.Error())
	p.WriteString("\n")
	p.Flush()
	return 1
}

func fetch(ctx context.Context, r *Request) (int, error) {
	c := client.NewClient(client.ClientConfig{
		DNSServer: r.DNSServer,
		HTTP:      r.HTTP,
		Insecure:  r.Insecure,
		Proxy:     r.Proxy,
		TLS:       r.TLS,
	})
	req, err := c.NewRequest(ctx, client.RequestConfig{
		Method:      r.Method,
		URL:         r.URL,
		Form:        r.Form,
		Multipart:   r.Multipart,
		Headers:     r.Headers,
		QueryParams: r.QueryParams,
		Body:        r.Body,
		NoEncode:    r.NoEncode,
		AWSSigV4:    r.AWSSigv4,
		Basic:       r.Basic,
		Bearer:      r.Bearer,
		JSON:        r.JSON,
		XML:         r.XML,
		HTTP:        r.HTTP,
	})
	if err != nil {
		return 0, err
	}
	if req.Body != nil {
		defer req.Body.Close()
	}

	// Open an editor if necessary.
	if r.Edit {
		var extension string
		switch {
		case r.JSON:
			extension = ".json"
		case r.XML:
			extension = ".xml"
		}

		buf, err := edit(req.Body, extension)
		if err != nil {
			return 0, err
		}

		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.ContentLength = int64(len(buf))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(buf)), nil
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

	return makeRequest(r, c, req)
}

func makeRequest(r *Request, c *client.Client, req *http.Request) (int, error) {
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

	body, err := formatResponse(r, resp, r.PrinterHandle.Stdout())
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

func formatResponse(r *Request, resp *http.Response, p *printer.Printer) (io.Reader, error) {
	if r.Output != "" && r.Output != "-" {
		f, err := os.Create(r.Output)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		// TODO: show a progress bar on stderr?
		_, err = io.Copy(f, resp.Body)
		return nil, err
	}

	if r.Format == core.FormatOff || (!core.IsStdoutTerm && r.Format != core.FormatOn) {
		return resp.Body, nil
	}

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

	// TODO: Should probably limit the bytes read here.
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	switch contentType {
	case TypeImage:
		return nil, image.Render(buf)
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
			switch subtype {
			case "jpeg", "png", "tiff", "webp":
				return TypeImage
			default:
				return TypeUnknown
			}
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

func streamToStdout(r io.Reader, p *printer.Printer, forceOutput, noPager bool) error {
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
