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
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/format"
	"github.com/ryanfowler/fetch/internal/image"
	"github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/printer"
	"github.com/ryanfowler/fetch/internal/vars"
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

type Format int

const (
	FormatUnknown Format = iota
	FormatAuto
	FormatOff
	FormatOn
)

type Request struct {
	DryRun        bool
	Edit          bool
	Format        Format
	HTTP          client.HTTPVersion
	IgnoreStatus  bool
	Insecure      bool
	NoEncode      bool
	NoPager       bool
	Output        string
	PrinterHandle *printer.Handle
	UserAgent     string
	Verbosity     Verbosity

	Method      string
	URL         *url.URL
	Body        io.Reader
	Form        []vars.KeyVal
	Multipart   *multipart.Multipart
	Headers     []vars.KeyVal
	QueryParams []vars.KeyVal
	AWSSigv4    *aws.Config
	Basic       *vars.KeyVal
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
	errPrinter := r.PrinterHandle.Stderr()
	outPrinter := r.PrinterHandle.Stdout()

	if r.URL.Scheme == "" {
		// Use HTTPS if no scheme is defined.
		r.URL.Scheme = "https"
	}

	c := client.NewClient(client.ClientConfig{
		HTTP:      r.HTTP,
		Insecure:  r.Insecure,
		Proxy:     r.Proxy,
		Timeout:   r.Timeout,
		UserAgent: r.UserAgent,
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
		req.GetBody = nil
	}

	if r.Verbosity >= VExtraVerbose || r.DryRun {
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

	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var exitCode int
	if !r.IgnoreStatus {
		exitCode = getExitCodeForStatus(resp.StatusCode)
	}

	if r.Verbosity >= VNormal {
		printResponseMetadata(errPrinter, r.Verbosity, resp)
		errPrinter.Flush()
	}

	body, err := formatResponse(r, resp, outPrinter)
	if err != nil {
		return 0, err
	}

	if body != nil {
		err = streamToStdout(body, errPrinter, r.Output == "-", r.NoPager)
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

	if r.Format == FormatOff || (!vars.IsStdoutTerm && r.Format != FormatOn) {
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

func printRequestMetadata(p *printer.Printer, req *http.Request) {
	p.Set(printer.Bold)
	p.Set(printer.Yellow)
	p.WriteString(req.Method)
	p.Reset()

	path := req.URL.Path
	if path == "" {
		path = "/"
	}

	p.WriteString(" ")
	p.Set(printer.Bold)
	p.Set(printer.Cyan)
	p.WriteString(path)
	p.Reset()

	q := req.URL.RawQuery
	if req.URL.ForceQuery || q != "" {
		p.Set(printer.Italic)
		p.Set(printer.Cyan)
		p.WriteString("?")
		p.WriteString(q)
		p.Reset()
	}

	p.WriteString(" ")
	p.Set(printer.Dim)
	p.WriteString(req.Proto)
	p.Reset()

	p.WriteString("\n")

	headers := getHeaders(req.Header)
	if req.Header.Get("Host") == "" {
		headers = addHeader(headers, vars.KeyVal{Key: "host", Val: req.URL.Host})
	}

	for _, h := range headers {
		p.Set(printer.Bold)
		p.Set(printer.Blue)
		p.WriteString(h.Key)
		p.Reset()
		p.WriteString(": ")
		p.WriteString(h.Val)
		p.WriteString("\n")
	}
}

func printResponseMetadata(p *printer.Printer, v Verbosity, resp *http.Response) {
	p.Set(printer.Dim)
	p.WriteString(resp.Proto)
	p.Reset()
	p.WriteString(" ")

	statusColor := colorForStatus(resp.StatusCode)
	p.Set(statusColor)
	p.Set(printer.Bold)
	p.WriteString(strconv.Itoa(resp.StatusCode))

	text := http.StatusText(resp.StatusCode)
	if text != "" {
		p.Reset()
		p.WriteString(" ")
		p.Set(statusColor)
		p.WriteString(text)
	}

	p.Reset()
	p.WriteString("\n")

	if v > VNormal {
		printResponseHeaders(p, resp)
	}

	p.WriteString("\n")
}

func printResponseHeaders(p *printer.Printer, resp *http.Response) {
	headers := getHeaders(resp.Header)
	if resp.ContentLength >= 0 && resp.Header.Get("Content-Length") == "" {
		val := strconv.FormatInt(resp.ContentLength, 10)
		headers = addHeader(headers, vars.KeyVal{Key: "content-length", Val: val})
	}
	if len(resp.TransferEncoding) > 0 && resp.Header.Get("Transfer-Encoding") == "" {
		val := strings.Join(resp.TransferEncoding, ",")
		headers = addHeader(headers, vars.KeyVal{Key: "transfer-encoding", Val: val})
	}

	for _, h := range headers {
		p.Set(printer.Bold)
		p.Set(printer.Cyan)
		p.WriteString(h.Key)
		p.Reset()
		p.WriteString(": ")
		p.WriteString(h.Val)
		p.WriteString("\n")
	}
}

func colorForStatus(code int) printer.Sequence {
	if code >= 200 && code < 300 {
		return printer.Green
	}
	if code >= 300 && code < 400 {
		return printer.Yellow
	}
	if code >= 400 {
		return printer.Red
	}
	return printer.Default
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
		if typ == "image" {
			switch subtype {
			case "jpeg", "png", "tiff", "webp":
				return TypeImage
			}
		}

		switch subtype {
		case "json":
			return TypeJSON
		case "ndjson", "x-ndjson", "jsonl", "x-jsonl", "x-jsonlines":
			return TypeNDJSON
		case "xml":
			return TypeXML
		}
	}

	switch mediaType {
	case "application/json":
		return TypeJSON
	case "application/x-ndjson":
		return TypeNDJSON
	case "application/xml", "text/xml":
		return TypeXML
	case "image/jpeg", "image/png", "image/tiff", "image/webp":
		return TypeImage
	case "text/event-stream":
		return TypeSSE
	default:
		return TypeUnknown
	}
}

func streamToStdout(r io.Reader, p *printer.Printer, forceOutput, noPager bool) error {
	// Check output to see if it's likely safe to print to stdout.
	if vars.IsStdoutTerm && !forceOutput {
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
	if !noPager && vars.IsStdoutTerm {
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

// isPrintable returns true if the data in the provided io.Reader is likely
// okay to print to a terminal.
func isPrintable(r io.Reader) (bool, io.Reader, error) {
	buf := make([]byte, 1024)
	n, err := io.ReadFull(r, buf)
	switch {
	case err == io.EOF || err == io.ErrUnexpectedEOF:
		buf = buf[:n]
		r = bytes.NewReader(buf)
	case err != nil:
		return false, nil, err
	default:
		r = io.MultiReader(bytes.NewReader(buf), r)
	}

	if bytes.ContainsRune(buf, '\x00') {
		return false, r, nil
	}

	var safe, total int
	for len(buf) > 0 {
		c, size := utf8.DecodeRune(buf)
		buf = buf[size:]
		if c == utf8.RuneError && len(buf) < 4 {
			break
		}
		total++
		if unicode.IsPrint(c) || unicode.IsSpace(c) || c == '\x1b' {
			safe++
		}
	}

	if total == 0 {
		return true, r, nil
	}
	return float64(safe)/float64(total) >= 0.9, r, nil
}

func printBinaryWarning(p *printer.Printer) {
	p.Set(printer.Bold)
	p.Set(printer.Yellow)
	p.WriteString("warning")
	p.Reset()
	p.WriteString(": the response body appears to be binary\n\n")
	p.WriteString("To output to the terminal anyway, use '--output -'\n")
	p.Flush()
}
