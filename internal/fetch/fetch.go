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
	TypeXML
)

type Request struct {
	DryRun        bool
	Edit          bool
	HTTP          client.HTTPVersion
	Insecure      bool
	NoEncode      bool
	NoFormat      bool
	NoPager       bool
	Output        string
	PrinterHandle *printer.Handle
	Verbosity     Verbosity

	Method      string
	URL         string
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
	ok, err := fetch(ctx, r)
	if err != nil {
		p := r.PrinterHandle.Stderr()
		p.Set(printer.Red)
		p.Set(printer.Bold)
		p.WriteString("error")
		p.Reset()
		p.WriteString(": ")
		p.WriteString(err.Error())
		p.WriteString("\n")
		p.Flush(os.Stderr)
		return 1
	}
	if ok {
		return 0
	}
	return 1
}

func fetch(ctx context.Context, r *Request) (bool, error) {
	errPrinter := r.PrinterHandle.Stderr()
	outPrinter := r.PrinterHandle.Stdout()

	u, err := url.Parse(r.URL)
	if err != nil {
		return false, err
	}
	if u.Scheme == "" {
		// Use HTTPS if no scheme is defined.
		u.Scheme = "https"
	}

	c := client.NewClient(client.ClientConfig{
		HTTP:     r.HTTP,
		Insecure: r.Insecure,
		Proxy:    r.Proxy,
		Timeout:  r.Timeout,
	})
	req, err := c.NewRequest(ctx, client.RequestConfig{
		Method:      r.Method,
		URL:         u,
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
		return false, err
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
			return false, err
		}

		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.ContentLength = int64(len(buf))
		req.GetBody = nil
	}

	if r.Verbosity >= VExtraVerbose || r.DryRun {
		printRequestMetadata(errPrinter, req)

		if r.DryRun {
			if req.Body == nil || req.Body == http.NoBody {
				errPrinter.Flush(os.Stderr)
				return true, nil
			}

			errPrinter.WriteString("\n")
			errPrinter.Flush(os.Stderr)

			_, err = io.Copy(os.Stderr, req.Body)
			return err == nil, err
		}

		errPrinter.WriteString("\n")
		errPrinter.Flush(os.Stderr)
	}

	resp, err := c.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	ok := resp.StatusCode >= 200 && resp.StatusCode < 400

	if r.Verbosity >= VNormal {
		printResponseMetadata(errPrinter, r.Verbosity, resp)
		errPrinter.Flush(os.Stderr)
	}

	if r.Output != "" {
		f, err := os.Create(r.Output)
		if err != nil {
			return false, err
		}
		defer f.Close()

		// TODO: show a progress bar on stderr?

		if _, err = io.Copy(f, resp.Body); err != nil {
			return false, err
		}
		return ok, nil
	}

	var body io.Reader = resp.Body
	if !r.NoFormat && vars.IsStdoutTerm {
		contentType := getContentType(resp.Header)
		if contentType != TypeUnknown {
			// TODO: limit bytes read
			buf, err := io.ReadAll(resp.Body)
			if err != nil {
				return false, err
			}

			switch contentType {
			case TypeImage:
				err = image.Render(buf)
				return err == nil, err
			case TypeJSON:
				r := bytes.NewReader(buf)
				if format.FormatJSON(r, outPrinter) == nil {
					buf = outPrinter.Bytes()
				}
			case TypeXML:
				r := bytes.NewReader(buf)
				if format.FormatXML(r, outPrinter) == nil {
					buf = outPrinter.Bytes()
				}
			}
			body = bytes.NewReader(buf)
		}
	}

	err = streamToStdout(body, r.NoPager)
	if err != nil {
		return false, err
	}

	return ok, nil
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
		case "xml":
			return TypeXML
		}
	}

	switch mediaType {
	case "application/json":
		return TypeJSON
	case "application/xml", "text/xml":
		return TypeXML
	case "image/jpeg", "image/png", "image/tiff", "image/webp":
		return TypeImage
	default:
		return TypeUnknown
	}
}

func streamToStdout(r io.Reader, noPager bool) error {
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
