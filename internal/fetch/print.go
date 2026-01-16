package fetch

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
)

func printRequestMetadata(p *core.Printer, req *http.Request, v core.HTTPVersion) {
	p.Set(core.Bold)
	p.Set(core.Yellow)
	p.WriteString(req.Method)
	p.Reset()

	path := req.URL.Path
	if path == "" {
		path = "/"
	}

	p.WriteString(" ")
	p.Set(core.Bold)
	p.Set(core.Cyan)
	p.WriteString(path)
	p.Reset()

	q := req.URL.RawQuery
	if req.URL.ForceQuery || q != "" {
		p.Set(core.Italic)
		p.Set(core.Cyan)
		p.WriteString("?")
		p.WriteString(q)
		p.Reset()
	}

	p.WriteString(" ")
	p.Set(core.Dim)
	proto := req.Proto
	// Force usage of protocol if explicitly specified.
	switch v {
	case core.HTTP2:
		proto = "HTTP/2.0"
	case core.HTTP3:
		proto = "HTTP/3.0"
	}
	p.WriteString(proto)
	p.Reset()

	p.WriteString("\n")

	headers := getHeaders(req.Header)
	if req.Body != nil && req.ContentLength > 0 {
		val := strconv.FormatInt(req.ContentLength, 10)
		headers = addHeader(headers, core.KeyVal{Key: "content-length", Val: val})
	}
	if req.Header.Get("Host") == "" {
		headers = addHeader(headers, core.KeyVal{Key: "host", Val: req.URL.Host})
	}

	for _, h := range headers {
		p.Set(core.Bold)
		p.Set(core.Blue)
		p.WriteString(h.Key)
		p.Reset()
		p.WriteString(": ")
		p.WriteString(h.Val)
		p.WriteString("\n")
	}
}

func printResponseMetadata(p *core.Printer, v core.Verbosity, resp *http.Response) {
	p.Set(core.Dim)
	p.WriteString(resp.Proto)
	p.Reset()
	p.WriteString(" ")

	statusColor := colorForStatus(resp.StatusCode)
	p.Set(statusColor)
	p.Set(core.Bold)
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

	if v > core.VNormal {
		printResponseHeaders(p, resp)
	}

	p.WriteString("\n")
}

func printResponseHeaders(p *core.Printer, resp *http.Response) {
	method := resp.Request.Method
	headers := getHeaders(resp.Header)
	if method != "HEAD" && resp.ContentLength >= 0 && resp.Header.Get("Content-Length") == "" {
		val := strconv.FormatInt(resp.ContentLength, 10)
		headers = addHeader(headers, core.KeyVal{Key: "content-length", Val: val})
	}
	if len(resp.TransferEncoding) > 0 && resp.Header.Get("Transfer-Encoding") == "" {
		val := strings.Join(resp.TransferEncoding, ",")
		headers = addHeader(headers, core.KeyVal{Key: "transfer-encoding", Val: val})
	}

	for _, h := range headers {
		p.Set(core.Bold)
		p.Set(core.Cyan)
		p.WriteString(h.Key)
		p.Reset()
		p.WriteString(": ")
		p.WriteString(h.Val)
		p.WriteString("\n")
	}
}

func printBinaryWarning(p *core.Printer) {
	msg := "the response body appears to be binary\n\nTo output to the terminal anyway, use '--output -'"
	core.WriteWarningMsg(p, msg)
}

func colorForStatus(code int) core.Sequence {
	switch {
	case code >= 200 && code < 300:
		return core.Green
	case code >= 300 && code < 400:
		return core.Yellow
	default:
		return core.Red
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
