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
	"github.com/ryanfowler/fetch/internal/printer"
)

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
		headers = addHeader(headers, core.KeyVal{Key: "host", Val: req.URL.Host})
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

func printResponseMetadata(p *printer.Printer, v core.Verbosity, resp *http.Response) {
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

	if v > core.VNormal {
		printResponseHeaders(p, resp)
	}

	p.WriteString("\n")
}

func printResponseHeaders(p *printer.Printer, resp *http.Response) {
	headers := getHeaders(resp.Header)
	if resp.ContentLength >= 0 && resp.Header.Get("Content-Length") == "" {
		val := strconv.FormatInt(resp.ContentLength, 10)
		headers = addHeader(headers, core.KeyVal{Key: "content-length", Val: val})
	}
	if len(resp.TransferEncoding) > 0 && resp.Header.Get("Transfer-Encoding") == "" {
		val := strings.Join(resp.TransferEncoding, ",")
		headers = addHeader(headers, core.KeyVal{Key: "transfer-encoding", Val: val})
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

func printBinaryWarning(p *printer.Printer) {
	p.Set(printer.Bold)
	p.Set(printer.Yellow)
	p.WriteString("warning")
	p.Reset()
	p.WriteString(": the response body appears to be binary\n\n")
	p.WriteString("To output to the terminal anyway, use '--output -'\n")
	p.Flush()
}

func colorForStatus(code int) printer.Sequence {
	switch {
	case code >= 200 && code < 300:
		return printer.Green
	case code >= 300 && code < 400:
		return printer.Yellow
	default:
		return printer.Red
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
