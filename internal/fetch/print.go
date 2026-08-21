package fetch

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
)

func printRequestMetadata(p *core.Printer, req *http.Request, httpVersion core.HTTPVersion, verbosity core.Verbosity) {
	printRequestMetadataWithURL(p, req, httpVersion, verbosity, false)
}

func printRequestMetadataWithURL(p *core.Printer, req *http.Request, httpVersion core.HTTPVersion, verbosity core.Verbosity, showURL bool) {
	debug := verbosity >= core.VExtraVerbose

	if debug {
		p.WriteRequestPrefix()
	}
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
	p.WriteString(core.TerminalSafeText(path))
	p.Reset()

	q := req.URL.RawQuery
	if req.URL.ForceQuery || q != "" {
		p.Set(core.Italic)
		p.Set(core.Cyan)
		p.WriteString("?")
		p.WriteString(core.TerminalSafeText(q))
		p.Reset()
	}

	p.WriteString(" ")
	p.Set(core.Dim)
	proto := req.Proto
	// Force usage of protocol if explicitly specified.
	switch httpVersion {
	case core.HTTP2:
		proto = "HTTP/2.0"
	case core.HTTP3:
		proto = "HTTP/3.0"
	}
	p.WriteString(proto)
	p.Reset()

	p.WriteString("\n")
	if showURL {
		if debug {
			p.WriteRequestPrefix()
		}
		p.Set(core.Bold)
		p.Set(core.Blue)
		p.WriteString("url")
		p.Reset()
		p.WriteString(": ")
		normalizedURL := *req.URL
		if normalizedURL.Path == "" && normalizedURL.Host != "" {
			normalizedURL.Path = "/"
		}
		p.WriteString(core.RedactedURL(&normalizedURL))
		p.WriteString("\n")
	}

	headers := slices.DeleteFunc(getHeaders(req.Header), func(kv core.KeyVal[string]) bool {
		return strings.EqualFold(kv.Key, "Host")
	})
	// Content-Length and Transfer-Encoding are request metadata, not normally
	// stored in Request.Header by net/http. Add the values that the transport
	// will use, but do not duplicate an explicitly supplied header.
	if req.Body != nil && req.ContentLength > 0 && req.Header.Get("Content-Length") == "" {
		val := strconv.FormatInt(req.ContentLength, 10)
		headers = addHeader(headers, core.KeyVal[string]{Key: "content-length", Val: val})
	}
	if len(req.TransferEncoding) > 0 && req.Header.Get("Transfer-Encoding") == "" {
		val := strings.Join(req.TransferEncoding, ",")
		headers = addHeader(headers, core.KeyVal[string]{Key: "transfer-encoding", Val: val})
	}
	host := req.URL.Host
	if req.Host != "" {
		host = req.Host
	}
	if host != "" {
		headers = addHeader(headers, core.KeyVal[string]{Key: "host", Val: core.TerminalSafeText(host)})
	}

	for _, h := range headers {
		if debug {
			p.WriteRequestPrefix()
		}
		p.Set(core.Bold)
		p.Set(core.Blue)
		p.WriteString(h.Key)
		p.Reset()
		p.WriteString(": ")
		p.WriteString(h.Val)
		p.WriteString("\n")
	}

	if debug {
		p.WriteRequestPrefix()
		p.WriteString("\n")
	}
}

func printResponseMetadata(p *core.Printer, v core.Verbosity, resp *http.Response) {
	debug := v >= core.VExtraVerbose

	if debug {
		p.WriteResponsePrefix()
	}
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
		printResponseHeaders(p, resp, debug)
	}

	if debug {
		p.WriteResponsePrefix()
	}
	p.WriteString("\n")
}

func printResponseHeaders(p *core.Printer, resp *http.Response, usePrefix bool) {
	method := resp.Request.Method
	headers := getHeaders(resp.Header)
	if method != "HEAD" && resp.ContentLength >= 0 && resp.Header.Get("Content-Length") == "" {
		val := strconv.FormatInt(resp.ContentLength, 10)
		headers = addHeader(headers, core.KeyVal[string]{Key: "content-length", Val: val})
	}
	if len(resp.TransferEncoding) > 0 && resp.Header.Get("Transfer-Encoding") == "" {
		val := strings.Join(resp.TransferEncoding, ",")
		headers = addHeader(headers, core.KeyVal[string]{Key: "transfer-encoding", Val: val})
	}

	for _, h := range headers {
		if usePrefix {
			p.WriteResponsePrefix()
		}
		p.Set(core.Bold)
		p.Set(core.Cyan)
		p.WriteString(h.Key)
		p.Reset()
		p.WriteString(": ")
		p.WriteString(h.Val)
		p.WriteString("\n")
	}
}

func printBinaryWarningContentType(p *core.Printer, silent bool, contentType string) {
	writeBinaryWarning(p, silent, contentType, false)
}

func printBinaryWarningAfterBody(p *core.Printer, silent bool, contentType string) {
	writeBinaryWarning(p, silent, contentType, true)
}

func writeBinaryWarning(p *core.Printer, silent bool, contentType string, afterBody bool) {
	msg := "the response body appears to be binary"
	if contentType == "" {
		msg += " (content type: <none>)"
	} else {
		msg += " (content type: " + contentType + ")"
	}
	msg += "\n\nTo output to the terminal anyway, use '--output -'"
	warning := core.NewWarningWriter(p, silent)
	if afterBody {
		_ = warning.AfterBody()
	}
	_ = warning.Write(msg)
}

// printRedirectHop prints a single redirect hop based on verbosity level.
func printRedirectHop(p *core.Printer, v core.Verbosity, hop client.RedirectHop, httpVersion core.HTTPVersion) {
	switch {
	case v >= core.VExtraVerbose:
		// Prefixes handle visual separation at -vv and -vvv.
		printResponseMetadata(p, v, hop.Response)
		p.Flush()
		printRequestMetadata(p, hop.NextRequest, httpVersion, v)
		p.Flush()
	default:
		// One-line summary at -v
		printRedirectHopSummary(p, hop)
	}
}

// printRedirectHopSummary prints a single redirect hop as a one-liner.
func printRedirectHopSummary(p *core.Printer, hop client.RedirectHop) {
	p.WriteString("-> ")

	// Print status code with color
	statusColor := colorForStatus(hop.Response.StatusCode)
	p.Set(statusColor)
	p.Set(core.Bold)
	p.WriteString(strconv.Itoa(hop.Response.StatusCode))
	p.Reset()
	p.WriteString(" ")

	// Print source URL
	p.Set(core.Dim)
	p.WriteString(core.RedactedURL(hop.Request.URL))
	p.Reset()

	// Print arrow and location
	p.WriteString(" -> ")
	location := hop.Response.Header.Get("Location")
	if location != "" {
		p.Set(core.Cyan)
		p.WriteString(redactedRedirectLocation(location))
		p.Reset()
	}

	p.WriteString("\n")
	p.Flush()
}

func redactedRedirectLocation(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return "[invalid redirect location]"
	}
	return core.RedactedURL(u)
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
	previewComplete := false
	switch {
	case err == io.EOF || err == io.ErrUnexpectedEOF:
		buf = buf[:n]
		r = bytes.NewReader(buf)
		previewComplete = true
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
		if !previewComplete && !utf8.FullRune(buf) {
			break
		}
		c, size := utf8.DecodeRune(buf)
		buf = buf[size:]
		total++
		validRune := c != utf8.RuneError || size > 1
		if validRune && (unicode.IsPrint(c) || unicode.IsSpace(c) || c == '\x1b') {
			safe++
		}
	}

	if total == 0 {
		return true, r, nil
	}
	return float64(safe)/float64(total) >= 0.9, r, nil
}
