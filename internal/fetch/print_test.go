package fetch

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
)

func newTestPrinter() *core.Printer {
	return core.NewHandle(core.ColorOff).Stderr()
}

func TestPrintRequestMetadataPrefixes(t *testing.T) {
	req := &http.Request{
		Method: "GET",
		URL:    mustParseURL("https://example.com/path"),
		Header: http.Header{"Accept": {"*/*"}},
		Proto:  "HTTP/1.1",
	}

	t.Run("no prefix below VExtraVerbose", func(t *testing.T) {
		p := newTestPrinter()
		printRequestMetadata(p, req, core.HTTPDefault, core.VVerbose)
		out := string(p.Bytes())

		if strings.Contains(out, "> ") {
			t.Errorf("expected no '> ' prefix at VVerbose, got:\n%s", out)
		}
		if !strings.Contains(out, "GET /path HTTP/1.1") {
			t.Errorf("expected method line, got:\n%s", out)
		}
	})

	t.Run("prefix at VExtraVerbose", func(t *testing.T) {
		p := newTestPrinter()
		printRequestMetadata(p, req, core.HTTPDefault, core.VExtraVerbose)
		out := string(p.Bytes())

		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		for _, line := range lines {
			if !strings.HasPrefix(line, "> ") {
				t.Errorf("expected '> ' prefix on line %q", line)
			}
		}
		// Last line should be a blank prefixed line.
		if last := lines[len(lines)-1]; last != "> " {
			t.Errorf("expected trailing '> ' blank line, got %q", last)
		}
	})

	t.Run("prefix at VDebug", func(t *testing.T) {
		p := newTestPrinter()
		printRequestMetadata(p, req, core.HTTPDefault, core.VDebug)
		out := string(p.Bytes())

		lines := strings.SplitSeq(strings.TrimRight(out, "\n"), "\n")
		for line := range lines {
			if !strings.HasPrefix(line, "> ") {
				t.Errorf("expected '> ' prefix on line %q", line)
			}
		}
	})
}

func TestPrintRequestMetadataEscapesURLPathControls(t *testing.T) {
	u := mustParseURL("https://example.com/%1b[2J")
	req := &http.Request{Method: "GET", URL: u, Proto: "HTTP/1.1"}

	p := newTestPrinter()
	printRequestMetadata(p, req, core.HTTPDefault, core.VVerbose)
	out := string(p.Bytes())
	if strings.Contains(out, "\x1b") {
		t.Fatalf("request path contains a raw escape: %q", out)
	}
	if !strings.Contains(out, `\x1b[2J`) {
		t.Fatalf("escaped path missing from metadata: %q", out)
	}
}

func TestPrintRequestMetadataPreservesDuplicateHeaders(t *testing.T) {
	req := &http.Request{
		Method:           "POST",
		URL:              mustParseURL("https://example.com/upload"),
		Header:           http.Header{"X-Trace": {"first", "second"}},
		ContentLength:    4,
		Body:             http.NoBody,
		TransferEncoding: []string{"chunked"},
		Proto:            "HTTP/1.1",
	}

	p := newTestPrinter()
	printRequestMetadata(p, req, core.HTTPDefault, core.VVerbose)
	out := string(p.Bytes())

	if strings.Count(out, "x-trace:") != 2 || !strings.Contains(out, "x-trace: first") || !strings.Contains(out, "x-trace: second") {
		t.Fatalf("duplicate headers were not preserved:\n%s", out)
	}
	if !strings.Contains(out, "transfer-encoding: chunked") {
		t.Fatalf("transfer encoding was not shown:\n%s", out)
	}
}

func TestPrintRequestMetadataUsesRequestHost(t *testing.T) {
	req := &http.Request{
		Method: "GET",
		URL:    mustParseURL("https://127.0.0.1/path"),
		Host:   "vhost.example",
		Header: http.Header{"Accept": {"*/*"}},
		Proto:  "HTTP/1.1",
	}

	p := newTestPrinter()
	printRequestMetadata(p, req, core.HTTPDefault, core.VVerbose)
	out := string(p.Bytes())

	if !strings.Contains(out, "host: vhost.example") {
		t.Fatalf("expected overridden host in request metadata, got:\n%s", out)
	}
	if strings.Contains(out, "host: 127.0.0.1") {
		t.Fatalf("expected URL host to be omitted when Request.Host is set, got:\n%s", out)
	}
}

func TestDiagnosticOutputRedactsURLsHeadersAndRedirectLocations(t *testing.T) {
	req := &http.Request{
		Method: "GET",
		URL:    mustParseURL("https://example.test/start?safe=ok&API_KEY=query-api-secret&access_token=query-token-secret&clientSecret=query-client-secret&request-signature=query-signature-secret"),
		Header: http.Header{
			"X-API-Key":           {"header-api-secret"},
			"X-AuthToken":         {"header-token-secret"},
			"X-ClientSecret":      {"header-client-secret"},
			"X-Request-Signature": {"header-signature-secret"},
			"X-KeyboardLayout":    {"keyboard-layout"},
		},
		Proto: "HTTP/1.1",
	}
	resp := &http.Response{
		StatusCode: 302,
		Proto:      "HTTP/1.1",
		Header: http.Header{
			"Location":         {"https://redirect.test/next?PASSWORD=location-password-secret&safe=ok"},
			"X-Response-Token": {"response-token-secret"},
			"X-Response-Trace": {"response-trace"},
		},
		Request: req,
	}
	hop := client.RedirectHop{
		Request:     req,
		Response:    resp,
		NextRequest: req.Clone(req.Context()),
	}

	secretValues := []string{
		"query-api-secret", "query-token-secret", "query-client-secret", "query-signature-secret",
		"header-api-secret", "header-token-secret", "header-client-secret", "header-signature-secret",
		"location-password-secret", "response-token-secret",
	}

	tests := []struct {
		name  string
		print func(*core.Printer)
	}{
		{name: "normal response", print: func(p *core.Printer) { printResponseMetadata(p, core.VNormal, resp) }},
		{name: "verbose request", print: func(p *core.Printer) { printRequestMetadata(p, req, core.HTTPDefault, core.VVerbose) }},
		{name: "verbose response", print: func(p *core.Printer) { printResponseMetadata(p, core.VVerbose, resp) }},
		{name: "verbose redirect", print: func(p *core.Printer) { printRedirectHop(p, core.VVerbose, hop, core.HTTPDefault) }},
		{name: "debug request", print: func(p *core.Printer) { printRequestMetadata(p, req, core.HTTPDefault, core.VDebug) }},
		{name: "debug response", print: func(p *core.Printer) { printResponseMetadata(p, core.VDebug, resp) }},
		{name: "debug redirect", print: func(p *core.Printer) { printRedirectHop(p, core.VDebug, hop, core.HTTPDefault) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestPrinter()
			tt.print(p)
			out := string(p.Bytes())
			for _, secret := range secretValues {
				if strings.Contains(out, secret) {
					t.Errorf("diagnostic output leaked %q:\n%s", secret, out)
				}
			}
		})
	}

	p := newTestPrinter()
	printRequestMetadata(p, req, core.HTTPDefault, core.VVerbose)
	out := string(p.Bytes())
	if !strings.Contains(out, "x-keyboardlayout: keyboard-layout") {
		t.Fatalf("non-credential compound header was not preserved:\n%s", out)
	}
}

func TestPrintResponseMetadataPrefixes(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Content-Type": {"text/html"}},
		Request:    &http.Request{Method: "GET"},
	}

	t.Run("no prefix at VVerbose", func(t *testing.T) {
		p := newTestPrinter()
		printResponseMetadata(p, core.VVerbose, resp)
		out := string(p.Bytes())

		if strings.Contains(out, "< ") {
			t.Errorf("expected no '< ' prefix at VVerbose, got:\n%s", out)
		}
		if !strings.Contains(out, "HTTP/1.1 200 OK") {
			t.Errorf("expected status line, got:\n%s", out)
		}
		if !strings.Contains(out, "content-type: text/html") {
			t.Errorf("expected response header, got:\n%s", out)
		}
	})

	t.Run("prefix at VExtraVerbose", func(t *testing.T) {
		p := newTestPrinter()
		printResponseMetadata(p, core.VExtraVerbose, resp)
		out := string(p.Bytes())

		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		for _, line := range lines {
			if !strings.HasPrefix(line, "< ") {
				t.Errorf("expected '< ' prefix on line %q", line)
			}
		}
		// Last line should be a blank prefixed line.
		if last := lines[len(lines)-1]; last != "< " {
			t.Errorf("expected trailing '< ' blank line, got %q", last)
		}
	})

	t.Run("prefix at VDebug", func(t *testing.T) {
		p := newTestPrinter()
		printResponseMetadata(p, core.VDebug, resp)
		out := string(p.Bytes())

		lines := strings.SplitSeq(strings.TrimRight(out, "\n"), "\n")
		for line := range lines {
			if !strings.HasPrefix(line, "< ") {
				t.Errorf("expected '< ' prefix on line %q", line)
			}
		}
	})

	t.Run("no headers at VNormal", func(t *testing.T) {
		p := newTestPrinter()
		printResponseMetadata(p, core.VNormal, resp)
		out := string(p.Bytes())

		if strings.Contains(out, "content-type") {
			t.Errorf("expected no headers at VNormal, got:\n%s", out)
		}
	})
}

func TestPrintResponseHeadersPrefix(t *testing.T) {
	resp := &http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		Header:        http.Header{"Content-Type": {"application/json"}, "X-Custom": {"value"}},
		ContentLength: 42,
		Request:       &http.Request{Method: "GET"},
	}

	t.Run("no prefix when usePrefix is false", func(t *testing.T) {
		p := newTestPrinter()
		printResponseHeaders(p, resp, false)
		out := string(p.Bytes())

		if strings.Contains(out, "< ") {
			t.Errorf("expected no '< ' prefix, got:\n%s", out)
		}
		if !strings.Contains(out, "content-type: application/json") {
			t.Errorf("expected header content, got:\n%s", out)
		}
	})

	t.Run("prefix when usePrefix is true", func(t *testing.T) {
		p := newTestPrinter()
		printResponseHeaders(p, resp, true)
		out := string(p.Bytes())

		lines := strings.SplitSeq(strings.TrimRight(out, "\n"), "\n")
		for line := range lines {
			if !strings.HasPrefix(line, "< ") {
				t.Errorf("expected '< ' prefix on line %q", line)
			}
		}
	})
}

func TestIsPrintableRejectsInvalidUTF8(t *testing.T) {
	input := []byte{0xff, 0xfe, 0xfd}
	ok, r, err := isPrintable(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("isPrintable returned error: %v", err)
	}
	if ok {
		t.Fatal("isPrintable accepted invalid UTF-8 bytes")
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading returned reader: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("returned reader = %v, want %v", got, input)
	}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
