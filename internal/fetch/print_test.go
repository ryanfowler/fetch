package fetch

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

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

		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		for _, line := range lines {
			if !strings.HasPrefix(line, "> ") {
				t.Errorf("expected '> ' prefix on line %q", line)
			}
		}
	})
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

		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		for _, line := range lines {
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

		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		for _, line := range lines {
			if !strings.HasPrefix(line, "< ") {
				t.Errorf("expected '< ' prefix on line %q", line)
			}
		}
	})
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
