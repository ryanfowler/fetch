package fetch

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFetchCanReuseRequestWithoutAccumulatingQueryParams(t *testing.T) {
	queries := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries <- r.URL.RawQuery
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	u, err := url.Parse(server.URL + "/path?existing=one")
	if err != nil {
		t.Fatal(err)
	}
	wantURL := u.String()
	r := &Request{
		Compression:   core.CompressionOff,
		Discard:       true,
		PrinterHandle: core.NewHandle(core.ColorOff),
		QueryParams:   []core.KeyVal[string]{{Key: "added", Val: "two words"}},
		URL:           u,
		Verbosity:     core.VSilent,
	}

	for range 2 {
		code, err := fetch(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
	}

	for range 2 {
		if got := <-queries; got != "existing=one&added=two%20words" {
			t.Fatalf("query = %q", got)
		}
	}
	if got := r.URL.String(); got != wantURL {
		t.Fatalf("input URL mutated: got %q, want %q", got, wantURL)
	}
}
