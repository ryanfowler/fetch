package fetch

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestHARRecordsFinalRetryExchange(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("retry"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("final"))
	}))
	defer server.Close()

	harPath := filepath.Join(t.TempDir(), "retry.har")
	r := &Request{URL: mustParseURL(server.URL), HAR: harPath, Discard: true, Retry: 1, RetryDelay: time.Millisecond, Compression: core.CompressionOff, PrinterHandle: core.NewHandle(core.ColorOff), Verbosity: core.VSilent}
	if status := Fetch(t.Context(), r); status != 0 {
		t.Fatalf("Fetch() status = %d", status)
	}
	data, err := os.ReadFile(harPath)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Log struct {
			Entries []struct {
				Response struct {
					Status  int `json:"status"`
					Content struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Log.Entries) != 1 || document.Log.Entries[0].Response.Status != http.StatusOK || document.Log.Entries[0].Response.Content.Text != "final" {
		t.Fatalf("HAR did not record final retry response: %s", data)
	}
}

func TestHARRecordsDecodedBodyAndWireSize(t *testing.T) {
	var encoded bytes.Buffer
	gz := gzip.NewWriter(&encoded)
	_, _ = gz.Write([]byte("decoded"))
	_ = gz.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(encoded.Len()))
		_, _ = w.Write(encoded.Bytes())
	}))
	defer server.Close()

	harPath := filepath.Join(t.TempDir(), "compressed.har")
	r := &Request{URL: mustParseURL(server.URL), HAR: harPath, Discard: true, Compression: core.CompressionAuto, PrinterHandle: core.NewHandle(core.ColorOff), Verbosity: core.VSilent}
	if status := Fetch(t.Context(), r); status != 0 {
		t.Fatalf("Fetch() status = %d", status)
	}
	data, err := os.ReadFile(harPath)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Log struct {
			Entries []struct {
				Response struct {
					BodySize int64 `json:"bodySize"`
					Content  struct {
						Size int64  `json:"size"`
						Text string `json:"text"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	response := document.Log.Entries[0].Response
	if response.Content.Text != "decoded" || response.Content.Size != int64(len("decoded")) || response.BodySize != int64(encoded.Len()) {
		t.Fatalf("decoded content/transfer size = %+v, encoded length = %d", response, encoded.Len())
	}
}

func TestHARRecordsFinalRedirectExchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "/final?one=1&one=2")
			w.WriteHeader(http.StatusFound)
		case "/final":
			w.Header().Add("X-Duplicate", "first")
			w.Header().Add("X-Duplicate", "second")
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("final body"))
		}
	}))
	defer server.Close()

	harPath := filepath.Join(t.TempDir(), "capture.har")
	r := &Request{
		URL:           mustParseURL(server.URL + "/redirect"),
		HAR:           harPath,
		Discard:       true,
		Compression:   core.CompressionOff,
		PrinterHandle: core.NewHandle(core.ColorOff),
		Verbosity:     core.VSilent,
	}
	if status := Fetch(t.Context(), r); status != 0 {
		t.Fatalf("Fetch() status = %d", status)
	}

	data, err := os.ReadFile(harPath)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Log struct {
			Entries []struct {
				Request struct {
					URL string `json:"url"`
				} `json:"request"`
				Response struct {
					Status  int `json:"status"`
					Content struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Log.Entries) != 1 {
		t.Fatalf("HAR entries = %d, want one", len(document.Log.Entries))
	}
	entry := document.Log.Entries[0]
	if !strings.Contains(entry.Request.URL, "/final?one=1&one=2") {
		t.Fatalf("final request URL = %q", entry.Request.URL)
	}
	if entry.Response.Status != http.StatusOK || entry.Response.Content.Text != "final body" {
		t.Fatalf("final response = %+v", entry.Response)
	}
}
