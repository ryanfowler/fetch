package integration_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/parity"
)

type observedRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}

type parityFixture struct {
	mu       sync.Mutex
	requests []observedRequest
	server   *httptest.Server
}

func newParityFixture(t *testing.T) *parityFixture {
	t.Helper()
	fixture := &parityFixture{}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadAllBounded(r.Body, 1<<20)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fixture.mu.Lock()
		fixture.requests = append(fixture.requests, observedRequest{
			Method:  r.Method,
			URL:     r.URL.String(),
			Headers: r.Header.Clone(),
			Body:    body,
		})
		fixture.mu.Unlock()
		w.Header().Add("X-Parity-Response", "first")
		w.Header().Add("X-Parity-Response", "second")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"items":["one","two"]}`))
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *parityFixture) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = nil
}

func (f *parityFixture) requestsSnapshot() []observedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	requests := make([]observedRequest, len(f.requests))
	for i, request := range f.requests {
		request.Headers = request.Headers.Clone()
		request.Body = append([]byte(nil), request.Body...)
		requests[i] = request
	}
	return requests
}

const rustParityRevision = "ea39416950cc89496b891fcc8bc75b0b68f0d0fe"

// TestDifferentialParity is intentionally opt-in. The Rust oracle is a test
// input, not a build dependency of normal Go CI.
func TestDifferentialParity(t *testing.T) {
	rustBinary := os.Getenv("FETCH_PARITY_RUST_BINARY")
	if rustBinary == "" {
		t.Skip("set FETCH_PARITY_RUST_BINARY to run the pinned Rust differential fixtures")
	}
	if _, err := os.Stat(rustBinary); err != nil {
		t.Fatalf("FETCH_PARITY_RUST_BINARY=%q: %v", rustBinary, err)
	}
	if revision := os.Getenv("FETCH_PARITY_RUST_REVISION"); revision != "" && revision != rustParityRevision {
		t.Fatalf("FETCH_PARITY_RUST_REVISION=%q, want %s", revision, rustParityRevision)
	}

	goBinary := os.Getenv("FETCH_PARITY_GO_BINARY")
	if goBinary == "" {
		goBinary = goBuild(t, t.TempDir())
	}

	fixture := newParityFixture(t)
	runner := parity.NewRunner()
	options := parity.DefaultOptions()

	tests := []struct {
		name  string
		args  []string
		files []string
	}{
		{
			name: "normal JSON request",
			args: []string{"--silent", "--color", "off", "--format", "on", fixture.server.URL},
		},
		{
			name: "duplicate response headers and verbose ordering",
			args: []string{
				"--color", "off", "--header", "X-Parity-Duplicate: first",
				"--verbose", fixture.server.URL,
			},
		},
		{
			name: "request body and duplicate query values",
			args: []string{
				"--silent", "--color", "off", "--format", "on",
				"--json", `{"value":"parity"}`,
				fixture.server.URL + "/body?item=one&item=two",
			},
		},
		{
			name:  "decoded output file",
			args:  []string{"--silent", "--output", "response.json", fixture.server.URL},
			files: []string{"response.json"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture.reset()
			caseDef := parity.Case{
				Name:         test.name,
				Args:         test.args,
				CaptureFiles: test.files,
				Timeout:      5 * time.Second,
			}
			if err := runner.Compare(context.Background(), goBinary, rustBinary, caseDef, options); err != nil {
				t.Fatal(err)
			}
			requests := fixture.requestsSnapshot()
			if len(requests) != 2 {
				t.Fatalf("expected one request from each binary, got %d", len(requests))
			}
			goRequest, rustRequest := requests[0], requests[1]
			if diff := compareObservedRequests(goRequest, rustRequest); diff != "" {
				t.Fatalf("request semantics differ: %s", diff)
			}
		})
	}
}

func TestNormalizeObservedHeaderValuesOnlyNormalizesBuildVersions(t *testing.T) {
	if got := normalizeObservedHeaderValues("User-Agent", []string{"fetch/v1.2.3-dev", "fetch/v0.0.0-dev"}); !reflect.DeepEqual(got, []string{"<fetch-user-agent>", "<fetch-user-agent>"}) {
		t.Fatalf("build user agents were not normalized: %v", got)
	}
	got := normalizeObservedHeaderValues("User-Agent", []string{"fetch/custom", "curl/8.0"})
	if !reflect.DeepEqual(got, []string{"fetch/custom", "curl/8.0"}) {
		t.Fatalf("non-build user agents were normalized: %v", got)
	}
}

func compareObservedRequests(goRequest, rustRequest observedRequest) string {
	if goRequest.Method != rustRequest.Method || goRequest.URL != rustRequest.URL {
		return fmt.Sprintf("method/url Go=%s %s Rust=%s %s", goRequest.Method, goRequest.URL, rustRequest.Method, rustRequest.URL)
	}
	names := make(map[string]struct{}, len(goRequest.Headers)+len(rustRequest.Headers))
	for name := range goRequest.Headers {
		names[http.CanonicalHeaderKey(name)] = struct{}{}
	}
	for name := range rustRequest.Headers {
		names[http.CanonicalHeaderKey(name)] = struct{}{}
	}
	orderedNames := make([]string, 0, len(names))
	for name := range names {
		orderedNames = append(orderedNames, name)
	}
	sort.Strings(orderedNames)
	for _, name := range orderedNames {
		goValues := normalizeObservedHeaderValues(name, goRequest.Headers.Values(name))
		rustValues := normalizeObservedHeaderValues(name, rustRequest.Headers.Values(name))
		if !reflect.DeepEqual(goValues, rustValues) {
			return fmt.Sprintf("%s headers Go=%v Rust=%v", name, goValues, rustValues)
		}
	}
	if string(goRequest.Body) != string(rustRequest.Body) {
		return fmt.Sprintf("body Go=%q Rust=%q", goRequest.Body, rustRequest.Body)
	}
	return ""
}

var parityBuildUserAgent = regexp.MustCompile(`^fetch/(?:\(devel\)|v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)*)$`)

func normalizeObservedHeaderValues(name string, values []string) []string {
	if !strings.EqualFold(name, "User-Agent") {
		return values
	}
	normalized := append([]string(nil), values...)
	for i, value := range normalized {
		if parityBuildUserAgent.MatchString(value) {
			normalized[i] = "<fetch-user-agent>"
		}
	}
	return normalized
}

func ioReadAllBounded(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("fixture body exceeds %d bytes", limit)
	}
	return data, nil
}
