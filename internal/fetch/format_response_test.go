package fetch

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFormatResponseFormatsExactMaxBodyBytes(t *testing.T) {
	body := []byte(`{"a":"` + strings.Repeat("x", maxBodyBytes-len(`{"a":""}`)) + `"}`)
	if len(body) != maxBodyBytes {
		t.Fatalf("test body is %d bytes, want %d", len(body), maxBodyBytes)
	}

	got := readFormattedResponse(t, body)
	if bytes.Equal(got, body) {
		t.Fatal("response exactly at maxBodyBytes was returned unformatted")
	}
	if !bytes.HasPrefix(got, []byte("{\n  \"a\": \"")) {
		t.Fatalf("response was not formatted as JSON, got prefix %q", got[:min(len(got), 16)])
	}
}

func TestFormatResponseSkipsFormattingOverMaxBodyBytes(t *testing.T) {
	body := []byte(`{"a":"` + strings.Repeat("x", maxBodyBytes-len(`{"a":""}`)) + `"}`)
	body = append(body, ' ')
	if len(body) != maxBodyBytes+1 {
		t.Fatalf("test body is %d bytes, want %d", len(body), maxBodyBytes+1)
	}

	got := readFormattedResponse(t, body)
	if !bytes.Equal(got, body) {
		t.Fatal("response over maxBodyBytes should be returned unformatted")
	}
}

func readFormattedResponse(t *testing.T, body []byte) []byte {
	t.Helper()

	resp := &http.Response{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Header: http.Header{"Content-Type": {"application/json"}},
		Request: &http.Request{
			Method: "GET",
		},
	}
	r := &Request{
		Format:        core.FormatOn,
		PrinterHandle: core.NewHandle(core.ColorOff),
	}

	reader, err := formatResponse(context.Background(), r, resp)
	if err != nil {
		t.Fatalf("formatResponse returned error: %v", err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading formatted response: %v", err)
	}
	return got
}
