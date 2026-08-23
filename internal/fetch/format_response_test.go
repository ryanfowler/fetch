package fetch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFormatWithBoundedOutput(t *testing.T) {
	p := core.TestPrinter(false)
	formatted, err := formatWithBoundedOutput(p, "formatted response", func(out *core.Printer) error {
		_, _ = out.Write(bytes.Repeat([]byte("x"), maxBodyBytes+1))
		return nil
	})
	if !errors.Is(err, core.ErrLimitExceeded) {
		t.Fatalf("formatWithBoundedOutput() error = %v, want limit error", err)
	}
	if formatted != nil || len(p.Bytes()) != 0 {
		t.Fatalf("bounded formatter returned partial output: %d bytes", len(p.Bytes()))
	}
}

func TestFormatResponseFormatsExactMaxBodyBytes(t *testing.T) {
	prefix := []byte(`{"a":1}`)
	body := append(append([]byte(nil), prefix...), bytes.Repeat([]byte(" "), maxBodyBytes-len(prefix))...)
	if len(body) != maxBodyBytes {
		t.Fatalf("test body is %d bytes, want %d", len(body), maxBodyBytes)
	}

	got := readFormattedResponse(t, body)
	if bytes.Equal(got, body) {
		t.Fatal("response exactly at maxBodyBytes was returned unformatted")
	}
	if !bytes.HasPrefix(got, []byte("{\n  \"a\": 1\n}")) {
		t.Fatalf("response was not formatted as JSON, got prefix %q", got[:min(len(got), 16)])
	}
}

func TestFormatResponseStreamsNDJSONThroughReader(t *testing.T) {
	resp := &http.Response{
		Body:   io.NopCloser(strings.NewReader("{\"value\":1}\n{\"value\":2}\n")),
		Header: http.Header{"Content-Type": {"application/x-ndjson"}},
		Request: &http.Request{
			Method: "GET",
		},
	}
	r := &Request{
		Format:        core.FormatOn,
		PrinterHandle: core.NewHandle(core.ColorOff),
	}

	reader, err := formatResponse(context.Background(), r, resp, nil)
	if err != nil {
		t.Fatalf("formatResponse returned error: %v", err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading streamed response: %v", err)
	}
	if !strings.Contains(string(got), "value") || !strings.Contains(string(got), "1") {
		t.Fatalf("streamed NDJSON output = %q", got)
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

	reader, err := formatResponse(context.Background(), r, resp, nil)
	if err != nil {
		t.Fatalf("formatResponse returned error: %v", err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading formatted response: %v", err)
	}
	return got
}
