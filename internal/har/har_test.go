package har

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestRecorderWritesBoundedHAR(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.har")
	recorder, err := New(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()

	reqURL, _ := url.Parse("https://example.test/resource?a=1&a=two+words&empty")
	req := &http.Request{
		Method: "POST", URL: reqURL, Proto: "HTTP/2.0",
		Header: http.Header{"X-Duplicate": {"one", "two"}, "Content-Type": {"text/plain"}},
		Body:   io.NopCloser(strings.NewReader("request body")),
	}
	recorder.ObserveRequest(req)
	if _, err := req.Body.Read(make([]byte, 0)); err != nil {
		t.Fatal(err)
	}
	requestBytes, _ := io.ReadAll(req.Body)
	if string(requestBytes) != "request body" {
		t.Fatalf("request body = %q", requestBytes)
	}

	resp := &http.Response{
		StatusCode: 201, Status: "201 Created", Proto: "HTTP/2.0",
		Header: http.Header{"X-Duplicate": {"a", "b"}, "Content-Type": {"application/octet-stream"}},
		Body:   io.NopCloser(bytes.NewReader([]byte{0xff, 0xfe, 0xfd})), Request: req,
	}
	capture := recorder.CaptureResponse(resp)
	if _, err := capture.Write([]byte{0xff, 0xfe, 0xfd}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Finalize(resp, capture, Timings{DNS: time.Millisecond, Connect: 2 * time.Millisecond, TLS: 3 * time.Millisecond, Wait: 4 * time.Millisecond, Receive: 5 * time.Millisecond, TransferSize: 3, TransferKnown: true, DNSKnown: true, ConnectKnown: true, TLSKnown: true, WaitKnown: true, ReceiveKnown: true}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Log struct {
			Version string `json:"version"`
			Entries []struct {
				Request struct {
					Headers []NameValue `json:"headers"`
					Query   []NameValue `json:"queryString"`
					Post    *PostData   `json:"postData"`
				} `json:"request"`
				Response struct {
					Content Content `json:"content"`
				} `json:"response"`
				Timings TimingsHAR `json:"timings"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document.Log.Version != Version || len(document.Log.Entries) != 1 {
		t.Fatalf("HAR log = %+v", document.Log)
	}
	entry := document.Log.Entries[0]
	if len(entry.Request.Headers) != 3 {
		t.Fatalf("request headers = %+v", entry.Request.Headers)
	}
	var duplicateValues []string
	for _, header := range entry.Request.Headers {
		if header.Name == "X-Duplicate" {
			duplicateValues = append(duplicateValues, header.Value)
		}
	}
	if len(duplicateValues) != 2 {
		t.Fatalf("duplicate request headers = %+v", entry.Request.Headers)
	}
	if len(entry.Request.Query) != 3 || entry.Request.Query[1].Value != "two words" {
		t.Fatalf("query = %+v", entry.Request.Query)
	}
	if entry.Request.Post == nil || entry.Request.Post.Text != "request body" {
		t.Fatalf("post data = %+v", entry.Request.Post)
	}
	want := base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0xfd})
	if entry.Response.Content.Text != want || entry.Response.Content.Encoding != "base64" {
		t.Fatalf("response content = %+v, want base64 %q", entry.Response.Content, want)
	}
	if entry.Timings.DNS != 1 || entry.Timings.Receive != 5 {
		t.Fatalf("timings = %+v", entry.Timings)
	}
}

func TestRecorderOmitsBodiesOverLimit(t *testing.T) {
	dir := t.TempDir()
	recorder, err := New(filepath.Join(dir, "capture.har"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()

	reqURL, _ := url.Parse("https://example.test/")
	req := &http.Request{Method: "POST", URL: reqURL, Body: io.NopCloser(strings.NewReader("request"))}
	recorder.ObserveRequest(req)
	_, _ = io.Copy(io.Discard, req.Body)
	resp := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", Header: make(http.Header), Body: http.NoBody, Request: req}
	capture := recorder.CaptureResponse(resp)
	large := bytes.Repeat([]byte{'x'}, int(core.MaxHARResponseBodyBytes)+1)
	_, _ = capture.Write(large)
	if err := recorder.Finalize(resp, capture, Timings{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "capture.har"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(BodyOmittedComment)) {
		t.Fatalf("HAR does not contain omission comment")
	}
}
