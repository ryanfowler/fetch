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

	gproto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
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

func TestHARRecordsUnaryGRPCBodiesAsBase64AndTrailers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc+proto")
		w.Header().Set("Trailer", "grpc-status, grpc-message")
		w.WriteHeader(http.StatusOK)
		payload := []byte{0x08, 0x01}
		frame := append([]byte{0, 0, 0, 0, byte(len(payload))}, payload...)
		_, _ = w.Write(frame)
		w.Header().Set("grpc-status", "0")
		w.Header().Set("grpc-message", "complete")
	}))
	defer server.Close()

	dir := t.TempDir()
	descPath := filepath.Join(dir, "service.pb")
	strType := descriptorpb.FieldDescriptorProto_TYPE_STRING
	fds := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name: new("service.proto"), Package: new("pkg"), Syntax: new("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: new("Request")},
			{Name: new("Response"), Field: []*descriptorpb.FieldDescriptorProto{{Name: new("value"), Number: new(int32(1)), Type: &strType}}},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: new("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: new("Call"), InputType: new(".pkg.Request"), OutputType: new(".pkg.Response")}}}},
	}}}
	descData, err := gproto.Marshal(fds)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descPath, descData, 0o600); err != nil {
		t.Fatal(err)
	}

	harPath := filepath.Join(dir, "grpc.har")
	r := &Request{
		URL:           mustParseURL(server.URL + "/pkg.Service/Call"),
		GRPC:          true,
		HTTP:          core.HTTP1,
		Data:          strings.NewReader("raw"),
		ContentType:   "application/octet-stream",
		ProtoDesc:     descPath,
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
					PostData struct {
						Text     string `json:"text"`
						Encoding string `json:"encoding"`
					} `json:"postData"`
				} `json:"request"`
				Response struct {
					Headers []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
					Content struct {
						Text     string `json:"text"`
						Encoding string `json:"encoding"`
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
	if entry.Request.PostData.Encoding != "base64" || entry.Response.Content.Encoding != "base64" {
		t.Fatalf("gRPC bodies were not encoded as base64: %+v", entry)
	}
	trailerFound := false
	for _, header := range entry.Response.Headers {
		if strings.EqualFold(header.Name, "grpc-status") && header.Value == "0" {
			trailerFound = true
		}
	}
	if !trailerFound {
		t.Fatalf("HAR response did not preserve grpc-status trailer: %+v", entry.Response.Headers)
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
