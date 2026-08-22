package fetch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/aws"
)

func TestSignAWSRequestUsesCurrentBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader(`{"name":"before"}`))
	if err != nil {
		t.Fatal(err)
	}
	setReplayableBody(req, []byte("final body"))

	if err := signAWSRequest(testAWSRequest(), req); err != nil {
		t.Fatal(err)
	}

	got := req.Header.Get("X-Amz-Content-Sha256")
	want := hexSHA256([]byte("final body"))
	if got != want {
		t.Fatalf("payload hash = %s, want %s", got, want)
	}
}

func TestSignWebSocketHandshakeUsesEmptyPayloadAndPreservesBody(t *testing.T) {
	u, err := url.Parse("wss://example.com/socket")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{
		Method:        http.MethodGet,
		URL:           u,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("initial message")),
		ContentLength: int64(len("initial message")),
	}

	if err := signWebSocketHandshake(testAWSRequest(), req); err != nil {
		t.Fatal(err)
	}

	if got := req.Header.Get("X-Amz-Content-Sha256"); got != hexSHA256(nil) {
		t.Fatalf("payload hash = %s, want empty payload hash", got)
	}
	if req.Body == nil || req.Body == http.NoBody {
		t.Fatal("expected WebSocket initial message body to be preserved")
	}
	gotBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBody) != "initial message" {
		t.Fatalf("body = %q, want initial message", gotBody)
	}
	if req.ContentLength != int64(len("initial message")) {
		t.Fatalf("content length = %d, want %d", req.ContentLength, len("initial message"))
	}
}

func TestWebSocketMetadataRequestIncludesEffectiveUpgrade(t *testing.T) {
	u, err := url.Parse("wss://example.com/socket")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Duplicate", "one")
	req.Header.Add("X-Duplicate", "two")

	metadata := websocketMetadataRequest(req, []string{"graphql-ws"})
	if metadata.URL.Scheme != "https" {
		t.Fatalf("metadata URL scheme = %q, want https", metadata.URL.Scheme)
	}
	for name, want := range map[string]string{
		"Connection":             "Upgrade",
		"Upgrade":                "websocket",
		"Sec-WebSocket-Version":  "13",
		"Sec-WebSocket-Key":      "[generated]",
		"Sec-WebSocket-Protocol": "graphql-ws",
	} {
		if got := metadata.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if got := metadata.Header.Values("X-Duplicate"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("duplicate headers = %v, want [one two]", got)
	}
	if req.URL.Scheme != "wss" {
		t.Fatal("metadata construction mutated the original URL")
	}
}

func TestWebSocketHandshakeErrorBoundsAndEscapesExcerpt(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Status:     "403 Forbidden",
		Body:       io.NopCloser(strings.NewReader("bad\x1b[2J" + strings.Repeat("x", 2048))),
	}
	err := websocketHandshakeError(resp, errors.New("upgrade rejected"))
	if err == nil {
		t.Fatal("expected handshake error")
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("error contains raw escape: %q", err)
	}
	if !strings.Contains(err.Error(), "response excerpt") || !strings.Contains(err.Error(), "403 Forbidden") {
		t.Fatalf("error = %q, want status and bounded excerpt", err)
	}
	if len(err.Error()) > 1400 {
		t.Fatalf("error length = %d, want bounded excerpt", len(err.Error()))
	}
}

func testAWSRequest() *Request {
	return &Request{
		AWSSigv4: &aws.Config{
			AccessKey: "AKIDEXAMPLE",
			SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
			Region:    "us-east-1",
			Service:   "execute-api",
		},
	}
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
