package fetch

import (
	"crypto/sha256"
	"encoding/hex"
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
