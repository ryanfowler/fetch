package cli

import (
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestWebTransportCLI(t *testing.T) {
	app, err := Parse([]string{"--webtransport", "--wt-mode", "datagram", "--wt-protocol", "chat", "--wt-protocol", "chat-v2", "https://example.com/path"})
	if err != nil {
		t.Fatal(err)
	}
	if !app.WebTransport || app.WTMode != core.WTDatagram || len(app.WTProtocols) != 2 {
		t.Fatalf("app = %+v", app)
	}
	for _, args := range [][]string{
		{"--webtransport", "http://example.com"},
		{"--webtransport", "--http", "1", "https://example.com"},
		{"--webtransport", "--wt-datagram-mode", "binary", "https://example.com"},
		{"--webtransport", "--format", "off", "https://example.com"},
		{"--wt-mode", "stream", "https://example.com"},
		{"--webtransport", "--wt-protocol", "", "https://example.com"},
	} {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%v) succeeded", args)
		}
	}
	if _, err := Parse([]string{"--webtransport", "--wt-protocol", "chat", "--wt-protocol", "chat", "https://example.com"}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v", err)
	}
}
