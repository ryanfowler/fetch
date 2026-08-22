package grpc

import (
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestHeadersAdvertiseGzip(t *testing.T) {
	headers := Headers()
	for _, header := range headers {
		if header.Key == "grpc-accept-encoding" {
			if header.Val != "gzip" {
				t.Fatalf("grpc-accept-encoding = %q, want gzip", header.Val)
			}
			return
		}
	}
	t.Fatal("Headers() did not include grpc-accept-encoding")
}

func TestHeadersRetainStandardValues(t *testing.T) {
	got := Headers()
	want := []core.KeyVal[string]{
		{Key: "Content-Type", Val: ContentType},
		{Key: "Te", Val: "trailers"},
		{Key: "grpc-accept-encoding", Val: "gzip"},
	}
	if len(got) != len(want) {
		t.Fatalf("Headers() length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Headers()[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}
