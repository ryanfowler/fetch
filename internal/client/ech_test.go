package client

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestECHModePolicyIsEnforcedBeforeTransportUse(t *testing.T) {
	u, err := url.Parse("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		cfg     ClientConfig
		wantErr string
	}{
		{
			name:    "hard ECH rejects explicit HTTP3",
			cfg:     ClientConfig{HTTP: core.HTTP3, ECH: core.ECHOn},
			wantErr: "explicit HTTP/3",
		},
		{
			name:    "ECH rejects explicit TLS 1.2",
			cfg:     ClientConfig{HTTP: core.HTTP2, ECH: core.ECHAuto, TLSMin: tls.VersionTLS12},
			wantErr: "TLS 1.3",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := NewClient(test.cfg)
			got := client.ValidateTransport(&http.Request{URL: u})
			if got == nil || !strings.Contains(got.Error(), test.wantErr) {
				t.Fatalf("ValidateTransport() = %v, want %q", got, test.wantErr)
			}
		})
	}
}
