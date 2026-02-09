package tlsinspect

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func newTestPrinter() *core.Printer {
	return core.NewHandle(core.ColorOff).Stderr()
}

func TestCertDisplayName(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "CN and Org different",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName:   "example.com",
					Organization: []string{"Example Inc"},
				},
			},
			want: "example.com, Example Inc",
		},
		{
			name: "CN only",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "example.com",
				},
			},
			want: "example.com",
		},
		{
			name: "CN equals Org",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName:   "Example Inc",
					Organization: []string{"Example Inc"},
				},
			},
			want: "Example Inc",
		},
		{
			name: "SAN fallback",
			cert: &x509.Certificate{
				Subject:  pkix.Name{},
				DNSNames: []string{"example.com"},
			},
			want: "example.com",
		},
		{
			name: "Org fallback",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					Organization: []string{"Example Inc"},
				},
			},
			want: "Example Inc",
		},
		{
			name: "full DN fallback",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					Country: []string{"US"},
				},
			},
			want: "C=US",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := certDisplayName(tt.cert)
			if got != tt.want {
				t.Errorf("certDisplayName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCertExpiryInfo(t *testing.T) {
	fixedNow := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	origNow := tlsInspectNow
	tlsInspectNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { tlsInspectNow = origNow })

	tests := []struct {
		name      string
		notAfter  time.Time
		wantText  string
		wantColor core.Sequence
	}{
		{
			name:      "expired",
			notAfter:  fixedNow.Add(-24 * time.Hour),
			wantText:  "expired",
			wantColor: core.Red,
		},
		{
			name:      "less than 1 day",
			notAfter:  fixedNow.Add(12 * time.Hour),
			wantText:  "expires in <1 day",
			wantColor: core.Red,
		},
		{
			name:      "exactly 1 day",
			notAfter:  fixedNow.Add(36 * time.Hour),
			wantText:  "expires in 1 day",
			wantColor: core.Red,
		},
		{
			name:      "less than 7 days red",
			notAfter:  fixedNow.Add(3 * 24 * time.Hour),
			wantText:  "expires in 3 days",
			wantColor: core.Red,
		},
		{
			name:      "exactly 6 days red",
			notAfter:  fixedNow.Add(6 * 24 * time.Hour),
			wantText:  "expires in 6 days",
			wantColor: core.Red,
		},
		{
			name:      "7 days yellow",
			notAfter:  fixedNow.Add(7 * 24 * time.Hour),
			wantText:  "expires in 7 days",
			wantColor: core.Yellow,
		},
		{
			name:      "29 days yellow",
			notAfter:  fixedNow.Add(29 * 24 * time.Hour),
			wantText:  "expires in 29 days",
			wantColor: core.Yellow,
		},
		{
			name:      "30 days green",
			notAfter:  fixedNow.Add(30 * 24 * time.Hour),
			wantText:  "expires in 30 days",
			wantColor: core.Green,
		},
		{
			name:      "365 days green",
			notAfter:  fixedNow.Add(365 * 24 * time.Hour),
			wantText:  "expires in 365 days",
			wantColor: core.Green,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{NotAfter: tt.notAfter}
			gotText, gotColor := certExpiryInfo(cert)
			if gotText != tt.wantText {
				t.Errorf("certExpiryInfo() text = %q, want %q", gotText, tt.wantText)
			}
			if gotColor != tt.wantColor {
				t.Errorf("certExpiryInfo() color = %q, want %q", gotColor, tt.wantColor)
			}
		})
	}
}

func TestRenderCertChain(t *testing.T) {
	fixedNow := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	origNow := tlsInspectNow
	tlsInspectNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { tlsInspectNow = origNow })

	chain := []*x509.Certificate{
		{
			Subject:  pkix.Name{CommonName: "example.com"},
			NotAfter: fixedNow.Add(43 * 24 * time.Hour),
		},
		{
			Subject: pkix.Name{
				CommonName:   "R3",
				Organization: []string{"Let's Encrypt"},
			},
			NotAfter: fixedNow.Add(583 * 24 * time.Hour),
		},
		{
			Subject: pkix.Name{
				CommonName:   "ISRG Root X1",
				Organization: []string{"Internet Security Research Group"},
			},
			NotAfter: fixedNow.Add(3280 * 24 * time.Hour),
		},
	}

	p := newTestPrinter()
	renderCertChain(p, chain)
	out := string(p.Bytes())

	// Verify all cert names appear.
	for _, want := range []string{"example.com", "R3, Let's Encrypt", "ISRG Root X1, Internet Security Research Group"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}

	// Verify tree structure with └─.
	if !strings.Contains(out, "└─") {
		t.Errorf("expected tree connector '└─' in output, got:\n%s", out)
	}

	// Verify indentation increases.
	if !strings.Contains(out, "   └─") {
		t.Errorf("expected indented tree connector in output, got:\n%s", out)
	}
}

func TestRenderSANs(t *testing.T) {
	t.Run("DNS and IP", func(t *testing.T) {
		leaf := &x509.Certificate{
			DNSNames:    []string{"example.com", "*.example.com"},
			IPAddresses: []net.IP{net.ParseIP("1.2.3.4")},
		}

		p := newTestPrinter()
		renderSANs(p, leaf)
		out := string(p.Bytes())

		if !strings.Contains(out, "SANs:") {
			t.Errorf("expected 'SANs:' in output, got:\n%s", out)
		}
		if !strings.Contains(out, "example.com") {
			t.Errorf("expected 'example.com' in output, got:\n%s", out)
		}
		if !strings.Contains(out, "*.example.com") {
			t.Errorf("expected '*.example.com' in output, got:\n%s", out)
		}
		if !strings.Contains(out, "1.2.3.4") {
			t.Errorf("expected '1.2.3.4' in output, got:\n%s", out)
		}
	})

	t.Run("empty SANs produces no output", func(t *testing.T) {
		leaf := &x509.Certificate{}

		p := newTestPrinter()
		renderSANs(p, leaf)
		out := string(p.Bytes())

		if out != "" {
			t.Errorf("expected empty output for no SANs, got:\n%s", out)
		}
	})
}

func TestRender(t *testing.T) {
	t.Run("nil ConnectionState", func(t *testing.T) {
		p := newTestPrinter()
		render(p, nil)
		out := string(p.Bytes())

		if !strings.Contains(out, "no TLS connection state available") {
			t.Errorf("expected warning for nil state, got:\n%s", out)
		}
	})

	t.Run("basic ConnectionState", func(t *testing.T) {
		fixedNow := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
		origNow := tlsInspectNow
		tlsInspectNow = func() time.Time { return fixedNow }
		t.Cleanup(func() { tlsInspectNow = origNow })

		cs := &tls.ConnectionState{
			Version:            tls.VersionTLS13,
			CipherSuite:        tls.TLS_AES_256_GCM_SHA384,
			NegotiatedProtocol: "h2",
			PeerCertificates: []*x509.Certificate{
				{
					Subject:      pkix.Name{CommonName: "example.com"},
					SerialNumber: big.NewInt(1),
					NotAfter:     fixedNow.Add(90 * 24 * time.Hour),
					DNSNames:     []string{"example.com", "*.example.com"},
				},
			},
		}

		p := newTestPrinter()
		render(p, cs)
		out := string(p.Bytes())

		if !strings.Contains(out, "TLS 1.3") {
			t.Errorf("expected 'TLS 1.3' in output, got:\n%s", out)
		}
		if !strings.Contains(out, "ALPN: h2") {
			t.Errorf("expected 'ALPN: h2' in output, got:\n%s", out)
		}
		if !strings.Contains(out, "Certificate chain") {
			t.Errorf("expected 'Certificate chain' in output, got:\n%s", out)
		}
		if !strings.Contains(out, "example.com") {
			t.Errorf("expected 'example.com' in output, got:\n%s", out)
		}
		if !strings.Contains(out, "SANs:") {
			t.Errorf("expected 'SANs:' in output, got:\n%s", out)
		}
	})
}
