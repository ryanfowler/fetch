package tlsinspect

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/ocsp"
)

func newTestPrinter() *core.Printer {
	return core.TestPrinter(false)
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

func TestVerifyConnectionUsesPeerChainAndHostname(t *testing.T) {
	caCert, caKey := generateTestCACert(t)
	leaf, _ := generateTestCert(t, caCert, caKey, "tls.example")
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, caCert}}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	trusted := verifyConnection(state, &tls.Config{RootCAs: roots}, "tls.example")
	if trusted.Err != nil {
		t.Fatalf("trusted certificate verification failed: %v", trusted.Err)
	}
	if len(trusted.Chains) != 1 || len(trusted.Chains[0]) != 2 {
		t.Fatalf("trusted verification chains = %v, want leaf and CA", trusted.Chains)
	}

	untrusted := verifyConnection(state, &tls.Config{RootCAs: x509.NewCertPool()}, "tls.example")
	if untrusted.Err == nil {
		t.Fatal("untrusted certificate verification unexpectedly succeeded")
	}

	mismatch := verifyConnection(state, &tls.Config{RootCAs: roots}, "other.example")
	if mismatch.Err == nil {
		t.Fatal("hostname mismatch unexpectedly succeeded")
	}
	if !strings.Contains(mismatch.Err.Error(), "is valid for") {
		t.Fatalf("hostname mismatch error = %v", mismatch.Err)
	}
}

func TestALPNProtocols(t *testing.T) {
	tests := []struct {
		name        string
		httpVersion core.HTTPVersion
		want        []string
	}{
		{name: "default offers HTTP/2 and HTTP/1.1", httpVersion: core.HTTPDefault, want: []string{"h2", "http/1.1"}},
		{name: "HTTP/2 offers HTTP/2 and HTTP/1.1", httpVersion: core.HTTP2, want: []string{"h2", "http/1.1"}},
		{name: "HTTP/1 offers only HTTP/1.1", httpVersion: core.HTTP1, want: []string{"http/1.1"}},
		{name: "HTTP/3 offers only HTTP/3", httpVersion: core.HTTP3, want: []string{http3.NextProtoH3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := alpnProtocols(tt.httpVersion)
			if len(got) != len(tt.want) {
				t.Fatalf("alpnProtocols() length = %d, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("alpnProtocols()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestInspectHTTP3UsesQUICAndH3ALPN(t *testing.T) {
	caCert, caKey := generateTestCACert(t)
	serverCert, serverKey := generateTestCert(t, caCert, caKey, "quic-server")

	handshakeSeen := make(chan struct{}, 1)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Raw},
			PrivateKey:  serverKey,
			Leaf:        serverCert,
		}},
		NextProtos: []string{http3.NextProtoH3},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case handshakeSeen <- struct{}{}:
			default:
			}
			return nil, nil
		},
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, nil)
	if err != nil {
		t.Fatalf("quic.ListenAddr() error = %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	u, err := url.Parse("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	p := newTestPrinter()
	code := Inspect(context.Background(), p, &Config{
		CACerts: []*x509.Certificate{caCert},
		HTTP:    core.HTTP3,
		Timeout: 5 * time.Second,
		URL:     u,
	})
	if code != 0 {
		t.Fatalf("Inspect() exit code = %d, output:\n%s", code, string(p.Bytes()))
	}

	select {
	case <-handshakeSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not observe QUIC TLS handshake")
	}

	out := string(p.Bytes())
	if !strings.Contains(out, "ALPN: h3") {
		t.Fatalf("expected h3 ALPN in output, got:\n%s", out)
	}
	if !strings.Contains(out, "TLS_AES_128_GCM_SHA256") {
		t.Fatalf("expected negotiated QUIC cipher suite in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Remote IP: 127.0.0.1") {
		t.Fatalf("expected remote IP in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Resolver: system") {
		t.Fatalf("expected resolver provenance in output, got:\n%s", out)
	}
	if !strings.Contains(out, "quic-server") {
		t.Fatalf("expected server chain in output, got:\n%s", out)
	}
}

func TestInspectClosesDoHResolver(t *testing.T) {
	caCert, caKey := generateTestCACert(t)
	serverCert, serverKey := generateTestCert(t, caCert, caKey, "tls.example")
	tlsListener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{serverCert.Raw},
		PrivateKey:  serverKey,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tlsListener.Close() })
	go func() {
		conn, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		if tlsConn, ok := conn.(*tls.Conn); ok {
			if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
				return
			}
		}
		_, _ = io.Copy(io.Discard, conn)
	}()

	dohClosed := make(chan struct{}, 1)
	doh := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		if r.URL.Query().Get("type") == "AAAA" {
			_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"name":"tls.example","type":28,"data":"::1"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"name":"tls.example","type":1,"data":"127.0.0.1"}]}`)
	}))
	doh.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case dohClosed <- struct{}{}:
			default:
			}
		}
	}
	doh.Start()
	t.Cleanup(func() { doh.Close() })

	dohURL, err := url.Parse(doh.URL)
	if err != nil {
		t.Fatal(err)
	}
	targetURL, err := url.Parse("https://tls.example:" + strconv.Itoa(tlsListener.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPrinter()
	if code := Inspect(context.Background(), p, &Config{
		CACerts:   []*x509.Certificate{caCert},
		DNSServer: dohURL,
		Timeout:   5 * time.Second,
		URL:       targetURL,
	}); code != 0 {
		t.Fatalf("Inspect() exit code = %d, output:\n%s", code, string(p.Bytes()))
	}

	select {
	case <-dohClosed:
	case <-time.After(time.Second):
		t.Fatal("Inspect did not close the DoH resolver connection")
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

func TestRenderCertificateChain(t *testing.T) {
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
	renderCertificateChain(p, "Server chain", chain)
	out := string(p.Bytes())

	if !strings.Contains(out, "Server chain") {
		t.Errorf("expected server-chain label in output, got:\n%s", out)
	}

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

		if !strings.Contains(out, "* SANs:") {
			t.Errorf("expected '* SANs:' in output, got:\n%s", out)
		}
		if strings.Contains(out, "*   SANs:") {
			t.Errorf("expected SANs line to align with Server chain line, got:\n%s", out)
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

func generateTestCACert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return cert, key
}

func generateTestCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, name string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return cert, key
}

func TestRenderConnectionMetadata(t *testing.T) {
	fixedNow := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	origNow := tlsInspectNow
	tlsInspectNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { tlsInspectNow = origNow })

	state := &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        0,
		CurveID:            tls.X25519MLKEM768,
		NegotiatedProtocol: http3.NextProtoH3,
		PeerCertificates: []*x509.Certificate{{
			Subject:  pkix.Name{CommonName: "quic.example"},
			NotAfter: fixedNow.Add(30 * 24 * time.Hour),
		}},
	}
	p := newTestPrinter()
	renderConnection(p, state, nil, connectionInfo{
		RemoteIP: net.ParseIP("2001:db8::1"),
		Resolver: "tls://resolver.example:853",
		QUIC:     true,
		Timing: client.DialTiming{
			DNSDuration:     2 * time.Millisecond,
			ConnectDuration: 3 * time.Millisecond,
		},
	})
	out := string(p.Bytes())
	for _, want := range []string{
		"TLS 1.3: cipher suite unavailable",
		"Key exchange: X25519MLKEM768",
		"ALPN: h3",
		"Remote IP: 2001:db8::1",
		"Resolver: tls://resolver.example:853",
		"Timing: DNS 2.0ms, QUIC 3.0ms",
		"Verification: not verified",
		"Trust anchor: not available",
		"Server chain",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func TestOCSPStapleRequiresMatchingCertificate(t *testing.T) {
	caCert, caKey := generateTestCACert(t)
	leaf, _ := generateTestCert(t, caCert, caKey, "ocsp.example")
	other, _ := generateTestCert(t, caCert, caKey, "other.example")
	staple, err := ocsp.CreateResponse(caCert, caCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}, caKey)
	if err != nil {
		t.Fatalf("ocsp.CreateResponse() error = %v", err)
	}

	status, _ := inspectOCSPStaple(staple, []*x509.Certificate{leaf, caCert})
	if !strings.Contains(status, "good") || !strings.Contains(status, "unverified") {
		t.Fatalf("matching staple status = %q", status)
	}
	status, _ = inspectOCSPStaple(staple, []*x509.Certificate{other, caCert})
	if status != "staple present, unverified" {
		t.Fatalf("mismatched staple status = %q", status)
	}
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
			CurveID:            tls.X25519MLKEM768,
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
		if !strings.Contains(out, "* Key exchange: X25519MLKEM768") {
			t.Errorf("expected negotiated key exchange in output, got:\n%s", out)
		}
		if !strings.Contains(out, "* ALPN: h2") {
			t.Errorf("expected '* ALPN: h2' in output, got:\n%s", out)
		}
		if strings.Contains(out, "*   ALPN: h2") {
			t.Errorf("expected ALPN line to align with TLS line, got:\n%s", out)
		}
		if !strings.Contains(out, "Server chain") {
			t.Errorf("expected 'Server chain' in output, got:\n%s", out)
		}
		if !strings.Contains(out, "example.com") {
			t.Errorf("expected 'example.com' in output, got:\n%s", out)
		}
		if !strings.Contains(out, "SANs:") {
			t.Errorf("expected 'SANs:' in output, got:\n%s", out)
		}
	})

	t.Run("verified ConnectionState", func(t *testing.T) {
		cs := &tls.ConnectionState{
			ServerName: "example.com",
			VerifiedChains: [][]*x509.Certificate{{
				{Subject: pkix.Name{CommonName: "example.com"}},
				{Subject: pkix.Name{CommonName: "Test Root"}},
			}},
		}

		p := newTestPrinter()
		render(p, cs)
		out := string(p.Bytes())

		if !strings.Contains(out, "Verification: verified for example.com") {
			t.Errorf("expected successful verification status with hostname, got:\n%s", out)
		}
		if !strings.Contains(out, "Trust anchor: Test Root") {
			t.Errorf("expected selected trust-anchor name, got:\n%s", out)
		}
		if !strings.Contains(out, "Verified path") {
			t.Errorf("expected verified path in output, got:\n%s", out)
		}
		if strings.Contains(out, "not reported by verifier") {
			t.Errorf("unexpected unavailable trust-anchor status in output:\n%s", out)
		}
	})

	t.Run("verified path is separate from server chain", func(t *testing.T) {
		caCert, caKey := generateTestCACert(t)
		leaf, _ := generateTestCert(t, caCert, caKey, "example.com")
		state := &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf},
		}
		roots := x509.NewCertPool()
		roots.AddCert(caCert)
		verification := verifyConnection(state, &tls.Config{RootCAs: roots}, "example.com")

		p := newTestPrinter()
		renderConnection(p, state, nil, connectionInfo{
			ServerName:   "example.com",
			Verification: verification,
		})
		out := string(p.Bytes())

		if !strings.Contains(out, "Verification: verified for example.com") {
			t.Errorf("expected successful verification status with hostname, got:\n%s", out)
		}
		if !strings.Contains(out, "Trust anchor: Test CA") {
			t.Errorf("expected selected trust-anchor name, got:\n%s", out)
		}
		if !strings.Contains(out, "Server chain") || !strings.Contains(out, "Verified path") {
			t.Errorf("expected separate chain labels, got:\n%s", out)
		}
		if strings.Index(out, "Server chain") > strings.Index(out, "Verified path") {
			t.Errorf("expected server chain before verified path, got:\n%s", out)
		}
		if strings.Count(out, "example.com") < 3 {
			t.Errorf("expected leaf in certificate details and both paths, got:\n%s", out)
		}
	})
}
