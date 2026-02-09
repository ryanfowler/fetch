package tlsinspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"

	"golang.org/x/crypto/ocsp"
)

// tlsInspectNow is overridden in tests to control time-based output.
var tlsInspectNow = time.Now

// Config holds the parameters needed to perform a TLS inspection.
type Config struct {
	CACerts    []*x509.Certificate
	ClientCert *tls.Certificate
	DNSServer  *url.URL
	Insecure   bool
	TLS        uint16
	Timeout    time.Duration
	URL        *url.URL
}

// Inspect performs a TLS handshake and renders the certificate chain to the
// printer. It returns a non-zero exit code on failure.
func Inspect(ctx context.Context, p *core.Printer, cfg *Config) int {
	tlsDialCfg := &client.TLSDialConfig{
		CACerts:    cfg.CACerts,
		ClientCert: cfg.ClientCert,
		DNSServer:  cfg.DNSServer,
		Insecure:   cfg.Insecure,
		TLS:        cfg.TLS,
	}
	tlsConfig := tlsDialCfg.BuildTLSConfig()

	// Resolve host:port.
	host := cfg.URL.Hostname()
	port := cfg.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)
	tlsConfig.ServerName = host

	// Apply timeout to context so it covers both code paths uniformly.
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	// Dial and handshake using context for cancellation support.
	dialCtx := tlsDialCfg.BuildDialContext()
	if dialCtx != nil {
		// Use custom dial context (e.g. DoH) to establish the TCP connection,
		// then perform the TLS handshake manually.
		rawConn, dialErr := dialCtx(ctx, "tcp", addr)
		if dialErr != nil {
			writeTLSError(p, dialErr)
			return 1
		}
		tlsConn := tls.Client(rawConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			writeTLSError(p, err)
			return 1
		}
		cs := tlsConn.ConnectionState()
		render(p, &cs)
		p.Flush()
		tlsConn.Close()
		return 0
	}

	dialer := &tls.Dialer{
		NetDialer: tlsDialCfg.BuildDialer(),
		Config:    tlsConfig,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		writeTLSError(p, err)
		return 1
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	cs := tlsConn.ConnectionState()
	render(p, &cs)
	p.Flush()
	return 0
}

// writeTLSError writes a TLS connection error, suggesting --insecure for cert errors.
func writeTLSError(p *core.Printer, err error) {
	core.WriteErrorMsgNoFlush(p, err)

	var certInvalidErr x509.CertificateInvalidError
	var hostErr x509.HostnameError
	var unknownErr x509.UnknownAuthorityError
	if errors.As(err, &certInvalidErr) || errors.As(err, &hostErr) || errors.As(err, &unknownErr) {
		p.WriteString("\n")
		p.WriteString("If you absolutely trust the server, try '")
		p.Set(core.Bold)
		p.WriteString("--insecure")
		p.Reset()
		p.WriteString("'.\n")
	}

	p.Flush()
}

// render displays TLS certificate chain inspection output to the printer.
func render(p *core.Printer, cs *tls.ConnectionState) {
	if cs == nil {
		p.WriteInfoPrefix()
		p.Set(core.Yellow)
		p.Set(core.Bold)
		p.WriteString("warning")
		p.Reset()
		p.WriteString(": no TLS connection state available\n")
		return
	}

	// TLS version and cipher suite.
	p.WriteInfoPrefix()
	p.Set(core.Bold)
	p.Set(core.Yellow)
	p.WriteString(tls.VersionName(cs.Version))
	p.Reset()
	p.WriteString(": ")
	p.WriteString(tls.CipherSuiteName(cs.CipherSuite))
	p.WriteString("\n")

	// ALPN negotiated protocol.
	if cs.NegotiatedProtocol != "" {
		p.WriteInfoPrefix()
		p.WriteString("  ALPN: ")
		p.Set(core.Italic)
		p.WriteString(cs.NegotiatedProtocol)
		p.Reset()
		p.WriteString("\n")
	}

	// Certificate chain.
	chain := getChain(cs)
	if len(chain) > 0 {
		p.WriteInfoPrefix()
		p.WriteString("\n")
		renderCertChain(p, chain)
	}

	// SANs from leaf certificate.
	if len(chain) > 0 {
		renderSANs(p, chain[0])
	}

	// OCSP stapled response.
	renderOCSPStatus(p, cs.OCSPResponse)
}

func getChain(cs *tls.ConnectionState) []*x509.Certificate {
	if len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0 {
		return cs.VerifiedChains[0]
	}
	return cs.PeerCertificates
}

func renderCertChain(p *core.Printer, chain []*x509.Certificate) {
	p.WriteInfoPrefix()
	p.Set(core.Bold)
	p.WriteString("Certificate chain")
	p.Reset()
	p.WriteString(":\n")

	for i, cert := range chain {
		p.WriteInfoPrefix()
		indent := strings.Repeat("   ", i)
		p.WriteString(indent)
		p.Set(core.Dim)
		p.WriteString("\u2514\u2500 ")
		p.Reset()

		name := certDisplayName(cert)
		p.Set(core.Bold)
		p.WriteString(name)
		p.Reset()

		expiryText, expiryColor := certExpiryInfo(cert)
		p.WriteString(" (")
		p.Set(expiryColor)
		p.WriteString(expiryText)
		p.Reset()
		p.WriteString(")")
		p.WriteString("\n")
	}
}

func certDisplayName(cert *x509.Certificate) string {
	cn := cert.Subject.CommonName
	org := ""
	if len(cert.Subject.Organization) > 0 {
		org = cert.Subject.Organization[0]
	}

	switch {
	case cn != "" && org != "" && cn != org:
		return cn + ", " + org
	case cn != "":
		return cn
	case len(cert.DNSNames) > 0:
		return cert.DNSNames[0]
	case org != "":
		return org
	default:
		return cert.Subject.String()
	}
}

func certExpiryInfo(cert *x509.Certificate) (string, core.Sequence) {
	now := tlsInspectNow()
	if now.After(cert.NotAfter) {
		return "expired", core.Red
	}

	remaining := cert.NotAfter.Sub(now)
	days := int(remaining.Hours() / 24)

	var text string
	switch {
	case days == 0:
		text = "expires in <1 day"
	case days == 1:
		text = "expires in 1 day"
	default:
		text = fmt.Sprintf("expires in %d days", days)
	}
	switch {
	case days < 7:
		return text, core.Red
	case days < 30:
		return text, core.Yellow
	default:
		return text, core.Green
	}
}

func renderSANs(p *core.Printer, leaf *x509.Certificate) {
	var sans []string
	sans = append(sans, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}

	if len(sans) == 0 {
		return
	}

	p.WriteInfoPrefix()
	p.WriteString("\n")
	p.WriteInfoPrefix()
	p.WriteString("  SANs: ")
	p.Set(core.Italic)
	p.WriteString(strings.Join(sans, ", "))
	p.Reset()
	p.WriteString("\n")
}

func renderOCSPStatus(p *core.Printer, rawOCSP []byte) {
	if len(rawOCSP) == 0 {
		return
	}

	resp, err := ocsp.ParseResponse(rawOCSP, nil)
	if err != nil {
		return
	}

	p.WriteInfoPrefix()
	p.WriteString("  OCSP: ")

	var status string
	var color core.Sequence
	switch resp.Status {
	case ocsp.Good:
		status = "good"
		color = core.Green
	case ocsp.Revoked:
		status = "revoked"
		color = core.Red
	default:
		status = "unknown"
		color = core.Yellow
	}

	p.Set(color)
	p.WriteString(status)
	p.Reset()
	p.WriteString(" (stapled)\n")
}
