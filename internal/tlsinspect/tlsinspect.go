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
	"github.com/ryanfowler/fetch/internal/resolver"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/ocsp"
)

// tlsInspectNow is overridden in tests to control time-based output.
var tlsInspectNow = time.Now

// Config holds the parameters needed to perform a TLS inspection.
type Config struct {
	CACerts          []*x509.Certificate
	ClientCert       *tls.Certificate
	ResolverEndpoint *resolver.Endpoint
	DNSServer        *url.URL
	HTTP             core.HTTPVersion
	ECH              core.ECHMode
	Insecure         bool
	TLSMax           uint16
	TLSMin           uint16
	Timeout          time.Duration
	URL              *url.URL
}

// Inspect performs a TLS handshake and renders the certificate chain to the
// printer. It returns a non-zero exit code on failure.
func Inspect(ctx context.Context, p *core.Printer, cfg *Config) int {
	if err := core.ValidateTLSVersions(cfg.TLSMin, cfg.TLSMax); err != nil {
		writeTLSError(p, err)
		return 1
	}
	if cfg.HTTP == core.HTTP3 && cfg.TLSMax != 0 && cfg.TLSMax < tls.VersionTLS13 {
		writeTLSError(p, errors.New("HTTP/3 requires max-tls 1.3 or higher"))
		return 1
	}
	if err := core.ValidateECHPolicy(cfg.ECH, cfg.HTTP, cfg.TLSMin, cfg.TLSMax); err != nil {
		writeTLSError(p, err)
		return 1
	}
	tlsDialCfg := &client.TLSDialConfig{
		CACerts:    cfg.CACerts,
		ClientCert: cfg.ClientCert,
		Insecure:   cfg.Insecure,
		TLSMax:     cfg.TLSMax,
		TLSMin:     cfg.TLSMin,
	}
	tlsConfig := tlsDialCfg.BuildTLSConfig()
	tlsConfig.NextProtos = alpnProtocols(cfg.HTTP)
	res := resolver.New(resolver.Config{
		Endpoint:   cfg.ResolverEndpoint,
		Server:     cfg.DNSServer,
		CACerts:    cfg.CACerts,
		ClientCert: cfg.ClientCert,
		Insecure:   cfg.Insecure,
		TLSMin:     cfg.TLSMin,
		TLSMax:     cfg.TLSMax,
	})

	// Resolve host:port.
	host := cfg.URL.Hostname()
	port := cfg.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)
	tlsConfig.ServerName = core.TLSVerificationName(host)

	// Apply timeout before discovery so DNS, ECH setup, and the eventual
	// handshake consume one inspection deadline.
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	// ECH discovery is host-scoped and shares the inspection deadline with
	// address resolution and the TLS handshake. The returned target may differ
	// from the origin for an HTTPS/SVCB ServiceMode record.
	var echConfig *client.ECHConnectionConfig
	var err error
	if cfg.ECH == core.ECHAuto || cfg.ECH == core.ECHOn {
		echConfig, err = client.DiscoverECHForConnection(ctx, res, host, port, tlsConfig, cfg.ECH, cfg.HTTP)
		if err != nil {
			writeTLSError(p, err)
			return 1
		}
		tlsConfig = echConfig.TLSConfig()
	}

	if cfg.HTTP == core.HTTP3 {
		quicAddr := addr
		var quicCandidates []net.IPAddr
		if echConfig != nil {
			targetHost, targetPort := echConfig.Target()
			quicAddr = net.JoinHostPort(targetHost, targetPort)
			quicCandidates = echConfig.Addresses()
		}
		var fallbackTLS *tls.Config
		if cfg.ECH == core.ECHAuto && echConfig != nil && echConfig.Offered() {
			fallbackTLS = tlsConfig.Clone()
			fallbackTLS.EncryptedClientHelloConfigList = nil
		}
		cs, err := inspectQUICWithECHFallback(ctx, res, quicAddr, quicCandidates, tlsConfig, fallbackTLS)
		if err != nil {
			writeTLSError(p, err)
			return 1
		}
		var info *client.ECHHandshakeInfo
		if echConfig != nil {
			state := cs != nil && cs.ECHAccepted
			info = &client.ECHHandshakeInfo{Offered: echConfig.Offered(), Real: echConfig.Real(), Accepted: state, Rejected: echConfig.Offered() && !state, Fallback: echConfig.Offered() && !state, OuterServerName: echConfig.OuterServerName()}
		}
		renderWithECH(p, cs, info)
		p.Flush()
		return 0
	}

	// Use the same resolver-aware dialer as HTTP, WebSocket, and gRPC. TLS
	// belongs to the connection setup budget so DNS, TCP, and the handshake
	// cannot each consume the full timeout.
	dialer := client.NewResolverDialer(res, cfg.Timeout)
	dialRequest := client.DialRequest{
		Network:    "tcp",
		Address:    addr,
		OriginHost: host,
		Resolver:   res,
		TLSConfig:  tlsConfig,
		ALPN:       tlsConfig.NextProtos,
	}
	if echConfig != nil {
		targetHost, targetPort := echConfig.Target()
		dialRequest.Address = ""
		dialRequest.Host = targetHost
		dialRequest.Port = targetPort
		dialRequest.Candidates = echConfig.Addresses()
	}
	var result client.DialResult
	if echConfig != nil {
		result, err = client.DialResolverWithECH(ctx, dialer, dialRequest, tlsConfig, cfg.ECH, echConfig.Real())
	} else {
		result, err = dialer.Dial(ctx, dialRequest)
	}
	if err != nil {
		writeTLSError(p, err)
		return 1
	}
	defer result.Conn.Close()
	if result.TLSState == nil {
		writeTLSError(p, errors.New("TLS dial completed without connection state"))
		return 1
	}
	var echInfo *client.ECHHandshakeInfo
	if value, ok := result.ECHInfo.(client.ECHHandshakeInfo); ok {
		echInfo = &value
		if echConfig != nil {
			echInfo.OuterServerName = echConfig.OuterServerName()
		}
	}
	renderWithECH(p, result.TLSState, echInfo)
	p.Flush()
	return 0
}

func inspectQUICWithECHFallback(ctx context.Context, res *resolver.Resolver, addr string, candidates []net.IPAddr, tlsConfig, fallbackTLS *tls.Config) (*tls.ConnectionState, error) {
	state, err := inspectQUICAttempt(ctx, res, addr, candidates, tlsConfig)
	if fallbackTLS == nil {
		return state, err
	}
	if err == nil && state != nil && state.ECHAccepted {
		return state, nil
	}
	if err != nil {
		var rejection *tls.ECHRejectionError
		if !errors.As(err, &rejection) && !looksLikeECHRejection(err) {
			return nil, err
		}
	}
	// A server may reject ECH with an explicit TLS error, or complete the
	// outer handshake without accepting a GREASE offer. Auto mode retries the
	// same inspection target without ECH, while preserving the shared context.
	return inspectQUICAttempt(ctx, res, addr, candidates, fallbackTLS)
}

func looksLikeECHRejection(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "ech") && (strings.Contains(text, "reject") || strings.Contains(text, "retry"))
}

func inspectQUICAttempt(ctx context.Context, res *resolver.Resolver, addr string, candidates []net.IPAddr, tlsConfig *tls.Config) (*tls.ConnectionState, error) {
	var endpoint resolver.ResolvedEndpoint
	var err error
	if len(candidates) > 0 {
		host, port, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			return nil, splitErr
		}
		endpoint = resolver.ResolvedEndpoint{Host: host, Port: port, Addrs: candidates}
	} else {
		endpoint, err = res.ResolveAddress(ctx, "udp", addr)
		if err != nil {
			return nil, err
		}
	}

	port, err := net.LookupPort("udp", endpoint.Port)
	if err != nil {
		return nil, err
	}
	type quicResult struct {
		conn       *quic.Conn
		packetConn net.PacketConn
	}
	result, err := resolver.RaceCandidates(ctx, endpoint.Addrs, func(attemptCtx context.Context, ip net.IPAddr) (quicResult, error) {
		var lc net.ListenConfig
		packetConn, listenErr := lc.ListenPacket(attemptCtx, "udp", ":0")
		if listenErr != nil {
			return quicResult{}, listenErr
		}
		conn, dialErr := quic.Dial(attemptCtx, packetConn, &net.UDPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}, tlsConfig.Clone(), nil)
		if dialErr != nil {
			_ = packetConn.Close()
			return quicResult{}, dialErr
		}
		return quicResult{conn: conn, packetConn: packetConn}, nil
	}, func(result quicResult) {
		if result.conn != nil {
			_ = result.conn.CloseWithError(0, "QUIC address race lost")
		}
		if result.packetConn != nil {
			_ = result.packetConn.Close()
		}
	})
	if err != nil {
		return nil, err
	}
	state := result.conn.ConnectionState().TLS
	_ = result.conn.CloseWithError(0, "")
	_ = result.packetConn.Close()
	return &state, nil
}

func alpnProtocols(httpVersion core.HTTPVersion) []string {
	switch httpVersion {
	case core.HTTP1:
		return []string{"http/1.1"}
	case core.HTTP3:
		return []string{http3.NextProtoH3}
	default:
		return []string{"h2", "http/1.1"}
	}
}

// writeTLSError writes a TLS connection error, suggesting --insecure for cert errors.
func writeTLSError(p *core.Printer, err error) {
	core.WriteErrorMsgNoFlush(p, err)

	_, certInvalid := errors.AsType[x509.CertificateInvalidError](err)
	_, hostErr := errors.AsType[x509.HostnameError](err)
	_, unknownErr := errors.AsType[x509.UnknownAuthorityError](err)
	if certInvalid || hostErr || unknownErr {
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
	renderWithECH(p, cs, nil)
}

func renderWithECH(p *core.Printer, cs *tls.ConnectionState, info *client.ECHHandshakeInfo) {
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
		p.WriteString("ALPN: ")
		p.Set(core.Italic)
		p.WriteString(core.TerminalSafeText(cs.NegotiatedProtocol))
		p.Reset()
		p.WriteString("\n")
	}

	if info != nil && info.Offered {
		p.WriteInfoPrefix()
		p.WriteString("ECH: ")
		switch {
		case info.Accepted && info.Real:
			p.Set(core.Green)
			p.WriteString("accepted (real)")
		case info.Accepted:
			p.Set(core.Yellow)
			p.WriteString("accepted (GREASE)")
		case info.Fallback && info.Real:
			p.Set(core.Yellow)
			p.WriteString("rejected (real/fallback)")
		case info.Fallback:
			p.Set(core.Yellow)
			p.WriteString("rejected (GREASE/fallback)")
		case info.Rejected:
			p.Set(core.Yellow)
			p.WriteString("rejected")
		default:
			p.WriteString("offered")
		}
		p.Reset()
		p.WriteString("\n")
	}
	if info != nil && info.OuterServerName != "" {
		p.WriteInfoPrefix()
		p.WriteString("Outer SNI: ")
		p.WriteString(core.TerminalSafeText(info.OuterServerName))
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
		p.WriteString(core.TerminalSafeText(name))
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
	p.WriteString("SANs: ")
	p.Set(core.Italic)
	p.WriteString(core.TerminalSafeText(strings.Join(sans, ", ")))
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
