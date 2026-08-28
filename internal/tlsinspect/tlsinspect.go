package tlsinspect

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
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
	Resolve          []resolver.ResolveEntry
	HTTP             core.HTTPVersion
	ECH              core.ECHMode
	Insecure         bool
	TLSMax           uint16
	TLSMin           uint16
	Timeout          time.Duration
	ConnectTimeout   time.Duration
	URL              *url.URL
}

type connectionInfo struct {
	RemoteIP     net.IP
	Resolver     string
	Timing       client.DialTiming
	QUIC         bool
	Insecure     bool
	ServerName   string
	Verification *verificationResult
}

type verificationResult struct {
	Err    error
	Chains [][]*x509.Certificate
}

type quicInspectionResult struct {
	State           *tls.ConnectionState
	RemoteIP        net.IP
	Resolver        string
	Timing          client.DialTiming
	OuterServerName string
	Fallback        bool
}

// Inspect performs a TLS handshake and renders the server chain and verified
// path to the printer. It returns a non-zero exit code on failure.
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
	// Certificate verification is deliberately deferred until after the
	// handshake. Inspection must be able to show the peer certificates and
	// the verification failure that caused a normal client to stop.
	tlsConfig.InsecureSkipVerify = true
	// Go verifies the outer certificate before it reports an ECH rejection,
	// even when InsecureSkipVerify is set. Let inspection handle that
	// certificate in verifyConnection, like any other peer certificate.
	tlsConfig.EncryptedClientHelloRejectionVerify = func(tls.ConnectionState) error {
		return nil
	}
	tlsConfig.NextProtos = alpnProtocols(cfg.HTTP)
	res := resolver.New(resolver.Config{
		Endpoint:   cfg.ResolverEndpoint,
		Server:     cfg.DNSServer,
		Resolve:    cfg.Resolve,
		CACerts:    cfg.CACerts,
		ClientCert: cfg.ClientCert,
		Insecure:   cfg.Insecure,
		TLSMin:     cfg.TLSMin,
		TLSMax:     cfg.TLSMax,
	})
	defer res.Close()

	// Resolve host:port.
	host := cfg.URL.Hostname()
	port := cfg.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)
	tlsConfig.ServerName = core.TLSVerificationName(host)

	// Inspection has no response body, so both timeout settings bound the
	// same setup operation. This keeps resolver bootstrap, ECH discovery, and
	// the handshake from each receiving a fresh deadline.
	inspectionTimeout := cfg.Timeout
	if cfg.ConnectTimeout > 0 && (inspectionTimeout == 0 || cfg.ConnectTimeout < inspectionTimeout) {
		inspectionTimeout = cfg.ConnectTimeout
	}
	if inspectionTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, inspectionTimeout)
		defer cancel()
	}

	// ECH discovery is host-scoped and shares the inspection deadline with
	// address resolution and the TLS handshake. The returned target may differ
	// from the origin for an HTTPS/SVCB ServiceMode record.
	var echConfig *client.ECHConnectionConfig
	var echDiscoveryDuration time.Duration
	var err error
	if cfg.ECH == core.ECHAuto || cfg.ECH == core.ECHOn {
		echDiscoveryStart := time.Now()
		echConfig, err = client.DiscoverECHForConnection(ctx, res, host, port, tlsConfig, cfg.ECH, cfg.HTTP)
		echDiscoveryDuration = time.Since(echDiscoveryStart)
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
		if override, ok, err := res.ResolveAddressOverride("udp", host, port); ok {
			if err != nil {
				writeTLSError(p, err)
				return 1
			}
			quicAddr = addr
			quicCandidates = override.Addrs
		}
		var fallbackTLS *tls.Config
		if cfg.ECH == core.ECHAuto && echConfig != nil && echConfig.Offered() {
			fallbackTLS = tlsConfig.Clone()
			fallbackTLS.EncryptedClientHelloConfigList = nil
		}
		quicResult, err := inspectQUICWithECHFallback(ctx, res, quicAddr, quicCandidates, tlsConfig, fallbackTLS, func(state *tls.ConnectionState) bool {
			if cfg.Insecure {
				return true
			}
			return verifyConnection(state, tlsConfig, connectionVerificationName(state, host)).Err == nil
		})
		quicResult.Timing.DNSDuration += echDiscoveryDuration
		if err != nil {
			writeTLSError(p, err)
			return 1
		}
		var info *client.ECHHandshakeInfo
		if echConfig != nil {
			state := quicResult.State != nil && quicResult.State.ECHAccepted
			outerName := echConfig.OuterServerName()
			if quicResult.OuterServerName != "" {
				outerName = quicResult.OuterServerName
			}
			info = &client.ECHHandshakeInfo{Offered: echConfig.Offered(), Real: echConfig.Real(), Accepted: state, Rejected: echConfig.Offered() && !state, Fallback: quicResult.Fallback, OuterServerName: outerName}
		}
		verificationName := connectionVerificationName(quicResult.State, host)
		verification := verifyConnection(quicResult.State, tlsConfig, verificationName)
		renderConnection(p, quicResult.State, info, connectionInfo{
			RemoteIP:     quicResult.RemoteIP,
			Resolver:     quicResult.Resolver,
			Timing:       quicResult.Timing,
			QUIC:         true,
			Insecure:     cfg.Insecure,
			ServerName:   verificationName,
			Verification: verification,
		})
		p.Flush()
		if verification.Err != nil && !cfg.Insecure {
			return 1
		}
		return 0
	}

	// Use the same resolver-aware dialer as HTTP, WebSocket, and gRPC. TLS
	// belongs to the connection setup budget so DNS, TCP, and the handshake
	// cannot each consume the full timeout.
	dialer := client.NewResolverDialer(res, cfg.ConnectTimeout)
	dialRequest := client.DialRequest{
		Network:    "tcp",
		Address:    addr,
		OriginHost: host,
		Resolver:   res,
		TLSConfig:  tlsConfig,
		ALPN:       tlsConfig.NextProtos,
		ECHRejectionAllowsFallback: func(state tls.ConnectionState) bool {
			if cfg.Insecure {
				return true
			}
			return verifyConnection(&state, tlsConfig, connectionVerificationName(&state, host)).Err == nil
		},
	}
	if echConfig != nil {
		targetHost, targetPort := echConfig.Target()
		dialRequest.Address = ""
		dialRequest.Host = targetHost
		dialRequest.Port = targetPort
		dialRequest.OriginPort = port
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
		if echConfig != nil && (echInfo.OuterServerName == "" || echInfo.OuterServerName == host) {
			echInfo.OuterServerName = echConfig.OuterServerName()
		}
		result.Timing.DNSDuration += echDiscoveryDuration
		result.Timing.ConnectDuration = value.TCPDuration
		result.Timing.TLSDuration = value.TLSDuration
	}
	verificationName := connectionVerificationName(result.TLSState, host)
	verification := verifyConnection(result.TLSState, tlsConfig, verificationName)
	renderConnection(p, result.TLSState, echInfo, connectionInfo{
		RemoteIP:     result.RemoteIP,
		Resolver:     result.Resolver,
		Timing:       result.Timing,
		Insecure:     cfg.Insecure,
		ServerName:   verificationName,
		Verification: verification,
	})
	p.Flush()
	if verification.Err != nil && !cfg.Insecure {
		return 1
	}
	return 0
}

func inspectQUICWithECHFallback(ctx context.Context, res *resolver.Resolver, addr string, candidates []net.IPAddr, tlsConfig, fallbackTLS *tls.Config, allowsFallback func(*tls.ConnectionState) bool) (quicInspectionResult, error) {
	result, err := inspectQUICAttempt(ctx, res, addr, candidates, tlsConfig)
	if err == nil && result.State != nil && result.State.ECHAccepted {
		return result, nil
	}
	if err == nil && fallbackTLS == nil && len(tlsConfig.EncryptedClientHelloConfigList) > 0 {
		return result, errors.New("ECH handshake completed without ECH acceptance")
	}
	if err != nil {
		var rejection *tls.ECHRejectionError
		if errors.As(err, &rejection) && len(rejection.RetryConfigList) > 0 {
			retryList, validateErr := resolver.SupportedECHConfigList(rejection.RetryConfigList)
			if validateErr != nil {
				return quicInspectionResult{}, validateErr
			}
			retryTLS := tlsConfig.Clone()
			retryTLS.MinVersion = tls.VersionTLS13
			retryTLS.EncryptedClientHelloConfigList = retryList
			retryOuterName, outerErr := resolver.ECHPublicName(retryList)
			if outerErr != nil {
				return quicInspectionResult{}, outerErr
			}
			result, err = inspectQUICAttempt(ctx, res, addr, candidates, retryTLS)
			result.OuterServerName = retryOuterName
			if err == nil && result.State != nil && result.State.ECHAccepted {
				return result, nil
			}
			if err == nil {
				err = errors.New("ECH handshake completed without ECH acceptance")
			}
		}
		if !errors.As(err, &rejection) && !looksLikeECHRejection(err) {
			return quicInspectionResult{}, err
		}
	}
	if fallbackTLS == nil {
		return result, err
	}
	if err != nil && allowsFallback != nil && !allowsFallback(nil) {
		// QUIC does not expose a ConnectionState when its TLS handshake
		// fails. Do not turn an uninspectable ECH rejection into a downgrade.
		return result, err
	}
	if err == nil && result.State != nil && allowsFallback != nil && !allowsFallback(result.State) {
		return result, nil
	}
	// A server may reject ECH with an explicit TLS error, or complete the
	// outer handshake without accepting a GREASE offer. Auto mode retries the
	// same inspection target without ECH, while preserving the shared context.
	fallbackResult, fallbackErr := inspectQUICAttempt(ctx, res, addr, candidates, fallbackTLS)
	fallbackResult.Fallback = true
	return fallbackResult, fallbackErr
}

func looksLikeECHRejection(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "ech") && (strings.Contains(text, "reject") || strings.Contains(text, "retry"))
}

func inspectQUICAttempt(ctx context.Context, res *resolver.Resolver, addr string, candidates []net.IPAddr, tlsConfig *tls.Config) (quicInspectionResult, error) {
	var endpoint resolver.ResolvedEndpoint
	var err error
	var timing client.DialTiming
	resolutionStart := time.Now()
	if len(candidates) > 0 {
		host, port, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			return quicInspectionResult{}, splitErr
		}
		endpoint = resolver.ResolvedEndpoint{Host: host, Port: port, Addrs: candidates}
	} else {
		endpoint, err = res.ResolveAddress(ctx, "udp", addr)
		if err != nil {
			return quicInspectionResult{}, err
		}
	}
	resolutionDone := time.Now()
	timing.ResolutionStart = resolutionStart
	timing.ResolutionDone = resolutionDone
	timing.DNSDuration = resolutionDone.Sub(resolutionStart)

	port, err := net.LookupPort("udp", endpoint.Port)
	if err != nil {
		return quicInspectionResult{}, err
	}
	timing.ConnectStart = time.Now()
	type quicResult struct {
		conn       *quic.Conn
		packetConn net.PacketConn
		ip         net.IPAddr
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
		return quicResult{conn: conn, packetConn: packetConn, ip: ip}, nil
	}, func(result quicResult) {
		if result.conn != nil {
			_ = result.conn.CloseWithError(0, "QUIC address race lost")
		}
		if result.packetConn != nil {
			_ = result.packetConn.Close()
		}
	})
	if err != nil {
		return quicInspectionResult{}, err
	}
	state := result.conn.ConnectionState().TLS
	_ = result.conn.CloseWithError(0, "")
	_ = result.packetConn.Close()
	connectDone := time.Now()
	timing.ConnectDone = connectDone
	timing.ConnectDuration = connectDone.Sub(timing.ConnectStart)
	return quicInspectionResult{
		State:    &state,
		RemoteIP: append(net.IP(nil), result.ip.IP...),
		Resolver: res.Provenance(),
		Timing:   timing,
	}, nil
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

// writeTLSError writes a TLS setup error. Certificate verification failures
// are rendered by the inspection result, so this path is reserved for errors
// that prevented a handshake or a valid inspection configuration.
func writeTLSError(p *core.Printer, err error) {
	core.WriteErrorMsgNoFlush(p, err)
	p.Flush()
}

// render displays TLS certificate inspection output to the printer.
func render(p *core.Printer, cs *tls.ConnectionState) {
	renderConnection(p, cs, nil, connectionInfo{})
}

func renderConnection(p *core.Printer, cs *tls.ConnectionState, info *client.ECHHandshakeInfo, meta connectionInfo) {
	if cs == nil {
		p.WriteInfoPrefix()
		p.Set(core.Yellow)
		p.Set(core.Bold)
		p.WriteString("warning")
		p.Reset()
		p.WriteString(": no TLS connection state available\n")
		return
	}

	// TLS version and cipher suite. quic-go exposes the negotiated TLS state
	// through ConnectionState().TLS. If a transport does not provide a suite,
	// leave the result explicitly unavailable rather than guessing.
	p.WriteInfoPrefix()
	p.Set(core.Bold)
	p.Set(core.Yellow)
	p.WriteString(tls.VersionName(cs.Version))
	p.Reset()
	p.WriteString(": ")
	if cs.CipherSuite != 0 {
		p.WriteString(tls.CipherSuiteName(cs.CipherSuite))
	} else {
		p.WriteString("cipher suite unavailable")
	}
	p.WriteString("\n")

	// ALPN negotiated protocol. An empty value is still a useful inspection
	// result and must not be confused with omitted output.
	p.WriteInfoPrefix()
	p.WriteString("ALPN: ")
	if cs.NegotiatedProtocol == "" {
		p.WriteString("not negotiated")
	} else {
		p.Set(core.Italic)
		p.WriteString(core.TerminalSafeText(cs.NegotiatedProtocol))
		p.Reset()
	}
	p.WriteString("\n")

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

	renderConnectionDetails(p, meta)
	verification := meta.Verification
	if verification == nil {
		verification = &verificationResult{Chains: cs.VerifiedChains}
	}
	renderVerification(p, cs, meta.Insecure, verification, meta.ServerName)

	serverChain := getServerChain(cs)
	if len(serverChain) > 0 {
		renderCertificateDetails(p, serverChain[0], meta.ServerName)
	}

	// The server chain contains only certificates supplied by the peer. The
	// verified path is rendered separately because it can include locally
	// trusted certificates that the server did not send.
	if len(serverChain) > 0 {
		p.WriteInfoPrefix()
		p.WriteString("\n")
		renderCertificateChain(p, "Server chain", serverChain)
	}
	if verifiedPath := getVerifiedPath(verification); len(verifiedPath) > 0 {
		p.WriteInfoPrefix()
		p.WriteString("\n")
		renderCertificateChain(p, "Verified path", verifiedPath)
	}

	// SANs and OCSP belong to the leaf and issuer actually supplied by the
	// peer. A locally completed chain is not a valid OCSP issuer substitute.
	if len(serverChain) > 0 {
		renderSANs(p, serverChain[0])
	}

	// OCSP stapled response.
	renderOCSPStatus(p, cs.OCSPResponse, serverChain)
}

func renderConnectionDetails(p *core.Printer, meta connectionInfo) {
	if meta.RemoteIP != nil {
		p.WriteInfoPrefix()
		p.WriteString("Remote IP: ")
		p.WriteString(core.TerminalSafeText(meta.RemoteIP.String()))
		p.WriteString("\n")
	}
	if meta.Resolver != "" {
		p.WriteInfoPrefix()
		p.WriteString("Resolver: ")
		p.WriteString(core.TerminalSafeText(meta.Resolver))
		p.WriteString("\n")
	}

	parts := make([]string, 0, 3)
	if meta.Timing.DNSDuration > 0 {
		parts = append(parts, "DNS "+formatDuration(meta.Timing.DNSDuration))
	}
	if meta.Timing.ConnectDuration > 0 {
		label := "TCP"
		if meta.QUIC {
			label = "QUIC"
		}
		parts = append(parts, label+" "+formatDuration(meta.Timing.ConnectDuration))
	}
	if meta.Timing.TLSDuration > 0 {
		parts = append(parts, "TLS "+formatDuration(meta.Timing.TLSDuration))
	}
	if len(parts) > 0 {
		p.WriteInfoPrefix()
		p.WriteString("Timing: ")
		p.WriteString(strings.Join(parts, ", "))
		p.WriteString("\n")
	}
}

func formatDuration(value time.Duration) string {
	return fmt.Sprintf("%.1fms", float64(value)/float64(time.Millisecond))
}

func renderVerification(p *core.Printer, cs *tls.ConnectionState, insecure bool, result *verificationResult, serverNames ...string) {
	// Keep the state-only behavior for callers that render a synthetic
	// ConnectionState in tests. Live inspections always provide a result from
	// the explicit verifier below.
	if result == nil {
		result = &verificationResult{Chains: cs.VerifiedChains}
	}

	serverName := firstString(serverNames)
	if serverName == "" && cs != nil {
		serverName = cs.ServerName
	}

	p.WriteInfoPrefix()
	p.WriteString("Verification: ")
	switch {
	case result.Err != nil && insecure:
		p.Set(core.Yellow)
		p.WriteString("FAILED (ignored by --insecure)")
	case result.Err != nil:
		p.Set(core.Red)
		p.WriteString("FAILED")
	case len(result.Chains) > 0:
		p.Set(core.Green)
		p.WriteString("verified")
		if serverName != "" {
			p.WriteString(" for ")
			p.WriteString(core.TerminalSafeText(serverName))
		}
	default:
		p.Set(core.Yellow)
		p.WriteString("not verified")
	}
	p.Reset()
	p.WriteString("\n")

	if result.Err != nil {
		p.WriteInfoPrefix()
		p.WriteString("Verification error: ")
		p.WriteString(core.TerminalSafeText(result.Err.Error()))
		p.WriteString("\n")
	}

	p.WriteInfoPrefix()
	p.WriteString("Trust anchor: ")
	if anchor := verifiedTrustAnchor(result); anchor != nil {
		p.WriteString(core.TerminalSafeText(certDisplayName(anchor)))
	} else {
		p.WriteString("not available")
	}
	p.WriteString("\n")
}

func connectionVerificationName(state *tls.ConnectionState, origin string) string {
	// A rejected ECH handshake presents the outer provider certificate. Go
	// records that certificate's SNI in ConnectionState.ServerName; use it for
	// the rejection decision and report the origin name for accepted ECH.
	if state != nil && !state.ECHAccepted && state.ServerName != "" {
		return state.ServerName
	}
	return origin
}

// verifyConnection repeats the checks that crypto/tls normally performs. The
// handshake itself runs with InsecureSkipVerify so that invalid peer data is
// still available for inspection.
func verifyConnection(cs *tls.ConnectionState, tlsConfig *tls.Config, serverName string) *verificationResult {
	result := &verificationResult{}
	if cs == nil || len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0] == nil {
		result.Err = errors.New("server did not present a certificate")
		return result
	}

	leaf := cs.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range cs.PeerCertificates[1:] {
		if cert != nil {
			intermediates.AddCert(cert)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         tlsConfig.RootCAs,
		Intermediates: intermediates,
		DNSName:       core.TLSVerificationName(serverName),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   tlsInspectNow(),
	}
	result.Chains, result.Err = leaf.Verify(opts)
	return result
}

func renderCertificateDetails(p *core.Printer, cert *x509.Certificate, serverName string) {
	p.WriteInfoPrefix()
	p.WriteString("Certificate: ")
	p.Set(core.Bold)
	p.WriteString(core.TerminalSafeText(certDisplayName(cert)))
	p.Reset()
	p.WriteString("\n")

	p.WriteInfoPrefix()
	p.WriteString("Issuer: ")
	p.WriteString(core.TerminalSafeText(certDisplayName(&x509.Certificate{Subject: cert.Issuer})))
	p.WriteString("\n")

	p.WriteInfoPrefix()
	p.WriteString("Valid: ")
	p.WriteString(cert.NotBefore.Format(time.RFC3339))
	p.WriteString(" → ")
	p.WriteString(cert.NotAfter.Format(time.RFC3339))
	p.WriteString("\n")

	fingerprint := sha256.Sum256(cert.Raw)
	parts := make([]string, len(fingerprint))
	for i, value := range fingerprint {
		parts[i] = fmt.Sprintf("%02x", value)
	}
	p.WriteInfoPrefix()
	p.WriteString("SHA-256: ")
	p.WriteString(strings.Join(parts, ":"))
	p.WriteString("\n")

	if serverName != "" {
		p.WriteInfoPrefix()
		p.WriteString("Hostname: ")
		if cert.VerifyHostname(core.TLSVerificationName(serverName)) == nil {
			p.Set(core.Green)
			p.WriteString("matches")
		} else {
			p.Set(core.Red)
			p.WriteString("does not match")
		}
		p.Reset()
		p.WriteString("\n")
	}
}

func getServerChain(cs *tls.ConnectionState) []*x509.Certificate {
	return cs.PeerCertificates
}

func getVerifiedPath(result *verificationResult) []*x509.Certificate {
	if result == nil || result.Err != nil || len(result.Chains) == 0 {
		return nil
	}
	return result.Chains[0]
}

func verifiedTrustAnchor(result *verificationResult) *x509.Certificate {
	path := getVerifiedPath(result)
	if len(path) == 0 {
		return nil
	}
	return path[len(path)-1]
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func renderCertificateChain(p *core.Printer, label string, chain []*x509.Certificate) {
	p.WriteInfoPrefix()
	p.Set(core.Bold)
	p.WriteString(label)
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

const maxOCSPStapleSize = 1 << 20

func renderOCSPStatus(p *core.Printer, rawOCSP []byte, chain []*x509.Certificate) {
	if len(rawOCSP) == 0 {
		return
	}

	status, color := inspectOCSPStaple(rawOCSP, chain)
	p.WriteInfoPrefix()
	p.WriteString("  OCSP: ")
	p.Set(color)
	p.WriteString(status)
	p.Reset()
	p.WriteString("\n")
}

func inspectOCSPStaple(raw []byte, chain []*x509.Certificate) (string, core.Sequence) {
	const unverified = "stapled, unverified"
	if len(raw) > maxOCSPStapleSize || len(chain) == 0 || chain[0] == nil {
		return "staple present, unverified", core.Default
	}

	leaf := chain[0]
	var issuer *x509.Certificate
	if len(chain) > 1 {
		issuer = chain[1]
	}

	if issuer == nil {
		return "staple present, unverified", core.Default
	}

	// First select the response by the complete CertID. ParseResponseForCert
	// selects by serial number only, so using it before this check could pair
	// the leaf with a different response carrying the same serial. Try the
	// hash algorithms supported by the OCSP package because the response's
	// hash algorithm is not exposed until after parsing it.
	var matched bool
	var status int
	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		requestDER, requestErr := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: hash})
		if requestErr != nil {
			continue
		}
		request, parseErr := ocsp.ParseRequest(requestDER)
		if parseErr != nil || request.SerialNumber == nil {
			continue
		}
		matched, status = ocspCertIDMatches(raw, request)
		if matched {
			break
		}
	}
	if !matched {
		return "staple present, unverified", core.Default
	}

	// Supplying the issuer makes ParseResponseForCert verify the OCSP
	// signature. We still do not claim responder authorization or freshness.
	resp, err := ocsp.ParseResponseForCert(raw, leaf, issuer)
	if err != nil || resp.Status != status {
		return "staple present, unverified", core.Default
	}
	return ocspStatusText(status) + " (" + unverified + ")", core.Default
}

// The OCSP package intentionally does not expose CertID from a response.
// Parse only the bounded response structure needed to compare the complete
// CertID. Signature and responder authorization remain deliberately outside
// this diagnostic's claims.
type ocspResponseEnvelope struct {
	Status   asn1.Enumerated
	Response ocspResponseBytes `asn1:"explicit,tag:0,optional"`
}

type ocspResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspBasicResponse struct {
	TBSResponseData    ocspResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type ocspResponseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []ocspSingleResponse
}

type ocspSingleResponse struct {
	CertID           ocspCertID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          asn1.RawValue    `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type ocspCertID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

func ocspCertIDMatches(raw []byte, expected *ocsp.Request) (bool, int) {
	var envelope ocspResponseEnvelope
	rest, err := asn1.Unmarshal(raw, &envelope)
	if err != nil || len(rest) != 0 || envelope.Status != 0 || len(envelope.Response.Response) == 0 {
		return false, 0
	}
	var basic ocspBasicResponse
	rest, err = asn1.Unmarshal(envelope.Response.Response, &basic)
	if err != nil || len(rest) != 0 || len(basic.TBSResponseData.Responses) == 0 {
		return false, 0
	}
	for _, response := range basic.TBSResponseData.Responses {
		if response.CertID.SerialNumber == nil || expected.SerialNumber == nil || response.CertID.SerialNumber.Cmp(expected.SerialNumber) != 0 {
			continue
		}
		// ParseResponseForCert chooses the first matching serial. Apply the
		// same selection rule before checking the remaining CertID fields.
		if !bytes.Equal(response.CertID.IssuerNameHash, expected.IssuerNameHash) || !bytes.Equal(response.CertID.IssuerKeyHash, expected.IssuerKeyHash) || !response.CertID.HashAlgorithm.Algorithm.Equal(ocspHashAlgorithmOID(expected.HashAlgorithm)) {
			return false, 0
		}
		status := ocsp.Unknown
		if bool(response.Good) {
			status = ocsp.Good
		} else if len(response.Revoked.FullBytes) > 0 {
			status = ocsp.Revoked
		}
		return true, status
	}
	return false, 0
}

func ocspHashAlgorithmOID(hash crypto.Hash) asn1.ObjectIdentifier {
	switch hash {
	case crypto.SHA1:
		return asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	case crypto.SHA256:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	case crypto.SHA384:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	case crypto.SHA512:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	default:
		return nil
	}
}

func ocspStatusText(status int) string {
	switch status {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	default:
		return "unknown"
	}
}
