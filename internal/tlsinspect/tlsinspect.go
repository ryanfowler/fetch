package tlsinspect

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
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
	"strconv"
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
	Verbosity        core.Verbosity
	URL              *url.URL
}

type connectionInfo struct {
	RemoteIP     net.IP
	Resolver     string
	Timing       client.DialTiming
	QUIC         bool
	Insecure     bool
	OriginHost   string
	Port         string
	ServerName   string
	Verbosity    core.Verbosity
	Verification *verificationResult
}

type verificationResult struct {
	Err    error
	Chains [][]*x509.Certificate
}

type quicInspectionResult struct {
	State           *tls.ConnectionState
	RemoteIP        net.IP
	Port            string
	Resolver        string
	Timing          client.DialTiming
	OuterServerName string
	Fallback        bool
}

// Inspect performs a TLS handshake and renders the server chain and verified
// path to the printer. It returns a non-zero exit code on failure.
func Inspect(ctx context.Context, p *core.Printer, cfg *Config) int {
	return InspectWithError(ctx, p, p, cfg)
}

// InspectWithError performs a TLS handshake, writes the inspection result to
// output, and writes setup errors to errorOutput. It returns a non-zero exit
// code on failure. Keeping these streams separate lets callers pipe a
// successful inspection without also receiving diagnostics.
func InspectWithError(ctx context.Context, output, errorOutput *core.Printer, cfg *Config) int {
	if err := core.ValidateTLSVersions(cfg.TLSMin, cfg.TLSMax); err != nil {
		writeTLSError(errorOutput, err)
		return 1
	}
	if cfg.HTTP == core.HTTP3 && cfg.TLSMax != 0 && cfg.TLSMax < tls.VersionTLS13 {
		writeTLSError(errorOutput, errors.New("HTTP/3 requires max-tls 1.3 or higher"))
		return 1
	}
	if err := core.ValidateECHPolicy(cfg.ECH, cfg.HTTP, cfg.TLSMin, cfg.TLSMax); err != nil {
		writeTLSError(errorOutput, err)
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
			writeTLSError(errorOutput, err)
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
				writeTLSError(errorOutput, err)
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
			writeTLSError(errorOutput, err)
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
		renderConnection(output, quicResult.State, info, connectionInfo{
			RemoteIP:     quicResult.RemoteIP,
			Resolver:     quicResult.Resolver,
			Timing:       quicResult.Timing,
			QUIC:         true,
			Insecure:     cfg.Insecure,
			OriginHost:   host,
			Port:         quicResult.Port,
			ServerName:   verificationName,
			Verbosity:    cfg.Verbosity,
			Verification: verification,
		})
		if flushInspectionOutput(output, errorOutput) != 0 {
			return 1
		}
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
		writeTLSError(errorOutput, err)
		return 1
	}
	defer result.Conn.Close()
	if result.TLSState == nil {
		writeTLSError(errorOutput, errors.New("TLS dial completed without connection state"))
		return 1
	}
	var echInfo *client.ECHHandshakeInfo
	if value, ok := result.ECHInfo.(client.ECHHandshakeInfo); ok {
		echInfo = &value
		if echConfig != nil && (echInfo.OuterServerName == "" || sameTLSHost(echInfo.OuterServerName, host)) {
			echInfo.OuterServerName = echConfig.OuterServerName()
		}
		result.Timing.DNSDuration += echDiscoveryDuration
		result.Timing.ConnectDuration = value.TCPDuration
		result.Timing.TLSDuration = value.TLSDuration
	}
	verificationName := connectionVerificationName(result.TLSState, host)
	verification := verifyConnection(result.TLSState, tlsConfig, verificationName)
	renderConnection(output, result.TLSState, echInfo, connectionInfo{
		RemoteIP:     result.RemoteIP,
		Resolver:     result.Resolver,
		Timing:       result.Timing,
		Insecure:     cfg.Insecure,
		OriginHost:   host,
		Port:         effectiveConnectionPort(result.Conn.RemoteAddr(), port),
		ServerName:   verificationName,
		Verbosity:    cfg.Verbosity,
		Verification: verification,
	})
	if flushInspectionOutput(output, errorOutput) != 0 {
		return 1
	}
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
	remotePort := effectiveConnectionPort(result.conn.RemoteAddr(), endpoint.Port)
	_ = result.conn.CloseWithError(0, "")
	_ = result.packetConn.Close()
	connectDone := time.Now()
	timing.ConnectDone = connectDone
	timing.ConnectDuration = connectDone.Sub(timing.ConnectStart)
	return quicInspectionResult{
		State:    &state,
		RemoteIP: append(net.IP(nil), result.ip.IP...),
		Port:     remotePort,
		Resolver: res.Provenance(),
		Timing:   timing,
	}, nil
}

func effectiveConnectionPort(addr net.Addr, fallback string) string {
	if addr == nil {
		return fallback
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err == nil && port != "" {
		return port
	}
	return fallback
}

func sameTLSHost(left, right string) bool {
	return strings.EqualFold(core.TLSVerificationName(left), core.TLSVerificationName(right))
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

func flushInspectionOutput(output, errorOutput *core.Printer) int {
	if err := output.Flush(); err != nil {
		if core.IsBrokenPipe(err) {
			return 0
		}
		writeTLSError(errorOutput, err)
		return 1
	}
	return 0
}

// writeTLSError writes a TLS setup error. Certificate verification failures
// are rendered by the inspection result, so this path is reserved for errors
// that prevented a handshake or a valid inspection configuration.
func writeTLSError(p *core.Printer, err error) {
	core.WriteErrorMsgNoFlush(p, err)
	p.Flush()
}

// render displays the default TLS certificate inspection output to the
// printer. It is used by package-level rendering tests.
func render(p *core.Printer, cs *tls.ConnectionState) {
	renderConnection(p, cs, nil, connectionInfo{Verbosity: core.VNormal})
}

func renderInspection(p *core.Printer, cs *tls.ConnectionState, info *client.ECHHandshakeInfo, meta connectionInfo) {
	if cs == nil {
		p.WriteInfoPrefix()
		p.Set(core.Yellow)
		p.Set(core.Bold)
		p.WriteString("warning")
		p.Reset()
		p.WriteString(": no TLS connection state available\n")
		return
	}

	// TLS inspection always uses the structured diagnostic view. Keep the
	// verbosity value for the extra certificate infrastructure details, but
	// do not require -v for the main inspection output.
	renderVerboseInspection(p, cs, info, meta)
}

func inspectionVerification(cs *tls.ConnectionState, meta connectionInfo) *verificationResult {
	if meta.Verification != nil {
		return meta.Verification
	}
	return &verificationResult{Chains: cs.VerifiedChains}
}

func inspectionLeaf(cs *tls.ConnectionState) *x509.Certificate {
	if chain := getServerChain(cs); len(chain) > 0 {
		return chain[0]
	}
	return nil
}

func inspectionTarget(meta connectionInfo) string {
	if meta.OriginHost == "" || meta.RemoteIP == nil {
		return ""
	}
	address := meta.RemoteIP.String()
	if meta.Port != "" {
		address = net.JoinHostPort(address, meta.Port)
	}
	return core.TerminalSafeText(meta.OriginHost) + " → " + core.TerminalSafeText(address)
}

func inspectionTimingParts(meta connectionInfo) []string {
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
	return parts
}

func compactCertName(cert *x509.Certificate) string {
	if cert == nil {
		return "unknown"
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return cert.Subject.String()
}

func compactOCSPStatus(raw []byte, chain []*x509.Certificate) string {
	if len(raw) == 0 {
		return "not stapled"
	}
	status, _ := inspectOCSPStaple(raw, chain)
	switch {
	case strings.HasPrefix(status, "good"):
		return "good, stapled; freshness not checked"
	case strings.HasPrefix(status, "revoked"):
		return "revoked, stapled; freshness not checked"
	case strings.HasPrefix(status, "unknown"):
		return "unknown, stapled; freshness not checked"
	default:
		return "stapled, unverified"
	}
}

func renderVerboseInspection(p *core.Printer, cs *tls.ConnectionState, info *client.ECHHandshakeInfo, meta connectionInfo) {
	renderInspectionSection(p, "Connection")
	if target := inspectionTarget(meta); target != "" {
		writeVerboseInspectionField(p, "Target", target)
	}
	if meta.Resolver != "" {
		writeVerboseInspectionField(p, "Resolver", meta.Resolver)
	}
	sni := cs.ServerName
	if cs.ECHAccepted && meta.OriginHost != "" {
		sni = core.TLSVerificationName(meta.OriginHost)
	}
	if sni == "" {
		sni = meta.ServerName
	}
	if sni != "" {
		writeVerboseInspectionField(p, "SNI", sni)
	}
	if info != nil && info.Offered {
		writeVerboseInspectionField(p, "ECH", echInspectionStatus(info))
	}
	if info != nil && info.OuterServerName != "" {
		writeVerboseInspectionField(p, "Outer SNI", info.OuterServerName)
	}
	writeVerboseInspectionField(p, "Protocol", tls.VersionName(cs.Version))
	if cs.NegotiatedProtocol != "" {
		writeVerboseInspectionField(p, "ALPN", cs.NegotiatedProtocol)
	} else {
		writeVerboseInspectionField(p, "ALPN", "not negotiated")
	}
	cipher := "unavailable"
	if cs.CipherSuite != 0 {
		cipher = tls.CipherSuiteName(cs.CipherSuite)
	}
	writeVerboseInspectionField(p, "Cipher", cipher)
	writeVerboseInspectionField(p, "Key exchange", core.TLSKeyExchangeName(cs.CurveID))
	if parts := inspectionTimingParts(meta); len(parts) > 0 {
		writeVerboseInspectionField(p, "Timing", strings.Join(parts, " · "))
	}

	verification := inspectionVerification(cs, meta)
	leaf := inspectionLeaf(cs)
	writeInspectionBlankLine(p)
	certificateHeading := "Certificate"
	if leaf != nil {
		certificateHeading += ": " + compactCertName(leaf)
	}
	renderInspectionSection(p, certificateHeading)
	renderVerboseVerification(p, verification, meta.Insecure, meta.ServerName)
	if leaf != nil {
		writeVerboseInspectionField(p, "Subject", leaf.Subject.String())
		writeVerboseInspectionField(p, "Issuer", leaf.Issuer.String())
		writeVerboseInspectionField(p, "Valid from", leaf.NotBefore.Format(time.RFC3339))
		writeVerboseInspectionField(p, "Valid until", leaf.NotAfter.Format(time.RFC3339)+" ("+certificateValidityStatus(leaf)+")")
		serial := "unavailable"
		if leaf.SerialNumber != nil {
			serial = leaf.SerialNumber.String()
		}
		writeVerboseInspectionField(p, "Serial number", serial)
		writeVerboseInspectionField(p, "Public key", publicKeyDescription(leaf.PublicKey))
		writeVerboseInspectionField(p, "Signature algorithm", leaf.SignatureAlgorithm.String())
		writeVerboseInspectionField(p, "SHA-256", certificateFingerprint(leaf))
		if sans := certificateSANs(leaf); len(sans) > 0 {
			writeVerboseInspectionField(p, "SANs", strings.Join(sans, ", "))
		}
	}
	writeVerboseInspectionField(p, "SCTs", strconv.Itoa(len(cs.SignedCertificateTimestamps)))
	chain := getServerChain(cs)
	writeVerboseInspectionField(p, "OCSP", compactOCSPStatus(cs.OCSPResponse, chain))
	if thisUpdate, nextUpdate, ok := ocspStapleTimes(cs.OCSPResponse, chain); ok {
		writeVerboseInspectionField(p, "OCSP ThisUpdate", thisUpdate.Format(time.RFC3339))
		if !nextUpdate.IsZero() {
			writeVerboseInspectionField(p, "OCSP NextUpdate", nextUpdate.Format(time.RFC3339))
		}
	}

	if len(chain) > 0 {
		writeInspectionBlankLine(p)
		renderCertificateChain(p, "Server chain", chain)
	}
	if verifiedPath := getVerifiedPath(verification); len(verifiedPath) > 0 {
		writeInspectionBlankLine(p)
		renderCertificateChain(p, "Verified path", verifiedPath)
	}
	if meta.Verbosity >= core.VExtraVerbose {
		writeInspectionBlankLine(p)
		renderInspectionSection(p, "Certificate infrastructure")
		renderNicheCertificateDetails(p, chain)
	}
}

func renderInspectionSection(p *core.Printer, heading string) {
	p.WriteInfoPrefix()
	p.Set(core.Bold)
	p.WriteString(core.TerminalSafeText(heading))
	p.Reset()
	p.WriteString("\n")
}

func writeInspectionBlankLine(p *core.Printer) {
	p.WriteInfoPrefix()
	p.WriteString("\n")
}

func writeVerboseInspectionField(p *core.Printer, label, value string) {
	p.WriteInfoPrefix()
	p.WriteString("  ")
	p.WriteString(label)
	p.WriteString(": ")
	p.WriteString(core.TerminalSafeText(value))
	p.WriteString("\n")
}

func echInspectionStatus(info *client.ECHHandshakeInfo) string {
	status := "offered"
	switch {
	case info.Accepted && info.Real:
		status = "accepted (real)"
	case info.Accepted:
		status = "accepted (GREASE)"
	case info.Fallback && info.Real:
		status = "rejected (real/fallback)"
	case info.Fallback:
		status = "rejected (GREASE/fallback)"
	case info.Rejected:
		status = "rejected"
	}
	return status
}

func renderVerboseVerification(p *core.Printer, result *verificationResult, insecure bool, serverName string) {
	status := "not verified"
	switch {
	case result.Err != nil && insecure:
		status = "FAILED (ignored by --insecure)"
	case result.Err != nil:
		status = "FAILED"
	case len(result.Chains) > 0 && serverName != "":
		status = "verified for " + serverName
	case len(result.Chains) > 0:
		status = "verified"
	}
	writeVerboseInspectionField(p, "Verification", status)
	if result.Err != nil {
		writeVerboseInspectionField(p, "Verification error", result.Err.Error())
	}
	anchor := "not available"
	if cert := verifiedTrustAnchor(result); cert != nil {
		anchor = certDisplayName(cert)
	}
	writeVerboseInspectionField(p, "Trust anchor", anchor)
}

func certificateValidityStatus(cert *x509.Certificate) string {
	now := tlsInspectNow()
	if now.After(cert.NotAfter) {
		return "expired"
	}
	days := int(cert.NotAfter.Sub(now).Hours() / 24)
	if days == 0 {
		return "less than 1 day remaining"
	}
	if days == 1 {
		return "1 day remaining"
	}
	return fmt.Sprintf("%d days remaining", days)
}

func certificateFingerprint(cert *x509.Certificate) string {
	fingerprint := sha256.Sum256(cert.Raw)
	parts := make([]string, len(fingerprint))
	for i, value := range fingerprint {
		parts[i] = fmt.Sprintf("%02x", value)
	}
	return strings.Join(parts, ":")
}

func certificateSANs(cert *x509.Certificate) []string {
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}
	return sans
}

func writeInspectionField(p *core.Printer, label, value string) {
	p.WriteInfoPrefix()
	p.WriteString(label)
	p.WriteString(": ")
	p.WriteString(core.TerminalSafeText(value))
	p.WriteString("\n")
}

func renderConnection(p *core.Printer, cs *tls.ConnectionState, info *client.ECHHandshakeInfo, meta connectionInfo) {
	renderInspection(p, cs, info, meta)
}

func formatDuration(value time.Duration) string {
	return fmt.Sprintf("%.1fms", float64(value)/float64(time.Millisecond))
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

func publicKeyDescription(key crypto.PublicKey) string {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", key.Size()*8)
	case *ecdsa.PublicKey:
		if key.Curve != nil && key.Curve.Params() != nil {
			return "ECDSA " + key.Curve.Params().Name
		}
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		if key == nil {
			return "unavailable"
		}
		return fmt.Sprintf("%T", key)
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
	sans = append(sans, leaf.EmailAddresses...)
	for _, uri := range leaf.URIs {
		sans = append(sans, uri.String())
	}

	if len(sans) == 0 {
		return
	}

	writeInspectionBlankLine(p)
	p.WriteInfoPrefix()
	p.WriteString("SANs: ")
	p.Set(core.Italic)
	p.WriteString(core.TerminalSafeText(strings.Join(sans, ", ")))
	p.Reset()
	p.WriteString("\n")
}

func renderNicheCertificateDetails(p *core.Printer, chain []*x509.Certificate) {
	for i, cert := range chain {
		if cert == nil {
			continue
		}
		prefix := fmt.Sprintf("Certificate %d ", i+1)
		if len(cert.OCSPServer) > 0 {
			writeInspectionField(p, prefix+"AIA OCSP", strings.Join(cert.OCSPServer, ", "))
		}
		if len(cert.IssuingCertificateURL) > 0 {
			writeInspectionField(p, prefix+"AIA issuing certificate", strings.Join(cert.IssuingCertificateURL, ", "))
		}
		if len(cert.CRLDistributionPoints) > 0 {
			writeInspectionField(p, prefix+"CRL distribution points", strings.Join(cert.CRLDistributionPoints, ", "))
		}
		if len(cert.PolicyIdentifiers) > 0 {
			policies := make([]string, len(cert.PolicyIdentifiers))
			for j, policy := range cert.PolicyIdentifiers {
				policies[j] = policy.String()
			}
			writeInspectionField(p, prefix+"Policies", strings.Join(policies, ", "))
		}
		if len(cert.UnhandledCriticalExtensions) > 0 {
			exts := make([]string, len(cert.UnhandledCriticalExtensions))
			for j, extension := range cert.UnhandledCriticalExtensions {
				exts[j] = extension.String()
			}
			writeInspectionField(p, prefix+"Unhandled critical extensions", strings.Join(exts, ", "))
		}
	}
}

func ocspStapleTimes(raw []byte, chain []*x509.Certificate) (time.Time, time.Time, bool) {
	if len(raw) > maxOCSPStapleSize || len(chain) < 2 || chain[0] == nil || chain[1] == nil {
		return time.Time{}, time.Time{}, false
	}
	leaf, issuer := chain[0], chain[1]
	var envelope ocspResponseEnvelope
	if rest, err := asn1.Unmarshal(raw, &envelope); err != nil || len(rest) != 0 || envelope.Status != 0 {
		return time.Time{}, time.Time{}, false
	}
	var basic ocspBasicResponse
	if rest, err := asn1.Unmarshal(envelope.Response.Response, &basic); err != nil || len(rest) != 0 {
		return time.Time{}, time.Time{}, false
	}
	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		requestDER, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: hash})
		if err != nil {
			continue
		}
		request, err := ocsp.ParseRequest(requestDER)
		if err != nil || request.SerialNumber == nil {
			continue
		}
		for _, response := range basic.TBSResponseData.Responses {
			if response.CertID.SerialNumber != nil && response.CertID.SerialNumber.Cmp(request.SerialNumber) == 0 &&
				bytes.Equal(response.CertID.IssuerNameHash, request.IssuerNameHash) &&
				bytes.Equal(response.CertID.IssuerKeyHash, request.IssuerKeyHash) &&
				response.CertID.HashAlgorithm.Algorithm.Equal(ocspHashAlgorithmOID(hash)) {
				return response.ThisUpdate, response.NextUpdate, true
			}
		}
	}
	return time.Time{}, time.Time{}, false
}

const maxOCSPStapleSize = 1 << 20

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
