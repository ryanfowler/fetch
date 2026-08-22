package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
)

var (
	// ErrECHConfigUnavailable is returned for ECH=on when authenticated
	// discovery completed but did not provide a configuration usable by this
	// client.
	ErrECHConfigUnavailable = errors.New("ECH is required but no usable ECH configuration was discovered")
)

// ECHDiscoveryNeedsWarning reports whether ECH configuration discovery uses
// a resolver whose transport is not authenticated. Discovery can protect the
// TLS handshake while still exposing or permitting modification of the
// hostname's HTTPS records. The caller decides whether the warning is shown
// (the CLI shows it only at -vvv and above).
func ECHDiscoveryNeedsWarning(mode core.ECHMode, target *url.URL, endpoint *resolver.Endpoint, insecure bool, explicitProxy *url.URL) bool {
	if target == nil {
		return false
	}
	if explicitProxy != nil {
		return false
	}
	if selected, err := ProxyForURL(nil, target); err == nil && selected != nil {
		return false
	}
	return echDiscoveryNeedsWarning(mode, target, endpoint, insecure)
}

// ECHDiscoveryNeedsResolverWarning is used by inspection modes that ignore
// proxy options. It deliberately does not consult proxy environment settings.
func ECHDiscoveryNeedsResolverWarning(mode core.ECHMode, target *url.URL, endpoint *resolver.Endpoint, insecure bool) bool {
	return echDiscoveryNeedsWarning(mode, target, endpoint, insecure)
}

func echDiscoveryNeedsWarning(mode core.ECHMode, target *url.URL, endpoint *resolver.Endpoint, insecure bool) bool {
	if target == nil || (mode != core.ECHAuto && mode != core.ECHOn) || !(strings.EqualFold(target.Scheme, "https") || strings.EqualFold(target.Scheme, "wss")) {
		return false
	}
	if net.ParseIP(target.Hostname()) != nil {
		return false
	}
	if endpoint == nil {
		return true // the platform resolver has no authenticated DNS guarantee
	}
	if insecure {
		return true
	}
	return endpoint.Security != resolver.SecurityVerifiedEncrypted
}

type ECHConnectionConfig struct {
	tlsConfig  *tls.Config
	targetHost string
	targetPort string
	addresses  []net.IPAddr
	configured bool
	grease     bool
	outerName  string
}

// discoverECHForConnection applies the discovery policy to a connection-
// specific TLS configuration. It also returns the effective SVCB target. The
// origin remains the TLS public name and HTTP authority; only the first hop
// uses targetHost/targetPort.
func discoverECHForConnection(ctx context.Context, res *resolver.Resolver, host, port string, base *tls.Config, mode core.ECHMode, version core.HTTPVersion) (*ECHConnectionConfig, error) {
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return nil, fmt.Errorf("invalid HTTPS port %q", port)
	}
	cfg := base
	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg = cfg.Clone()
	fallback := &ECHConnectionConfig{tlsConfig: cfg, targetHost: host, targetPort: port}
	if mode == core.ECHUnknown || mode == core.ECHOff {
		return fallback, nil
	}
	if res == nil {
		if mode == core.ECHOn {
			return nil, ErrECHConfigUnavailable
		}
		return configureECHGREASE(fallback)
	}

	discovery, err := res.DiscoverHTTPS(ctx, host, uint16(parsedPort), nil)
	if err != nil {
		// NODATA/NXDOMAIN and an unauthenticated resolver failure are safe
		// to handle as "no advertised configuration" in auto mode. A
		// verified resolver failure is different: accepting ordinary TLS
		// would hide a potentially active downgrade.
		if mode == core.ECHOn || resolver.IsAuthenticatedDiscoveryFailure(err) || !resolver.MayDowngrade(err) {
			return nil, err
		}
		return configureECHGREASE(fallback)
	}

	candidate := selectECHCandidate(discovery, version)
	if candidate == nil {
		if mode == core.ECHOn {
			return nil, ErrECHConfigUnavailable
		}
		return configureECHGREASE(fallback)
	}
	configList, err := resolver.SupportedECHConfigList(candidate.ECH)
	if err != nil {
		return nil, err
	}
	cfg.MinVersion = tls.VersionTLS13
	cfg.EncryptedClientHelloConfigList = configList
	if cfg.ServerName == "" {
		cfg.ServerName = core.TLSVerificationName(host)
	}
	outerName, nameErr := resolver.ECHPublicName(configList)
	if nameErr != nil {
		return nil, nameErr
	}
	result := &ECHConnectionConfig{
		tlsConfig:  cfg,
		targetHost: host,
		targetPort: port,
		addresses:  append([]net.IPAddr(nil), candidate.Addresses...),
		configured: true,
		outerName:  outerName,
	}
	if target := candidate.TargetName.String(); target != "" && target != "." {
		result.targetHost = target
	}
	if candidate.Port != 0 {
		result.targetPort = strconv.Itoa(int(candidate.Port))
	}
	return result, nil
}

// DiscoverECHForConnection performs host-scoped HTTPS/SVCB discovery and
// prepares the TLS configuration for an inspection or application dial.
func DiscoverECHForConnection(ctx context.Context, res *resolver.Resolver, host, port string, base *tls.Config, mode core.ECHMode, version core.HTTPVersion) (*ECHConnectionConfig, error) {
	return discoverECHForConnection(ctx, res, host, port, base, mode, version)
}

// TLSConfig returns the cloned, connection-specific TLS configuration.
func (c *ECHConnectionConfig) TLSConfig() *tls.Config {
	if c == nil || c.tlsConfig == nil {
		return nil
	}
	return c.tlsConfig.Clone()
}

// Target returns the effective SVCB service target and port.
func (c *ECHConnectionConfig) Target() (string, string) {
	if c == nil {
		return "", ""
	}
	return c.targetHost, c.targetPort
}

// Addresses returns the validated service addresses, if discovery supplied
// them. The returned slice is independent of the connection configuration.
func (c *ECHConnectionConfig) Addresses() []net.IPAddr {
	if c == nil {
		return nil
	}
	return append([]net.IPAddr(nil), c.addresses...)
}

// Real reports whether the TLS configuration came from an advertised ECH
// configuration rather than generated GREASE.
func (c *ECHConnectionConfig) Real() bool { return c != nil && c.configured && !c.grease }

// Offered reports whether this connection will send an ECH extension.
func (c *ECHConnectionConfig) Offered() bool { return c != nil && c.configured }

// OuterServerName returns the public SNI used for the outer ClientHello.
func (c *ECHConnectionConfig) OuterServerName() string {
	if c == nil {
		return ""
	}
	return c.outerName
}

func selectECHCandidate(discovery resolver.HTTPSDiscovery, version core.HTTPVersion) *resolver.ServiceCandidate {
	for i := range discovery.Candidates {
		candidate := &discovery.Candidates[i]
		if len(candidate.ECH) == 0 || !serviceSupportsECHProtocol(*candidate, version) {
			continue
		}
		return candidate
	}
	return nil
}

func serviceSupportsECHProtocol(candidate resolver.ServiceCandidate, version core.HTTPVersion) bool {
	if len(candidate.ALPN) == 0 {
		return true
	}
	for _, alpn := range candidate.ALPN {
		value := string(alpn)
		switch version {
		case core.HTTP1:
			if value == "http/1.1" {
				return true
			}
		case core.HTTP2:
			if value == "h2" {
				return true
			}
		case core.HTTP3:
			if value == "h3" {
				return true
			}
		default:
			if value == "h2" || value == "http/1.1" {
				return true
			}
		}
	}
	return false
}

// newECHHTTPDialTLS is used by net/http's HTTP/1 transport when ECH is
// enabled. It returns an already-handshaken connection, as required by
// DialTLSContext.
func newECHHTTPDialTLS(base func(context.Context, string, string) (net.Conn, error), res *resolver.Resolver, baseTLS *tls.Config, mode core.ECHMode, timeout time.Duration, version core.HTTPVersion) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		connectCtx, cancel := connectContext(ctx, timeout, "ECH discovery and TLS connect")
		defer cancel()
		connection, err := discoverECHForConnection(connectCtx, res, host, port, baseTLS, mode, version)
		if err != nil {
			return nil, err
		}
		connection.tlsConfig.NextProtos = echALPN(version)
		if !connection.configured {
			return dialAndHandshake(connectCtx, base, network, address, connection.tlsConfig)
		}
		got, err := dialResolverWithECH(connectCtx, NewResolverDialer(res, timeout), DialRequest{
			Network: "tcp", Host: connection.targetHost, Port: connection.targetPort,
			OriginHost: host, Candidates: connection.addresses,
		}, connection.tlsConfig, mode)
		if err != nil {
			return nil, err
		}
		return got.Conn, nil
	}
}

func echALPN(version core.HTTPVersion) []string {
	switch version {
	case core.HTTP1:
		return []string{"http/1.1"}
	case core.HTTP2:
		return []string{"h2"}
	default:
		return []string{"h2", "http/1.1"}
	}
}

func dialAndHandshake(ctx context.Context, base func(context.Context, string, string) (net.Conn, error), network, address string, cfg *tls.Config) (net.Conn, error) {
	return dialTLSWithECHPolicy(ctx, func(rawCtx context.Context) (net.Conn, error) {
		return base(rawCtx, network, address)
	}, cfg, core.ECHOff)
}

func configureECHGREASE(fallback *ECHConnectionConfig) (*ECHConnectionConfig, error) {
	configList, err := GenerateGREASEECHConfigList()
	if err != nil {
		return nil, err
	}
	cfg := fallback.tlsConfig.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.EncryptedClientHelloConfigList = configList
	if cfg.ServerName == "" {
		cfg.ServerName = core.TLSVerificationName(fallback.targetHost)
	}
	return &ECHConnectionConfig{
		tlsConfig:  cfg,
		targetHost: fallback.targetHost,
		targetPort: fallback.targetPort,
		configured: true,
		grease:     true,
		outerName:  string(greaseECHPublicName),
	}, nil
}
