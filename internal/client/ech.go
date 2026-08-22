package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
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

type echConnectionConfig struct {
	tlsConfig  *tls.Config
	targetHost string
	targetPort string
	addresses  []net.IPAddr
	configured bool
	grease     bool
}

// discoverECHForConnection applies the discovery policy to a connection-
// specific TLS configuration. It also returns the effective SVCB target. The
// origin remains the TLS public name and HTTP authority; only the first hop
// uses targetHost/targetPort.
func discoverECHForConnection(ctx context.Context, res *resolver.Resolver, host, port string, base *tls.Config, mode core.ECHMode, version core.HTTPVersion) (*echConnectionConfig, error) {
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return nil, fmt.Errorf("invalid HTTPS port %q", port)
	}
	cfg := base
	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg = cfg.Clone()
	fallback := &echConnectionConfig{tlsConfig: cfg, targetHost: host, targetPort: port}
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
	result := &echConnectionConfig{
		tlsConfig:  cfg,
		targetHost: host,
		targetPort: port,
		addresses:  append([]net.IPAddr(nil), candidate.Addresses...),
		configured: true,
	}
	if target := candidate.TargetName.String(); target != "" && target != "." {
		result.targetHost = target
	}
	if candidate.Port != 0 {
		result.targetPort = strconv.Itoa(int(candidate.Port))
	}
	return result, nil
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

func configureECHGREASE(fallback *echConnectionConfig) (*echConnectionConfig, error) {
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
	return &echConnectionConfig{
		tlsConfig:  cfg,
		targetHost: fallback.targetHost,
		targetPort: fallback.targetPort,
		configured: true,
		grease:     true,
	}, nil
}
