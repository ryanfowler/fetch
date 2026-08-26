package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strconv"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
)

// dialAutomaticECHTCP replaces a speculative plain TCP connection with one
// configured from the completed HTTPS/SVCB discovery. The speculative
// connection is closed by the caller. This keeps address and ECH discovery
// concurrent without allowing a plain connection to win ECH=on.
func serviceAdvertisesTCP(candidate resolver.ServiceCandidate) bool {
	if len(candidate.ALPN) == 0 {
		return true
	}
	for _, alpn := range candidate.ALPN {
		if string(alpn) == "h2" || string(alpn) == "http/1.1" {
			return true
		}
	}
	return false
}

func cloneServiceCandidates(values []resolver.ServiceCandidate) []resolver.ServiceCandidate {
	out := make([]resolver.ServiceCandidate, len(values))
	copy(out, values)
	for i := range out {
		out[i].ALPN = cloneECHALPN(out[i].ALPN)
		out[i].ECH = append([]byte(nil), out[i].ECH...)
		out[i].Hints = append([]net.IPAddr(nil), out[i].Hints...)
		out[i].Addresses = append([]net.IPAddr(nil), out[i].Addresses...)
	}
	return out
}

func cloneECHALPN(values [][]byte) [][]byte {
	out := make([][]byte, len(values))
	for i, value := range values {
		out[i] = append([]byte(nil), value...)
	}
	return out
}

func (t *automaticHTTP3Transport) dialAutomaticECHTCP(ctx context.Context, origin *url.URL, tcpAddrs []net.IPAddr, tcpPort string, services []resolver.ServiceCandidate) (net.Conn, error) {
	if len(services) == 0 {
		return nil, errors.New("ECH is required but no usable ECH configuration was discovered")
	}
	service := services[0]
	configList, err := resolver.SupportedECHConfigList(service.ECH)
	if err != nil {
		return nil, err
	}
	cfg := t.tlsConfig.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.EncryptedClientHelloConfigList = configList
	cfg.NextProtos = []string{"h2", "http/1.1"}
	if cfg.ServerName == "" {
		cfg.ServerName = core.TLSVerificationName(origin.Hostname())
	}
	addresses := service.Addresses
	if len(addresses) == 0 {
		addresses = tcpAddrs
	}
	port := tcpPort
	if service.Port != 0 {
		port = strconv.Itoa(int(service.Port))
	}
	host := origin.Hostname()
	if service.TargetName.String() != "" && service.TargetName.String() != "." {
		host = service.TargetName.String()
	}
	got, err := dialResolverWithECH(ctx, t.dialer, DialRequest{
		Network:    "tcp",
		Host:       host,
		Port:       port,
		OriginHost: origin.Hostname(),
		OriginPort: originPort(origin),
		Resolver:   t.resolver,
		Candidates: addresses,
	}, cfg, t.ech)
	if err != nil {
		return nil, err
	}
	return got.Conn, nil
}
