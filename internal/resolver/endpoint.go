package resolver

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Transport identifies the protocol used to send DNS queries to an endpoint.
type Transport string

const (
	TransportUDP    Transport = "udp"
	TransportTCP    Transport = "tcp"
	TransportTLS    Transport = "tls"
	TransportQUIC   Transport = "quic"
	TransportHTTPS  Transport = "https"
	TransportSystem Transport = "system"
)

// Security describes the transport's protection against network observers and
// endpoint impersonation. Resolver authentication is separate from the
// authentication of DNS answers.
type Security string

const (
	SecurityPlaintext         Security = "plaintext/unauthenticated"
	SecurityVerifiedEncrypted Security = "certificate-verified encrypted"
	SecurityUnverifiedEncrypt Security = "encrypted but verification disabled"
)

// Endpoint is the transport-neutral configuration for a DNS resolver.
//
// ConnectHost is kept separate from TLSServerName because a future dialer may
// connect to an explicit bootstrap address while still verifying the resolver
// hostname. BootstrapAddrs contains addresses that are safe to use without a
// recursive lookup through this endpoint.
type Endpoint struct {
	Transport      Transport
	ConnectHost    string
	Port           uint16
	Path           string
	RawPath        string
	RawQuery       string
	TLSServerName  string
	BootstrapAddrs []net.IP
	VerifyTLS      bool
	Security       Security
	Display        string
}

// ParseEndpoint parses a resolver endpoint. It accepts bare UDP endpoints and
// the explicit UDP, TCP, DoT, DoQ, and DoH forms described by the CLI contract.
// DoH must use HTTPS; test transports can use ParseEndpointURL with an explicit
// opt-in when they need a local plaintext HTTP server.
func ParseEndpoint(value string) (*Endpoint, error) {
	return parseEndpoint(value, false)
}

// ParseEndpointURL parses a URL supplied by an internal test transport. The
// allowInsecureHTTPS flag permits http:// for local DoH fixtures only. Normal
// CLI and config parsing must use ParseEndpoint.
func ParseEndpointURL(value string, allowInsecureHTTPS bool) (*Endpoint, error) {
	return parseEndpoint(value, allowInsecureHTTPS)
}

func parseEndpoint(value string, allowInsecureHTTPS bool) (*Endpoint, error) {
	if value == "" {
		return nil, endpointError(value, "endpoint is empty")
	}
	if strings.TrimSpace(value) != value {
		return nil, endpointError(value, "endpoint must not have leading or trailing whitespace")
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return nil, endpointError(value, "endpoint contains a control character")
	}

	if !strings.Contains(value, "://") {
		host, port, err := parseHostPort(value, 53)
		if err != nil {
			return nil, endpointError(value, err.Error())
		}
		return newEndpoint(TransportUDP, host, port, "", "", "", false), nil
	}

	u, err := url.Parse(value)
	if err != nil {
		return nil, endpointError(value, "invalid URL: "+err.Error())
	}
	if u.Scheme == "" {
		return nil, endpointError(value, "missing resolver scheme")
	}
	if u.User != nil {
		return nil, endpointError(value, "userinfo is not supported")
	}
	if strings.Contains(value, "#") || u.Fragment != "" {
		return nil, endpointError(value, "fragments are not supported")
	}

	scheme := strings.ToLower(u.Scheme)
	transport, ok := map[string]Transport{
		"udp":   TransportUDP,
		"tcp":   TransportTCP,
		"tls":   TransportTLS,
		"dot":   TransportTLS,
		"quic":  TransportQUIC,
		"doq":   TransportQUIC,
		"https": TransportHTTPS,
		"http":  TransportHTTPS,
	}[scheme]
	if !ok || (scheme == "http" && !allowInsecureHTTPS) {
		if scheme == "http" {
			return nil, endpointError(value, "DoH requires https://")
		}
		return nil, endpointError(value, "unsupported scheme "+u.Scheme)
	}
	if u.Host == "" {
		return nil, endpointError(value, "host is empty")
	}

	path := u.EscapedPath()
	if transport != TransportHTTPS && (u.RawQuery != "" || path != "") {
		return nil, endpointError(value, "path and query are not supported for this transport")
	}
	if transport != TransportHTTPS && u.ForceQuery {
		return nil, endpointError(value, "query is not supported for this transport")
	}

	host, port, err := parseURLHostPort(u, defaultPort(transport))
	if err != nil {
		return nil, endpointError(value, err.Error())
	}
	verify := transport == TransportTLS || transport == TransportQUIC || (transport == TransportHTTPS && scheme != "http")
	ep := newEndpoint(transport, host, port, u.Path, u.RawPath, u.RawQuery, verify)
	if scheme == "http" {
		ep.Security = SecurityPlaintext
	}
	return ep, nil
}

func defaultPort(transport Transport) uint16 {
	if transport == TransportTLS || transport == TransportQUIC {
		return 853
	}
	if transport == TransportHTTPS {
		return 443
	}
	return 53
}

func parseURLHostPort(u *url.URL, defaultPort uint16) (string, uint16, error) {
	// url.Parse validates bracket pairing, but it intentionally leaves some
	// invalid port spellings to callers. Parse the authority explicitly so a
	// zero, missing, or non-numeric port cannot be accepted accidentally.
	host := u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("host is empty")
	}
	if err := validateHost(host); err != nil {
		return "", 0, err
	}

	authority := u.Host
	portText := ""
	switch {
	case strings.HasPrefix(authority, "["):
		close := strings.IndexByte(authority, ']')
		if close < 0 {
			return "", 0, fmt.Errorf("invalid IPv6 bracket syntax")
		}
		if net.ParseIP(host) == nil {
			return "", 0, fmt.Errorf("brackets are only valid for IPv6 addresses")
		}
		rest := authority[close+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || len(rest) == 1 {
				return "", 0, fmt.Errorf("invalid port")
			}
			portText = rest[1:]
		}
	case strings.Count(authority, ":") == 0:
		// No explicit port.
	case strings.Count(authority, ":") == 1:
		idx := strings.LastIndexByte(authority, ':')
		if idx == 0 || idx == len(authority)-1 {
			return "", 0, fmt.Errorf("invalid port")
		}
		portText = authority[idx+1:]
	default:
		return "", 0, fmt.Errorf("invalid IPv6 bracket syntax")
	}
	port, err := parsePort(portText, defaultPort)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func parseHostPort(value string, defaultPort uint16) (string, uint16, error) {
	if strings.ContainsAny(value, "/?#") {
		return "", 0, fmt.Errorf("path, query, and fragments are not supported")
	}
	if strings.HasPrefix(value, "[") {
		close := strings.IndexByte(value, ']')
		if close < 0 {
			return "", 0, fmt.Errorf("invalid IPv6 bracket syntax")
		}
		host := value[1:close]
		if net.ParseIP(host) == nil {
			return "", 0, fmt.Errorf("brackets are only valid for IPv6 addresses")
		}
		rest := value[close+1:]
		if rest != "" && !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("invalid IPv6 bracket syntax")
		}
		portText := ""
		if rest != "" {
			if len(rest) == 1 {
				return "", 0, fmt.Errorf("invalid port")
			}
			portText = rest[1:]
		}
		if err := validateHost(host); err != nil {
			return "", 0, err
		}
		port, err := parsePort(portText, defaultPort)
		return host, port, err
	}
	if strings.Count(value, ":") > 1 {
		return "", 0, fmt.Errorf("IPv6 addresses must use brackets")
	}

	host := value
	portText := ""
	if idx := strings.IndexByte(value, ':'); idx >= 0 {
		host, portText = value[:idx], value[idx+1:]
		if portText == "" {
			return "", 0, fmt.Errorf("invalid port")
		}
	} else if net.ParseIP(host) == nil {
		return "", 0, fmt.Errorf("hostname endpoints require an explicit port")
	}
	if err := validateHost(host); err != nil {
		return "", 0, err
	}
	port, err := parsePort(portText, defaultPort)
	return host, port, err
}

func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("host is empty")
	}
	if strings.ContainsAny(host, "\r\n\x00/\\@?#") {
		return fmt.Errorf("invalid host")
	}
	for _, r := range host {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("invalid host")
		}
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return fmt.Errorf("invalid IPv6 address")
	}
	return nil
}

func parsePort(value string, fallback uint16) (uint16, error) {
	if value == "" {
		return fallback, nil
	}
	if strings.Trim(value, "0123456789") != "" {
		return 0, fmt.Errorf("port must be a decimal number")
	}
	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return uint16(n), nil
}

func newEndpoint(transport Transport, host string, port uint16, path, rawPath, rawQuery string, verify bool) *Endpoint {
	ep := &Endpoint{
		Transport:     transport,
		ConnectHost:   host,
		Port:          port,
		Path:          path,
		RawPath:       rawPath,
		RawQuery:      rawQuery,
		TLSServerName: host,
		VerifyTLS:     verify,
		Security:      SecurityPlaintext,
	}
	if ip := net.ParseIP(host); ip != nil {
		ep.BootstrapAddrs = []net.IP{append(net.IP(nil), ip...)}
	}
	if verify {
		ep.Security = SecurityVerifiedEncrypted
	}
	ep.Display = endpointDisplay(ep)
	return ep
}

func endpointDisplay(ep *Endpoint) string {
	host := net.JoinHostPort(ep.ConnectHost, strconv.Itoa(int(ep.Port)))
	if ep.Transport == TransportHTTPS {
		scheme := "http"
		if ep.VerifyTLS {
			scheme = "https"
		}
		u := &url.URL{Scheme: scheme, Host: host, Path: ep.Path, RawPath: ep.RawPath}
		return u.String()
	}
	return string(ep.Transport) + "://" + host
}

// Address returns the endpoint's network address.
func (e *Endpoint) Address() string {
	if e == nil {
		return ""
	}
	return net.JoinHostPort(e.ConnectHost, strconv.Itoa(int(e.Port)))
}

// String returns a canonical, secret-free display form.
func (e *Endpoint) String() string {
	if e == nil {
		return ""
	}
	return e.Display
}

// URL returns a compatibility URL for code that has not yet migrated to the
// transport-neutral fields. New network code should use the endpoint fields.
func (e *Endpoint) URL() *url.URL {
	if e == nil {
		return nil
	}
	if e.Transport == TransportHTTPS {
		scheme := "http"
		if e.VerifyTLS {
			scheme = "https"
		}
		return &url.URL{Scheme: scheme, Host: e.Address(), Path: e.Path, RawPath: e.RawPath, RawQuery: e.RawQuery}
	}
	if e.Transport == TransportUDP {
		return &url.URL{Host: e.Address()}
	}
	return &url.URL{Scheme: string(e.Transport), Host: e.Address()}
}

func endpointError(value, detail string) error {
	return fmt.Errorf("invalid resolver endpoint %q: %s", value, detail)
}
