package client

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"

	"golang.org/x/net/idna"
)

// ProxyDecision describes the proxy selected for one request. URL is nil for
// a direct request. The source and bypass fields are intended for diagnostics;
// they never contain proxy credentials.
type ProxyDecision struct {
	URL          *url.URL
	Source       string
	Bypassed     bool
	BypassReason string
}

// ProxyForURL selects the proxy for target. An explicit proxy always wins and
// is not affected by NO_PROXY. A nil explicit proxy enables environment
// selection.
func ProxyForURL(explicit, target *url.URL) (*url.URL, error) {
	decision, err := SelectProxy(explicit, target)
	if err != nil {
		return nil, err
	}
	return decision.URL, nil
}

// SelectProxy applies the fetch proxy precedence rules to target.
//
// The selector reads the environment for each call. This avoids the process
// global caching used by net/http.ProxyFromEnvironment and makes redirects,
// tests, and long-running callers use the same current policy.
func SelectProxy(explicit, target *url.URL) (ProxyDecision, error) {
	if target == nil {
		return ProxyDecision{}, nil
	}
	if explicit != nil {
		proxy, err := validateProxyURL(explicit)
		if err != nil {
			return ProxyDecision{}, fmt.Errorf("invalid proxy %q: %w", core.RedactedURL(explicit), err)
		}
		return ProxyDecision{URL: proxy, Source: "explicit"}, nil
	}

	noProxy := environmentValue("NO_PROXY", "no_proxy")
	if matched, entry := noProxyMatchesURL(target, noProxy); matched {
		return ProxyDecision{
			Source:       "direct",
			Bypassed:     true,
			BypassReason: fmt.Sprintf("NO_PROXY matched %q", entry),
		}, nil
	}

	var names []string
	switch strings.ToLower(target.Scheme) {
	case "http", "ws":
		names = []string{"HTTP_PROXY", "http_proxy"}
	case "https", "wss":
		names = []string{"HTTPS_PROXY", "https_proxy"}
	default:
		// ALL_PROXY is still useful for non-HTTP callers, such as a custom
		// resolver's HTTPS endpoint. There is no scheme-specific variable for
		// those requests.
		names = nil
	}

	if proxy, name := firstValidProxy(names); proxy != nil {
		return ProxyDecision{URL: proxy, Source: "environment " + name}, nil
	}
	if proxy, name := firstValidProxy([]string{"ALL_PROXY", "all_proxy"}); proxy != nil {
		return ProxyDecision{URL: proxy, Source: "environment " + name}, nil
	}
	if proxy := systemProxyForURL(target); proxy != nil {
		return ProxyDecision{URL: proxy, Source: "system"}, nil
	}

	return ProxyDecision{Source: "direct"}, nil
}

// ProxyFunc returns a net/http-compatible selector shared by all HTTP-based
// transports, including WebSocket, gRPC, DoH, and update requests.
func ProxyFunc(explicit *url.URL) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if req == nil {
			return nil, nil
		}
		return ProxyForURL(explicit, req.URL)
	}
}

func firstValidProxy(names []string) (*url.URL, string) {
	for _, name := range names {
		if name == "HTTP_PROXY" && strings.TrimSpace(getenv("REQUEST_METHOD")) != "" {
			// HTTP_PROXY is unsafe in CGI environments because it can be
			// supplied by an untrusted HTTP header.
			continue
		}
		value := strings.TrimSpace(getenv(name))
		if value == "" {
			continue
		}
		proxy, err := url.Parse(value)
		if err != nil {
			continue
		}
		proxy, err = validateProxyURL(proxy)
		if err != nil {
			// A malformed higher-precedence variable must not prevent a
			// valid lower-precedence variable or ALL_PROXY from being used.
			continue
		}
		return proxy, name
	}
	return nil, ""
}

// Keep environment access replaceable in package tests without changing the
// public selector API.
var getenv = os.Getenv

func environmentValue(upper, lower string) string {
	if value := strings.TrimSpace(getenv(upper)); value != "" {
		return value
	}
	return strings.TrimSpace(getenv(lower))
}

func validateProxyURL(proxy *url.URL) (*url.URL, error) {
	if proxy == nil {
		return nil, nil
	}
	if proxy.Scheme == "" {
		return nil, fmt.Errorf("proxy URL has no scheme")
	}
	scheme := strings.ToLower(proxy.Scheme)
	switch scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", proxy.Scheme)
	}
	if proxy.Hostname() == "" {
		return nil, fmt.Errorf("proxy URL has no host")
	}
	if proxy.Fragment != "" {
		return nil, fmt.Errorf("proxy URL must not contain a fragment")
	}
	if rawPort := proxy.Port(); rawPort != "" {
		port, err := strconv.Atoi(rawPort)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("proxy URL has invalid port %q", rawPort)
		}
	}
	copy := *proxy
	copy.Scheme = scheme
	return &copy, nil
}

func noProxyMatchesURL(target *url.URL, value string) (bool, string) {
	if target == nil || strings.TrimSpace(value) == "" {
		return false, ""
	}
	host := target.Hostname()
	if host == "" {
		return false, ""
	}
	normalizedHost, hostIP, ok := normalizeHost(host)
	if !ok {
		return false, ""
	}
	port, hasPort := URLPort(target)
	for _, raw := range strings.Split(value, ",") {
		entryText := strings.TrimSpace(raw)
		if entryText == "" {
			continue
		}
		if entryText == "*" {
			return true, entryText
		}
		entry, ok := parseNoProxyEntry(entryText)
		if !ok || (entry.port != 0 && (!hasPort || entry.port != port)) {
			continue
		}
		if noProxyHostMatches(normalizedHost, hostIP, entry.host) {
			return true, entryText
		}
	}
	return false, ""
}

type noProxyEntry struct {
	host string
	port int
}

func parseNoProxyEntry(raw string) (noProxyEntry, bool) {
	if raw == "" {
		return noProxyEntry{}, false
	}
	if strings.HasPrefix(raw, "[") {
		close := strings.IndexByte(raw, ']')
		if close <= 1 {
			return noProxyEntry{}, false
		}
		host := raw[1:close]
		tail := raw[close+1:]
		if tail == "" {
			return noProxyEntry{host: host}, true
		}
		if !strings.HasPrefix(tail, ":") {
			return noProxyEntry{}, false
		}
		port, ok := parseProxyPort(tail[1:])
		return noProxyEntry{host: host, port: port}, ok
	}

	// An unbracketed IPv6 address contains more than one colon and therefore
	// cannot have a port qualifier. IPv4 and host names may use host:port.
	if strings.Count(raw, ":") == 1 {
		host, portText, _ := strings.Cut(raw, ":")
		port, ok := parseProxyPort(portText)
		if host == "" || !ok {
			return noProxyEntry{}, false
		}
		return noProxyEntry{host: host, port: port}, true
	}
	return noProxyEntry{host: raw}, true
}

func parseProxyPort(value string) (int, bool) {
	port, err := strconv.Atoi(value)
	return port, err == nil && port > 0 && port <= 65535
}

func URLPort(target *url.URL) (int, bool) {
	if target == nil {
		return 0, false
	}
	if raw := target.Port(); raw != "" {
		port, err := strconv.Atoi(raw)
		return port, err == nil && port > 0 && port <= 65535
	}
	switch strings.ToLower(target.Scheme) {
	case "http", "ws":
		return 80, true
	case "https", "wss":
		return 443, true
	default:
		return 0, false
	}
}

func normalizeHost(host string) (string, net.IP, bool) {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return "", nil, false
	}
	if ip := net.ParseIP(strings.TrimSuffix(host, ".")); ip != nil {
		return strings.ToLower(strings.TrimSuffix(host, ".")), ip, true
	}
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(host, "."))
	if err != nil || ascii == "" {
		return "", nil, false
	}
	return strings.ToLower(ascii), nil, true
}

func noProxyHostMatches(host string, hostIP net.IP, entryHost string) bool {
	entryHost = strings.TrimSpace(entryHost)
	if entryHost == "" {
		return false
	}
	if hostIP != nil {
		if _, network, err := net.ParseCIDR(entryHost); err == nil && network.Contains(hostIP) {
			return true
		}
		entryIP := net.ParseIP(strings.Trim(entryHost, "[]"))
		return entryIP != nil && entryIP.Equal(hostIP)
	}
	if strings.Contains(entryHost, "/") {
		return false
	}
	normalized, entryIP, ok := normalizeHost(entryHost)
	if !ok || entryIP != nil {
		return false
	}
	normalized = strings.TrimPrefix(normalized, ".")
	return host == normalized || strings.HasSuffix(host, "."+normalized)
}
