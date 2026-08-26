package resolver

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// ResolveEntry is a static host-to-address mapping supplied by --resolve.
// Host and Port are the request authority; IP is used only for the first hop.
type ResolveEntry struct {
	Host string
	Port string
	IP   net.IP
}

// ParseResolve parses one curl HOST:PORT:IP mapping. Use ParseResolveEntries
// when the address component may contain multiple comma-separated addresses.
func ParseResolve(value string) (ResolveEntry, error) {
	entries, err := ParseResolveEntries(value)
	if err != nil {
		return ResolveEntry{}, err
	}
	if len(entries) != 1 {
		return ResolveEntry{}, fmt.Errorf("multiple addresses require ParseResolveEntries")
	}
	return entries[0], nil
}

// ParseResolveEntries parses curl's HOST:PORT:IP[,IP] mapping syntax. The
// optional leading '+' is accepted for compatibility with curl's expiring
// resolve entries; this client keeps entries for the lifetime of the request.
func ParseResolveEntries(value string) ([]ResolveEntry, error) {
	if value == "" {
		return nil, fmt.Errorf("value is empty")
	}
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return nil, fmt.Errorf("value must not contain leading/trailing whitespace or control characters")
	}
	if strings.HasPrefix(value, "+") {
		value = value[1:]
		if value == "" {
			return nil, fmt.Errorf("value is empty")
		}
	}
	host, port, addresses, err := splitResolveValue(value)
	if err != nil {
		return nil, err
	}
	ipValues, err := splitResolveAddresses(addresses)
	if err != nil {
		return nil, err
	}
	entries := make([]ResolveEntry, 0, len(ipValues))
	for _, ipText := range ipValues {
		entry, err := parseResolveParts(host, port, ipText)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func parseResolveParts(host, port, ipText string) (ResolveEntry, error) {
	if host == "" {
		return ResolveEntry{}, fmt.Errorf("host is empty")
	}
	if host != "*" {
		if strings.Contains(host, "*") || strings.ContainsAny(host, "/?#[]") || strings.IndexFunc(host, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) >= 0 || (net.ParseIP(host) == nil && strings.Contains(host, ":")) {
			return ResolveEntry{}, fmt.Errorf("invalid host %q", host)
		}
	}

	if port == "" {
		return ResolveEntry{}, fmt.Errorf("port is empty")
	}
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return ResolveEntry{}, fmt.Errorf("invalid port %q", port)
		}
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return ResolveEntry{}, fmt.Errorf("invalid port %q", port)
	}

	if strings.HasPrefix(ipText, "[") {
		if !strings.HasSuffix(ipText, "]") {
			return ResolveEntry{}, fmt.Errorf("invalid IP address %q", ipText)
		}
		ipText = ipText[1 : len(ipText)-1]
	} else if strings.ContainsAny(ipText, "[]") || strings.Contains(ipText, ":") {
		return ResolveEntry{}, fmt.Errorf("invalid IP address %q", ipText)
	}
	ip := net.ParseIP(ipText)
	if ip == nil {
		return ResolveEntry{}, fmt.Errorf("invalid IP address %q", ipText)
	}

	if host != "*" {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if host == "" {
			return ResolveEntry{}, fmt.Errorf("host is empty")
		}
	}
	return ResolveEntry{Host: host, Port: strconv.FormatUint(portNumber, 10), IP: append(net.IP(nil), ip...)}, nil
}

func splitResolveAddresses(value string) ([]string, error) {
	values := make([]string, 0, 1)
	start := 0
	brackets := 0
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '[':
			brackets++
		case ']':
			if brackets == 0 {
				return nil, fmt.Errorf("invalid closing bracket")
			}
			brackets--
		case ',':
			if brackets != 0 {
				continue
			}
			if i > start {
				values = append(values, value[start:i])
			}
			start = i + 1
		}
	}
	if brackets != 0 {
		return nil, fmt.Errorf("invalid bracketed address")
	}
	if start < len(value) {
		values = append(values, value[start:])
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("IP address is empty")
	}
	return values, nil
}

func splitResolveValue(value string) (host, port, ip string, err error) {
	rest := value
	if strings.HasPrefix(rest, "[") {
		close := strings.IndexByte(rest, ']')
		if close < 0 {
			return "", "", "", fmt.Errorf("invalid bracketed host")
		}
		host = rest[1:close]
		rest = rest[close+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", "", "", fmt.Errorf("must be in the format HOST:PORT:IP")
		}
		rest = rest[1:]
	} else {
		idx := strings.IndexByte(rest, ':')
		if idx < 0 {
			return "", "", "", fmt.Errorf("must be in the format HOST:PORT:IP")
		}
		host = rest[:idx]
		rest = rest[idx+1:]
	}
	idx := strings.IndexByte(rest, ':')
	if idx < 0 {
		return "", "", "", fmt.Errorf("must be in the format HOST:PORT:IP")
	}
	port, ip = rest[:idx], rest[idx+1:]
	if ip == "" {
		return "", "", "", fmt.Errorf("IP address is empty")
	}
	return host, port, ip, nil
}
