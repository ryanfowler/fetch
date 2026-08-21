package resolver

import (
	"net"
	"strings"
	"testing"
)

func TestParseEndpointValidForms(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		transport Transport
		host      string
		port      uint16
		path      string
		query     string
		verified  bool
	}{
		{"bare IPv4", "1.1.1.1", TransportUDP, "1.1.1.1", 53, "", "", false},
		{"bare IPv6", "[2001:db8::1]", TransportUDP, "2001:db8::1", 53, "", "", false},
		{"hostname", "resolver.example:5353", TransportUDP, "resolver.example", 5353, "", "", false},
		{"udp", "UDP://resolver.example:5300", TransportUDP, "resolver.example", 5300, "", "", false},
		{"tcp", "tcp://resolver.example", TransportTCP, "resolver.example", 53, "", "", false},
		{"dot", "DoT://resolver.example", TransportTLS, "resolver.example", 853, "", "", true},
		{"doq", "doq://[2001:db8::53]:8853", TransportQUIC, "2001:db8::53", 8853, "", "", true},
		{"doh", "https://resolver.example/dns-query?edns=1", TransportHTTPS, "resolver.example", 443, "/dns-query", "edns=1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := ParseEndpoint(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if ep.Transport != tt.transport || ep.ConnectHost != tt.host || ep.Port != tt.port {
				t.Fatalf("endpoint = %#v, want %s %s:%d", ep, tt.transport, tt.host, tt.port)
			}
			if ep.Path != tt.path || ep.RawQuery != tt.query || ep.VerifyTLS != tt.verified {
				t.Fatalf("path/query/verification = %q/%q/%t", ep.Path, ep.RawQuery, ep.VerifyTLS)
			}
			if tt.host == "resolver.example" && len(ep.BootstrapAddrs) != 0 {
				t.Fatalf("hostname endpoint unexpectedly has bootstrap addresses: %v", ep.BootstrapAddrs)
			}
			if net.ParseIP(tt.host) != nil && len(ep.BootstrapAddrs) != 1 {
				t.Fatalf("IP endpoint bootstrap addresses = %v, want one", ep.BootstrapAddrs)
			}
			if ep.String() == "" || strings.Contains(ep.String(), "@") {
				t.Fatalf("invalid display form %q", ep.String())
			}
		})
	}
}

func TestParseEndpointRejectsInvalidValues(t *testing.T) {
	values := []string{
		"",
		" http://resolver.example",
		"http://resolver.example/dns-query",
		"ftp://resolver.example",
		"udp://",
		"udp://resolver.example:0",
		"udp://resolver.example:65536",
		"udp://resolver.example:abc",
		"udp://resolver.example/path",
		"udp://resolver.example?name=x",
		"udp://user:pass@resolver.example",
		"udp://resolver.example#fragment",
		"[2001:db8::1",
		"2001:db8::1",
		"resolver.example:",
		"resolver.example/extra",
	}
	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			_, err := ParseEndpoint(value)
			if err == nil {
				t.Fatalf("ParseEndpoint(%q) succeeded", value)
			}
			if !strings.Contains(err.Error(), value) {
				t.Fatalf("error %q does not identify endpoint value %q", err, value)
			}
		})
	}
}

func TestParseEndpointURLAllowsOnlyExplicitInsecureTestDoH(t *testing.T) {
	if _, err := ParseEndpoint("http://127.0.0.1/dns-query"); err == nil {
		t.Fatal("plain HTTP DoH endpoint accepted by production parser")
	}
	ep, err := ParseEndpointURL("http://127.0.0.1:8080/dns-query", true)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Transport != TransportHTTPS || ep.VerifyTLS || ep.Security != SecurityPlaintext {
		t.Fatalf("insecure test endpoint = %#v", ep)
	}
}

func TestEndpointURLPreservesDoHPathAndQuery(t *testing.T) {
	ep, err := ParseEndpoint("https://resolver.example/dns-query?foo=bar")
	if err != nil {
		t.Fatal(err)
	}
	u := ep.URL()
	if got, want := u.String(), "https://resolver.example:443/dns-query?foo=bar"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}
