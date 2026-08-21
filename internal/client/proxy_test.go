package client

import (
	"net/http"
	"net/url"
	"testing"
)

func TestSelectProxyPrecedenceAndSchemes(t *testing.T) {
	tests := []struct {
		name   string
		target string
		setup  map[string]string
		unset  []string
		want   string
	}{
		{
			name:   "http uppercase before lowercase",
			target: "http://service.example/",
			setup:  map[string]string{"HTTP_PROXY": "http://upper.example:8080", "http_proxy": "http://lower.example:8080"},
			want:   "http://upper.example:8080",
		},
		{
			name:   "https uses HTTPS proxy",
			target: "https://service.example/",
			setup:  map[string]string{"HTTP_PROXY": "http://wrong.example:8080", "HTTPS_PROXY": "http://secure.example:8080"},
			want:   "http://secure.example:8080",
		},
		{
			name:   "all proxy fallback",
			target: "https://service.example/",
			setup:  map[string]string{"ALL_PROXY": "socks5://all.example:1080"},
			want:   "socks5://all.example:1080",
		},
		{
			name:   "malformed higher precedence falls through",
			target: "http://service.example/",
			setup:  map[string]string{"HTTP_PROXY": "://bad", "http_proxy": "http://lower.example:8080"},
			want:   "http://lower.example:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{}
			for name, value := range tt.setup {
				env[name] = value
			}
			setProxyEnvironment(t, env)
			target := mustProxyURL(t, tt.target)
			got, err := ProxyForURL(nil, target)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || got.String() != tt.want {
				t.Fatalf("proxy = %v, want %q", got, tt.want)
			}
		})
	}
}

func TestSelectProxyCGIAndExplicitPrecedence(t *testing.T) {
	setProxyEnvironment(t, map[string]string{
		"HTTP_PROXY":     "http://unsafe.example:8080",
		"http_proxy":     "http://safe.example:8080",
		"REQUEST_METHOD": "GET",
	})

	got, err := ProxyForURL(nil, mustProxyURL(t, "http://service.example/"))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.String() != "http://safe.example:8080" {
		t.Fatalf("CGI proxy = %v, want lowercase HTTP_PROXY", got)
	}

	explicit := mustProxyURL(t, "http://explicit.example:8080")
	t.Setenv("NO_PROXY", "*")
	got, err = ProxyForURL(explicit, mustProxyURL(t, "https://service.example/"))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.String() != explicit.String() {
		t.Fatalf("explicit proxy = %v, want %v", got, explicit)
	}
}

func TestNoProxyMatching(t *testing.T) {
	tests := []struct {
		name   string
		target string
		value  string
		want   bool
	}{
		{"wildcard", "https://service.example/", "*", true},
		{"exact host", "https://service.example/", "service.example", true},
		{"subdomain", "https://a.service.example/", "service.example", true},
		{"leading dot", "https://a.service.example/", ".service.example", true},
		{"suffix boundary", "https://notservice.example/", "service.example", false},
		{"host port match", "https://service.example:8443/", "service.example:8443", true},
		{"host port mismatch", "https://service.example:8443/", "service.example:443", false},
		{"default port", "https://service.example/", "service.example:443", true},
		{"ipv4", "http://192.168.1.42/", "192.168.1.42", true},
		{"ipv4 cidr", "http://192.168.1.42/", "192.168.1.0/24", true},
		{"ipv4 cidr miss", "http://192.168.1.42/", "192.168.2.0/24", false},
		{"ipv6", "http://[fd00::42]/", "fd00::42", true},
		{"ipv6 cidr", "http://[fd00::42]/", "fd00::/8", true},
		{"ipv6 port", "http://[fd00::42]:8080/", "[fd00::42]:8080", true},
		{"idna", "https://xn--bcher-kva.example/", "bücher.example", true},
		{"malformed ignored", "https://service.example/", "not a valid entry,service.example", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := mustProxyURL(t, tt.target)
			got, _ := noProxyMatchesURL(target, tt.value)
			if got != tt.want {
				t.Fatalf("noProxyMatchesURL(%q, %q) = %v, want %v", tt.target, tt.value, got, tt.want)
			}
		})
	}
}

func TestMalformedNoProxyDoesNotDisableProxy(t *testing.T) {
	setProxyEnvironment(t, map[string]string{
		"HTTP_PROXY": "http://proxy.example:8080",
		"NO_PROXY":   "[broken,service.example:bad,other.example",
	})

	got, err := ProxyForURL(nil, mustProxyURL(t, "http://service.example/"))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.String() != "http://proxy.example:8080" {
		t.Fatalf("proxy = %v, want proxy despite malformed NO_PROXY entries", got)
	}
}

func TestSystemProxyParsing(t *testing.T) {
	settings := parseColonSettings("HTTPEnable : 1\nHTTPProxy : proxy.example\nHTTPPort : 8080\nExceptionsList : (\n  \"localhost\",\n  \".internal.example\",\n)\n")
	if settings["ExceptionsList"] != "localhost,.internal.example" {
		t.Fatalf("exceptions = %q", settings["ExceptionsList"])
	}
	arraySettings := parseColonSettings("ExceptionsList : <array> {\n  0 : localhost\n  1 : .internal.example\n}\n")
	if arraySettings["ExceptionsList"] != "localhost,.internal.example" {
		t.Fatalf("scutil exceptions = %q", arraySettings["ExceptionsList"])
	}
	proxy := makeSystemProxy("[::1]", 8080)
	if proxy == nil || proxy.String() != "http://[::1]:8080" {
		t.Fatalf("proxy = %v, want bracketed IPv6 proxy", proxy)
	}
}

func TestProxyFuncUsesRequestURL(t *testing.T) {
	setProxyEnvironment(t, map[string]string{"HTTP_PROXY": "http://proxy.example:8080"})
	proxy := ProxyFunc(nil)
	req, err := http.NewRequest(http.MethodGet, "http://service.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := proxy(req)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Host != "proxy.example:8080" {
		t.Fatalf("proxy = %v, want proxy.example:8080", got)
	}
}

func setProxyEnvironment(t *testing.T, values map[string]string) {
	t.Helper()
	previous := getenv
	getenv = func(name string) string { return values[name] }
	t.Cleanup(func() { getenv = previous })
}

func mustProxyURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
