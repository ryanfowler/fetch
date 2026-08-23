package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
)

func TestProxyTransportCarriesPerRequestSelection(t *testing.T) {
	proxyURL := &url.URL{Scheme: "https", Host: "proxy.example:443"}
	base := h3RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		selected, ok := selectedProxy(req.Context())
		if !ok {
			return nil, fmt.Errorf("proxy selection is missing from request context")
		}
		if req.URL.Host == "proxied.example" && selected != proxyURL {
			return nil, fmt.Errorf("selected proxy = %v, want %v", selected, proxyURL)
		}
		if req.URL.Host == "direct.example" && selected != nil {
			return nil, fmt.Errorf("selected proxy = %v, want nil", selected)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})
	transport := &proxyTransport{
		base: base,
		selectProxy: func(req *http.Request) (*url.URL, error) {
			if req.URL.Host == "proxied.example" {
				return proxyURL, nil
			}
			return nil, nil
		},
	}

	for _, host := range []string{"proxied.example", "direct.example"} {
		req, err := http.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}

func TestProxyTransportCarriesConcurrentSelections(t *testing.T) {
	proxyURLs := map[string]*url.URL{
		"one.example": {Scheme: "http", Host: "proxy-one.example:8080"},
		"two.example": {Scheme: "http", Host: "proxy-two.example:8080"},
	}
	base := &http.Transport{}
	base.Proxy = func(req *http.Request) (*url.URL, error) {
		selected, ok := selectedProxy(req.Context())
		if !ok {
			return nil, fmt.Errorf("proxy selection is missing from request context")
		}
		return selected, nil
	}
	type dialObservation struct {
		proxy   *url.URL
		address string
	}
	observed := make(chan dialObservation, len(proxyURLs))
	started := make(chan struct{}, len(proxyURLs))
	release := make(chan struct{})
	base.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		selected, ok := selectedProxy(ctx)
		if !ok {
			return nil, fmt.Errorf("proxy selection is missing from dial context")
		}
		observed <- dialObservation{proxy: selected, address: address}
		started <- struct{}{}
		<-release
		return nil, fmt.Errorf("stop test dial")
	}
	defer base.CloseIdleConnections()

	transport := &proxyTransport{
		base: base,
		selectProxy: func(req *http.Request) (*url.URL, error) {
			return proxyURLs[req.URL.Hostname()], nil
		},
	}
	errs := make(chan error, len(proxyURLs))
	for host := range proxyURLs {
		req, err := http.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			_, err := transport.RoundTrip(req)
			errs <- err
		}()
	}
	for range proxyURLs {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("concurrent requests did not reach the dialer")
		}
	}
	close(release)
	for range proxyURLs {
		if err := <-errs; err == nil {
			t.Fatal("request succeeded, want dial error")
		}
	}

	seen := map[string]bool{}
	for range proxyURLs {
		observation := <-observed
		if observation.address != canonicalProxyAddress(observation.proxy) {
			t.Errorf("dial address = %q for proxy %s, want %q", observation.address, observation.proxy, canonicalProxyAddress(observation.proxy))
		}
		seen[observation.proxy.String()] = true
	}
	for host, proxy := range proxyURLs {
		if !seen[proxy.String()] {
			t.Errorf("request for %s did not use proxy %s", host, proxy)
		}
	}
}

func TestHTTPProxyUsesAbsoluteForm(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.IsAbs() == false || r.URL.Host != "origin.example" {
			t.Errorf("proxy request URL = %q, want absolute origin URL", r.URL)
		}
		_, _ = io.WriteString(w, "through http proxy")
	}))
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	c := NewClient(ClientConfig{Proxy: proxyURL, HTTP: core.HTTP1})
	defer c.Close()
	req, err := c.NewRequest(context.Background(), RequestConfig{URL: mustURL(t, "http://origin.example/path")})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "through http proxy" {
		t.Fatalf("body = %q", body)
	}
}

func TestHTTPSProxyDoesNotUseOriginInsecureSetting(t *testing.T) {
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted HTTPS proxy should not receive a request")
	}))
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	c := NewClient(ClientConfig{Proxy: proxyURL, Insecure: true, HTTP: core.HTTP1})
	defer c.Close()
	req, err := c.NewRequest(context.Background(), RequestConfig{URL: mustURL(t, "http://origin.example/")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(req); err == nil || !strings.Contains(err.Error(), "HTTPS proxy TLS handshake") {
		t.Fatalf("Do error = %v, want proxy TLS verification error", err)
	}
}

func TestSOCKS5AndSOCKS5HAddressSemantics(t *testing.T) {
	tests := []struct {
		name       string
		scheme     string
		target     string
		wantATYP   byte
		wantLookup bool
	}{
		{name: "local IP", scheme: "socks5", target: "127.0.0.1", wantATYP: 1},
		{name: "proxy hostname", scheme: "socks5h", target: "service.example", wantATYP: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			seen := make(chan byte, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				var greeting [3]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil {
					return
				}
				_, _ = conn.Write([]byte{5, 0})
				header := make([]byte, 4)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				seen <- header[3]
				addressLength := 0
				if header[3] == 3 {
					var length [1]byte
					if _, err := io.ReadFull(conn, length[:]); err != nil {
						return
					}
					addressLength = int(length[0])
				} else {
					switch header[3] {
					case 1:
						addressLength = 4
					case 4:
						addressLength = 16
					default:
						return
					}
				}
				payload := make([]byte, addressLength+2)
				if _, err := io.ReadFull(conn, payload); err != nil {
					return
				}
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
				reader := bufio.NewReader(conn)
				request, err := http.ReadRequest(reader)
				if err == nil {
					_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
					_ = request.Body.Close()
				}
			}()

			proxyURL := &url.URL{Scheme: tt.scheme, Host: listener.Addr().String()}
			c := NewClient(ClientConfig{Proxy: proxyURL, HTTP: core.HTTP1})
			defer c.Close()
			req, err := c.NewRequest(context.Background(), RequestConfig{URL: mustURL(t, "http://"+tt.target+"/")})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			select {
			case atyp := <-seen:
				if atyp != tt.wantATYP {
					t.Fatalf("SOCKS address type = %d, want %d", atyp, tt.wantATYP)
				}
			case <-time.After(time.Second):
				t.Fatal("proxy did not receive a destination")
			}
		})
	}
}

func TestSOCKS5LocalResolutionUsesConfiguredResolver(t *testing.T) {
	proxyURL := &url.URL{Scheme: "socks5", Host: "127.0.0.1:1"}
	res := resolverForTest(t)
	dial := newSOCKS5Dialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("stop after destination resolution")
	}, res, proxyURL, true, 0)
	_, err := dial(context.Background(), "tcp", "service.example:80")
	if err == nil || !strings.Contains(err.Error(), "stop after destination resolution") {
		t.Fatalf("dial error = %v, want proxy dial after local resolution", err)
	}
}

func resolverForTest(t *testing.T) *resolver.Resolver {
	t.Helper()
	return resolver.New(resolver.Config{SystemLookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}, nil
	}})
}
