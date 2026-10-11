package fetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
)

func TestSafeArticleImageURLRejectsNonPublicResolvedAddresses(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{name: "shared", ip: "100.100.100.200"},
		{name: "metadata", ip: "169.254.169.254"},
		{name: "documentation", ip: "192.0.2.10"},
		{name: "ipv6 documentation", ip: "2001:db8::10"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := url.Parse("https://images.example/photo.jpg")
			if err != nil {
				t.Fatal(err)
			}
			lookup := func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP(test.ip)}}, nil
			}
			if safeArticleImageURL(context.Background(), target, lookup) {
				t.Fatalf("safeArticleImageURL accepted %s", test.ip)
			}
		})
	}
}

func TestSafeArticleImageURLAcceptsPublicResolvedAddress(t *testing.T) {
	target, err := url.Parse("https://images.example/photo.jpg")
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.114.10")}}, nil
	}
	if !safeArticleImageURL(context.Background(), target, lookup) {
		t.Fatal("safeArticleImageURL rejected a public address")
	}
}

func TestArticleImageFetchScopesClientCertificate(t *testing.T) {
	tests := []struct {
		name        string
		pageURL     string
		imageURL    string
		certificate bool
		wantBlocked bool
		wantHits    int64
	}{
		{
			name: "same origin", pageURL: "https://example.com/article",
			imageURL: "https://example.com/image", certificate: true, wantHits: 1,
		},
		{
			name: "same origin redirect", pageURL: "https://example.com/article",
			imageURL: "https://example.com/relative-redirect", certificate: true, wantHits: 2,
		},
		{
			name: "different hostname", pageURL: "https://article.example.org/article",
			imageURL: "https://example.com/image", certificate: true, wantBlocked: true,
		},
		{
			name: "different port", pageURL: "https://example.com/article",
			imageURL: "https://example.com:8443/image", certificate: true, wantBlocked: true,
		},
		{
			name: "different scheme", pageURL: "http://example.com/article",
			imageURL: "https://example.com/image", certificate: true, wantBlocked: true,
		},
		{
			name: "cross origin redirect", pageURL: "https://example.com/article",
			imageURL: "https://example.com/cross-origin-redirect", certificate: true, wantBlocked: true, wantHits: 1,
		},
		{
			name: "cross origin without certificate", pageURL: "https://article.example.org/article",
			imageURL: "https://example.com/image", wantHits: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var handshakes, requests, certificateRequests atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if len(r.TLS.PeerCertificates) > 0 {
					certificateRequests.Add(1)
				}
				switch r.URL.Path {
				case "/relative-redirect":
					http.Redirect(w, r, "/image", http.StatusFound)
				case "/cross-origin-redirect":
					http.Redirect(w, r, "https://example.com:8443/image", http.StatusFound)
				default:
					_, _ = io.WriteString(w, "image bytes")
				}
			}))
			server.TLS = &tls.Config{
				ClientAuth: tls.RequestClientCert,
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					handshakes.Add(1)
					return nil, nil
				},
			}
			server.StartTLS()
			defer server.Close()

			// Route a public image URL to the local TLS fixture through a proxy.
			// This exercises the real TLS transport while preserving image URL
			// validation and avoiding the private-peer guard for local fixtures.
			proxy := newArticleImageTestProxy(t, server.Listener.Addr().String())
			proxyURL, err := url.Parse(proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			cfg := client.ClientConfig{
				HTTP: core.HTTP1, Proxy: proxyURL,
				CACerts: []*x509.Certificate{server.Certificate()},
				SystemLookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP("203.0.114.10")}}, nil
				},
			}
			if test.certificate {
				// The fixture requests any client certificate, so its test
				// certificate can also serve as the client's identity.
				cfg.ClientCert = &server.TLS.Certificates[0]
			}
			c := client.NewClient(cfg)
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			images := newArticleImageFetcher(ctx, c, core.ImageUnknown, test.pageURL)
			target, err := url.Parse(test.imageURL)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantBlocked && test.wantHits == 0 {
				if _, ok := images.resolve(test.imageURL); ok {
					t.Error("cross-origin image resolved with a client certificate configured")
				}
			}
			// Exercise fetch directly too: certificate safety must not depend
			// on the caller having resolved the image first.
			data, err := images.fetch(target)
			if test.wantBlocked {
				if err == nil || !strings.Contains(err.Error(), "cross-origin") {
					t.Errorf("fetch error = %v, want cross-origin refusal", err)
				}
			} else if err != nil || string(data) != "image bytes" {
				t.Errorf("fetch = %q, %v, want image bytes", data, err)
			}
			if got := requests.Load(); got != test.wantHits {
				t.Errorf("image requests = %d, want %d", got, test.wantHits)
			}
			wantCertificates := int64(0)
			if test.certificate {
				wantCertificates = test.wantHits
			}
			if got := certificateRequests.Load(); got != wantCertificates {
				t.Errorf("requests with client certificate = %d, want %d", got, wantCertificates)
			}
			if test.wantBlocked && test.wantHits == 0 && handshakes.Load() != 0 {
				t.Errorf("blocked image performed %d TLS handshakes", handshakes.Load())
			}
		})
	}
}

func newArticleImageTestProxy(t *testing.T, address string) *httptest.Server {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusBadRequest)
			return
		}
		upstream, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		downstream, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack proxy connection: %v", err)
			return
		}
		defer downstream.Close()
		if _, err := io.WriteString(downstream, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		go func() {
			_, _ = io.Copy(upstream, downstream)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(downstream, upstream)
	}))
	t.Cleanup(proxy.Close)
	return proxy
}
