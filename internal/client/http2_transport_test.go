package client

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestHTTP2TransportUsesStandardTLSHTTP2(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "https-http2")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	client := NewClient(ClientConfig{HTTP: core.HTTP2, Insecure: true})
	defer client.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("response protocol = %s, want HTTP/2", resp.Proto)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "https-http2" {
		t.Fatalf("response body = %q, want https-http2", body)
	}
}

func TestH2CTransportUsesStandardUnencryptedHTTP2(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "h2c")
	}))
	server.Config.Protocols = &http.Protocols{}
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	defer server.Close()

	client := NewClient(ClientConfig{HTTP: core.HTTP2, H2C: true})
	defer client.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("response protocol = %s, want HTTP/2", resp.Proto)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "h2c" {
		t.Fatalf("response body = %q, want h2c", body)
	}
}

func TestHTTP2TransportUsesHTTPProxyCONNECT(t *testing.T) {
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "proxied-http2")
	}))
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()

	proxy := startHTTPConnectProxy(t)
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}

	client := NewClient(ClientConfig{HTTP: core.HTTP2, Insecure: true, Proxy: proxyURL})
	defer client.Close()

	req, err := http.NewRequest(http.MethodGet, target.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("response protocol = %s, want HTTP/2", resp.Proto)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "proxied-http2" {
		t.Fatalf("response body = %q, want proxied-http2", body)
	}
}

func TestH2CTransportUsesHTTPProxyCONNECT(t *testing.T) {
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "proxied-h2c")
	}))
	target.Config.Protocols = &http.Protocols{}
	target.Config.Protocols.SetUnencryptedHTTP2(true)
	target.Start()
	defer target.Close()

	proxy := startHTTPConnectProxy(t)
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}

	client := NewClient(ClientConfig{HTTP: core.HTTP2, H2C: true, Proxy: proxyURL})
	defer client.Close()

	req, err := http.NewRequest(http.MethodGet, target.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("response protocol = %s, want HTTP/2", resp.Proto)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "proxied-h2c" {
		t.Fatalf("response body = %q, want proxied-h2c", body)
	}
}

func startHTTPConnectProxy(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("proxy ResponseWriter does not support hijacking")
			return
		}
		proxyConn, _, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("proxy hijack: %v", err)
			return
		}
		targetConn, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			_, _ = io.WriteString(proxyConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			_ = proxyConn.Close()
			return
		}
		_, _ = io.WriteString(proxyConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() {
			_, _ = io.Copy(targetConn, proxyConn)
			_ = targetConn.Close()
			_ = proxyConn.Close()
		}()
		go func() {
			_, _ = io.Copy(proxyConn, targetConn)
			_ = targetConn.Close()
			_ = proxyConn.Close()
		}()
	}))
}
