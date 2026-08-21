package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/resolver"
)

// unifiedProxyTransport selects a complete first-hop route per request. This
// avoids sharing proxy state between concurrent requests while retaining the
// standard HTTP transport's pooling and redirect behavior inside each route.
type unifiedProxyTransport struct {
	mu        sync.Mutex
	routes    map[string]*http.Transport
	explicit  *url.URL
	base      func(context.Context, string, string) (net.Conn, error)
	proxyBase func(context.Context, string, string) (net.Conn, error)
	res       *resolver.Resolver
	tls       *tls.Config
	timeout   time.Duration
}

func newUnifiedProxyTransport(cfg ClientConfig, base func(context.Context, string, string) (net.Conn, error), res *resolver.Resolver, tlsConfig *tls.Config) *unifiedProxyTransport {
	return &unifiedProxyTransport{
		routes:   make(map[string]*http.Transport),
		explicit: cfg.Proxy,
		base:     base,
		res:      res,
		tls:      tlsConfig,
		timeout:  cfg.ConnectTimeout,
	}
}

func (t *unifiedProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	selected, err := SelectProxy(t.explicit, req.URL)
	if err != nil {
		return nil, err
	}
	key := "direct"
	if selected.URL != nil {
		key = selected.URL.String()
	}
	rt := t.route(key, selected.URL)
	return rt.RoundTrip(req)
}

func (t *unifiedProxyTransport) route(key string, proxy *url.URL) *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	if rt := t.routes[key]; rt != nil {
		return rt
	}
	rt := &http.Transport{
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
		Protocols:          &http.Protocols{},
		TLSClientConfig:    t.tls,
	}
	var dial func(context.Context, string, string) (net.Conn, error)
	firstHop := t.base
	if proxy != nil && t.proxyBase != nil {
		firstHop = t.proxyBase
	}
	switch {
	case proxy == nil:
		dial = wrapDialWithConnectTimeout(firstHop, t.timeout)
	case strings.EqualFold(proxy.Scheme, "http"):
		rt.Proxy = http.ProxyURL(proxy)
		dial = wrapDialWithConnectTimeout(firstHop, t.timeout)
	case strings.EqualFold(proxy.Scheme, "https"):
		rt.Proxy = http.ProxyURL(httpsProxyAsHTTP(proxy))
		dial = newHTTPSProxyDialer(firstHop, proxy, t.timeout)
	case strings.EqualFold(proxy.Scheme, "socks5"), strings.EqualFold(proxy.Scheme, "socks5h"):
		dial = newSOCKS5Dialer(firstHop, t.res, proxy, strings.EqualFold(proxy.Scheme, "socks5"), t.timeout)
	default:
		dial = wrapDialWithConnectTimeout(firstHop, t.timeout)
	}
	rt.DialContext = dial
	rt.Protocols.SetHTTP1(true)
	rt.Protocols.SetHTTP2(true)
	t.routes[key] = rt
	return rt
}

func (t *unifiedProxyTransport) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, rt := range t.routes {
		rt.CloseIdleConnections()
	}
}

func (t *unifiedProxyTransport) Close() error {
	t.mu.Lock()
	routes := make([]*http.Transport, 0, len(t.routes))
	for _, rt := range t.routes {
		routes = append(routes, rt)
	}
	t.routes = make(map[string]*http.Transport)
	t.mu.Unlock()
	for _, rt := range routes {
		rt.CloseIdleConnections()
	}
	return nil
}

func useUnifiedProxyTransport(explicit *url.URL) bool {
	if explicit != nil {
		scheme := strings.ToLower(explicit.Scheme)
		return scheme == "https" || scheme == "socks5" || scheme == "socks5h"
	}
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		value := strings.TrimSpace(getenv(name))
		if value == "" {
			continue
		}
		u, err := url.Parse(value)
		if err == nil {
			scheme := strings.ToLower(u.Scheme)
			if scheme == "https" || scheme == "socks5" || scheme == "socks5h" {
				return true
			}
		}
	}
	return false
}

var _ http.RoundTripper = (*unifiedProxyTransport)(nil)
