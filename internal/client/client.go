package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/resolver"

	"github.com/google/brotli/go/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// Client represents a wrapped HTTP client.
type Client struct {
	c            *http.Client
	maxRedirects int
	initErr      error
	proxy        *url.URL
	httpVersion  core.HTTPVersion
	echMode      core.ECHMode
	resolver     *resolver.Resolver
}

// RedirectHop represents a single redirect in the chain.
type RedirectHop struct {
	Request     *http.Request  // The request that triggered the redirect
	Response    *http.Response // The redirect response (e.g., 302)
	NextRequest *http.Request  // The new request about to be made
}

// RedirectCallback is called when a redirect occurs.
type RedirectCallback func(hop RedirectHop)

// RedirectValidator can reject a redirect before the next request is sent.
// It is useful for narrow clients, such as the updater, that need a stricter
// redirect policy than ordinary fetch requests.
type RedirectValidator func(hop RedirectHop) error

// RequestObserver is called immediately before a request is sent and for
// every request created by a redirect. Observers may replace the request body
// and mutate the request context.
type RequestObserver func(req *http.Request)

// ctxRedirectCallbackKeyType is the context key type for storing redirect callback.
type ctxRedirectCallbackKeyType int

const (
	ctxRedirectCallbackKey  ctxRedirectCallbackKeyType = 1
	ctxRequestObserverKey   ctxRedirectCallbackKeyType = 2
	ctxRedirectCrossedKey   ctxRedirectCallbackKeyType = 3
	ctxOriginCookiesKey     ctxRedirectCallbackKeyType = 4
	ctxConnectBudgetKey     ctxRedirectCallbackKeyType = 5
	ctxRedirectValidatorKey ctxRedirectCallbackKeyType = 6
)

// WithRedirectCallback returns a context with a redirect callback.
func WithRedirectCallback(ctx context.Context, cb RedirectCallback) context.Context {
	return context.WithValue(ctx, ctxRedirectCallbackKey, cb)
}

// WithRedirectValidator returns a context that validates each redirect before
// the client sends the redirected request.
func WithRedirectValidator(ctx context.Context, validator RedirectValidator) context.Context {
	if validator == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxRedirectValidatorKey, validator)
}

// WithRequestObserver attaches an observer to a request context. The
// transport invokes it for the initial request and redirect requests. When an
// observer is already present, the new observer runs first. This lets request
// signing happen before observers record the effective request.
func WithRequestObserver(ctx context.Context, observer RequestObserver) context.Context {
	if observer == nil {
		return ctx
	}
	if existing := requestObserver(ctx); existing != nil {
		newObserver := observer
		observer = func(req *http.Request) {
			newObserver(req)
			existing(req)
		}
	}
	return context.WithValue(ctx, ctxRequestObserverKey, observer)
}

func requestObserver(ctx context.Context) RequestObserver {
	observer, _ := ctx.Value(ctxRequestObserverKey).(RequestObserver)
	return observer
}

// WithConnectBudget associates one absolute connection-establishment budget
// with a request. Dialers use it for DNS, proxy setup, TCP, TLS, and QUIC so
// a retry cannot restart the connection timeout.
func WithConnectBudget(ctx context.Context, budget core.Budget) context.Context {
	return context.WithValue(ctx, ctxConnectBudgetKey, budget)
}

func connectContext(ctx context.Context, timeout time.Duration, phase string) (context.Context, context.CancelFunc) {
	if budget, ok := ctx.Value(ctxConnectBudgetKey).(core.Budget); ok && budget.Limited() {
		return budget.WithConnectionContext(ctx, phase)
	}
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	cause := core.TimeoutError{Duration: timeout, Phase: phase, Connection: true}
	return context.WithTimeoutCause(ctx, timeout, cause)
}

// ClientConfig represents the optional configuration parameters for a Client.
type ClientConfig struct {
	CACerts        []*x509.Certificate
	ClientCert     *tls.Certificate
	ConnectTimeout time.Duration
	// ResolverEndpoint is the validated endpoint from CLI/config parsing.
	// DNSServer remains for compatibility with direct internal callers/tests.
	ResolverEndpoint *resolver.Endpoint
	DNSServer        *url.URL
	// SystemLookupIPAddr is a test hook for deterministic proxy destination
	// resolution. Production callers leave it nil.
	SystemLookupIPAddr func(context.Context, string) ([]net.IPAddr, error)
	H2C                bool
	HTTP               core.HTTPVersion
	Insecure           bool
	Proxy              *url.URL
	Redirects          *int
	TLSMax             uint16
	TLSMin             uint16
	UnixSocket         string
	ECH                core.ECHMode
}

// NewClient returns an initialized Client given the provided configuration.
func NewClient(cfg ClientConfig) *Client {
	proxy := ProxyFunc(cfg.Proxy)

	// Build TLS config and dial function from shared configuration.
	tlsDialCfg := &TLSDialConfig{
		CACerts:    cfg.CACerts,
		ClientCert: cfg.ClientCert,
		Insecure:   cfg.Insecure,
		TLSMax:     cfg.TLSMax,
		TLSMin:     cfg.TLSMin,
	}
	tlsConfig := tlsDialCfg.BuildTLSConfig()
	res := resolver.New(resolver.Config{
		Endpoint:           cfg.ResolverEndpoint,
		Server:             cfg.DNSServer,
		SystemLookupIPAddr: cfg.SystemLookupIPAddr,
		Proxy:              proxy,
		TLSConfig:          tlsConfig,
		CACerts:            cfg.CACerts,
		ClientCert:         cfg.ClientCert,
		Insecure:           cfg.Insecure,
		TLSMin:             cfg.TLSMin,
		TLSMax:             cfg.TLSMax,
	})
	dialer := NewResolverDialer(res, cfg.ConnectTimeout)
	baseDial := dialer.DialContext
	proxyState := &proxyTransportState{}

	if cfg.UnixSocket != "" {
		baseDial = func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", cfg.UnixSocket)
		}
	}

	// Create the http.RoundTripper based on the configured HTTP version.
	var transport http.RoundTripper
	switch cfg.HTTP {
	case core.HTTP2:
		if cfg.H2C {
			transport = getH2CTransport(baseDial, res, cfg.Proxy, cfg.ConnectTimeout)
		} else {
			transport = getHTTP2Transport(baseDial, res, cfg.Proxy, tlsConfig, cfg.ConnectTimeout, cfg.ECH)
		}
	case core.HTTP3:
		transport = getHTTP3Transport(res, tlsConfig, cfg.ConnectTimeout, cfg.ECH)
	default:
		if useUnifiedProxyTransport(cfg.Proxy) {
			transport = newUnifiedProxyTransport(cfg, baseDial, res, tlsConfig)
			break
		}
		rt := &http.Transport{
			DisableCompression: true,
			ForceAttemptHTTP2:  cfg.HTTP != core.HTTP1,
			Protocols:          &http.Protocols{},
			TLSClientConfig:    tlsConfig.Clone(),
		}
		if cfg.ECH != core.ECHUnknown && cfg.ECH != core.ECHOff && cfg.Proxy == nil {
			// A custom TLS dial is required because net/http otherwise creates
			// the tls.Config before the resolver can supply the origin's ECH
			// configuration. Proxy-specific ECH wiring belongs to the proxy
			// transport integration and must not weaken its certificate checks.
			rt.DialTLSContext = newECHHTTPDialTLS(baseDial, res, tlsConfig, cfg.ECH, cfg.ConnectTimeout, cfg.HTTP)
		}

		// net/http provides the HTTP proxy CONNECT machinery, but its SOCKS
		// implementation treats socks5 and socks5h identically. It also uses
		// the origin TLS configuration for an HTTPS proxy. Keep the transport
		// as the single HTTP implementation, and replace only the first-hop
		// dial for the schemes whose semantics need to be explicit.
		transportProxy := func(req *http.Request) (*url.URL, error) {
			proxyState.forgetTarget(req.URL)
			proxyState.clearHTTPS()
			selected, err := proxy(req)
			if err != nil || selected == nil {
				return selected, err
			}
			switch strings.ToLower(selected.Scheme) {
			case "https":
				proxyState.remember(selected)
				return httpsProxyAsHTTP(selected), nil
			case "socks5", "socks5h":
				// SOCKS destinations are carried by DialContext rather than
				// net/http's SOCKS implementation so socks5 can resolve
				// locally and socks5h can preserve the hostname.
				proxyState.rememberSocks(req.URL, selected)
				return nil, nil
			default:
				return selected, nil
			}
		}
		dial := wrapDialWithConnectTimeout(baseDial, cfg.ConnectTimeout)
		if cfg.ConnectTimeout <= 0 {
			dial = baseDial
		}
		if cfg.Proxy != nil {
			switch strings.ToLower(cfg.Proxy.Scheme) {
			case "socks5", "socks5h":
				transportProxy = func(*http.Request) (*url.URL, error) { return nil, nil }
				dial = newSOCKS5Dialer(baseDial, res, cfg.Proxy, strings.EqualFold(cfg.Proxy.Scheme, "socks5"), cfg.ConnectTimeout)
			case "https":
				transportProxy = func(*http.Request) (*url.URL, error) {
					return httpsProxyAsHTTP(cfg.Proxy), nil
				}
				dial = newHTTPSProxyDialer(baseDial, cfg.Proxy, cfg.ConnectTimeout)
			default:
				transportProxy = proxy
			}
		}
		if cfg.Proxy == nil {
			// Environment HTTPS proxies are recorded by transportProxy and
			// upgraded in the dial path without changing the public
			// *http.Transport type used by existing callers.
			wrappedDial := dial
			dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				if selected, socks := proxyState.lookup(address); selected != nil {
					if socks {
						return newSOCKS5Dialer(baseDial, res, selected, strings.EqualFold(selected.Scheme, "socks5"), cfg.ConnectTimeout)(ctx, network, address)
					}
					return newHTTPSProxyDialer(baseDial, selected, cfg.ConnectTimeout)(ctx, network, address)
				}
				return wrappedDial(ctx, network, address)
			}
		}
		rt.Proxy = transportProxy
		rt.DialContext = dial
		rt.Protocols.SetHTTP1(true)
		rt.Protocols.SetHTTP2(cfg.HTTP != core.HTTP1)
		transport = rt
		// Automatic HTTP/3 is only safe for direct HTTPS requests. The
		// wrapper delegates HTTP, proxy, and Unix-socket requests to this
		// ordinary transport, and prepares exactly one complete TCP/TLS or
		// QUIC connection before sending an eligible request.
		if cfg.HTTP == core.HTTPDefault && cfg.Proxy == nil && cfg.UnixSocket == "" {
			// Environment-selected proxies are not eligible for automatic H3.
			// Keep the ordinary transport visible in that case so proxy setup
			// remains the single source of truth.
			autoHTTPSProxy, httpsProxyErr := ProxyForURL(nil, &url.URL{Scheme: "https", Host: "example.com"})
			autoHTTPProxy, httpProxyErr := ProxyForURL(nil, &url.URL{Scheme: "http", Host: "example.com"})
			if httpsProxyErr == nil && httpProxyErr == nil && autoHTTPSProxy == nil && autoHTTPProxy == nil {
				transport = newAutomaticHTTP3Transport(rt, res, cfg.ConnectTimeout, tlsConfig, cfg.ECH)
			}
		}
	}

	// Set up the redirect handler. Cookie filtering is installed when a jar is
	// attached, because net/http adds jar cookies after CheckRedirect runs.
	client := &http.Client{Transport: transport}
	maxRedirects := 10
	if cfg.Redirects != nil {
		maxRedirects = *cfg.Redirects
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Do not inspect or replay a body when redirects are disabled or the
		// redirect limit has already been reached.
		if maxRedirects == 0 {
			return http.ErrUseLastResponse
		}
		if maxRedirects > 0 && len(via) > maxRedirects {
			return fmt.Errorf("exceeded maximum number of redirects: %d", maxRedirects)
		}

		// HTTP/2 has its own proxy-aware dialer. HTTP/3 still has no
		// supported proxy path; reject it before any connection attempt.
		if cfg.HTTP == core.HTTP3 {
			proxy, err := ProxyForURL(cfg.Proxy, req.URL)
			if err != nil {
				return err
			}
			if proxy != nil {
				return errors.New("HTTP/3 cannot be used with a proxy")
			}
		}

		// net/http applies its historical redirect policy before this callback:
		// it changes every non-GET/HEAD method to GET for 301/302/303 and drops
		// the body. Restore the fetch policy before observers inspect the next
		// request.
		if err := normalizeRedirectRequest(req, via); err != nil {
			return err
		}
		// A redirect URL is server-controlled. Never retain userinfo from a
		// Location header in the request URL or treat it as origin credentials.
		if req.URL != nil {
			req.URL.User = nil
		}

		// Apply the credential boundary after net/http has copied the initial
		// headers. The standard library compares host suffixes, but an HTTP
		// origin also includes scheme and port; credentials must not cross any
		// origin boundary.
		applyRedirectCredentialPolicy(req, via)

		// A redirect can change the TLS, resolver, proxy, or ECH scope. Rebuild
		// the transport before a cross-origin request so those settings are
		// evaluated for the destination rather than retained from the source.
		if len(via) > 0 && via[len(via)-1].URL != nil && req.URL != nil &&
			!SameOrigin(via[len(via)-1].URL, req.URL) {
			rebuilt := NewClient(cfg)
			if rebuilt.initErr != nil {
				return rebuilt.initErr
			}
			wrappedRedirectCredentials := false
			if _, ok := client.Transport.(*redirectCredentialTransport); ok {
				wrappedRedirectCredentials = true
			}
			if closer, ok := client.Transport.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
			client.Transport = rebuilt.c.Transport
			if wrappedRedirectCredentials {
				client.Transport = &redirectCredentialTransport{base: client.Transport}
			}
			res = rebuilt.resolver
		}

		// Call request observers after redirect normalization and credential
		// filtering. At this point net/http has already created the replay body
		// for the new request.
		if observer := requestObserver(req.Context()); observer != nil {
			observer(req)
		}
		// Build the redirect event after normalization and credential filtering.
		// Validators run before observers and before the next request is sent.
		if len(via) > 0 && req.Response != nil {
			hop := RedirectHop{
				Request:     via[len(via)-1],
				Response:    req.Response,
				NextRequest: req,
			}
			if validator, ok := req.Context().Value(ctxRedirectValidatorKey).(RedirectValidator); ok && validator != nil {
				if err := validator(hop); err != nil {
					return err
				}
			}
			if cb, ok := req.Context().Value(ctxRedirectCallbackKey).(RedirectCallback); ok && cb != nil {
				cb(hop)
			}
		}
		if len(via) > 0 && req.Response != nil &&
			(req.Response.StatusCode == http.StatusTemporaryRedirect || req.Response.StatusCode == http.StatusPermanentRedirect) &&
			req.GetBody == nil && req.Body != nil && req.Body != http.NoBody {
			return fmt.Errorf("cannot replay request body for redirect: %w", body.ErrNotReplayable)
		}

		return nil
	}

	var initErr error
	if useUnifiedProxyTransport(cfg.Proxy) {
		// DoH is constructed by the resolver before the application transport
		// exists. Replace it now so HTTPS proxy verification and SOCKS
		// hostname semantics are shared with ordinary requests. Proxy
		// endpoints themselves use platform bootstrap to avoid resolving a
		// DoH proxy through that same DoH endpoint.
		dohTransport := newUnifiedProxyTransport(cfg, baseDial, res, tlsConfig)
		dohTransport.proxyBase = func(ctx context.Context, network, address string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		}
		initErr = res.SetRoundTripper(dohTransport)
	}
	if cfg.HTTP == core.HTTP3 && cfg.Proxy != nil {
		initErr = errors.New("HTTP/3 cannot be used with a proxy")
	}
	if initErr == nil {
		initErr = core.ValidateTLSVersions(cfg.TLSMin, cfg.TLSMax)
	}
	if initErr == nil && cfg.H2C && cfg.ECH != core.ECHUnknown && cfg.ECH != core.ECHOff {
		initErr = errors.New("ECH cannot be used with cleartext HTTP/2")
	}
	if initErr == nil {
		initErr = core.ValidateECHPolicy(cfg.ECH, cfg.HTTP, cfg.TLSMin, cfg.TLSMax)
	}
	if initErr == nil && cfg.HTTP == core.HTTP3 && cfg.TLSMax != 0 && cfg.TLSMax < tls.VersionTLS13 {
		initErr = errors.New("HTTP/3 requires max-tls 1.3 or higher")
	}
	return &Client{
		c:            client,
		maxRedirects: maxRedirects,
		initErr:      initErr,
		proxy:        cfg.Proxy,
		httpVersion:  cfg.HTTP,
		echMode:      cfg.ECH,
		resolver:     res,
	}
}

// connectDeadlineConn keeps the connection-establishment deadline after the
// dial function returns. This covers the HTTPS proxy CONNECT and origin TLS
// handshake that net/http performs after DialContext returns. The deadline is
// cleared when the first non-CONNECT request is written or when an encrypted
// application record is written after CONNECT, so it does not limit the body.
type connectDeadlineConn struct {
	net.Conn
	mu           sync.Mutex
	cleared      bool
	proxyConnect bool
}

func newConnectDeadlineConn(conn net.Conn, ctx context.Context) net.Conn {
	if conn == nil {
		return nil
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return conn
	}
	_ = conn.SetDeadline(deadline)
	return &connectDeadlineConn{Conn: conn}
}

func (c *connectDeadlineConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.cleared {
		switch {
		case !c.proxyConnect && bytes.HasPrefix(p, []byte("CONNECT ")):
			c.proxyConnect = true
		case isTLSHandshakeRecord(p):
			// Keep the connection deadline through proxy and origin TLS
			// handshakes. The first application record clears it.
		case isTLSApplicationRecord(p):
			c.clearDeadlineLocked()
		default:
			c.clearDeadlineLocked()
		}
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func isTLSHandshakeRecord(p []byte) bool {
	return len(p) >= 3 && p[0] == 0x16 && p[1] == 0x03
}

func isTLSApplicationRecord(p []byte) bool {
	return len(p) >= 3 && p[0] == 0x17 && p[1] == 0x03
}

func (c *connectDeadlineConn) clearDeadlineLocked() {
	if c.cleared {
		return
	}
	c.cleared = true
	_ = c.Conn.SetDeadline(time.Time{})
}

// wrapDialWithConnectTimeout wraps a dial function with a connect timeout sub-context.
func wrapDialWithConnectTimeout(baseDial func(context.Context, string, string) (net.Conn, error), timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := connectContext(ctx, timeout, "DNS/TCP connect")
		defer cancel()
		var conn net.Conn
		var err error
		if baseDial != nil {
			conn, err = baseDial(ctx, network, address)
		} else {
			var d net.Dialer
			conn, err = d.DialContext(ctx, network, address)
		}
		if err != nil {
			return nil, err
		}
		return newConnectDeadlineConn(conn, ctx), nil
	}
}

func getHTTP2Transport(baseDial func(context.Context, string, string) (net.Conn, error), res *resolver.Resolver, explicitProxy *url.URL, tlsConfig *tls.Config, connectTimeout time.Duration, echMode core.ECHMode) http.RoundTripper {
	return &http2.Transport{
		AllowHTTP:          false,
		DialTLSContext:     newHTTP2DialTLS(baseDial, res, explicitProxy, "https", tlsConfig, connectTimeout, echMode),
		DisableCompression: true,
		TLSClientConfig:    tlsConfig.Clone(),
	}
}

func getH2CTransport(baseDial func(context.Context, string, string) (net.Conn, error), res *resolver.Resolver, explicitProxy *url.URL, connectTimeout time.Duration) http.RoundTripper {
	return &http2.Transport{
		AllowHTTP:          true,
		DialTLSContext:     newHTTP2DialTLS(baseDial, res, explicitProxy, "http", nil, connectTimeout, core.ECHOff),
		DisableCompression: true,
	}
}

func getHTTP3Transport(res *resolver.Resolver, tlsConfig *tls.Config, connectTimeout time.Duration, echMode core.ECHMode) http.RoundTripper {
	rt := &http3.Transport{
		DisableCompression: true,
		TLSClientConfig:    tlsConfig.Clone(),
	}

	wrapper := &http3TimingTransport{rt: rt}

	// Always set custom Dial to ensure trace hooks work.
	rt.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
		ctx, cancel := connectContext(ctx, connectTimeout, "DNS/QUIC/TLS connect")
		defer cancel()
		trace := httptrace.ContextClientTrace(ctx)
		if trace != nil && trace.DNSStart != nil {
			trace.DNSStart(httptrace.DNSStartInfo{Host: addr})
		}
		endpoint, err := res.ResolveAddress(ctx, "udp", addr)
		if trace != nil && trace.DNSDone != nil {
			info := httptrace.DNSDoneInfo{Addrs: nil, Err: err}
			if err == nil {
				info.Addrs = make([]net.IPAddr, len(endpoint.Addrs))
				copy(info.Addrs, endpoint.Addrs)
			}
			trace.DNSDone(info)
		}
		if err != nil {
			return nil, err
		}

		// HTTPS/SVCB discovery is scoped to this resolver and target. It is
		// opportunistic for ordinary forced H3, but ECH=on requires an
		// advertised, validated configuration.
		originHost, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			originHost = addr
		}
		originPort, portErr := strconv.ParseUint(endpoint.Port, 10, 16)
		if portErr != nil {
			return nil, portErr
		}
		discovery, discoveryErr := res.DiscoverHTTPS(ctx, originHost, uint16(originPort), nil)
		if discoveryErr != nil {
			if echMode == core.ECHOn || resolver.IsAuthenticatedDiscoveryFailure(discoveryErr) {
				return nil, discoveryErr
			}
		} else {
			var selected *resolver.ServiceCandidate
			for i := range discovery.Candidates {
				candidate := &discovery.Candidates[i]
				for _, alpn := range candidate.ALPN {
					if string(alpn) == "h3" {
						selected = candidate
						break
					}
				}
				if selected != nil {
					break
				}
			}
			if selected != nil {
				if len(selected.Addresses) > 0 {
					endpoint.Addrs = selected.Addresses
				}
				endpoint.Port = strconv.Itoa(int(selected.Port))
				if len(selected.ECH) > 0 && (echMode == core.ECHAuto || echMode == core.ECHOn) {
					tlsCfg = tlsCfg.Clone()
					tlsCfg.MinVersion = tls.VersionTLS13
					tlsCfg.EncryptedClientHelloConfigList = append([]byte(nil), selected.ECH...)
				} else if echMode == core.ECHOn {
					return nil, errors.New("ECH is required but the selected HTTPS record has no ECH configuration")
				}
			} else if echMode == core.ECHOn {
				return nil, errors.New("ECH is required but no HTTPS service configuration supports HTTP/3")
			}
		}
		if echMode == core.ECHAuto && len(tlsCfg.EncryptedClientHelloConfigList) == 0 {
			configList, greaseErr := GenerateGREASEECHConfigList()
			if greaseErr != nil {
				return nil, greaseErr
			}
			tlsCfg = tlsCfg.Clone()
			tlsCfg.MinVersion = tls.VersionTLS13
			tlsCfg.EncryptedClientHelloConfigList = configList
		}

		port, err := net.LookupPort("udp", endpoint.Port)
		if err != nil {
			return nil, err
		}

		// Race QUIC setup using the same family-preserving Happy Eyeballs
		// policy as TCP. A black-holed preferred address must not consume the
		// entire connection budget before another family is tried.
		type quicResult struct {
			conn       *quic.Conn
			packetConn net.PacketConn
		}
		result, err := resolver.RaceCandidates(ctx, endpoint.Addrs, func(attemptCtx context.Context, ip net.IPAddr) (quicResult, error) {
			address := core.JoinIPHostPort(ip, strconv.Itoa(port))
			if trace != nil && trace.ConnectStart != nil {
				trace.ConnectStart("udp", address)
			}
			var lc net.ListenConfig
			packetConn, listenErr := lc.ListenPacket(attemptCtx, "udp", ":0")
			if listenErr != nil && trace != nil && trace.ConnectDone != nil {
				trace.ConnectDone("udp", address, listenErr)
			}
			if listenErr != nil {
				return quicResult{}, listenErr
			}
			config := qcfg
			if config != nil {
				config = config.Clone()
			}
			if trace != nil && trace.TLSHandshakeStart != nil {
				trace.TLSHandshakeStart()
			}
			// Give every raced QUIC handshake its own TLS state.
			attemptTLS := tlsCfg.Clone()
			conn, dialErr := quic.DialEarly(attemptCtx, packetConn, &net.UDPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}, attemptTLS, config)
			if dialErr == nil {
				select {
				case <-conn.HandshakeComplete():
				case <-attemptCtx.Done():
					dialErr = context.Cause(attemptCtx)
				}
			}
			if trace != nil && trace.TLSHandshakeDone != nil {
				var state tls.ConnectionState
				if conn != nil && dialErr == nil {
					state = conn.ConnectionState().TLS
				}
				trace.TLSHandshakeDone(state, dialErr)
			}
			if dialErr != nil {
				if conn != nil {
					_ = conn.CloseWithError(0, "HTTP/3 handshake failed")
				}
				_ = packetConn.Close()
				if trace != nil && trace.ConnectDone != nil {
					trace.ConnectDone("udp", address, dialErr)
				}
				return quicResult{}, dialErr
			}
			if trace != nil && trace.ConnectDone != nil {
				trace.ConnectDone("udp", address, nil)
			}
			return quicResult{conn: conn, packetConn: packetConn}, nil
		}, func(result quicResult) {
			if result.conn != nil {
				_ = result.conn.CloseWithError(0, "QUIC address race lost")
			}
			if result.packetConn != nil {
				_ = result.packetConn.Close()
			}
		})
		if err != nil {
			return nil, err
		}
		if trace != nil && trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{Conn: traceAddrConn{remote: result.conn.RemoteAddr()}})
		}
		wrapper.addPacketConn(result.packetConn)
		return result.conn, nil
	}

	return wrapper
}

// traceAddrConn supplies the peer address to httptrace for QUIC. A quic.Conn
// is not a net.Conn because its application streams are separate, but the
// trace callback only needs the address for HAR and diagnostics.
type traceAddrConn struct{ remote net.Addr }

func (c traceAddrConn) Read([]byte) (int, error) {
	return 0, errors.New("QUIC trace connection is not readable")
}
func (c traceAddrConn) Write([]byte) (int, error) {
	return 0, errors.New("QUIC trace connection is not writable")
}
func (c traceAddrConn) Close() error                     { return nil }
func (c traceAddrConn) LocalAddr() net.Addr              { return nil }
func (c traceAddrConn) RemoteAddr() net.Addr             { return c.remote }
func (c traceAddrConn) SetDeadline(time.Time) error      { return nil }
func (c traceAddrConn) SetReadDeadline(time.Time) error  { return nil }
func (c traceAddrConn) SetWriteDeadline(time.Time) error { return nil }

// http3TimingTransport wraps http3.Transport to provide TTFB trace hooks
// and tracks PacketConns for cleanup.
type http3TimingTransport struct {
	rt          *http3.Transport
	mu          sync.Mutex
	closed      bool
	packetConns []net.PacketConn
}

func (t *http3TimingTransport) addPacketConn(conn net.PacketConn) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = conn.Close()
		return
	}
	t.packetConns = append(t.packetConns, conn)
	t.mu.Unlock()
}

func (t *http3TimingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := roundTripHTTP3(t.rt, req)

	// Call GotFirstResponseByte when response headers arrive.
	if err == nil {
		if trace := httptrace.ContextClientTrace(req.Context()); trace != nil {
			if trace.GotFirstResponseByte != nil {
				trace.GotFirstResponseByte()
			}
		}
	}

	return resp, err
}

// CloseIdleConnections releases idle QUIC sessions without interrupting an
// active response. Client.Close calls Close after this method and therefore
// also releases the packet sockets owned by this wrapper.
func (t *http3TimingTransport) CloseIdleConnections() {
	if t == nil || t.rt == nil {
		return
	}
	t.rt.CloseIdleConnections()
}

func (t *http3TimingTransport) Close() error {
	t.mu.Lock()
	t.closed = true
	packetConns := t.packetConns
	t.packetConns = nil
	t.mu.Unlock()
	err := t.rt.Close()
	for _, pc := range packetConns {
		_ = pc.Close()
	}
	return err
}

// Close closes the underlying transport, releasing any resources.
func (c *Client) Close() error {
	if idleCloser, ok := c.c.Transport.(interface{ CloseIdleConnections() }); ok {
		idleCloser.CloseIdleConnections()
	}
	if closer, ok := c.c.Transport.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// HTTPClient returns the underlying *http.Client.
func (c *Client) HTTPClient() *http.Client {
	return c.c
}

// ResolverProvenance identifies the resolver policy used by this client. It
// is safe for diagnostics because resolver endpoints redact credentials during
// parsing and display construction.
func (c *Client) ResolverProvenance() string {
	if c == nil || c.resolver == nil {
		return "system"
	}
	return c.resolver.Provenance()
}

// SetJar sets the cookie jar on the HTTP client.
func (c *Client) SetJar(jar http.CookieJar) {
	c.c.Jar = jar
	if jar != nil {
		if _, wrapped := c.c.Transport.(*redirectCredentialTransport); !wrapped {
			c.c.Transport = &redirectCredentialTransport{base: c.c.Transport}
		}
	}
}

// ApplyJarCookies adds the same cookie-jar values that net/http will add
// before sending a request. It is intended for dry-run metadata, which is
// rendered before Client.Do would normally apply the jar. The caller must not
// call it more than once for the same request.
func (c *Client) ApplyJarCookies(req *http.Request) *http.Request {
	if c.c.Jar == nil {
		return req
	}
	req = withOriginCookies(req, c.c.Jar)
	for _, cookie := range c.c.Jar.Cookies(cookieRequestURL(req)) {
		req.AddCookie(cookie)
	}
	return req
}

// RequestConfig represents the configuration for creating an HTTP request.
type RequestConfig struct {
	Article     bool
	Basic       *core.KeyVal[string]
	Bearer      string
	Compression core.CompressionMode
	ContentType string
	Data        io.Reader
	Form        []core.KeyVal[string]
	Headers     []core.KeyVal[string]
	HTTP        core.HTTPVersion
	Method      string
	Multipart   *multipart.Multipart
	NoEncode    bool // Compatibility override for --no-encode.
	QueryParams []core.KeyVal[string]
	Range       []string
	URL         *url.URL
}

// NewRequest returns an *http.Request given the provided configuration.
func (c *Client) NewRequest(ctx context.Context, cfg RequestConfig) (*http.Request, error) {
	// URL userinfo is an authentication source, not part of the request URL.
	// Convert it to Basic auth before constructing the request so diagnostics,
	// redirects, and signatures never retain credentials in the URL. Explicit
	// Authorization headers and auth flags are applied below and take their
	// established precedence over URL userinfo.
	var urlBasic *core.KeyVal[string]
	if cfg.URL.User != nil {
		username := cfg.URL.User.Username()
		password, hasPassword := cfg.URL.User.Password()
		if username != "" || hasPassword {
			urlBasic = &core.KeyVal[string]{Key: username, Val: password}
		}
		cfg.URL.User = nil
	}

	// Append query params directly to RawQuery. url.Values.Encode sorts keys,
	// which loses the user's ordering even though duplicate parameters are
	// valid and meaningful to many servers.
	if len(cfg.QueryParams) > 0 {
		cfg.URL.RawQuery = appendQueryParams(cfg.URL.RawQuery, cfg.QueryParams)
	}

	// Build a lazy body source. The request receives the source itself so that
	// files and stdin are not opened/consumed until the transport reads them.
	var source *body.Body
	var requestBody io.Reader
	switch {
	case cfg.Data != nil:
		var err error
		source, err = requestBodySource(cfg.Data, cfg.ContentType)
		if err != nil {
			return nil, err
		}
		requestBody = source
	case len(cfg.Form) > 0:
		q := make(url.Values, len(cfg.Form))
		for _, f := range cfg.Form {
			q.Add(f.Key, f.Val)
		}
		source = body.NewBytes([]byte(q.Encode()), "application/x-www-form-urlencoded")
		requestBody = source
	case cfg.Multipart != nil:
		source = body.NewFactory(cfg.Multipart.Open, -1, cfg.Multipart.ContentType(), true)
		requestBody = source
	}

	// If no scheme was provided, default to HTTPS except for localhost and all
	// IP literals, which default to HTTP.
	if cfg.URL.Scheme == "" {
		if isIPLiteral(cfg.URL.Hostname()) || IsLoopback(cfg.URL.Hostname()) {
			cfg.URL.Scheme = "http"
		} else {
			cfg.URL.Scheme = "https"
		}
	}

	// If no method was provided, a body implies POST. The caller can still
	// explicitly choose any method, including GET with a body.
	if cfg.Method == "" {
		if requestBody != nil {
			cfg.Method = http.MethodPost
		} else {
			cfg.Method = http.MethodGet
		}
	}

	// Create the initial HTTP request.
	req, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.URL.String(), requestBody)
	if err != nil {
		if source != nil {
			_ = source.Close()
		}
		return nil, err
	}
	if source != nil {
		body.Attach(req, source)
	}
	if urlBasic != nil {
		req.SetBasicAuth(urlBasic.Key, urlBasic.Val)
	}

	// Set the default accept and user-agent headers. Explicit headers below
	// replace the defaults without losing duplicate user-provided values.
	if cfg.Article {
		req.Header.Set("Accept", "text/html, application/xhtml+xml;q=0.9, text/markdown;q=0.8, */*;q=0.1")
	} else {
		req.Header.Set("Accept", "application/json, */*;q=0.5")
	}
	req.Header.Set("User-Agent", core.UserAgent)

	// Optionally set the content-type header.
	switch {
	case len(cfg.Form) > 0:
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case cfg.Multipart != nil:
		req.Header.Set("Content-Type", cfg.Multipart.ContentType())
	case cfg.ContentType != "":
		req.Header.Set("Content-Type", cfg.ContentType)
	}

	// Optionally set the range header.
	if len(cfg.Range) > 0 {
		req.Header.Set("Range", "bytes="+strings.Join(cfg.Range, ", "))
	}

	// Set any provided headers. Clear each defaulted name only before its first
	// explicit value, then append so repeated headers remain distinct.
	seenHeaders := make(map[string]struct{}, len(cfg.Headers))
	acceptEncodingSet := false
	for _, kv := range cfg.Headers {
		if strings.EqualFold(kv.Key, "Host") {
			req.Host = kv.Val
			continue
		}
		name := strings.ToLower(kv.Key)
		if name == "accept-encoding" {
			acceptEncodingSet = true
		}
		if _, seen := seenHeaders[name]; !seen {
			req.Header.Del(kv.Key)
			seenHeaders[name] = struct{}{}
		}
		req.Header.Add(kv.Key, kv.Val)
		switch strings.ToLower(kv.Key) {
		case "content-length":
			length, err := strconv.ParseInt(strings.TrimSpace(kv.Val), 10, 64)
			if err != nil || length < 0 {
				return nil, fmt.Errorf("invalid Content-Length header %q", kv.Val)
			}
			req.ContentLength = length
		case "transfer-encoding":
			var encodings []string
			for encoding := range strings.SplitSeq(kv.Val, ",") {
				encoding = strings.TrimSpace(encoding)
				if encoding != "" {
					encodings = append(encodings, encoding)
				}
			}
			req.TransferEncoding = encodings
			if len(encodings) > 0 {
				req.ContentLength = -1
			}
		}
	}

	// Set the compression policy after explicit headers have been applied. An
	// explicit Accept-Encoding value is never replaced. The policy still
	// controls which response encodings are safe to decode; --compress off and
	// --no-encode preserve the response bytes exactly.
	mode := cfg.Compression
	if cfg.NoEncode {
		mode = core.CompressionOff
	}
	if mode == core.CompressionUnknown {
		mode = core.CompressionAuto
	}
	policy := newResponseEncodingPolicy(mode)
	if cfg.Article {
		// Article extraction must see decoded bytes even when the user turns
		// automatic compression negotiation off. Do not add an encoding request;
		// this only permits decoding encodings supplied by the response.
		policy = newResponseEncodingPolicy(core.CompressionAuto)
	}
	requestContext := context.WithValue(req.Context(), ctxEncodingPolicyKey, policy)
	req = req.WithContext(requestContext)

	// Optionally request gzip, Brotli, or zstd encoding.
	if !cfg.NoEncode && !acceptEncodingSet && mode != core.CompressionOff {
		req.Header.Set("Accept-Encoding", compressionAcceptEncoding(mode))
		policy.generated = true
		requestContext = context.WithValue(requestContext, ctxEncodingPolicyKey, policy)
		req = req.WithContext(requestContext)
	}

	// Optionally set the authorization header.
	switch {
	case cfg.Basic != nil:
		req.SetBasicAuth(cfg.Basic.Key, cfg.Basic.Val)
	case cfg.Bearer != "":
		req.Header.Set("Authorization", "Bearer "+cfg.Bearer)
	}

	return req, nil
}

func isIPLiteral(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if zone := strings.LastIndexByte(host, '%'); zone > 0 {
		return net.ParseIP(host[:zone]) != nil
	}
	return false
}

func appendQueryParams(raw string, params []core.KeyVal[string]) string {
	parts := make([]string, 0, 1+len(params))
	if raw != "" {
		parts = append(parts, raw)
	}
	for _, kv := range params {
		parts = append(parts, escapeQueryParam(kv.Key)+"="+escapeQueryParam(kv.Val))
	}
	return strings.Join(parts, "&")
}

// escapeQueryParam uses RFC 3986 encoding. Unlike form encoding, spaces are
// encoded as %20, so a later SigV4 pass can distinguish them from literal '+'.
func escapeQueryParam(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func requestBodySource(r io.Reader, contentType string) (*body.Body, error) {
	if f, ok := r.(*os.File); ok && f != os.Stdin {
		return body.NewFileFromOpenFile(f, contentType)
	}
	// CLI literals and generated form bodies use in-memory readers. Copy their
	// unread portion into a replayable source so dry-run can preview them
	// without consuming the body that the real request would send.
	switch value := r.(type) {
	case *bytes.Reader:
		data, err := io.ReadAll(value)
		if err != nil {
			return nil, err
		}
		return body.NewBytes(data, contentType), nil
	case *bytes.Buffer:
		return body.NewBytes(value.Bytes(), contentType), nil
	case *strings.Reader:
		data, err := io.ReadAll(value)
		if err != nil {
			return nil, err
		}
		return body.NewBytes(data, contentType), nil
	}
	if rs, ok := r.(io.ReadSeeker); ok {
		return newSeekableBody(rs, contentType), nil
	}
	return body.NewReader(r, -1, contentType), nil
}

// SameOrigin reports whether two URLs have the same HTTP origin. URL.Host is
// not compared directly because an omitted default port and its explicit form
// represent the same origin.
func SameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return originPort(a) == originPort(b)
}

func originPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func normalizeRedirectRequest(req *http.Request, via []*http.Request) error {
	if req == nil || len(via) == 0 || req.Response == nil {
		return nil
	}
	previous := via[len(via)-1]
	status := req.Response.StatusCode

	// Go's redirect behavior is intentionally conservative for 301/302. The
	// fetch contract preserves every method except POST, and therefore must
	// restore the method and replay the body for PUT, PATCH, and other methods.
	if status == http.StatusMovedPermanently || status == http.StatusFound {
		if strings.EqualFold(previous.Method, http.MethodPost) {
			req.Method = http.MethodGet
			clearRedirectBody(req)
			return nil
		}
		req.Method = previous.Method
		if err := restoreRedirectBody(req, previous, via[0]); err != nil {
			return err
		}
		return nil
	}

	// 303 changes every method to GET except HEAD. net/http has already made
	// this change, but explicitly clear all entity state so a custom header or
	// zero-length body cannot survive the rewrite.
	if status == http.StatusSeeOther {
		if strings.EqualFold(previous.Method, http.MethodHead) {
			req.Method = http.MethodHead
		} else {
			req.Method = http.MethodGet
		}
		clearRedirectBody(req)
		return nil
	}

	// 307/308 preserve the immediately previous request. Go's internal
	// includeBody flag is based on the initial request and can therefore lose a
	// body after an earlier 301/302. Restore from the previous hop instead.
	if status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect {
		req.Method = previous.Method
		if previous.Body == nil || previous.Body == http.NoBody {
			clearRedirectBody(req)
			return nil
		}
		return restoreRedirectBody(req, previous, via[0])
	}

	return nil
}

func restoreRedirectBody(req, previous, initial *http.Request) error {
	if previous.Body == nil || previous.Body == http.NoBody {
		clearRedirectBody(req)
		return nil
	}
	if previous.GetBody == nil {
		return fmt.Errorf("cannot replay request body for redirect: %w", body.ErrNotReplayable)
	}
	replay, err := previous.GetBody()
	if err != nil {
		return fmt.Errorf("cannot replay request body for redirect: %w", err)
	}
	req.Body = replay
	req.GetBody = previous.GetBody
	req.ContentLength = previous.ContentLength
	req.TransferEncoding = append([]string(nil), previous.TransferEncoding...)

	// net/http removes body-related headers when it creates the GET request.
	// Restore the initial values for a method whose body is retained. Header
	// values are cloned so later redirect hops cannot mutate the initial map.
	for _, name := range redirectEntityHeaders() {
		req.Header.Del(name)
		for _, value := range initial.Header.Values(name) {
			req.Header.Add(name, value)
		}
	}
	return nil
}

func redirectEntityHeaders() []string {
	return []string{"Content-Length", "Content-Type", "Content-Encoding", "Content-Language", "Content-Location", "Content-Range", "Content-MD5", "Content-Digest", "Content-Disposition", "Transfer-Encoding"}
}

func deleteHeaderInsensitive(headers http.Header, name string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			delete(headers, key)
		}
	}
}

func cloneOriginCookieSet(cookies originCookieSet) originCookieSet {
	clone := make(originCookieSet, len(cookies))
	for name := range cookies {
		clone[name] = struct{}{}
	}
	return clone
}

func clearRedirectBody(req *http.Request) {
	req.Body = http.NoBody
	req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	req.ContentLength = 0
	req.TransferEncoding = nil
	for _, name := range redirectEntityHeaders() {
		req.Header.Del(name)
	}
}

type originCookieSet map[string]struct{}

func withOriginCookies(req *http.Request, jar http.CookieJar) *http.Request {
	cookies := make(originCookieSet)
	for _, value := range req.Header.Values("Cookie") {
		addCookieNames(cookies, value)
	}
	for _, cookie := range jar.Cookies(cookieRequestURL(req)) {
		cookies[cookie.Name] = struct{}{}
	}
	return req.WithContext(context.WithValue(req.Context(), ctxOriginCookiesKey, cookies))
}

func cookieRequestURL(req *http.Request) *url.URL {
	if req == nil || req.URL == nil || req.Host == "" {
		if req == nil {
			return nil
		}
		return req.URL
	}
	clone := *req.URL
	clone.Host = req.Host
	return &clone
}

func addCookieNames(set originCookieSet, header string) {
	for pair := range strings.SplitSeq(header, ";") {
		name, _, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if ok && name != "" {
			set[name] = struct{}{}
		}
	}
}

// RedirectCrossedOrigin reports whether a request followed a redirect chain
// that crossed an origin boundary. The value remains true if a later hop
// returns to the original origin, preventing credentials from being restored.
func RedirectCrossedOrigin(req *http.Request) bool {
	if req == nil {
		return false
	}
	crossed, _ := req.Context().Value(ctxRedirectCrossedKey).(bool)
	return crossed
}

// redirectCredentialTransport runs after net/http has added cookies from its
// CookieJar. Remove only cookies that belonged to the original origin, while
// allowing cookies scoped to the redirected destination to remain usable.
type redirectCredentialTransport struct {
	base http.RoundTripper
}

func (t *redirectCredentialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !RedirectCrossedOrigin(req) {
		return t.base.RoundTrip(req)
	}
	cookies, _ := req.Context().Value(ctxOriginCookiesKey).(originCookieSet)
	if len(cookies) == 0 || req.Header.Get("Cookie") == "" {
		return t.base.RoundTrip(req)
	}
	clone := req.Clone(req.Context())
	var kept []string
	for _, header := range req.Header.Values("Cookie") {
		for pair := range strings.SplitSeq(header, ";") {
			pair = strings.TrimSpace(pair)
			name, _, ok := strings.Cut(pair, "=")
			if !ok || name == "" {
				continue
			}
			if _, forbidden := cookies[name]; !forbidden {
				kept = append(kept, pair)
			}
		}
	}
	clone.Header.Del("Cookie")
	if len(kept) > 0 {
		clone.Header.Set("Cookie", strings.Join(kept, "; "))
	}
	return t.base.RoundTrip(clone)
}

func (t *redirectCredentialTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t *redirectCredentialTransport) Close() error {
	if closer, ok := t.base.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func applyRedirectCredentialPolicy(req *http.Request, via []*http.Request) {
	if req == nil || len(via) == 0 || req.URL == nil {
		return
	}
	initial := via[0]
	crossed := !SameOrigin(initial.URL, req.URL)
	if !crossed {
		for _, previous := range via {
			if !SameOrigin(initial.URL, previous.URL) {
				crossed = true
				break
			}
		}
	}

	if crossed {
		cookies, _ := req.Context().Value(ctxOriginCookiesKey).(originCookieSet)
		if cookies == nil {
			cookies = make(originCookieSet)
		} else {
			cookies = cloneOriginCookieSet(cookies)
		}
		if req.Response != nil {
			for _, cookie := range req.Response.Cookies() {
				cookies[cookie.Name] = struct{}{}
			}
		}
		ctx := context.WithValue(req.Context(), ctxRedirectCrossedKey, true)
		ctx = context.WithValue(ctx, ctxOriginCookiesKey, cookies)
		*req = *req.WithContext(ctx)
		for _, name := range []string{
			"Authorization", "Cookie", "Cookie2", "Proxy-Authorization",
			"Www-Authenticate", "Proxy-Authenticate", "X-Amz-Date",
			"X-Amz-Content-Sha256", "X-Amz-Security-Token", "X-Amz-Session-Token",
		} {
			deleteHeaderInsensitive(req.Header, name)
		}
		req.Host = ""
		// Host can also be represented in Header on requests built outside
		// NewRequest. The transport uses Request.Host, but remove both forms.
		deleteHeaderInsensitive(req.Header, "Host")
		return
	}

	// net/http only preserves a custom Host for relative redirects. Keep it
	// for absolute same-origin redirects as well.
	if req.Host == "" {
		for i := len(via) - 1; i >= 0; i-- {
			if via[i].Host != "" {
				req.Host = via[i].Host
				break
			}
		}
	}
}

func newSeekableBody(rs io.ReadSeeker, contentType string) *body.Body {
	if r, ok := rs.(interface {
		io.ReadSeeker
		io.ReaderAt
		Size() int64
	}); ok {
		offset, err := r.Seek(0, io.SeekCurrent)
		if err == nil && offset >= 0 && r.Size() >= offset {
			return body.NewReaderAt(r, offset, r.Size()-offset, contentType)
		}
	}
	// An arbitrary ReadSeeker may not provide independent cursors. Treat it as
	// one-shot rather than allowing a replay to reset the active request.
	return body.NewReader(rs, -1, contentType)
}

// Do performs the provided http Request, returning the response.
// ValidateTransport checks configuration that must fail before a handshake.
// WebSocket uses HTTPClient directly, so it calls this method before dialing.
func (c *Client) ValidateTransport(req *http.Request) error {
	if c == nil {
		return errors.New("nil HTTP client")
	}
	if c.initErr != nil {
		return c.initErr
	}
	if req == nil || req.URL == nil {
		return errors.New("request URL is required")
	}
	proxy, err := ProxyForURL(c.proxy, req.URL)
	if err != nil {
		return err
	}
	if c.echMode != core.ECHUnknown && c.echMode != core.ECHOff && proxy != nil {
		return errors.New("ECH is not available through a proxy")
	}
	if c.httpVersion == core.HTTP3 && proxy != nil {
		return errors.New("HTTP/3 cannot be used with a proxy")
	}
	return nil
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := c.ValidateTransport(req); err != nil {
		return nil, err
	}
	if c.c.Jar != nil {
		req = withOriginCookies(req, c.c.Jar)
	}
	if observer := requestObserver(req.Context()); observer != nil {
		observer(req)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		return nil, err
	}

	// net/http intentionally stops following a 307/308 when a body has no
	// GetBody function. That default is too quiet for a CLI: a request that
	// requires replay must fail clearly rather than look like a successful
	// final redirect response. Respect --redirects 0, which explicitly asks
	// for the redirect response instead of following it.
	finalRequest := req
	if resp != nil && resp.Request != nil {
		finalRequest = resp.Request
	}
	if c.maxRedirects != 0 && resp != nil && finalRequest != nil &&
		(resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect) &&
		resp.Header.Get("Location") != "" &&
		finalRequest.Body != nil && finalRequest.Body != http.NoBody && finalRequest.GetBody == nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("cannot replay request body for redirect: %w", body.ErrNotReplayable)
	}

	rememberWireContentLength(resp, req)

	// Decode only the encodings permitted by the request's compression mode.
	// Keep this outside net/http's transport so all HTTP versions use the same
	// streaming decoders and malformed encodings produce the same error.
	if resp.Body != nil {
		if policy, ok := responseEncodingPolicyFromRequest(req); ok {
			if !policy.enabled {
				return resp, nil
			}
			decoders, err := contentEncodingDecodersForPolicy(resp.Header, policy.allowed)
			if err != nil {
				_ = resp.Body.Close()
				return nil, err
			}
			if err := decodeResponseBodyChain(resp, decoders); err != nil {
				return nil, err
			}
		} else if encodingRequested(req) {
			// Preserve the old behavior for requests constructed directly by
			// package users that predate CompressionMode.
			decoders, ok := contentEncodingDecoders(resp.Header)
			if ok {
				if err := decodeResponseBodyChain(resp, decoders); err != nil {
					return nil, err
				}
			}
		}
	}

	return resp, nil
}

type responseBodyDecoder func(io.ReadCloser) (io.ReadCloser, error)

type namedResponseBodyDecoder struct {
	name    string
	decoder responseBodyDecoder
}

func decodeResponseBodyChain(resp *http.Response, decoders []namedResponseBodyDecoder) error {
	if len(decoders) == 0 {
		return nil
	}
	counter := &wireByteCounter{}
	resp.Body = &wireCountingReadCloser{ReadCloser: resp.Body, counter: counter}
	for _, decoder := range decoders {
		if err := decodeResponseBody(resp, decoder.name, decoder.decoder, counter); err != nil {
			return err
		}
	}
	return nil
}

func decodeResponseBody(resp *http.Response, name string, decoder responseBodyDecoder, counters ...*wireByteCounter) error {
	decoded, err := decoder(resp.Body)
	if err != nil {
		resp.Body.Close()
		return fmt.Errorf("%s: %w", name, err)
	}
	var counter *wireByteCounter
	if len(counters) > 0 {
		counter = counters[0]
	} else if source, ok := resp.Body.(interface{ wireCounter() *wireByteCounter }); ok {
		counter = source.wireCounter()
	}
	resp.Body = &encodingReadCloser{name: name, reader: decoded, closer: decoded, counter: counter}
	resp.ContentLength = -1
	return nil
}

type wireByteCounter struct{ bytes atomic.Int64 }

type wireCountingReadCloser struct {
	io.ReadCloser
	counter *wireByteCounter
}

func (r *wireCountingReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.counter.bytes.Add(int64(n))
	}
	return n, err
}

func (r *wireCountingReadCloser) wireCounter() *wireByteCounter { return r.counter }

type encodingReadCloser struct {
	name    string
	reader  io.Reader
	closer  io.Closer
	counter *wireByteCounter
}

func (r *encodingReadCloser) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("%s: %w", r.name, err)
	}
	return n, err
}

func (r *encodingReadCloser) Close() error { return r.closer.Close() }

func (r *encodingReadCloser) ProgressBytes() (int64, bool) {
	if r.counter == nil {
		return 0, false
	}
	return r.counter.bytes.Load(), true
}

func rememberWireContentLength(resp *http.Response, req *http.Request) {
	if resp == nil {
		return
	}
	base := resp.Request
	if base == nil {
		base = req
	}
	if base == nil {
		return
	}
	ctx := context.WithValue(base.Context(), wireContentLengthKey{}, resp.ContentLength)
	resp.Request = base.WithContext(ctx)
}

// WireContentLength returns the encoded response length when the server
// supplied one. It remains available after a streaming decoder changes
// http.Response.ContentLength to -1.
func WireContentLength(resp *http.Response) int64 {
	if resp == nil {
		return -1
	}
	if resp.Request != nil {
		if length, ok := resp.Request.Context().Value(wireContentLengthKey{}).(int64); ok {
			return length
		}
	}
	return resp.ContentLength
}

type wireContentLengthKey struct{}

func contentEncodingDecoders(h http.Header) ([]namedResponseBodyDecoder, bool) {
	encodings := contentEncodings(h)
	decoders := make([]namedResponseBodyDecoder, 0, len(encodings))
	for i := len(encodings) - 1; i >= 0; i-- {
		switch strings.ToLower(encodings[i]) {
		case "br":
			decoders = append(decoders, namedResponseBodyDecoder{
				name: "br",
				decoder: func(rc io.ReadCloser) (io.ReadCloser, error) {
					return &brotliReader{ReadCloser: brotli.NewReader(rc), c: rc}, nil
				},
			})
		case "gzip":
			decoders = append(decoders, namedResponseBodyDecoder{
				name: "gzip",
				decoder: func(rc io.ReadCloser) (io.ReadCloser, error) {
					return newGZIPReader(rc)
				},
			})
		case "zstd":
			decoders = append(decoders, namedResponseBodyDecoder{
				name: "zstd",
				decoder: func(rc io.ReadCloser) (io.ReadCloser, error) {
					return newZSTDReader(rc)
				},
			})
		case "identity", "aws-chunked":
		default:
			return nil, false
		}
	}
	return decoders, true
}

// contentEncodingDecodersForPolicy validates the complete encoding chain
// before installing any decoder. This avoids partially decoding a response
// whose later encoding is unsupported.
func contentEncodingDecodersForPolicy(h http.Header, allowed map[string]bool) ([]namedResponseBodyDecoder, error) {
	values := h.Values("Content-Encoding")
	var encodings []string
	for _, value := range values {
		for token := range strings.SplitSeq(value, ",") {
			encoding := strings.TrimSpace(token)
			if encoding == "" {
				return nil, errors.New("malformed Content-Encoding header: empty encoding")
			}
			encoding = strings.ToLower(encoding)
			if encoding != "identity" && encoding != "aws-chunked" && !allowed[encoding] {
				return nil, fmt.Errorf("unsupported response content encoding: %s", encoding)
			}
			encodings = append(encodings, encoding)
		}
	}

	decoders := make([]namedResponseBodyDecoder, 0, len(encodings))
	for i := len(encodings) - 1; i >= 0; i-- {
		switch encodings[i] {
		case "br":
			decoders = append(decoders, namedResponseBodyDecoder{
				name: "br",
				decoder: func(rc io.ReadCloser) (io.ReadCloser, error) {
					return &brotliReader{ReadCloser: brotli.NewReader(rc), c: rc}, nil
				},
			})
		case "gzip":
			decoders = append(decoders, namedResponseBodyDecoder{
				name: "gzip",
				decoder: func(rc io.ReadCloser) (io.ReadCloser, error) {
					return newGZIPReader(rc)
				},
			})
		case "zstd":
			decoders = append(decoders, namedResponseBodyDecoder{
				name: "zstd",
				decoder: func(rc io.ReadCloser) (io.ReadCloser, error) {
					return newZSTDReader(rc)
				},
			})
		case "identity", "aws-chunked":
		}
	}
	return decoders, nil
}

func contentEncodings(h http.Header) []string {
	values := h.Values("Content-Encoding")
	var encodings []string
	for _, v := range values {
		for encoding := range strings.SplitSeq(v, ",") {
			encoding = strings.TrimSpace(encoding)
			if encoding != "" {
				encodings = append(encodings, encoding)
			}
		}
	}
	return encodings
}

type responseEncodingPolicy struct {
	enabled   bool
	auto      bool
	generated bool
	allowed   map[string]bool
}

type ctxEncodingPolicyKeyType int

const (
	ctxEncodingPolicyKey    ctxEncodingPolicyKeyType = 0
	ctxEncodingRequestedKey ctxEncodingPolicyKeyType = 1 // Legacy test/client hook.
)

func newResponseEncodingPolicy(mode core.CompressionMode) responseEncodingPolicy {
	if mode == core.CompressionOff {
		return responseEncodingPolicy{}
	}

	allowed := make(map[string]bool, 3)
	switch mode {
	case core.CompressionBrotli:
		allowed["br"] = true
	case core.CompressionGzip:
		allowed["gzip"] = true
	case core.CompressionZstd:
		allowed["zstd"] = true
	default:
		allowed["gzip"] = true
		allowed["br"] = true
		allowed["zstd"] = true
	}
	return responseEncodingPolicy{enabled: true, auto: mode == core.CompressionAuto, allowed: allowed}
}

func responseEncodingPolicyFromRequest(r *http.Request) (responseEncodingPolicy, bool) {
	policy, ok := r.Context().Value(ctxEncodingPolicyKey).(responseEncodingPolicy)
	return policy, ok
}

// AutomaticCompressionEnabled reports whether the request's
// Accept-Encoding header was generated by the automatic compression policy.
// It has no body or replay side effects.
func AutomaticCompressionEnabled(req *http.Request) bool {
	if req == nil {
		return false
	}
	policy, ok := responseEncodingPolicyFromRequest(req)
	return ok && policy.enabled && policy.auto && policy.generated
}

// UncompressedRequest returns a replay of req with automatic response
// compression disabled. It only succeeds when the request's Accept-Encoding
// header was generated by the automatic compression policy. Explicit headers
// are never silently changed.
func UncompressedRequest(req *http.Request) (*http.Request, bool) {
	if !AutomaticCompressionEnabled(req) {
		return nil, false
	}

	ctx := context.WithValue(req.Context(), ctxEncodingPolicyKey, responseEncodingPolicy{})
	replay := req.Clone(ctx)
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, false
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, false
		}
		replay.Body = body
		replay.GetBody = req.GetBody
	}
	replay.Header.Del("Accept-Encoding")
	return replay, true
}

func compressionAcceptEncoding(mode core.CompressionMode) string {
	switch mode {
	case core.CompressionBrotli:
		return "br"
	case core.CompressionGzip:
		return "gzip"
	case core.CompressionZstd:
		return "zstd"
	default:
		return "gzip, br, zstd"
	}
}

// encodingRequested retains the small hook used by older direct Client tests
// and package users. New requests carry the full responseEncodingPolicy above.
func encodingRequested(r *http.Request) bool {
	v, ok := r.Context().Value(ctxEncodingRequestedKey).(bool)
	return ok && v
}

type brotliReader struct {
	io.ReadCloser
	c io.Closer
}

func (r *brotliReader) Close() error {
	err := r.ReadCloser.Close()
	err2 := r.c.Close()
	if err != nil {
		return err
	}
	return err2
}

type gzipReader struct {
	*gzip.Reader
	c io.Closer
}

// newGZIPReader returns a new io.ReadCloser that automatically decodes the
// gzipped data.
func newGZIPReader(rc io.ReadCloser) (*gzipReader, error) {
	gr, err := gzip.NewReader(rc)
	if err != nil {
		return nil, err
	}
	return &gzipReader{Reader: gr, c: rc}, nil
}

func (r *gzipReader) Close() error {
	err := r.Reader.Close()
	err2 := r.c.Close()
	if err != nil {
		return err
	}
	return err2
}

type zstdReader struct {
	*zstd.Decoder
	c io.Closer
}

func newZSTDReader(rc io.ReadCloser) (*zstdReader, error) {
	zr, err := zstd.NewReader(rc, zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxWindow(1<<23))
	if err != nil {
		return nil, err
	}
	return &zstdReader{Decoder: zr, c: rc}, nil
}

func (r *zstdReader) Close() error {
	r.Decoder.Close()
	return r.c.Close()
}

// IsLoopback returns true if the host is a loopback address.
// This includes "localhost" and IP addresses in the loopback range
// (127.0.0.0/8 for IPv4, ::1 for IPv6).
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
