package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
)

const (
	// automaticH3CacheLimit bounds the in-process cache. Persistent storage is
	// deliberately left to the resolver-scoped cache implementation.
	automaticH3CacheLimit         = 4
	automaticH3OriginLimit        = 1024
	automaticTransportOriginLimit = 64
	cachedH3Grace                 = 20 * time.Millisecond
)

// automaticHTTP3Transport starts TCP setup and HTTPS-record discovery
// together. It only sends the request after one complete TCP/TLS or QUIC/H3
// setup has won, so a raced request is never sent twice.
type automaticHTTP3Transport struct {
	fallback              *http.Transport
	resolver              *resolver.Resolver
	dialer                *ResolverDialer
	tlsConfig             *tls.Config
	ech                   core.ECHMode
	connectLimit          time.Duration
	cache                 *automaticH3Cache
	persistent            *persistentH3Cache
	mu                    sync.Mutex
	tcpTransports         map[string]*http.Transport
	h3Transports          map[string]*http3.Transport
	h3TransportCandidates map[string]automaticH3Candidate
	h3Packets             map[string]net.PacketConn
	tcpECHCandidates      map[string][]resolver.ServiceCandidate
	altSvcSlots           chan struct{}
}

func newAutomaticHTTP3Transport(fallback *http.Transport, res *resolver.Resolver, connectTimeout time.Duration, tlsConfig *tls.Config, echMode core.ECHMode) http.RoundTripper {
	persistent := newPersistentH3Cache()
	return &automaticHTTP3Transport{
		fallback:              fallback,
		resolver:              res,
		dialer:                NewResolverDialer(res, connectTimeout),
		tlsConfig:             tlsConfig,
		ech:                   echMode,
		connectLimit:          connectTimeout,
		cache:                 newAutomaticH3CacheWithPersistent(persistent),
		persistent:            persistent,
		tcpTransports:         make(map[string]*http.Transport),
		h3Transports:          make(map[string]*http3.Transport),
		h3TransportCandidates: make(map[string]automaticH3Candidate),
		h3Packets:             make(map[string]net.PacketConn),
		tcpECHCandidates:      make(map[string][]resolver.ServiceCandidate),
		altSvcSlots:           make(chan struct{}, 8),
	}
}

func (t *automaticHTTP3Transport) CloseIdleConnections() {
	if t == nil {
		return
	}
	t.mu.Lock()
	tcp := make([]*http.Transport, 0, len(t.tcpTransports))
	h3 := make([]*http3.Transport, 0, len(t.h3Transports))
	for _, transport := range t.tcpTransports {
		tcp = append(tcp, transport)
	}
	for _, transport := range t.h3Transports {
		h3 = append(h3, transport)
	}
	t.mu.Unlock()
	if t.fallback != nil {
		t.fallback.CloseIdleConnections()
	}
	for _, transport := range tcp {
		transport.CloseIdleConnections()
	}
	for _, transport := range h3 {
		transport.CloseIdleConnections()
	}
}

func (t *automaticHTTP3Transport) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	h3 := make([]*http3.Transport, 0, len(t.h3Transports))
	packets := make([]net.PacketConn, 0, len(t.h3Packets))
	for _, transport := range t.h3Transports {
		h3 = append(h3, transport)
	}
	for _, packet := range t.h3Packets {
		packets = append(packets, packet)
	}
	t.h3Packets = make(map[string]net.PacketConn)
	t.mu.Unlock()
	t.CloseIdleConnections()
	var firstErr error
	for _, transport := range h3 {
		if err := transport.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, packet := range packets {
		_ = packet.Close()
	}
	if t.persistent != nil {
		t.persistent.close()
	}
	return firstErr
}

type automaticH3Cache struct {
	mu         sync.Mutex
	entries    map[string][]automaticH3Candidate
	loaded     map[string]bool
	versions   map[string]uint64
	dirty      map[string]bool
	persistent *persistentH3Cache
}

type automaticH3Candidate struct {
	host      string
	port      uint16
	ech       []byte
	addresses []net.IPAddr
	expires   time.Time
	source    h3CandidateSource
	priority  uint16
	learned   time.Time
	lastUsed  time.Time
}

type h3CandidateSource uint8

const (
	h3SourceDNS h3CandidateSource = iota + 1
	h3SourceAltSvc
)

func newAutomaticH3Cache() *automaticH3Cache {
	return newAutomaticH3CacheWithPersistent(nil)
}

func newAutomaticH3CacheWithPersistent(persistent *persistentH3Cache) *automaticH3Cache {
	return &automaticH3Cache{
		entries:    make(map[string][]automaticH3Candidate),
		loaded:     make(map[string]bool),
		versions:   make(map[string]uint64),
		dirty:      make(map[string]bool),
		persistent: persistent,
	}
}

func (c *automaticH3Cache) get(key string, now time.Time) []automaticH3Candidate {
	if c == nil {
		return nil
	}
	var loaded []automaticH3Candidate
	var loadVersion uint64
	localDirty := false
	shouldLoad := false
	c.mu.Lock()
	if c.persistent != nil && !c.loaded[key] {
		shouldLoad = true
		loadVersion = c.versions[key]
		localDirty = c.dirty[key]
	}
	c.mu.Unlock()
	if shouldLoad {
		loaded = c.persistent.load(key, now)
	}

	c.mu.Lock()
	if shouldLoad && !c.loaded[key] {
		// A local discovery or Alt-Svc update wins over a disk snapshot that
		// was started earlier. Do not overwrite newer in-memory state.
		if !localDirty && c.versions[key] == loadVersion && !c.dirty[key] {
			c.entries[key] = loaded
		}
		c.loaded[key] = true
	}
	values := c.entries[key]
	out := make([]automaticH3Candidate, 0, len(values))
	kept := values[:0]
	touch := false
	for _, value := range values {
		if !value.expires.IsZero() && !now.Before(value.expires) {
			continue
		}
		if !value.learned.IsZero() && !now.Before(value.learned.Add(h3CacheMaxAge)) {
			continue
		}
		value.addresses = append([]net.IPAddr(nil), value.addresses...)
		if value.lastUsed.IsZero() || now.Sub(value.lastUsed) >= h3CacheTouchInterval {
			value.lastUsed = now
			touch = true
		}
		out = append(out, value)
		kept = append(kept, value)
	}
	if touch && c.persistent != nil {
		c.persistent.touch(key, out)
	}
	if len(kept) == 0 {
		delete(c.entries, key)
	} else {
		c.entries[key] = kept
	}
	c.mu.Unlock()
	return out
}

func (c *automaticH3Cache) replaceDNS(key string, values []automaticH3Candidate) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.versions[key]++
	c.dirty[key] = true
	old := c.entries[key]
	alts := make([]automaticH3Candidate, 0, len(old))
	for _, value := range old {
		if value.source == h3SourceAltSvc {
			alts = append(alts, value)
		}
	}
	for i := range values {
		if values[i].learned.IsZero() {
			values[i].learned = time.Now()
		}
	}
	c.entries[key] = append(alts, cloneH3Candidates(values)...)
	if c.persistent != nil {
		c.persistent.replaceDNS(key, c.entries[key])
	}
	if len(c.entries[key]) == 0 {
		delete(c.entries, key)
		return
	}
	c.trimLocked(key)
}

func (c *automaticH3Cache) addAltSvc(key string, value automaticH3Candidate) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entries := c.entries[key]
	if value.port == 0 {
		return
	}
	c.versions[key]++
	c.dirty[key] = true
	if !value.expires.IsZero() && !value.expires.After(time.Now()) {
		values := entries[:0]
		for _, existing := range entries {
			if existing.source == h3SourceAltSvc && existing.host == value.host && existing.port == value.port {
				continue
			}
			values = append(values, existing)
		}
		if len(values) == 0 {
			delete(c.entries, key)
		} else {
			c.entries[key] = values
		}
		if c.persistent != nil {
			c.persistent.remove(key, value, false)
		}
		return
	}
	for i := range entries {
		if entries[i].source == h3SourceAltSvc && entries[i].host == value.host && entries[i].port == value.port {
			if value.learned.IsZero() {
				value.learned = time.Now()
			}
			entries[i] = value
			c.entries[key] = entries
			if c.persistent != nil {
				c.persistent.addAltSvc(key, value)
			}
			return
		}
	}
	if value.learned.IsZero() {
		value.learned = time.Now()
	}
	insertAt := len(entries)
	for i, existing := range entries {
		if existing.source == h3SourceDNS {
			insertAt = i
			break
		}
	}
	entries = append(entries, automaticH3Candidate{})
	copy(entries[insertAt+1:], entries[insertAt:])
	entries[insertAt] = value
	c.entries[key] = entries
	c.trimLocked(key)
	if c.persistent != nil {
		c.persistent.addAltSvc(key, value)
	}
}

func (c *automaticH3Cache) clearAltSvc(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.versions[key]++
	c.dirty[key] = true
	values := c.entries[key][:0]
	for _, value := range c.entries[key] {
		if value.source != h3SourceAltSvc {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		delete(c.entries, key)
	} else {
		c.entries[key] = values
	}
	if c.persistent != nil {
		c.persistent.clearAltSvc(key)
	}
}

func (c *automaticH3Cache) remove(value automaticH3Candidate, key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.versions[key]++
	c.dirty[key] = true
	values := c.entries[key][:0]
	for _, existing := range c.entries[key] {
		if h3CandidateMatches(existing, value, true) {
			continue
		}
		values = append(values, existing)
	}
	if len(values) == 0 {
		delete(c.entries, key)
	} else {
		c.entries[key] = values
	}
	if c.persistent != nil {
		c.persistent.remove(key, value, true)
	}
}

func h3CandidateMatches(existing, value automaticH3Candidate, generation bool) bool {
	if existing.source != value.source || existing.host != value.host || existing.port != value.port {
		return false
	}
	if generation && !value.learned.IsZero() && !existing.learned.IsZero() && !existing.learned.Equal(value.learned) {
		return false
	}
	return true
}

func (c *automaticH3Cache) trimLocked(key string) {
	c.entries[key] = selectH3Candidates(c.entries[key])
	if len(c.entries) > automaticH3OriginLimit {
		for existing := range c.entries {
			if existing != key {
				delete(c.entries, existing)
				delete(c.loaded, existing)
				delete(c.versions, existing)
				delete(c.dirty, existing)
				break
			}
		}
	}
}

func selectH3Candidates(values []automaticH3Candidate) []automaticH3Candidate {
	out := cloneH3Candidates(values)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].source != out[j].source {
			return out[i].source == h3SourceAltSvc
		}
		if out[i].source == h3SourceDNS && out[i].priority != out[j].priority {
			return out[i].priority < out[j].priority
		}
		return out[i].learned.After(out[j].learned)
	})
	if len(out) > automaticH3CacheLimit {
		out = out[:automaticH3CacheLimit]
	}
	return out
}

func cloneH3Candidates(values []automaticH3Candidate) []automaticH3Candidate {
	out := make([]automaticH3Candidate, len(values))
	copy(out, values)
	for i := range out {
		out[i].addresses = append([]net.IPAddr(nil), out[i].addresses...)
	}
	return out
}

func (t *automaticHTTP3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil || !strings.EqualFold(req.URL.Scheme, "https") {
		return t.fallback.RoundTrip(req)
	}
	proxy, err := ProxyForURL(nil, req.URL)
	if err != nil {
		return nil, err
	}
	if proxy != nil {
		return t.fallback.RoundTrip(req)
	}
	if net.ParseIP(req.URL.Hostname()) != nil {
		return t.fallback.RoundTrip(req)
	}

	key := automaticH3CacheKey(req.URL, t.resolver)
	t.mu.Lock()
	h3Transport := t.h3Transports[key]
	tcpTransport := t.tcpTransports[key]
	t.mu.Unlock()
	if h3Transport != nil {
		resp, err := roundTripHTTP3(h3Transport, req)
		if err == nil {
			return resp, nil
		}
		t.mu.Lock()
		candidate := t.h3TransportCandidates[key]
		t.mu.Unlock()
		var bodyErr *HTTP3RequestBodyError
		if errors.As(err, &bodyErr) || (req != nil && req.Context().Err() != nil) {
			return nil, err
		}
		t.removeH3Transport(key, h3Transport)
		if candidate.port != 0 && !suppressH3Candidate(req, err) {
			t.cache.remove(candidate, key)
		}
		if !automaticRequestCanFallback(req) {
			return nil, err
		}
		retryReq, replayErr := replayAutomaticRequest(req)
		if replayErr != nil {
			return nil, replayErr
		}
		return t.RoundTrip(retryReq)
	}
	if tcpTransport != nil && (t.ech == core.ECHUnknown || t.ech == core.ECHOff) {
		return tcpTransport.RoundTrip(req)
	}
	if tcpTransport != nil {
		// ECH configurations are DNS-scoped and may change between
		// connections. Do not let a long-lived automatic TCP transport reuse
		// a stale decision for a later request.
		t.mu.Lock()
		if t.tcpTransports[key] == tcpTransport {
			delete(t.tcpTransports, key)
			delete(t.tcpECHCandidates, key)
		}
		t.mu.Unlock()
		tcpTransport.CloseIdleConnections()
	}
	prepared, err := t.prepare(req.Context(), req.URL, key)
	if err != nil {
		return nil, err
	}
	if prepared.h3 != nil {
		return t.roundTripH3(req, prepared, key)
	}
	return t.roundTripTCP(req, prepared, key)
}

type preparedAutomaticConnection struct {
	tcp           net.Conn
	h3            *quic.Conn
	packet        net.PacketConn
	candidate     automaticH3Candidate
	echCandidates []resolver.ServiceCandidate
}

func (t *automaticHTTP3Transport) prepare(ctx context.Context, origin *url.URL, key string) (preparedAutomaticConnection, error) {
	if t == nil || t.resolver == nil || t.dialer == nil {
		return preparedAutomaticConnection{}, errors.New("automatic HTTP/3 transport is not initialized")
	}
	connectCtx, cancel := connectContext(ctx, t.connectLimit, "automatic HTTP/3 connection")
	defer cancel()

	type result struct {
		kind          string
		tcp           net.Conn
		h3            *quic.Conn
		packet        net.PacketConn
		candidate     automaticH3Candidate
		candidates    []automaticH3Candidate
		tcpAddrs      []net.IPAddr
		tcpPort       string
		echCandidates []resolver.ServiceCandidate
		err           error
	}
	results := make(chan result, automaticH3CacheLimit+4)
	raceCtx, stop := context.WithCancel(connectCtx)
	defer stop()

	go func() {
		endpoint, err := t.resolver.ResolveAddress(raceCtx, "tcp", net.JoinHostPort(origin.Hostname(), originPort(origin)))
		if err != nil {
			results <- result{kind: "tcp", err: err}
			return
		}
		cfg := t.tlsConfig.Clone()
		cfg.NextProtos = []string{"h2", "http/1.1"}
		got, err := t.dialer.Dial(raceCtx, DialRequest{
			Network:    "tcp",
			Host:       origin.Hostname(),
			Port:       originPort(origin),
			OriginHost: origin.Hostname(),
			Resolver:   t.resolver,
			Candidates: endpoint.Addrs,
			TLSConfig:  cfg,
			ALPN:       cfg.NextProtos,
			Timeout:    t.connectLimit,
		})
		if err != nil {
			results <- result{kind: "tcp", err: err}
			return
		}
		select {
		case results <- result{kind: "tcp", tcp: got.Conn, tcpAddrs: endpoint.Addrs, tcpPort: originPort(origin)}:
		case <-raceCtx.Done():
			_ = got.Conn.Close()
		}
	}()

	// Loading persistent candidates is deliberately outside the request
	// goroutine. It races normal TCP and fresh discovery instead of making
	// cache I/O part of the connection hot path.
	go func() {
		cached := t.cache.get(key, time.Now())
		select {
		case results <- result{kind: "cached", candidates: cached}:
		case <-raceCtx.Done():
		}
	}()

	go func() {
		discovery, err := t.resolver.DiscoverHTTPS(raceCtx, origin.Hostname(), uint16(parsePort(originPort(origin))), nil)
		if err != nil {
			kind := resolver.DiscoveryFailure(err)
			if kind == resolver.DiscoveryFailureNODATA || kind == resolver.DiscoveryFailureNXDOMAIN {
				// Authenticated NODATA/NXDOMAIN is a successful fresh
				// replacement of the DNS RRset, not a transient failure.
				t.cache.replaceDNS(key, nil)
			}
			results <- result{kind: "discovery", err: err}
			return
		}
		values := make([]automaticH3Candidate, 0, len(discovery.Candidates))
		echCandidates := make([]resolver.ServiceCandidate, 0, len(discovery.Candidates))
		for _, service := range discovery.Candidates {
			if len(service.ECH) > 0 && serviceAdvertisesTCP(service) {
				echCandidates = append(echCandidates, service)
			}
			if !serviceAdvertisesH3(service) || len(service.Addresses) == 0 {
				continue
			}
			values = append(values, automaticH3Candidate{
				host:      service.TargetName.String(),
				port:      service.Port,
				ech:       append([]byte(nil), service.ECH...),
				addresses: append([]net.IPAddr(nil), service.Addresses...),
				expires:   ttlExpiry(service.TTL, service.TTLPresent),
				source:    h3SourceDNS,
				priority:  service.Priority,
				learned:   time.Now(),
			})
		}
		// A successful fresh RRset replaces old DNS candidates, including an
		// authenticated NODATA result represented by an empty list.
		t.cache.replaceDNS(key, values)
		results <- result{kind: "discovery", candidates: values, echCandidates: echCandidates}
	}()

	pending := 3 // TCP, persistent-cache load, and discovery.
	var lastErr error
	var tcpPending result
	var haveTCP bool
	discoveryDone := false
	var discoveredECH []resolver.ServiceCandidate
	echEnabled := t.ech != core.ECHUnknown && t.ech != core.ECHOff
	for pending > 0 {
		select {
		case got := <-results:
			pending--
			switch got.kind {
			case "cached":
				// ECH=on must use a fresh, validated configuration. Cached
				// HTTP/3 alternatives are not sufficient policy evidence.
				if t.ech == core.ECHOn {
					continue
				}
				for _, candidate := range got.candidates {
					candidate := candidate
					pending++
					go func() {
						got, packet, err := t.dialH3(raceCtx, origin, candidate)
						select {
						case results <- result{kind: "h3", h3: got, packet: packet, candidate: candidate, err: err}:
						case <-raceCtx.Done():
							if got != nil {
								_ = got.CloseWithError(0, "HTTP/3 race cancelled")
							}
							if packet != nil {
								_ = packet.Close()
							}
						}
					}()
				}
			case "tcp":
				if got.err == nil && got.tcp != nil && echEnabled && discoveryDone {
					if len(discoveredECH) > 0 {
						_ = got.tcp.Close()
						conn, dialErr := t.dialAutomaticECHTCP(raceCtx, origin, got.tcpAddrs, got.tcpPort, discoveredECH)
						if dialErr != nil {
							return preparedAutomaticConnection{}, dialErr
						}
						return preparedAutomaticConnection{tcp: conn, echCandidates: cloneServiceCandidates(discoveredECH)}, nil
					}
					if t.ech == core.ECHOn {
						_ = got.tcp.Close()
						return preparedAutomaticConnection{}, ErrECHConfigUnavailable
					}
					return preparedAutomaticConnection{tcp: got.tcp}, nil
				}
				if got.err == nil && got.tcp != nil && echEnabled && !discoveryDone {
					// Keep the speculative connection until HTTPS discovery
					// completes. If a real config is found, redial with ECH;
					// otherwise auto mode may use this connection.
					tcpPending = got
					haveTCP = true
					continue
				}
				if got.err == nil && got.tcp != nil {
					return preparedAutomaticConnection{tcp: got.tcp}, nil
				}
				lastErr = got.err
			case "h3":
				if t.ech == core.ECHOn {
					if got.h3 != nil {
						_ = got.h3.CloseWithError(0, "ECH=on requires TCP")
					}
					if got.packet != nil {
						_ = got.packet.Close()
					}
					continue
				}
				if got.err == nil && got.h3 != nil {
					return preparedAutomaticConnection{h3: got.h3, packet: got.packet, candidate: got.candidate}, nil
				}
				lastErr = got.err
				if got.err != nil {
					t.cache.remove(got.candidate, key)
				}
			case "discovery":
				discoveryDone = true
				discoveredECH = append([]resolver.ServiceCandidate(nil), got.echCandidates...)
				if got.err != nil {
					if !resolver.MayDowngrade(got.err) {
						if haveTCP {
							_ = tcpPending.tcp.Close()
						}
						return preparedAutomaticConnection{}, got.err
					}
					lastErr = got.err
					if echEnabled && haveTCP {
						if t.ech == core.ECHOn {
							_ = tcpPending.tcp.Close()
							return preparedAutomaticConnection{}, ErrECHConfigUnavailable
						}
						return preparedAutomaticConnection{tcp: tcpPending.tcp}, nil
					}
					continue
				}
				if echEnabled && haveTCP {
					if len(got.echCandidates) > 0 {
						_ = tcpPending.tcp.Close()
						conn, dialErr := t.dialAutomaticECHTCP(raceCtx, origin, tcpPending.tcpAddrs, tcpPending.tcpPort, got.echCandidates)
						if dialErr != nil {
							return preparedAutomaticConnection{}, dialErr
						}
						return preparedAutomaticConnection{tcp: conn, echCandidates: cloneServiceCandidates(got.echCandidates)}, nil
					}
					if t.ech == core.ECHOn {
						_ = tcpPending.tcp.Close()
						return preparedAutomaticConnection{}, ErrECHConfigUnavailable
					}
					return preparedAutomaticConnection{tcp: tcpPending.tcp}, nil
				}
				if t.ech == core.ECHOn {
					continue
				}
				for _, candidate := range got.candidates {
					candidate := candidate
					pending++
					go func() {
						// Fresh DNS candidates get a small opportunity to win over
						// an older Alt-Svc candidate without waiting for discovery.
						timer := time.NewTimer(cachedH3Grace)
						select {
						case <-timer.C:
						case <-raceCtx.Done():
							if !timer.Stop() {
								select {
								case <-timer.C:
								default:
								}
							}
							return
						}
						got, packet, dialErr := t.dialH3(raceCtx, origin, candidate)
						select {
						case results <- result{kind: "h3", h3: got, packet: packet, candidate: candidate, err: dialErr}:
						case <-raceCtx.Done():
							if got != nil {
								_ = got.CloseWithError(0, "HTTP/3 race cancelled")
							}
							if packet != nil {
								_ = packet.Close()
							}
						}
					}()
				}
			}
		case <-raceCtx.Done():
			if err := context.Cause(raceCtx); err != nil {
				return preparedAutomaticConnection{}, err
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("automatic HTTP/3 and TCP connection failed")
	}
	return preparedAutomaticConnection{}, lastErr
}

func (t *automaticHTTP3Transport) dialH3(ctx context.Context, origin *url.URL, candidate automaticH3Candidate) (*quic.Conn, net.PacketConn, error) {
	if candidate.port == 0 || len(candidate.addresses) == 0 {
		return nil, nil, errors.New("HTTP/3 candidate has no address")
	}
	if t.ech == core.ECHOn && len(candidate.ech) == 0 {
		return nil, nil, errors.New("ECH is required but the HTTP/3 candidate has no ECH configuration")
	}
	baseTLSConfig := t.tlsConfig.Clone()
	if len(candidate.ech) > 0 && (t.ech == core.ECHAuto || t.ech == core.ECHOn) {
		baseTLSConfig.MinVersion = tls.VersionTLS13
		baseTLSConfig.EncryptedClientHelloConfigList = append([]byte(nil), candidate.ech...)
	}
	baseTLSConfig.NextProtos = []string{http3.NextProtoH3}
	if baseTLSConfig.ServerName == "" {
		baseTLSConfig.ServerName = core.TLSVerificationName(origin.Hostname())
	}
	qcfg := (&quic.Config{}).Clone()
	type result struct {
		conn   *quic.Conn
		packet net.PacketConn
	}
	trace := httptrace.ContextClientTrace(ctx)
	winner, err := resolver.RaceCandidates(ctx, candidate.addresses, func(attemptCtx context.Context, ip net.IPAddr) (result, error) {
		address := core.JoinIPHostPort(ip, strconv.Itoa(int(candidate.port)))
		if trace != nil && trace.ConnectStart != nil {
			trace.ConnectStart("udp", address)
		}
		var listen net.ListenConfig
		packet, err := listen.ListenPacket(attemptCtx, "udp", ":0")
		if err != nil {
			if trace != nil && trace.ConnectDone != nil {
				trace.ConnectDone("udp", address, err)
			}
			return result{}, err
		}
		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		// Each raced QUIC handshake must receive independent TLS state.
		attemptTLS := baseTLSConfig.Clone()
		attemptQUIC := qcfg.Clone()
		conn, err := quic.DialEarly(attemptCtx, packet, &net.UDPAddr{IP: ip.IP, Port: int(candidate.port), Zone: ip.Zone}, attemptTLS, attemptQUIC)
		if err == nil {
			select {
			case <-conn.HandshakeComplete():
			case <-attemptCtx.Done():
				err = context.Cause(attemptCtx)
			}
		}
		if trace != nil && trace.TLSHandshakeDone != nil {
			var state tls.ConnectionState
			if conn != nil && err == nil {
				state = conn.ConnectionState().TLS
			}
			trace.TLSHandshakeDone(state, err)
		}
		if err != nil {
			if conn != nil {
				_ = conn.CloseWithError(0, "HTTP/3 handshake failed")
			}
			_ = packet.Close()
			if trace != nil && trace.ConnectDone != nil {
				trace.ConnectDone("udp", address, err)
			}
			return result{}, err
		}
		if trace != nil && trace.ConnectDone != nil {
			trace.ConnectDone("udp", address, nil)
		}
		return result{conn: conn, packet: packet}, nil
	}, func(loser result) {
		if loser.conn != nil {
			_ = loser.conn.CloseWithError(0, "HTTP/3 address race lost")
		}
		if loser.packet != nil {
			_ = loser.packet.Close()
		}
	})
	if err != nil {
		return nil, nil, err
	}
	if trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Conn: traceAddrConn{remote: winner.conn.RemoteAddr()}})
	}
	return winner.conn, winner.packet, nil
}

func (t *automaticHTTP3Transport) roundTripTCP(req *http.Request, prepared preparedAutomaticConnection, key string) (*http.Response, error) {
	t.mu.Lock()
	rt := t.tcpTransports[key]
	if rt == nil {
		rt = t.fallback.Clone()
		first := prepared.tcp
		echCandidates := cloneServiceCandidates(prepared.echCandidates)
		tcpECH := len(echCandidates) > 0 && t.ech != core.ECHUnknown && t.ech != core.ECHOff
		var firstMu sync.Mutex
		rt.DialContext = nil
		rt.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			firstMu.Lock()
			conn := first
			first = nil
			firstMu.Unlock()
			if conn != nil {
				return conn, nil
			}
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if tcpECH {
				return t.dialAutomaticECHTCP(ctx, req.URL, nil, port, echCandidates)
			}
			cfg := t.tlsConfig.Clone()
			cfg.NextProtos = []string{"h2", "http/1.1"}
			got, err := t.dialer.Dial(ctx, DialRequest{
				Network: "tcp", Host: host, Port: port, OriginHost: req.URL.Hostname(),
				Resolver: t.resolver, TLSConfig: cfg, ALPN: cfg.NextProtos,
			})
			if err != nil {
				return nil, err
			}
			return got.Conn, nil
		}
		t.tcpTransports[key] = rt
		t.tcpECHCandidates[key] = echCandidates
		t.evictTransportOriginLocked(key)
	} else {
		_ = prepared.tcp.Close()
	}
	t.mu.Unlock()
	resp, err := rt.RoundTrip(req)
	if resp != nil && resp.Header != nil {
		t.scheduleAltSvc(req.Context(), req.URL, resp.Header.Get("Alt-Svc"))
	}
	return resp, err
}

func (t *automaticHTTP3Transport) roundTripH3(req *http.Request, prepared preparedAutomaticConnection, key string) (*http.Response, error) {
	candidate := prepared.candidate
	t.mu.Lock()
	h3 := t.h3Transports[key]
	if h3 == nil {
		first := prepared.h3
		h3 = &http3.Transport{
			DisableCompression: true,
			TLSClientConfig:    t.tlsConfig.Clone(),
			Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
				if first != nil {
					conn := first
					first = nil
					return conn, nil
				}
				conn, packet, err := t.dialH3(ctx, req.URL, candidate)
				if err != nil {
					return nil, err
				}
				t.replaceH3Packet(key, packet)
				return conn, nil
			},
		}
		t.h3Transports[key] = h3
		t.h3TransportCandidates[key] = candidate
		t.h3Packets[key] = prepared.packet
		t.evictTransportOriginLocked(key)
	} else {
		_ = prepared.h3.CloseWithError(0, "duplicate HTTP/3 race winner")
		_ = prepared.packet.Close()
	}
	t.mu.Unlock()
	resp, err := roundTripHTTP3(h3, req)
	if err != nil {
		var bodyErr *HTTP3RequestBodyError
		if errors.As(err, &bodyErr) || (req != nil && req.Context().Err() != nil) {
			return nil, err
		}
		t.removeH3Transport(key, h3)
		if !suppressH3Candidate(req, err) {
			t.cache.remove(candidate, key)
		}
		if automaticRequestCanFallback(req) {
			fallbackReq, replayErr := replayAutomaticRequest(req)
			if replayErr != nil {
				return nil, replayErr
			}
			return t.fallback.RoundTrip(fallbackReq)
		}
		return nil, err
	}
	if resp != nil && resp.Header != nil {
		t.scheduleAltSvc(req.Context(), req.URL, resp.Header.Get("Alt-Svc"))
	}
	return resp, nil
}

func suppressH3Candidate(req *http.Request, err error) bool {
	if req != nil && req.Context().Err() != nil {
		return true
	}
	return errors.Is(err, context.Canceled)
}

func automaticRequestCanFallback(req *http.Request) bool {
	if req == nil || (req.Body != nil && req.Body != http.NoBody) {
		return false
	}
	return req.Method == http.MethodGet || req.Method == http.MethodHead
}

// replayAutomaticRequest returns a request with an independent body for a
// policy-approved fallback. Bodyless requests are returned unchanged. Keeping
// this helper explicit prevents a future fallback path from accidentally
// reusing a stream already consumed by QUIC.
func replayAutomaticRequest(req *http.Request) (*http.Request, error) {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("HTTP/3 fallback requires a replayable request body")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("replay request body for HTTP/3 fallback: %w", err)
	}
	copy := req.Clone(req.Context())
	copy.Body = body
	return copy, nil
}

// evictTransportOriginLocked bounds retained per-origin transports. It is
// called while t.mu is held; HTTP/3 Close is intentionally synchronous so an
// evicted packet socket cannot outlive the transport that owns it.
func (t *automaticHTTP3Transport) evictTransportOriginLocked(exclude string) {
	if len(t.tcpTransports)+len(t.h3Transports) <= automaticTransportOriginLimit {
		return
	}
	for key, transport := range t.h3Transports {
		if key == exclude {
			continue
		}
		delete(t.h3Transports, key)
		delete(t.h3TransportCandidates, key)
		packet := t.h3Packets[key]
		delete(t.h3Packets, key)
		_ = transport.Close()
		if packet != nil {
			_ = packet.Close()
		}
		return
	}
	for key, transport := range t.tcpTransports {
		if key == exclude {
			continue
		}
		delete(t.tcpTransports, key)
		delete(t.tcpECHCandidates, key)
		transport.CloseIdleConnections()
		return
	}
}

func (t *automaticHTTP3Transport) replaceH3Packet(key string, packet net.PacketConn) {
	t.mu.Lock()
	old := t.h3Packets[key]
	t.h3Packets[key] = packet
	t.mu.Unlock()
	if old != nil && old != packet {
		_ = old.Close()
	}
}

func (t *automaticHTTP3Transport) removeH3Transport(key string, transport *http3.Transport) {
	t.mu.Lock()
	if t.h3Transports[key] != transport {
		t.mu.Unlock()
		return
	}
	delete(t.h3Transports, key)
	delete(t.h3TransportCandidates, key)
	packet := t.h3Packets[key]
	delete(t.h3Packets, key)
	t.mu.Unlock()
	_ = transport.Close()
	if packet != nil {
		_ = packet.Close()
	}
}

func serviceAdvertisesH3(candidate resolver.ServiceCandidate) bool {
	for _, alpn := range candidate.ALPN {
		if string(alpn) == http3.NextProtoH3 {
			return true
		}
	}
	return false
}

func automaticH3CacheKey(u *url.URL, res *resolver.Resolver) string {
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port := 0
	if parsed, err := strconv.Atoi(originPort(u)); err == nil {
		port = parsed
	}
	return strings.ToLower(u.Scheme) + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + "|" + res.CacheIdentity()
}

func ttlExpiry(ttl uint32, present bool) time.Time {
	if !present {
		return time.Now().Add(24 * time.Hour)
	}
	return time.Now().Add(time.Duration(ttl) * time.Second)
}

func parsePort(value string) int {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 443
	}
	return port
}

func (t *automaticHTTP3Transport) scheduleAltSvc(ctx context.Context, origin *url.URL, header string) {
	if t == nil || strings.TrimSpace(header) == "" || origin == nil {
		return
	}
	select {
	case t.altSvcSlots <- struct{}{}:
	default:
		// Alt-Svc is an optimization. Never make response delivery wait for
		// DNS or cache maintenance, and never create an unbounded goroutine
		// backlog when a server sends it on every response.
		return
	}
	go func() {
		defer func() { <-t.altSvcSlots }()
		t.recordAltSvc(ctx, origin, header)
	}()
}

func (t *automaticHTTP3Transport) recordAltSvc(ctx context.Context, origin *url.URL, header string) {
	if strings.TrimSpace(header) == "" {
		return
	}
	lookupTimeout := time.Second
	if t.connectLimit > 0 && t.connectLimit < lookupTimeout {
		lookupTimeout = t.connectLimit
	}
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	key := automaticH3CacheKey(origin, t.resolver)
	for _, item := range splitAltSvc(header) {
		if item.clear {
			t.cache.clearAltSvc(key)
			continue
		}
		if item.alpn != http3.NextProtoH3 {
			continue
		}
		host := item.host
		if host == "" {
			host = origin.Hostname()
		}
		addresses, err := t.resolver.LookupIPAddr(lookupCtx, host)
		if err != nil {
			continue
		}
		t.cache.addAltSvc(key, automaticH3Candidate{host: host, port: item.port, addresses: addresses, expires: time.Now().Add(item.maxAge), source: h3SourceAltSvc, learned: time.Now()})
	}
}

type altSvcValue struct {
	alpn   string
	host   string
	port   uint16
	maxAge time.Duration
	clear  bool
}

func splitAltSvc(header string) []altSvcValue {
	var out []altSvcValue
	for _, field := range strings.Split(header, ",") {
		field = strings.TrimSpace(field)
		if strings.EqualFold(field, "clear") {
			out = append(out, altSvcValue{clear: true})
			continue
		}
		parts := strings.Split(field, ";")
		if len(parts) == 0 {
			continue
		}
		alpn, authority, ok := strings.Cut(strings.TrimSpace(parts[0]), "=")
		if !ok {
			continue
		}
		alpn = strings.Trim(strings.TrimSpace(alpn), `"`)
		authority = strings.Trim(strings.TrimSpace(authority), `"`)
		if alpn == "" || authority == "" {
			continue
		}
		host, portText, err := parseAltSvcAuthority(authority)
		if err != nil {
			continue
		}
		value := altSvcValue{alpn: alpn, host: host, port: portText, maxAge: 24 * time.Hour}
		for _, parameter := range parts[1:] {
			name, raw, has := strings.Cut(strings.TrimSpace(parameter), "=")
			if !has || !strings.EqualFold(name, "ma") {
				continue
			}
			seconds, err := strconv.ParseUint(strings.Trim(strings.TrimSpace(raw), `"`), 10, 31)
			if err == nil {
				value.maxAge = time.Duration(seconds) * time.Second
			}
		}
		out = append(out, value)
	}
	return out
}

func parseAltSvcAuthority(value string) (string, uint16, error) {
	if strings.HasPrefix(value, ":") {
		port, err := strconv.ParseUint(value[1:], 10, 16)
		if err != nil || port == 0 {
			return "", 0, fmt.Errorf("invalid Alt-Svc port")
		}
		return "", uint16(port), nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, err
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", 0, fmt.Errorf("invalid Alt-Svc port")
	}
	return strings.Trim(host, "[]"), uint16(portNumber), nil
}
