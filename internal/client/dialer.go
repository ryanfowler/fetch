package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http/httptrace"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
)

// DialMode describes the first-hop strategy used by a DialRequest. A proxy
// mode does not implement a proxy protocol by itself. The Attempt callback
// does that work after the dialer has selected an address. Keeping that
// protocol detail outside the race coordinator lets HTTP, SOCKS, Unix-socket,
// and test transports share one lifecycle and timeout policy.
type DialMode string

const (
	DialDirect     DialMode = "direct"
	DialHTTPProxy  DialMode = "http-proxy"
	DialHTTPSProxy DialMode = "https-proxy"
	DialSOCKS5     DialMode = "socks5"
	DialSOCKS5H    DialMode = "socks5h"
	DialUnix       DialMode = "unix"
)

// DialTiming contains connection-establishment measurements. A zero field
// means that the phase did not run. The value describes the winning attempt;
// failed and cancelled race candidates are not included in the result.
type DialTiming struct {
	ResolutionStart time.Time
	ResolutionDone  time.Time
	ConnectStart    time.Time
	ConnectDone     time.Time
	TLSStart        time.Time
	TLSDone         time.Time
	DNSDuration     time.Duration
	ConnectDuration time.Duration
	TLSDuration     time.Duration
}

// DialTimingRecorder is an optional low-overhead event sink. Implementations
// must not retain mutable address slices supplied to ResolutionDone.
type DialTimingRecorder interface {
	ResolutionStarted(host string)
	ResolutionDone(host string, addrs []net.IPAddr, err error)
	ConnectionStarted(network, address string)
	ConnectionDone(network, address string, err error)
	TLSStarted()
	TLSDone(state tls.ConnectionState, err error)
}

// DialRequest describes one connection setup operation. Host and Port identify
// the effective service target. OriginHost is used for TLS SNI only when the
// TLS config does not already provide ServerName; this preserves origin
// authority when an HTTPS/SVCB service target differs from the origin host.
type DialRequest struct {
	Network    string
	Address    string
	Host       string
	Port       string
	OriginHost string
	Mode       DialMode

	Resolver      *resolver.Resolver
	ResolverScope string
	Candidates    []net.IPAddr
	UnixSocket    string
	Budget        core.Budget
	Timeout       time.Duration

	TLSConfig *tls.Config
	ALPN      []string
	Attempt   func(context.Context, string, net.IPAddr) (net.Conn, error)
	// AttemptWithInfo associates protocol negotiation metadata with the
	// connection that wins the address race.
	AttemptWithInfo func(context.Context, string, net.IPAddr) (net.Conn, any, error)
	Recorder        DialTimingRecorder
}

// DialResult is the successful connection and the metadata selected during
// setup. The caller owns Conn and must close it.
type DialResult struct {
	Conn          net.Conn
	RemoteIP      net.IP
	ResolvedAddrs []net.IPAddr
	Resolver      string
	Timing        DialTiming
	TLSState      *tls.ConnectionState
	// ECHInfo is populated by ECH-aware attempts and is intentionally typed as
	// any here so the generic dialer does not depend on the ECH policy model.
	ECHInfo          any
	ResolverScope    string
	EffectiveAddress string
}

// ResolverDialer is the shared resolver-aware Happy Eyeballs coordinator.
// It resolves a target once, preserves the resolver's preferred family, races
// bounded candidates, and applies one absolute connection budget to DNS,
// proxy callbacks, TCP, and optional TLS.
type ResolverDialer struct {
	Resolver       *resolver.Resolver
	ConnectTimeout time.Duration
	BaseDial       func(context.Context, string, string) (net.Conn, error)
}

// NewResolverDialer constructs the dialer used by application transports.
func NewResolverDialer(res *resolver.Resolver, connectTimeout time.Duration) *ResolverDialer {
	return &ResolverDialer{Resolver: res, ConnectTimeout: connectTimeout}
}

// DialContext is the net/http-compatible direct TCP entry point. Use Dial for
// optional TLS, timing metadata, proxy strategies, or Unix sockets.
func (d *ResolverDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	result, err := d.Dial(ctx, DialRequest{Network: network, Address: address})
	if err != nil {
		return nil, err
	}
	return result.Conn, nil
}

// Dial performs one resolver-aware connection setup operation.
func (d *ResolverDialer) Dial(ctx context.Context, req DialRequest) (DialResult, error) {
	if ctx == nil {
		return DialResult{}, errors.New("dial context is nil")
	}
	if d == nil {
		return DialResult{}, errors.New("resolver dialer is nil")
	}
	if req.Timeout < 0 {
		return DialResult{}, fmt.Errorf("dial timeout must be non-negative: %s", req.Timeout)
	}
	if d.ConnectTimeout < 0 {
		return DialResult{}, fmt.Errorf("connect timeout must be non-negative: %s", d.ConnectTimeout)
	}
	if req.Network == "" {
		req.Network = "tcp"
	}
	if req.TLSConfig != nil {
		if err := core.ValidateTLSVersions(req.TLSConfig.MinVersion, req.TLSConfig.MaxVersion); err != nil {
			return DialResult{}, err
		}
	}
	if req.Mode == "" {
		req.Mode = DialDirect
	}
	switch req.Mode {
	case DialDirect, DialUnix:
	case DialHTTPProxy, DialHTTPSProxy, DialSOCKS5, DialSOCKS5H:
		if req.Attempt == nil && req.AttemptWithInfo == nil {
			return DialResult{}, fmt.Errorf("%s mode requires a connection attempt strategy", req.Mode)
		}
	default:
		return DialResult{}, fmt.Errorf("unsupported dial mode %q", req.Mode)
	}
	if req.Address != "" {
		host, port, err := net.SplitHostPort(req.Address)
		if err != nil {
			return DialResult{}, fmt.Errorf("invalid dial address %q: %w", req.Address, err)
		}
		if req.Host == "" {
			req.Host = host
		}
		if req.Port == "" {
			req.Port = port
		}
	}
	if req.Mode == DialUnix && req.UnixSocket == "" {
		return DialResult{}, errors.New("unix dial mode requires a socket path")
	}
	if req.Host == "" || req.Port == "" {
		if req.UnixSocket == "" {
			return DialResult{}, errors.New("dial host and port are required")
		}
	}

	connectCtx, cancel := d.connectionContext(ctx, req)
	defer cancel()

	if req.UnixSocket != "" {
		return d.dialUnix(connectCtx, req)
	}

	res := req.Resolver
	if res == nil {
		res = d.Resolver
	}
	if res == nil {
		res = resolver.New(resolver.Config{})
	}

	result := DialResult{ResolverScope: req.ResolverScope, Resolver: res.Provenance()}
	if result.ResolverScope == "" {
		result.ResolverScope = result.Resolver
	}

	candidates := append([]net.IPAddr(nil), req.Candidates...)
	if len(candidates) == 0 {
		result.Timing.ResolutionStart = time.Now()
		if req.Recorder != nil {
			req.Recorder.ResolutionStarted(req.Host)
		}
		resolved, err := res.ResolveAddress(connectCtx, req.Network, net.JoinHostPort(req.Host, req.Port))
		result.Timing.ResolutionDone = time.Now()
		result.Timing.DNSDuration = result.Timing.ResolutionDone.Sub(result.Timing.ResolutionStart)
		if req.Recorder != nil {
			req.Recorder.ResolutionDone(req.Host, append([]net.IPAddr(nil), resolved.Addrs...), err)
		}
		if err != nil {
			return DialResult{}, err
		}
		candidates = resolved.Addrs
	}
	result.ResolvedAddrs = append([]net.IPAddr(nil), candidates...)
	if len(candidates) == 0 {
		return DialResult{}, errors.New("no addresses found")
	}

	type connection struct {
		conn  net.Conn
		ip    net.IP
		state *tls.ConnectionState
		info  any
		time  DialTiming
	}
	attempt := func(attemptCtx context.Context, ip net.IPAddr) (connection, error) {
		started := time.Now()
		address := core.JoinIPHostPort(ip, req.Port)
		if req.Recorder != nil {
			req.Recorder.ConnectionStarted(req.Network, address)
		}
		var conn net.Conn
		var info any
		var err error
		trace := httptrace.ContextClientTrace(attemptCtx)
		manualConnectTrace := req.Attempt != nil || req.AttemptWithInfo != nil || d.BaseDial != nil
		if manualConnectTrace && trace != nil && trace.ConnectStart != nil {
			trace.ConnectStart(req.Network, address)
		}
		if req.AttemptWithInfo != nil {
			conn, info, err = req.AttemptWithInfo(attemptCtx, req.Network, ip)
		} else if req.Attempt != nil {
			conn, err = req.Attempt(attemptCtx, req.Network, ip)
		} else if d.BaseDial != nil {
			conn, err = d.BaseDial(attemptCtx, req.Network, address)
		} else {
			var netDialer net.Dialer
			conn, err = netDialer.DialContext(attemptCtx, req.Network, address)
		}
		if manualConnectTrace && trace != nil && trace.ConnectDone != nil {
			trace.ConnectDone(req.Network, address, err)
		}
		if req.Recorder != nil {
			req.Recorder.ConnectionDone(req.Network, address, err)
		}
		if err != nil {
			return connection{}, err
		}
		if conn == nil {
			return connection{}, errors.New("dial attempt returned a nil connection")
		}
		timing := DialTiming{ConnectStart: started, ConnectDone: time.Now()}
		timing.ConnectDuration = timing.ConnectDone.Sub(timing.ConnectStart)
		// Some platforms expose a coarse wall clock. Preserve the invariant
		// that a completed connection has a positive measured duration even
		// when both samples fall in one clock tick.
		if timing.ConnectDuration <= 0 {
			timing.ConnectDuration = time.Nanosecond
		}
		if deadline, ok := attemptCtx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}

		var state *tls.ConnectionState
		if req.TLSConfig != nil {
			cfg := req.TLSConfig.Clone()
			if cfg.ServerName == "" {
				serverName := req.OriginHost
				if serverName == "" {
					serverName = req.Host
				}
				// Keep IP literals in ServerName so certificate hostname
				// verification still checks the IP SAN. crypto/tls omits an IP
				// literal from SNI itself.
				cfg.ServerName = core.TLSVerificationName(serverName)
			}
			if len(cfg.NextProtos) == 0 && len(req.ALPN) > 0 {
				cfg.NextProtos = append([]string(nil), req.ALPN...)
			}
			if req.Recorder != nil {
				req.Recorder.TLSStarted()
			}
			if trace != nil && trace.TLSHandshakeStart != nil {
				trace.TLSHandshakeStart()
			}
			timing.TLSStart = time.Now()
			tlsConn := tls.Client(conn, cfg)
			err = tlsConn.HandshakeContext(attemptCtx)
			timing.TLSDone = time.Now()
			timing.TLSDuration = timing.TLSDone.Sub(timing.TLSStart)
			if err != nil {
				if req.Recorder != nil {
					req.Recorder.TLSDone(tls.ConnectionState{}, err)
				}
				if trace != nil && trace.TLSHandshakeDone != nil {
					trace.TLSHandshakeDone(tls.ConnectionState{}, err)
				}
				_ = conn.Close()
				return connection{}, err
			}
			cs := tlsConn.ConnectionState()
			state = &cs
			if req.Recorder != nil {
				req.Recorder.TLSDone(cs, nil)
			}
			if trace != nil && trace.TLSHandshakeDone != nil {
				trace.TLSHandshakeDone(cs, nil)
			}
			_ = tlsConn.SetDeadline(time.Time{})
			conn = tlsConn
		} else {
			_ = conn.SetDeadline(time.Time{})
		}
		return connection{conn: conn, ip: append(net.IP(nil), ip.IP...), state: state, info: info, time: timing}, nil
	}

	winner, err := resolver.RaceCandidates(connectCtx, candidates, attempt, func(loser connection) {
		if loser.conn != nil {
			_ = loser.conn.Close()
		}
	})
	if err != nil {
		return DialResult{}, err
	}
	result.Conn = winner.conn
	result.RemoteIP = winner.ip
	result.TLSState = winner.state
	result.ECHInfo = winner.info
	result.Timing.ConnectStart = winner.time.ConnectStart
	result.Timing.ConnectDone = winner.time.ConnectDone
	result.Timing.ConnectDuration = winner.time.ConnectDuration
	result.Timing.TLSStart = winner.time.TLSStart
	result.Timing.TLSDone = winner.time.TLSDone
	result.Timing.TLSDuration = winner.time.TLSDuration
	result.EffectiveAddress = net.JoinHostPort(winner.ip.String(), req.Port)
	return result, nil
}

func (d *ResolverDialer) connectionContext(ctx context.Context, req DialRequest) (context.Context, context.CancelFunc) {
	if req.Budget.Limited() {
		return req.Budget.WithConnectionContext(ctx, "resolver/DNS/TCP/TLS connect")
	}
	timeout := req.Timeout
	if timeout == 0 {
		timeout = d.ConnectTimeout
	}
	return connectContext(ctx, timeout, "resolver/DNS/TCP/TLS connect")
}

func (d *ResolverDialer) dialUnix(ctx context.Context, req DialRequest) (DialResult, error) {
	started := time.Now()
	var conn net.Conn
	var err error
	if req.Attempt != nil {
		conn, err = req.Attempt(ctx, "unix", net.IPAddr{})
	} else if d.BaseDial != nil {
		conn, err = d.BaseDial(ctx, "unix", req.UnixSocket)
	} else {
		var dialer net.Dialer
		conn, err = dialer.DialContext(ctx, "unix", req.UnixSocket)
	}
	if err != nil {
		return DialResult{}, err
	}
	if conn == nil {
		return DialResult{}, errors.New("unix dial returned a nil connection")
	}
	_ = conn.SetDeadline(time.Time{})
	return DialResult{
		Conn:             conn,
		Resolver:         "none (Unix socket)",
		ResolverScope:    req.ResolverScope,
		EffectiveAddress: req.UnixSocket,
		Timing: DialTiming{
			ConnectStart:    started,
			ConnectDone:     time.Now(),
			ConnectDuration: time.Since(started),
		},
	}, nil
}
