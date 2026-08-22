package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
)

var errECHNotAccepted = errors.New("ECH handshake completed without ECH acceptance")

// ECHHandshakeInfo describes the ECH offer and the final outcome of a TLS
// connection. It is used by TLS inspection; normal HTTP callers do not need
// to interpret it.
type ECHHandshakeInfo struct {
	Offered         bool
	Real            bool
	Accepted        bool
	Rejected        bool
	Fallback        bool
	OuterServerName string
}

// dialTLSWithECHPolicy performs a TLS handshake and applies the ECH retry and
// downgrade rules. rawDial must create a new TCP connection on every call:
// TLS connections that return ECHRejectionError cannot be reused for a retry.
func dialTLSWithECHPolicy(ctx context.Context, rawDial func(context.Context) (net.Conn, error), base *tls.Config, mode core.ECHMode) (net.Conn, error) {
	conn, _, err := dialTLSWithECHPolicyInfo(ctx, rawDial, base, mode, false)
	return conn, err
}

func dialTLSWithECHPolicyInfo(ctx context.Context, rawDial func(context.Context) (net.Conn, error), base *tls.Config, mode core.ECHMode, real bool) (net.Conn, ECHHandshakeInfo, error) {
	info := ECHHandshakeInfo{Real: real}
	if base != nil {
		info.Offered = len(base.EncryptedClientHelloConfigList) > 0
		info.OuterServerName = base.ServerName
	}
	if rawDial == nil {
		return nil, info, errors.New("ECH raw dialer is nil")
	}
	if base == nil {
		base = &tls.Config{}
	}
	cfg := base.Clone()
	for attempt := 0; ; attempt++ {
		conn, err := rawDial(ctx)
		if err != nil {
			return nil, info, err
		}
		if conn == nil {
			return nil, info, errors.New("ECH raw dialer returned a nil connection")
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}

		tlsConn := tls.Client(conn, cfg)
		err = tlsConn.HandshakeContext(ctx)
		if err == nil {
			state := tlsConn.ConnectionState()
			if len(cfg.EncryptedClientHelloConfigList) > 0 && !state.ECHAccepted {
				_ = conn.Close()
				info.Rejected = true
				if mode == core.ECHAuto {
					// crypto/tls normally reports a rejection as
					// ECHRejectionError. Keep this check as a policy guard
					// for future implementations that may complete the
					// outer handshake without returning that error.
					cfg = cfg.Clone()
					cfg.EncryptedClientHelloConfigList = nil
					mode = core.ECHOff
					info.Fallback = true
					continue
				}
				return nil, info, errECHNotAccepted
			}
			info.Accepted = state.ECHAccepted
			_ = tlsConn.SetDeadline(time.Time{})
			return tlsConn, info, nil
		}
		_ = conn.Close()

		var rejection *tls.ECHRejectionError
		if !errors.As(err, &rejection) {
			return nil, info, err
		}
		info.Rejected = true
		if attempt == 0 && len(rejection.RetryConfigList) > 0 {
			retryList, validateErr := resolver.SupportedECHConfigList(rejection.RetryConfigList)
			if validateErr != nil {
				return nil, info, validateErr
			}
			cfg = cfg.Clone()
			cfg.MinVersion = tls.VersionTLS13
			cfg.EncryptedClientHelloConfigList = retryList
			continue
		}
		if mode != core.ECHAuto {
			return nil, info, err
		}

		// A verified rejection is the expected result of a GREASE offer and is
		// also a permitted outcome for auto mode when a real configuration is
		// stale. Retry ordinary TLS exactly once, using the same context and
		// therefore the same connect budget. No certificate error reaches this
		// branch: crypto/tls verifies the outer ECH provider before returning an
		// ECHRejectionError, even when InsecureSkipVerify is set.
		cfg = cfg.Clone()
		cfg.EncryptedClientHelloConfigList = nil
		mode = core.ECHOff
		info.Fallback = true
	}
}

// dialResolverWithECH uses the resolver-aware address race while keeping ECH
// retries inside each address attempt. This is needed because a rejected ECH
// handshake requires a fresh TCP connection and must not make the resolver
// race restart from scratch.
func dialResolverWithECH(ctx context.Context, dialer *ResolverDialer, request DialRequest, cfg *tls.Config, mode core.ECHMode) (DialResult, error) {
	return dialResolverWithECHInfo(ctx, dialer, request, cfg, mode, false)
}

// DialResolverWithECH performs a resolver-aware TLS connection and returns
// ECH outcome metadata for inspection callers. real must be true when cfg was
// built from an advertised ECHConfigList and false for GREASE.
func DialResolverWithECH(ctx context.Context, dialer *ResolverDialer, request DialRequest, cfg *tls.Config, mode core.ECHMode, real bool) (DialResult, error) {
	return dialResolverWithECHInfo(ctx, dialer, request, cfg, mode, real)
}

func dialResolverWithECHInfo(ctx context.Context, dialer *ResolverDialer, request DialRequest, cfg *tls.Config, mode core.ECHMode, real bool) (DialResult, error) {
	if dialer == nil {
		return DialResult{}, errors.New("ECH resolver dialer is nil")
	}
	baseDial := dialer.BaseDial
	if baseDial == nil {
		var netDialer net.Dialer
		baseDial = netDialer.DialContext
	}
	port := request.Port
	if port == "" && request.Address != "" {
		_, parsedPort, err := net.SplitHostPort(request.Address)
		if err != nil {
			return DialResult{}, err
		}
		port = parsedPort
	}
	if port == "" {
		return DialResult{}, errors.New("ECH resolver dial requires a port")
	}
	request.TLSConfig = nil
	request.ALPN = nil
	request.AttemptWithInfo = func(attemptCtx context.Context, network string, ip net.IPAddr) (net.Conn, any, error) {
		address := core.JoinIPHostPort(ip, port)
		conn, info, err := dialTLSWithECHPolicyInfo(attemptCtx, func(rawCtx context.Context) (net.Conn, error) {
			return baseDial(rawCtx, network, address)
		}, cfg, mode, real)
		return conn, info, err
	}
	return dialer.Dial(ctx, request)
}
