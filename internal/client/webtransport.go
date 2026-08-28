package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http/httptrace"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
)

// NewWebTransport returns the configured WebTransport transport. The caller
// owns the returned transport through Client.Close; packet sockets are kept
// private so a failed or canceled session cannot leak them.
func (c *Client) NewWebTransport(protocols []string) (*webtransport.Transport, error) {
	if c == nil {
		return nil, errors.New("nil client")
	}
	if !c.webTransport {
		return nil, errors.New("client was not configured for WebTransport")
	}
	if c.initErr != nil {
		return nil, c.initErr
	}
	t := &webtransport.Transport{
		Config: &webtransport.Config{MaxIncomingStreams: -1, MaxIncomingUniStreams: -1},
		TLSClientConfig: func() *tls.Config {
			cfg := c.tlsConfig.Clone()
			cfg.NextProtos = []string{http3.NextProtoH3}
			return cfg
		}(),
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
		ApplicationProtocols: append([]string(nil), protocols...),
	}
	t.DialAddr = c.webTransportDial
	return t, nil
}

func (c *Client) webTransportDial(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
	connectCtx, cancel := connectContext(ctx, c.connectTimeout, "DNS/QUIC/TLS connect")
	defer cancel()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = strings.Trim(host, "[]"), "443"
		host = strings.ReplaceAll(host, "%25", "%")
	}
	trace := httptrace.ContextClientTrace(connectCtx)
	if trace != nil && trace.DNSStart != nil {
		trace.DNSStart(httptrace.DNSStartInfo{Host: host})
	}
	_, hasResolve, err := c.resolver.ResolveAddressOverride("udp", host, port)
	if err != nil {
		return nil, err
	}
	endpoint, err := c.resolver.ResolveAddress(connectCtx, "udp", net.JoinHostPort(host, port))
	if trace != nil && trace.DNSDone != nil {
		info := httptrace.DNSDoneInfo{Err: err}
		if err == nil {
			info.Addrs = append([]net.IPAddr(nil), endpoint.Addrs...)
		}
		trace.DNSDone(info)
	}
	if err != nil {
		return nil, err
	}
	if !hasResolve {
		discoveryPort := 443
		if parsed, parseErr := strconv.Atoi(port); parseErr == nil && parsed > 0 && parsed <= 65535 {
			discoveryPort = parsed
		}
		discovery, discoveryErr := c.resolver.DiscoverHTTPS(connectCtx, host, uint16(discoveryPort), nil)
		if discoveryErr != nil && (c.echMode == core.ECHOn || resolver.IsAuthenticatedDiscoveryFailure(discoveryErr)) {
			return nil, discoveryErr
		}
		if discoveryErr == nil {
			for i := range discovery.Candidates {
				candidate := &discovery.Candidates[i]
				supportsH3 := false
				for _, alpn := range candidate.ALPN {
					if string(alpn) == "h3" {
						supportsH3 = true
						break
					}
				}
				if supportsH3 { // selected HTTP/3 service
					if len(candidate.Addresses) > 0 {
						endpoint.Addrs = candidate.Addresses
					}
					if candidate.Port != 0 {
						endpoint.Port = strconv.Itoa(int(candidate.Port))
					}
					break
				}
			}
		}
	}
	portNumber, err := strconv.Atoi(endpoint.Port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("invalid WebTransport port %q", endpoint.Port)
	}
	baseTLS := tlsCfg.Clone()
	if baseTLS.ServerName == "" {
		baseTLS.ServerName = core.TLSVerificationName(host)
	}
	// ECH discovery is deliberately performed on the same resolver and within
	// the same connection budget as address resolution.
	if c.echMode != core.ECHUnknown && c.echMode != core.ECHOff {
		echResolver := c.resolver
		if hasResolve {
			if c.echMode == core.ECHOn {
				return nil, ErrECHConfigUnavailable
			}
			echResolver = nil // authoritative --resolve does not trigger discovery
		}
		ech, echErr := DiscoverECHForConnection(connectCtx, echResolver, host, endpoint.Port, baseTLS, c.echMode, core.HTTP3)
		if echErr != nil {
			return nil, echErr
		}
		baseTLS = ech.TLSConfig()
		if targetHost, targetPort := ech.Target(); targetHost != "" {
			host, endpoint.Port = targetHost, targetPort
			portNumber, _ = strconv.Atoi(targetPort)
		}
		if addresses := ech.Addresses(); len(addresses) > 0 {
			endpoint.Addrs = addresses
		}
	}
	if len(endpoint.Addrs) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}
	winner, err := raceQUIC(connectCtx, endpoint.Addrs, portNumber, baseTLS, qcfg, trace, func(p net.PacketConn) {
		c.wtMu.Lock()
		if c.wtClosed {
			c.wtMu.Unlock()
			_ = p.Close()
			return
		}
		c.wtPackets = append(c.wtPackets, p)
		c.wtMu.Unlock()
	})
	if err != nil {
		return nil, err
	}
	return winner, nil
}

// raceQUIC keeps the QUIC attempt and its packet socket together. A socket is
// caller-owned even after quic.Conn.Close, so both are closed on every loss.
func raceQUIC(ctx context.Context, addresses []net.IPAddr, port int, tlsCfg *tls.Config, qcfg *quic.Config, trace *httptrace.ClientTrace, own func(net.PacketConn)) (*quic.Conn, error) {
	type attemptResult struct {
		conn   *quic.Conn
		packet net.PacketConn
	}
	result, err := resolver.RaceCandidates(ctx, addresses, func(attemptCtx context.Context, ip net.IPAddr) (attemptResult, error) {
		address := core.JoinIPHostPort(ip, strconv.Itoa(port))
		if trace != nil && trace.ConnectStart != nil {
			trace.ConnectStart("udp", address)
		}
		packet, err := (&net.ListenConfig{}).ListenPacket(attemptCtx, "udp", ":0")
		if err != nil {
			return attemptResult{}, err
		}
		cfg := qcfg
		if cfg != nil {
			cfg = cfg.Clone()
		} else {
			cfg = &quic.Config{}
		}
		cfg.EnableDatagrams = true
		cfg.EnableStreamResetPartialDelivery = true
		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		conn, err := quic.DialEarly(attemptCtx, packet, &net.UDPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}, tlsCfg.Clone(), cfg)
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
		if trace != nil && trace.ConnectDone != nil {
			trace.ConnectDone("udp", address, err)
		}
		if err != nil {
			if conn != nil {
				_ = conn.CloseWithError(0, "handshake failed")
			}
			_ = packet.Close()
			return attemptResult{}, err
		}
		return attemptResult{conn: conn, packet: packet}, nil
	}, func(loser attemptResult) {
		if loser.conn != nil {
			_ = loser.conn.CloseWithError(0, "address race lost")
		}
		if loser.packet != nil {
			_ = loser.packet.Close()
		}
	})
	if err != nil {
		return nil, err
	}
	own(result.packet)
	if trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Conn: traceAddrConn{remote: result.conn.RemoteAddr()}})
	}
	return result.conn, nil
}
