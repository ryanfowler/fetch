package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// doqALPN is the ALPN token assigned to DNS-over-QUIC by RFC 9250.
	doqALPN = "doq"
	// A DNS message is framed by an unsigned two-byte length on a DoQ stream.
	maxDoQFrame = 65535
)

// QUICDialFunc is the injectable QUIC connection operation used by DoQ. The
// packet connection is owned by the caller and must remain open until the
// returned connection is closed.
type QUICDialFunc func(context.Context, net.PacketConn, *net.UDPAddr, *tls.Config, *quic.Config) (*quic.Conn, error)

// DoQConfig is an alias for the transport-neutral stream configuration. The
// same endpoint bootstrap and TLS policy is used by DoT and DoQ.
type DoQConfig = StreamConfig

// QUICConfig is retained as a descriptive alias for callers that select the
// transport by protocol name.
type QUICConfig = StreamConfig

// DoQClient sends DNS queries over one operation-scoped QUIC connection. Each
// query uses a separate bidirectional stream, as required by RFC 9250.
type DoQClient struct {
	conn       *quic.Conn
	packetConn net.PacketConn
	once       sync.Once
}

// NewDoQClient establishes a verified DNS-over-QUIC connection. Resolver
// endpoint hostnames are bootstrapped with cfg.Bootstrap, or with the system
// resolver when no hook is supplied. The bootstrap hook must not recursively
// use this DoQ endpoint.
func NewDoQClient(ctx context.Context, cfg DoQConfig) (*DoQClient, error) {
	if cfg.Endpoint == nil {
		return nil, errors.New("DNS-over-QUIC endpoint is missing")
	}
	if cfg.Endpoint.Transport != TransportQUIC {
		return nil, fmt.Errorf("DNS-over-QUIC endpoint uses %s transport", cfg.Endpoint.Transport)
	}

	tlsConfig, err := doqTLSConfig(cfg, cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	addresses, err := bootstrapDoQEndpoint(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if len(addresses) > maxStreamEndpointAddresses {
		addresses = addresses[:maxStreamEndpointAddresses]
	}

	dial := cfg.QUICDial
	if dial == nil {
		dial = func(ctx context.Context, packetConn net.PacketConn, address *net.UDPAddr, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			return quic.Dial(ctx, packetConn, address, tlsConfig, quicConfig)
		}
	}

	addresses = interleaveAddressFamilies(deduplicateAddresses(addresses))
	result, err := RaceCandidates(ctx, addresses, func(attemptCtx context.Context, address net.IPAddr) (doqDialResult, error) {
		packetConn, listenErr := listenDoQPacketConn(attemptCtx)
		if listenErr != nil {
			return doqDialResult{}, listenErr
		}
		quicConfig := &quic.Config{}
		if quicTimeout, ok := doqQUICTimeout(attemptCtx); ok {
			quicConfig.HandshakeIdleTimeout = quicTimeout
			quicConfig.MaxIdleTimeout = quicTimeout
		}
		conn, dialErr := dial(attemptCtx, packetConn, &net.UDPAddr{IP: address.IP, Port: int(cfg.Endpoint.Port)}, tlsConfig, quicConfig)
		if dialErr != nil {
			_ = packetConn.Close()
			if strings.Contains(strings.ToLower(dialErr.Error()), "application protocol") {
				dialErr = fmt.Errorf("DNS-over-QUIC ALPN negotiation failed: %w", dialErr)
			}
			return doqDialResult{}, dialErr
		}
		if negotiated := conn.ConnectionState().TLS.NegotiatedProtocol; negotiated != doqALPN {
			_ = conn.CloseWithError(0, "DNS-over-QUIC ALPN negotiation failed")
			_ = packetConn.Close()
			return doqDialResult{}, fmt.Errorf("DNS-over-QUIC negotiated ALPN %q, want %q", negotiated, doqALPN)
		}
		return doqDialResult{conn: conn, packetConn: packetConn}, nil
	}, func(result doqDialResult) {
		if result.conn != nil {
			_ = result.conn.CloseWithError(0, "DNS-over-QUIC address race lost")
		}
		if result.packetConn != nil {
			_ = result.packetConn.Close()
		}
	})
	if err != nil {
		return nil, fmt.Errorf("connect to DNS-over-QUIC endpoint %s: %w", cfg.Endpoint, err)
	}
	return &DoQClient{conn: result.conn, packetConn: result.packetConn}, nil
}

type doqDialResult struct {
	conn       *quic.Conn
	packetConn net.PacketConn
}

func listenDoQPacketConn(ctx context.Context) (net.PacketConn, error) {
	var listenConfig net.ListenConfig
	return listenConfig.ListenPacket(ctx, "udp", ":0")
}

func doqQUICTimeout(ctx context.Context) (time.Duration, bool) {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return time.Nanosecond, true
		}
		return remaining, true
	}
	// Leave both fields unset when the caller has no deadline. This preserves
	// the transport's normal behavior and avoids inventing a second timeout
	// budget in the resolver.
	return 0, false
}

func bootstrapDoQEndpoint(ctx context.Context, cfg DoQConfig) ([]net.IPAddr, error) {
	ep := cfg.Endpoint
	addresses := make([]net.IPAddr, 0, len(ep.BootstrapAddrs))
	for _, ip := range ep.BootstrapAddrs {
		addresses = append(addresses, net.IPAddr{IP: append(net.IP(nil), ip...)})
	}
	if len(addresses) == 0 {
		if ip := net.ParseIP(ep.ConnectHost); ip != nil {
			addresses = append(addresses, net.IPAddr{IP: ip})
		} else {
			bootstrap := cfg.Bootstrap
			if bootstrap == nil {
				bootstrap = func(ctx context.Context, host string) ([]net.IPAddr, error) {
					return net.DefaultResolver.LookupIPAddr(ctx, host)
				}
			}
			var err error
			addresses, err = bootstrap(ctx, ep.ConnectHost)
			if err != nil {
				return nil, fmt.Errorf("resolve DNS-over-QUIC endpoint %q: %w", ep.ConnectHost, err)
			}
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve DNS-over-QUIC endpoint %q: no addresses found", ep.ConnectHost)
	}
	return addresses, nil
}

func doqTLSConfig(cfg DoQConfig, ep *Endpoint) (*tls.Config, error) {
	var out *tls.Config
	if cfg.TLSConfig != nil {
		out = cfg.TLSConfig.Clone()
	} else {
		out = &tls.Config{}
	}

	// QUIC uses TLS 1.3. Do not allow a caller's lower minimum to make the
	// result look like a valid but unusable DoQ configuration.
	if cfg.TLSMax != 0 && cfg.TLSMax < tls.VersionTLS13 {
		return nil, errors.New("DNS-over-QUIC requires TLS 1.3")
	}
	if cfg.TLSMin > tls.VersionTLS13 {
		return nil, errors.New("DNS-over-QUIC does not support a TLS version above 1.3")
	}
	out.MinVersion = tls.VersionTLS13
	if cfg.TLSMax != 0 {
		out.MaxVersion = cfg.TLSMax
	}
	if out.MaxVersion != 0 && out.MaxVersion < tls.VersionTLS13 {
		return nil, errors.New("DNS-over-QUIC requires TLS 1.3")
	}
	if cfg.Insecure {
		out.InsecureSkipVerify = true
	}
	if len(cfg.CACerts) > 0 {
		pool := out.RootCAs
		if pool == nil {
			pool, _ = x509.SystemCertPool()
		}
		if pool == nil {
			pool = x509.NewCertPool()
		} else {
			pool = pool.Clone()
		}
		for _, cert := range cfg.CACerts {
			if cert != nil {
				pool.AddCert(cert)
			}
		}
		out.RootCAs = pool
	}
	out.ServerName = ep.TLSServerName
	// DoQ has one standard ALPN. Replacing, rather than appending to, a
	// caller-supplied list prevents accidental negotiation of HTTP/3.
	out.NextProtos = []string{doqALPN}
	return out, nil
}

// Query sends one DNS query on its own bidirectional QUIC stream and validates
// the response against the transaction ID and question.
func (c *DoQClient) Query(ctx context.Context, name string, typ uint16) (*Message, error) {
	if c == nil || c.conn == nil {
		return nil, errors.New("DNS-over-QUIC client is closed")
	}
	questionName, err := ParseName(name)
	if err != nil {
		return nil, err
	}
	question := Question{Name: questionName, Type: typ, Class: 1}
	query, id, err := EncodeQuery(name, typ)
	if err != nil {
		return nil, err
	}
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, doqOperationError(ctx, err)
	}
	defer stream.Close()
	defer stream.CancelRead(0)

	stopCancel := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			stream.CancelWrite(0)
			stream.CancelRead(0)
		case <-stopCancel:
		}
	}()
	defer close(stopCancel)
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetDeadline(deadline); err != nil {
			return nil, doqOperationError(ctx, err)
		}
	}

	var frame [2]byte
	if len(query) > maxDoQFrame {
		return nil, errors.New("DNS-over-QUIC query exceeds the 65535-byte frame limit")
	}
	binary.BigEndian.PutUint16(frame[:], uint16(len(query)))
	if err := writeAll(stream, frame[:]); err != nil {
		return nil, fmt.Errorf("write DNS-over-QUIC frame: %w", doqOperationError(ctx, err))
	}
	if err := writeAll(stream, query); err != nil {
		return nil, fmt.Errorf("write DNS-over-QUIC query: %w", doqOperationError(ctx, err))
	}
	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("finish DNS-over-QUIC query: %w", doqOperationError(ctx, err))
	}

	if _, err := io.ReadFull(stream, frame[:]); err != nil {
		return nil, fmt.Errorf("read DNS-over-QUIC response frame: %w", doqOperationError(ctx, err))
	}
	length := int(binary.BigEndian.Uint16(frame[:]))
	if length == 0 {
		return nil, errors.New("DNS-over-QUIC response has an empty frame")
	}
	if length > maxDoQFrame {
		return nil, errors.New("DNS-over-QUIC response exceeds the 65535-byte frame limit")
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(stream, response); err != nil {
		return nil, fmt.Errorf("read DNS-over-QUIC response: %w", doqOperationError(ctx, err))
	}
	// RFC 9250 carries exactly one DNS message per stream. A peer that sends
	// additional bytes is malformed; check without allocating attacker data.
	var extra [1]byte
	if n, readErr := stream.Read(extra[:]); n != 0 {
		return nil, errors.New("DNS-over-QUIC stream contains data after the DNS response")
	} else if readErr != io.EOF {
		return nil, fmt.Errorf("DNS-over-QUIC response stream did not finish: %w", doqOperationError(ctx, readErr))
	}
	message, err := DecodeResponse(response, id, question)
	if err != nil {
		return nil, fmt.Errorf("invalid DNS-over-QUIC response: %w", err)
	}
	return message, nil
}

func doqOperationError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}

// QueryMany pipelines concurrent queries over one DoQ connection and returns
// responses in input order.
func (c *DoQClient) QueryMany(ctx context.Context, queries []Question) ([]*Message, error) {
	if len(queries) > maxStreamInflight {
		return nil, errors.New("DNS-over-QUIC batch exceeds the in-flight query limit")
	}
	results := make([]*Message, len(queries))
	errs := make(chan streamBatchResult, len(queries))
	for i, question := range queries {
		go func(i int, question Question) {
			message, err := c.Query(ctx, question.Name.String(), question.Type)
			errs <- streamBatchResult{index: i, message: message, err: err}
		}(i, question)
	}
	var firstErr error
	for range queries {
		result := <-errs
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		results[result.index] = result.message
	}
	if firstErr != nil {
		return results, firstErr
	}
	return results, nil
}

// Close terminates the operation-scoped QUIC connection and its UDP socket.
func (c *DoQClient) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		if c.conn != nil {
			_ = c.conn.CloseWithError(0, "DNS-over-QUIC resolver operation complete")
		}
		if c.packetConn != nil {
			_ = c.packetConn.Close()
		}
	})
	return nil
}

// LookupDoQMessage performs one operation-scoped DNS-over-QUIC query.
func LookupDoQMessage(ctx context.Context, cfg DoQConfig, name string, typ uint16) (*Message, error) {
	client, err := NewDoQClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Query(ctx, name, typ)
}

// LookupQUICMessage is a descriptive alias for LookupDoQMessage.
func LookupQUICMessage(ctx context.Context, cfg QUICConfig, name string, typ uint16) (*Message, error) {
	return LookupDoQMessage(ctx, cfg, name, typ)
}

func lookupDoQIPs(ctx context.Context, cfg DoQConfig, host string) ([]net.IPAddr, error) {
	client, err := NewDoQClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	return resolveAddressFamilies(ctx, func(ctx context.Context, typ uint16) ([]net.IPAddr, error) {
		message, err := client.Query(ctx, host, typ)
		if err != nil {
			return nil, err
		}
		name, err := ParseName(host)
		if err != nil {
			return nil, err
		}
		if message.Header.RCode != 0 {
			return nil, fmt.Errorf("DNS response: %s", RCodeName(message.Header.RCode))
		}
		authorized, err := AuthorizeAddressAnswers(message, Question{Name: name, Type: typ, Class: 1})
		if err != nil {
			return nil, err
		}
		out := make([]net.IPAddr, 0, len(authorized))
		for _, answer := range authorized {
			if answer.Type == typ {
				if ip := RecordAddress(answer); ip != nil {
					out = append(out, net.IPAddr{IP: ip})
				}
			}
		}
		if len(out) == 0 {
			return nil, errDNSNoData
		}
		return out, nil
	})
}
