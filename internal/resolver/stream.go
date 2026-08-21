package resolver

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	maxStreamFrame       = 65535
	maxStreamInflight    = 128
	maxStreamBuffered    = 128 * 1024
	streamIdleLifetime   = 30 * time.Second
	streamIDAllocRetries = 32
)

// DialContextFunc opens a connection. It is injectable so encrypted DNS can
// share the application's dial policy without making resolver depend on the
// client package.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// BootstrapFunc resolves a resolver endpoint hostname. It must use a
// resolver other than the endpoint being bootstrapped.
type BootstrapFunc func(context.Context, string) ([]net.IPAddr, error)

// StreamConfig controls one bounded DNS-over-TCP or DNS-over-TLS connection.
// The connection is intentionally operation-scoped. It is not a global pool.
type StreamConfig struct {
	Endpoint    *Endpoint
	DialContext DialContextFunc
	Bootstrap   BootstrapFunc
	TLSConfig   *tls.Config
	CACerts     []*x509.Certificate
	Insecure    bool
	TLSMin      uint16
	TLSMax      uint16

	// QUICDial optionally replaces the default quic-go dial operation. It is
	// useful for deterministic tests and for callers that provide a shared
	// packet-dial policy. It is ignored by TCP and TLS transports.
	QUICDial QUICDialFunc
}

// StreamClient pipelines DNS queries over one stream and correlates responses
// by transaction ID. Query may be called concurrently.
type StreamClient struct {
	conn   net.Conn
	reader *bufio.Reader

	writeMu  chan struct{}
	mu       sync.Mutex
	pending  map[uint16]*streamPending
	closed   bool
	closeErr error
	closeCh  chan struct{}
	once     sync.Once
}

type streamPending struct {
	question Question
	result   chan streamResult
}

type streamResult struct {
	message *Message
	err     error
}

// NewStreamClient opens a pipelined TCP or TLS DNS connection. The endpoint
// must use tcp://, tls://, or dot://. Endpoint hostnames are bootstrapped via
// cfg.Bootstrap or the platform resolver, never through the endpoint itself.
func NewStreamClient(ctx context.Context, cfg StreamConfig) (*StreamClient, error) {
	if cfg.Endpoint == nil {
		return nil, errors.New("DNS stream endpoint is missing")
	}
	if cfg.Endpoint.Transport != TransportTCP && cfg.Endpoint.Transport != TransportTLS {
		return nil, fmt.Errorf("DNS stream transport %s is not supported", cfg.Endpoint.Transport)
	}
	conn, err := dialStreamEndpoint(ctx, cfg)
	if err != nil {
		return nil, err
	}
	client := &StreamClient{
		conn:    conn,
		reader:  bufio.NewReaderSize(conn, maxStreamBuffered),
		pending: make(map[uint16]*streamPending),
		writeMu: make(chan struct{}, 1),
		closeCh: make(chan struct{}),
	}
	client.writeMu <- struct{}{}
	go client.readLoop()
	return client, nil
}

func dialStreamEndpoint(ctx context.Context, cfg StreamConfig) (net.Conn, error) {
	ep := cfg.Endpoint
	dial := cfg.DialContext
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}

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
				return nil, fmt.Errorf("resolve DNS endpoint %q: %w", ep.ConnectHost, err)
			}
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve DNS endpoint %q: no addresses found", ep.ConnectHost)
	}

	addresses = interleaveAddressFamilies(deduplicateAddresses(addresses))
	if len(addresses) > maxStreamEndpointAddresses {
		addresses = addresses[:maxStreamEndpointAddresses]
	}
	conn, err := RaceCandidates(ctx, addresses, func(attemptCtx context.Context, address net.IPAddr) (net.Conn, error) {
		conn, err := dial(attemptCtx, "tcp", net.JoinHostPort(address.IP.String(), fmt.Sprint(ep.Port)))
		if err != nil || ep.Transport != TransportTLS {
			return conn, err
		}
		tlsConn := tls.Client(conn, streamTLSConfig(cfg, ep))
		if err := tlsConn.HandshakeContext(attemptCtx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}, func(conn net.Conn) {
		if conn != nil {
			_ = conn.Close()
		}
	})
	if err != nil {
		return nil, fmt.Errorf("connect to DNS endpoint %s: %w", ep, err)
	}
	return conn, nil
}

const maxStreamEndpointAddresses = 16

func streamTLSConfig(cfg StreamConfig, ep *Endpoint) *tls.Config {
	var out *tls.Config
	if cfg.TLSConfig != nil {
		out = cfg.TLSConfig.Clone()
	} else {
		out = &tls.Config{}
	}
	if cfg.TLSMin != 0 {
		out.MinVersion = cfg.TLSMin
	} else if out.MinVersion == 0 {
		out.MinVersion = tls.VersionTLS12
	}
	if cfg.TLSMax != 0 {
		out.MaxVersion = cfg.TLSMax
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
	// The endpoint name is authoritative. Go omits an IP literal from the
	// TLS SNI extension while still using it for certificate verification.
	out.ServerName = ep.TLSServerName
	return out
}

// LookupStreamMessage opens an operation-scoped stream, sends one query, and
// closes the stream after the response. Use NewStreamClient when related
// queries should be pipelined on one connection.
func LookupStreamMessage(ctx context.Context, cfg StreamConfig, name string, typ uint16) (*Message, error) {
	client, err := NewStreamClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Query(ctx, name, typ)
}

// Query sends one query and waits for its correlated response. Multiple Query
// calls may share the connection and responses may arrive in any order.
func (c *StreamClient) Query(ctx context.Context, name string, typ uint16) (*Message, error) {
	questionName, err := ParseName(name)
	if err != nil {
		return nil, err
	}
	question := Question{Name: questionName, Type: typ, Class: 1}

	c.mu.Lock()
	if c.closed {
		err := c.closeErr
		c.mu.Unlock()
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	}
	if len(c.pending) >= maxStreamInflight {
		c.mu.Unlock()
		return nil, errors.New("DNS stream has too many in-flight queries")
	}
	id, query, err := c.allocateQueryLocked(name, typ)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	pending := &streamPending{question: question, result: make(chan streamResult, 1)}
	c.pending[id] = pending
	c.mu.Unlock()

	if err := contextError(ctx); err != nil {
		c.removePending(id, pending)
		return nil, err
	}
	if err, wrote := c.writeQuery(ctx, query); err != nil {
		c.removePending(id, pending)
		if wrote || (!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)) {
			c.failAll(err)
		}
		return nil, err
	}
	select {
	case result := <-pending.result:
		return result.message, result.err
	case <-ctx.Done():
		// Once the frame is on the wire, removing its ID would permit a late
		// response to collide with a future query. Close this operation-scoped
		// connection instead of reusing it.
		c.failAll(ctx.Err())
		return nil, ctx.Err()
	case <-c.closeCh:
		select {
		case result := <-pending.result:
			return result.message, result.err
		default:
		}
		c.mu.Lock()
		err := c.closeErr
		c.mu.Unlock()
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	}
}

func (c *StreamClient) allocateQueryLocked(name string, typ uint16) (uint16, []byte, error) {
	for i := 0; i < streamIDAllocRetries; i++ {
		var raw [2]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return 0, nil, fmt.Errorf("generate DNS transaction ID: %w", err)
		}
		id := binary.BigEndian.Uint16(raw[:])
		if _, exists := c.pending[id]; exists {
			continue
		}
		query, _, err := EncodeQueryWithID(id, name, typ)
		if err != nil {
			return 0, nil, err
		}
		return id, query, nil
	}
	return 0, nil, errors.New("unable to allocate a distinct DNS transaction ID")
}

func (c *StreamClient) writeQuery(ctx context.Context, query []byte) (error, bool) {
	if len(query) == 0 || len(query) > maxStreamFrame {
		return errors.New("DNS query exceeds the TCP frame limit"), false
	}
	select {
	case <-ctx.Done():
		return ctx.Err(), false
	case <-c.writeMu:
	}
	defer func() { c.writeMu <- struct{}{} }()

	// net.Conn has no context-aware Write. Close the connection if this
	// query is canceled so a blocked writer is released promptly.
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.conn.Close()
		case <-watchDone:
		}
	}()
	defer close(watchDone)
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetWriteDeadline(deadline); err != nil {
			return err, false
		}
	} else if err := c.conn.SetWriteDeadline(time.Time{}); err != nil {
		return err, false
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(query)))
	if err := writeAll(c.conn, length[:]); err != nil {
		return err, true
	}
	if err := writeAll(c.conn, query); err != nil {
		return err, true
	}
	return nil, true
}

func (c *StreamClient) removePending(id uint16, expected *streamPending) {
	c.mu.Lock()
	if current, ok := c.pending[id]; ok && current == expected {
		delete(c.pending, id)
	}
	c.mu.Unlock()
}

func (c *StreamClient) readLoop() {
	for {
		if err := c.conn.SetReadDeadline(time.Now().Add(streamIdleLifetime)); err != nil {
			c.failAll(err)
			return
		}
		var length [2]byte
		if _, err := io.ReadFull(c.reader, length[:]); err != nil {
			if isTimeout(err) {
				err = errors.New("DNS stream idle lifetime exceeded")
			}
			c.failAll(err)
			return
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if n == 0 {
			c.failAll(errors.New("DNS stream response has an empty frame"))
			return
		}
		if n > maxStreamFrame {
			c.failAll(errors.New("DNS stream response exceeds the frame limit"))
			return
		}
		packet := make([]byte, n)
		if _, err := io.ReadFull(c.reader, packet); err != nil {
			c.failAll(err)
			return
		}
		message, err := DecodeMessage(packet)
		if err != nil {
			c.failAll(fmt.Errorf("invalid DNS stream response: %w", err))
			return
		}

		c.mu.Lock()
		pending := c.pending[message.Header.ID]
		if pending != nil {
			delete(c.pending, message.Header.ID)
		}
		c.mu.Unlock()
		if pending == nil {
			// A response for a timed-out query can already be in the stream. It
			// cannot be assigned to another query because IDs are never reused
			// while a response is pending.
			continue
		}
		if err := message.ValidateResponse(message.Header.ID, pending.question); err != nil {
			pending.result <- streamResult{err: err}
			c.failAll(errors.New("DNS stream response question did not match the query"))
			return
		}
		pending.result <- streamResult{message: message}
	}
}

// Close stops the reader and fails all pending queries. It is safe to call
// more than once.
func (c *StreamClient) Close() error {
	c.failAll(net.ErrClosed)
	return nil
}

func (c *StreamClient) failAll(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.closeErr = err
		pending := c.pending
		c.pending = make(map[uint16]*streamPending)
		c.mu.Unlock()
		close(c.closeCh)
		_ = c.conn.Close()
		for _, query := range pending {
			query.result <- streamResult{err: err}
		}
	})
}

// QueryMany pipelines all queries on one connection and returns responses in
// input order. It is useful to inspection and related A/AAAA discovery.
func (c *StreamClient) QueryMany(ctx context.Context, queries []Question) ([]*Message, error) {
	if len(queries) > maxStreamInflight {
		return nil, errors.New("DNS stream batch exceeds the in-flight query limit")
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

type streamBatchResult struct {
	index   int
	message *Message
	err     error
}

func lookupStreamIPs(ctx context.Context, cfg StreamConfig, host string) ([]net.IPAddr, error) {
	client, err := NewStreamClient(ctx, cfg)
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
		answers, err := AuthorizeAddressAnswers(message, Question{Name: name, Type: typ, Class: 1})
		if err != nil {
			return nil, err
		}
		addrs := make([]net.IPAddr, 0, len(answers))
		for _, answer := range answers {
			if answer.Type == typ {
				if ip := RecordAddress(answer); ip != nil {
					addrs = append(addrs, net.IPAddr{IP: ip})
				}
			}
		}
		if len(addrs) == 0 {
			return nil, errDNSNoData
		}
		return addrs, nil
	})
}
