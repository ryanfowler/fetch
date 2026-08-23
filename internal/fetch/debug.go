package fetch

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
)

// connectionMetrics holds timing data captured via httptrace hooks.
//
// httptrace.ClientTrace hooks may be called concurrently from different
// goroutines. In particular, Go's default Happy Eyeballs dialing runs IPv4
// and IPv6 ConnectStart/ConnectDone pairs in parallel. All field access must
// therefore hold mu. Readers outside the hooks call snapshot to get a
// consistent plain-data copy.
type connectionMetrics struct {
	mu      sync.Mutex
	printMu sync.Mutex

	// DNS timing
	dnsStart time.Time
	dnsHost  string
	dnsDur   time.Duration

	// TCP connection timing. tcpStart records the first ConnectStart across
	// racing dials; tcpDials tracks each dial's starts by "network addr".
	// tcpDur is committed only by the first successful dial, which is the
	// connection selected by Happy Eyeballs.
	tcpStart    time.Time
	tcpDials    map[string][]time.Time
	tcpDur      time.Duration
	tcpDurKnown bool

	// TLS handshake timing. httptrace does not include the connection in its
	// TLS hooks, so only one handshake is tracked at a time. A second start is
	// ignored instead of overwriting the active handshake's start time.
	tlsStart     time.Time
	tlsDur       time.Duration
	tlsActive    bool
	tlsAmbiguous bool
	tlsDurKnown  bool

	// Time to first byte
	ttfbStart time.Time
	ttfbDur   time.Duration

	// Connection reuse
	reused   bool
	remoteIP string
}

// connTimings is a plain-data snapshot of connectionMetrics.
type connTimings struct {
	dnsStart  time.Time
	dnsDur    time.Duration
	tcpStart  time.Time
	tcpDur    time.Duration
	tlsStart  time.Time
	tlsDur    time.Duration
	ttfbStart time.Time
	ttfbDur   time.Duration
	reused    bool
	remoteIP  string
}

// printEvent serializes a complete debug event. Printer is intentionally a
// buffered, stateful type and cannot be written by concurrent trace hooks.
func (m *connectionMetrics) printEvent(p *core.Printer, fn func()) {
	if p == nil {
		return
	}
	m.printMu.Lock()
	defer m.printMu.Unlock()
	fn()
}

// ConnectionSelected replaces race-attempt timings with the selected
// connection's timings. ResolverDialer calls this after its race coordinator
// chooses a winner; this avoids confusing a completed loser with the winner.
func (m *connectionMetrics) ConnectionSelected(t client.DialTiming) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tcpStart = t.ConnectStart
	m.tcpDur = t.ConnectDuration
	m.tcpDurKnown = !t.ConnectStart.IsZero()
	m.tcpDials = nil
	m.tlsStart = t.TLSStart
	m.tlsDur = t.TLSDuration
	m.tlsActive = false
	m.tlsAmbiguous = false
	m.tlsDurKnown = !t.TLSStart.IsZero()
}

// snapshot returns a consistent copy of the recorded timings. It is safe to
// call while trace hooks are still running.
func (m *connectionMetrics) snapshot() connTimings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return connTimings{
		dnsStart:  m.dnsStart,
		dnsDur:    m.dnsDur,
		tcpStart:  m.tcpStart,
		tcpDur:    m.tcpDur,
		tlsStart:  m.tlsStart,
		tlsDur:    m.tlsDur,
		ttfbStart: m.ttfbStart,
		ttfbDur:   m.ttfbDur,
		reused:    m.reused,
		remoteIP:  m.remoteIP,
	}
}

// newDebugTrace creates an httptrace.ClientTrace that collects connection
// timing metrics. When p is non-nil, inline debug text is also printed
// (for -vvv). When p is nil, metrics are collected silently (for --timing).
func newDebugTrace(p *core.Printer) (*httptrace.ClientTrace, *connectionMetrics) {
	m := &connectionMetrics{}

	return &httptrace.ClientTrace{
		GetConn: func(_ string) {
			m.mu.Lock()
			defer m.mu.Unlock()
			// A trace is reused for every request in a redirect chain. Start
			// each hop with a clean connection snapshot so timing output and
			// HAR data describe the response that is actually returned.
			m.dnsStart = time.Time{}
			m.dnsHost = ""
			m.dnsDur = 0
			m.tcpStart = time.Time{}
			m.tcpDials = nil
			m.tcpDur = 0
			m.tcpDurKnown = false
			m.tlsStart = time.Time{}
			m.tlsDur = 0
			m.tlsActive = false
			m.tlsAmbiguous = false
			m.tlsDurKnown = false
			m.ttfbStart = time.Time{}
			m.ttfbDur = 0
			m.reused = false
			m.remoteIP = ""
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.dnsStart = time.Now()
			m.dnsHost = info.Host
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			if info.Err != nil {
				return
			}

			m.mu.Lock()
			duration := time.Since(m.dnsStart)
			m.dnsDur = duration
			host := m.dnsHost
			m.mu.Unlock()

			m.printEvent(p, func() {
				p.WriteInfoPrefix()
				p.Set(core.Bold)
				p.Set(core.Yellow)
				p.WriteString("DNS")
				p.Reset()
				p.WriteString(": ")
				if host != "" {
					p.WriteString(core.TerminalSafeText(host))
					p.WriteString(" ")
					p.Set(core.Dim)
					p.WriteString(fmt.Sprintf("(%s)", formatTimingDuration(duration)))
					p.Reset()
					p.WriteString("\n")
				}
				for _, addr := range info.Addrs {
					p.WriteInfoPrefix()
					p.WriteString("  ")
					p.Set(core.Italic)
					p.WriteString(core.TerminalSafeText(addr.String()))
					p.Reset()
					p.WriteString("\n")
				}
				p.Flush()
			})
		},
		ConnectStart: func(network, addr string) {
			key := network + " " + addr
			now := time.Now()
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.tcpStart.IsZero() {
				m.tcpStart = now
			}
			if m.tcpDials == nil {
				m.tcpDials = make(map[string][]time.Time)
			}
			m.tcpDials[key] = append(m.tcpDials[key], now)
		},
		ConnectDone: func(network, addr string, err error) {
			key := network + " " + addr

			var duration time.Duration
			var matched bool
			m.mu.Lock()
			starts := m.tcpDials[key]
			if len(starts) > 0 {
				start := starts[0]
				matched = true
				if len(starts) == 1 {
					delete(m.tcpDials, key)
				} else {
					m.tcpDials[key] = starts[1:]
				}
				// Failed dials (including the losing Happy Eyeballs dial) do not
				// record a duration. Keep the first successful duration because
				// a later successful dial may be the losing race candidate.
				if err == nil {
					duration = time.Since(start)
					if !m.tcpDurKnown {
						m.tcpDur = duration
						m.tcpDurKnown = true
					}
				}
			}
			m.mu.Unlock()

			if err != nil || !matched || p == nil {
				return
			}

			m.printEvent(p, func() {
				p.WriteInfoPrefix()
				p.Set(core.Bold)
				p.Set(core.Yellow)
				p.WriteString("TCP")
				p.Reset()
				p.WriteString(": ")
				p.WriteString(core.TerminalSafeText(addr))
				p.WriteString(" ")
				p.Set(core.Dim)
				p.WriteString(fmt.Sprintf("(%s)", formatTimingDuration(duration)))
				p.Reset()
				p.WriteString("\n")
				p.Flush()
			})
		},
		TLSHandshakeStart: func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.tlsDurKnown {
				return
			}
			if m.tlsActive {
				// TLSHandshakeStart has no connection identifier. Do not
				// publish a duration if callbacks prove that handshakes
				// overlapped and cannot be matched to a dial.
				m.tlsAmbiguous = true
				return
			}
			m.tlsStart = time.Now()
			m.tlsActive = true
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			m.mu.Lock()
			if !m.tlsActive {
				m.mu.Unlock()
				return
			}
			duration := time.Since(m.tlsStart)
			ambiguous := m.tlsAmbiguous
			m.tlsActive = false
			m.tlsAmbiguous = false
			if err == nil && !ambiguous {
				m.tlsDur = duration
				m.tlsDurKnown = true
			} else {
				m.tlsStart = time.Time{}
			}
			m.mu.Unlock()

			if err != nil || ambiguous {
				return
			}

			m.printEvent(p, func() {
				p.WriteInfoPrefix()
				p.Set(core.Bold)
				p.Set(core.Yellow)
				p.WriteString(tls.VersionName(cs.Version))
				p.Reset()
				p.WriteString(": ")
				p.WriteString(tls.CipherSuiteName(cs.CipherSuite))
				p.WriteString(" ")
				p.Set(core.Dim)
				p.WriteString(fmt.Sprintf("(%s)", formatTimingDuration(duration)))
				p.Reset()
				p.WriteString("\n")

				// Print ALPN negotiated protocol
				if cs.NegotiatedProtocol != "" {
					p.WriteInfoPrefix()
					p.WriteString("  ALPN: ")
					p.Set(core.Italic)
					p.WriteString(core.TerminalSafeText(cs.NegotiatedProtocol))
					p.Reset()
					p.WriteString("\n")
				}

				// Print session resumption status
				p.WriteInfoPrefix()
				p.WriteString("  Resumed: ")
				if cs.DidResume {
					p.WriteString("yes")
				} else {
					p.WriteString("no")
				}
				p.WriteString("\n")

				// Print certificate info if available
				if len(cs.PeerCertificates) > 0 {
					cert := cs.PeerCertificates[0]
					p.WriteInfoPrefix()
					p.Set(core.Bold)
					p.Set(core.Yellow)
					p.WriteString("Certificate")
					p.Reset()
					p.WriteString(":\n")

					p.WriteInfoPrefix()
					p.WriteString("  Subject: ")
					p.Set(core.Italic)
					p.WriteString(core.TerminalSafeText(cert.Subject.String()))
					p.Reset()
					p.WriteString("\n")

					p.WriteInfoPrefix()
					p.WriteString("  Issuer: ")
					p.Set(core.Italic)
					p.WriteString(core.TerminalSafeText(cert.Issuer.String()))
					p.Reset()
					p.WriteString("\n")

					p.WriteInfoPrefix()
					p.WriteString("  Valid: ")
					p.Set(core.Italic)
					p.WriteString(cert.NotBefore.Format("2006-01-02"))
					p.WriteString(" to ")
					p.WriteString(cert.NotAfter.Format("2006-01-02"))
					p.Reset()
					p.WriteString("\n")
				}

				p.Flush()
			})
		},
		GotConn: func(info httptrace.GotConnInfo) {
			m.mu.Lock()
			m.ttfbStart = time.Now()
			m.reused = info.Reused
			if info.Conn != nil {
				remote := info.Conn.RemoteAddr().String()
				if host, _, err := net.SplitHostPort(remote); err == nil {
					if net.ParseIP(strings.Trim(host, "[]")) != nil {
						m.remoteIP = host
					}
				} else if net.ParseIP(strings.Trim(remote, "[]")) != nil {
					m.remoteIP = remote
				}
			}
			m.mu.Unlock()

			if info.Reused {
				m.printEvent(p, func() {
					p.WriteInfoPrefix()
					p.WriteString("Connection reused\n")
					p.Flush()
				})
			}
		},
		GotFirstResponseByte: func() {
			var duration time.Duration
			var known bool
			m.mu.Lock()
			if !m.ttfbStart.IsZero() {
				duration = time.Since(m.ttfbStart)
				m.ttfbDur = duration
				known = true
			}
			m.mu.Unlock()

			if !known {
				return
			}

			m.printEvent(p, func() {
				p.WriteInfoPrefix()
				p.Set(core.Bold)
				p.Set(core.Yellow)
				p.WriteString("TTFB")
				p.Reset()
				p.WriteString(": ")
				p.WriteString(formatTimingDuration(duration))
				p.WriteString("\n")
				p.WriteInfoPrefix()
				p.WriteString("\n")
				p.Flush()
			})
		},
	}, m
}

// formatTimingDuration formats a duration for connection timing display.
func formatTimingDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2f s", d.Seconds())
}
