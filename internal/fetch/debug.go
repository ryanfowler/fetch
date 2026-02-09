package fetch

import (
	"crypto/tls"
	"fmt"
	"net/http/httptrace"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// connectionMetrics holds timing data captured via httptrace hooks.
type connectionMetrics struct {
	// DNS timing
	dnsStart time.Time
	dnsHost  string
	dnsDur   time.Duration

	// TCP connection timing
	tcpStart time.Time
	tcpDur   time.Duration

	// TLS handshake timing
	tlsStart time.Time
	tlsDur   time.Duration

	// Time to first byte
	ttfbStart time.Time
	ttfbDur   time.Duration

	// Connection reuse
	reused bool
}

// newDebugTrace creates an httptrace.ClientTrace that collects connection
// timing metrics. When p is non-nil, inline debug text is also printed
// (for -vvv). When p is nil, metrics are collected silently (for --timing).
func newDebugTrace(p *core.Printer) (*httptrace.ClientTrace, *connectionMetrics) {
	m := &connectionMetrics{}

	return &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			m.dnsStart = time.Now()
			m.dnsHost = info.Host
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			if info.Err != nil {
				return
			}

			duration := time.Since(m.dnsStart)
			m.dnsDur = duration

			if p != nil {
				p.WriteInfoPrefix()
				p.Set(core.Bold)
				p.Set(core.Yellow)
				p.WriteString("DNS")
				p.Reset()
				p.WriteString(": ")
				if m.dnsHost != "" {
					p.WriteString(m.dnsHost)
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
					p.WriteString(addr.String())
					p.Reset()
					p.WriteString("\n")
				}
				p.Flush()
			}
		},
		ConnectStart: func(network, addr string) {
			m.tcpStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			if err != nil {
				return
			}

			duration := time.Since(m.tcpStart)
			m.tcpDur = duration

			if p != nil {
				p.WriteInfoPrefix()
				p.Set(core.Bold)
				p.Set(core.Yellow)
				p.WriteString("TCP")
				p.Reset()
				p.WriteString(": ")
				p.WriteString(addr)
				p.WriteString(" ")
				p.Set(core.Dim)
				p.WriteString(fmt.Sprintf("(%s)", formatTimingDuration(duration)))
				p.Reset()
				p.WriteString("\n")
				p.Flush()
			}
		},
		TLSHandshakeStart: func() {
			m.tlsStart = time.Now()
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err != nil {
				return
			}

			duration := time.Since(m.tlsStart)
			m.tlsDur = duration

			if p != nil {
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
					p.WriteString(cs.NegotiatedProtocol)
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
					p.WriteString(cert.Subject.String())
					p.Reset()
					p.WriteString("\n")

					p.WriteInfoPrefix()
					p.WriteString("  Issuer: ")
					p.Set(core.Italic)
					p.WriteString(cert.Issuer.String())
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
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			m.ttfbStart = time.Now()
			m.reused = info.Reused

			if p != nil && info.Reused {
				p.WriteInfoPrefix()
				p.WriteString("Connection reused\n")
				p.Flush()
			}
		},
		GotFirstResponseByte: func() {
			if m.ttfbStart.IsZero() {
				return
			}

			duration := time.Since(m.ttfbStart)
			m.ttfbDur = duration

			if p != nil {
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
			}
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
