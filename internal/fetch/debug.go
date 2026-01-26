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

	// TCP connection timing
	tcpStart time.Time
	tcpAddr  string

	// TLS handshake timing
	tlsStart time.Time

	// Time to first byte
	ttfbStart time.Time

	// Connection reuse
	connReused bool
}

func newDebugTrace(p *core.Printer) *httptrace.ClientTrace {
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

			p.Set(core.Bold)
			p.Set(core.Cyan)
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
				p.WriteString("  -> ")
				p.Set(core.Italic)
				p.WriteString(addr.String())
				p.Reset()
				p.WriteString("\n")
			}
			p.WriteString("\n")
			p.Flush()
		},
		ConnectStart: func(network, addr string) {
			m.tcpStart = time.Now()
			m.tcpAddr = addr
		},
		ConnectDone: func(network, addr string, err error) {
			if err != nil {
				return
			}

			duration := time.Since(m.tcpStart)

			p.Set(core.Bold)
			p.Set(core.Magenta)
			p.WriteString("TCP")
			p.Reset()
			p.WriteString(": ")
			p.WriteString(addr)
			p.WriteString(" ")
			p.Set(core.Dim)
			p.WriteString(fmt.Sprintf("(%s)", formatTimingDuration(duration)))
			p.Reset()
			p.WriteString("\n\n")
			p.Flush()
		},
		TLSHandshakeStart: func() {
			m.tlsStart = time.Now()
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err != nil {
				return
			}

			duration := time.Since(m.tlsStart)

			p.Set(core.Bold)
			p.Set(core.Blue)
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
				p.WriteString("  ALPN: ")
				p.Set(core.Italic)
				p.WriteString(cs.NegotiatedProtocol)
				p.Reset()
				p.WriteString("\n")
			}

			// Print session resumption status
			p.WriteString("  Session Resumed: ")
			if cs.DidResume {
				p.WriteString("yes")
			} else {
				p.WriteString("no")
			}
			p.WriteString("\n")

			// Print certificate info if available
			if len(cs.PeerCertificates) > 0 {
				cert := cs.PeerCertificates[0]
				p.WriteString("\n")
				p.Set(core.Bold)
				p.WriteString("Certificate")
				p.Reset()
				p.WriteString(":\n")

				p.WriteString("  Subject: ")
				p.Set(core.Italic)
				p.WriteString(cert.Subject.String())
				p.Reset()
				p.WriteString("\n")

				p.WriteString("  Issuer: ")
				p.Set(core.Italic)
				p.WriteString(cert.Issuer.String())
				p.Reset()
				p.WriteString("\n")

				p.WriteString("  Valid: ")
				p.Set(core.Italic)
				p.WriteString(cert.NotBefore.Format("2006-01-02"))
				p.WriteString(" to ")
				p.WriteString(cert.NotAfter.Format("2006-01-02"))
				p.Reset()
				p.WriteString("\n")
			}

			p.WriteString("\n")
			p.Flush()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			m.connReused = info.Reused
			m.ttfbStart = time.Now()

			if info.Reused {
				p.Set(core.Dim)
				p.WriteString("(connection reused)\n\n")
				p.Reset()
				p.Flush()
			}
		},
		GotFirstResponseByte: func() {
			if m.ttfbStart.IsZero() {
				return
			}

			duration := time.Since(m.ttfbStart)

			p.Set(core.Bold)
			p.Set(core.Green)
			p.WriteString("TTFB")
			p.Reset()
			p.WriteString(": ")
			p.WriteString(formatTimingDuration(duration))
			p.WriteString("\n\n")
			p.Flush()
		},
	}
}

// formatTimingDuration formats a duration for connection timing display.
func formatTimingDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fµs", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}
