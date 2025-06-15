package fetch

import (
	"crypto/tls"
	"net/http/httptrace"

	"github.com/ryanfowler/fetch/internal/core"
)

func newDebugTrace(p *core.Printer) *httptrace.ClientTrace {
	// hosts stores DNS lookup names in call order
	var hosts []string
	return &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			hosts = append(hosts, info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			if info.Err != nil {
				return
			}

			var host string
			if n := len(hosts); n > 0 {
				host = hosts[n-1]
				hosts = hosts[:n-1]
			}

			p.Set(core.Bold)
			p.Set(core.Cyan)
			p.WriteString("DNS")
			p.Reset()
			p.WriteString(": ")
			if host != "" {
				p.WriteString(host)
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
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err != nil {
				return
			}

			p.Set(core.Bold)
			p.Set(core.Blue)
			p.WriteString(tls.VersionName(cs.Version))
			p.Reset()
			p.WriteString(": ")
			p.WriteString(tls.CipherSuiteName(cs.CipherSuite))
			p.WriteString("\n\n")
			p.Flush()
		},
	}
}
