# Encrypted ClientHello

`fetch` uses Go's `crypto/tls` implementation for Encrypted ClientHello (ECH).
Control it with `--ech off|auto|on`.

- `off` is the default. It does not query HTTPS/SVCB records only for ECH and
  does not send ECH or GREASE.
- `auto` discovers HTTPS/SVCB records with address resolution. It uses a valid
  advertised ECH configuration when available. When no real configuration is
  usable, it may send structurally valid randomized GREASE and falls back to
  ordinary TLS after a verified rejection.
- `on` requires a usable advertised configuration and an accepted ECH
  handshake. It fails on missing configuration, discovery failure, or rejection.

ECH requires TLS 1.3. Explicit TLS 1.2 bounds are rejected. `--ech on` cannot
be combined with forced HTTP/3 because acceptance must be verified over the
TCP TLS path. ECH is not used through proxies or cleartext HTTP/2. Automatic
HTTP version selection uses TCP when hard ECH is requested.

## Discovery and downgrade safety

HTTPS/SVCB discovery is scoped to the effective host and configured resolver.
Validated ECH configurations keep DNS priority order. Authenticated resolver
transport, parsing, and malformed-RRset failures are not silently downgraded.
Authenticated no-data results may continue according to the selected mode.
Unverified resolver failures may fall back with a verbose warning.

At `-vvv`, `fetch` warns once when discovery uses system or plaintext DNS, or an
encrypted resolver whose certificate verification is disabled. `--silent`
suppresses that warning. Redirects perform fresh host-scoped discovery.

## Inspection

Use these commands to inspect the path before changing trust settings:

```sh
fetch --inspect-dns --dns-server https://1.1.1.1/dns-query example.com
fetch --inspect-tls --ech auto -v https://example.com
```

With `-v`, TLS inspection reports real ECH acceptance or rejection, GREASE
offer and rejection, outer SNI, and final fallback when the rejection can be
verified. The default output remains compact. If
QUIC cannot expose a rejected handshake's certificate state, inspection fails
closed instead of downgrading (unless `--insecure` is explicit). DNS inspection
displays ECH bytes as base64. Terminal diagnostics escape untrusted values.

See [Advanced Features](advanced-features.md) for resolver, TLS, proxy, and
HTTP/3 details and [Limits and safety](limits.md) for shared bounds.
