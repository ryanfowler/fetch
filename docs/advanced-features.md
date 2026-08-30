# Advanced Features

This guide covers advanced networking, protocol, and TLS options in the Go
implementation of `fetch`. For shared caps, see [Limits and safety](limits.md).

## Retry safety

`--retry` retries only GET, HEAD, OPTIONS, and TRACE by default, even when the
request body is replayable. Replayable bytes make retransmission possible but
do not prove that a server-side operation is safe to repeat. PUT and DELETE
are treated conservatively with POST, PATCH, and custom methods: they require
`--retry-unsafe` (or `retry-unsafe = true` in configuration) because an API's
implementation may have non-idempotent side effects.

Use the opt-in only for an endpoint with a documented replay guarantee, such
as a service that validates an idempotency key:

```sh
fetch --method POST --header 'Idempotency-Key: order-123' \
  --data '{"item":"book"}' --retry 2 --retry-unsafe example.com/orders
```

Digest authentication is intentionally separate from transient-failure
retries. When a server challenges with Digest, the authentication handshake
may resend the request body, including for an unsafe method; this bounded
challenge replay remains enabled by `--digest` and is not changed by the
transient retry policy.

## Custom DNS Resolution

### `--dns-server`

Use a custom DNS server instead of the system resolver. The endpoint is
validated before a request starts. Supported forms include bare UDP addresses,
`udp://`, `tcp://`, `tls://`/`dot://`, `quic://`/`doq://`, and HTTPS DoH URLs.
Non-DoH transports reject paths and queries; userinfo and fragments are never
accepted. The same resolver policy is used by HTTP/1.1, HTTP/2, forced HTTP/3,
gRPC, WebSocket, TLS inspection, and update downloads. Resolved candidates use
Happy Eyeballs while preserving the preferred address family. TCP and DoT use
pipelined, operation-scoped connections. DoQ uses one verified QUIC connection
per operation, one bidirectional stream per query, and the standard `doq` ALPN.
Hostname resolver endpoints use a nonrecursive platform bootstrap; target
hostnames never fall back to system DNS when a custom resolver is configured.

### UDP DNS

Specify an IP address with optional port:

```sh
# Google DNS
fetch --dns-server 8.8.8.8 example.com

# Cloudflare DNS with custom port
fetch --dns-server 1.1.1.1:53 example.com

# IPv6 DNS server
fetch --dns-server "[2001:4860:4860::8888]:53" example.com
```

### DNS-over-HTTPS (DoH)

Use an HTTPS URL for encrypted DNS queries. Plain HTTP is not accepted for
configured resolver endpoints:

```sh
# Cloudflare DoH
fetch --dns-server https://1.1.1.1/dns-query example.com

# Google DoH
fetch --dns-server https://dns.google/dns-query example.com

# Quad9 DoH
fetch --dns-server https://dns.quad9.net/dns-query example.com
```

### DNS Inspection

`--inspect-dns` resolves the URL hostname and exits without making an HTTP request:

```sh
fetch --inspect-dns example.com
fetch --inspect-dns --dns-server https://1.1.1.1/dns-query example.com
```

Without `--dns-server`, inspection queries the nameservers listed in the system resolver configuration (`/etc/resolv.conf`) directly, including on macOS. It reports every record type (A, AAAA, CNAME, TXT, MX, NS, SOA, SRV, CAA, SVCB, and HTTPS) with per-record TTLs, but does not apply macOS scoped, per-interface, VPN, or `/etc/resolver` routing. On platforms without a usable resolver file (notably Windows), or when the name is resolved only through OS mechanisms (the hosts file, NSS modules, or mDNS), it uses the platform resolver for A and AAAA records without per-record TTLs. Platform-resolver records show their source and `TTL unavailable` individually. If direct DNS returns no address records, platform-resolver addresses are added while any records already returned by direct DNS remain visible. The `Lookup` section identifies this mixed resolver path and reports the platform fallback. With an explicit resolver, inspection queries the same record types concurrently. When system failover occurs, `Resolver` or `Resolvers` reports the nameserver(s) that actually answered. Use `-vv` to see each query's responder, transport, duration, and failover attempts. The default output uses `Lookup` and `Records` sections with the inspected name, resolver path, transport, transport security, source, status, result counts, query counts, and duration. Each record shows its normalized, fully qualified owner name before its value. Inspection output is written to stdout; invocation warnings and setup/configuration errors are written to stderr. If a query fails, successful records are retained, a `Failures` section reports the incomplete record types on stdout, and the command exits with status 1. `Transport security` describes encryption and certificate verification between fetch and the resolver; it does not indicate DNSSEC validation, which fetch does not perform. If a UDP response is truncated, fetch retries the query over TCP and reports the normal protocol fallback as `Transport: UDP → TCP fallback`, not as a warning. Use `-vv` to see which record-type queries used the fallback.

### Configuration File

```ini
# Use Cloudflare DNS globally
dns-server = 1.1.1.1

# Use DoH for specific hosts
[secure.example.com]
dns-server = https://1.1.1.1/dns-query
```

## Proxy Configuration

### `--proxy`

Route requests through a proxy server.

### HTTP Proxy

```sh
fetch --proxy http://proxy.example.com:8080 example.com
```

### HTTPS Proxy

```sh
fetch --proxy https://secure-proxy.example.com:8443 example.com
```

### SOCKS5 Proxy

```sh
fetch --proxy socks5://localhost:1080 example.com
fetch --proxy socks5h://localhost:1080 example.com
```

`socks5` resolves the destination with `fetch`'s configured resolver and sends
an IP address to the proxy. `socks5h` sends the hostname and leaves resolution
to the proxy. Both forms support username-only and username/password
credentials.

An `https` proxy is TLS-protected and verified using system roots. Its TLS
verification is separate from the origin: `--insecure` and origin CA files do
not disable proxy verification. HTTP, HTTPS, SOCKS5, and SOCKS5H use the same
proxy selection and transport policy.

### Authenticated Proxy

```sh
fetch --proxy http://user:password@proxy.example.com:8080 example.com
```

### Environment Variables

`fetch` respects standard proxy environment variables. Uppercase names take
precedence over lowercase names. `HTTP_PROXY` is ignored when `REQUEST_METHOD`
is set. Explicit `--proxy` and configuration values take precedence over the
environment. `NO_PROXY` entries may be `*`, exact hosts, domain suffixes,
IP literals, CIDR ranges, or entries with a port. Invalid entries are ignored.

```sh
export HTTP_PROXY="http://proxy.example.com:8080"
export HTTPS_PROXY="http://proxy.example.com:8080"
export ALL_PROXY="socks5://proxy.example.com:1080"
export NO_PROXY="localhost,127.0.0.1,192.168.0.0/16,.internal.com"

fetch example.com  # Uses the HTTPS proxy from the environment
```

### Configuration File

```ini
# Global proxy
proxy = http://proxy.example.com:8080

# Host-specific proxy
[internal.example.com]
proxy = socks5://internal-proxy:1080
```

## Unix Domain Sockets

### `--unix`

Connect via Unix domain socket instead of TCP. Available on Unix-like systems only.

### Docker API

```sh
fetch --unix /var/run/docker.sock http://localhost/containers/json
fetch --unix /var/run/docker.sock http://localhost/images/json
```

### Custom Services

```sh
fetch --unix /var/run/myservice.sock http://localhost/api/status
fetch --unix ~/myapp.sock http://localhost/health
```

**Note**: The hostname in the URL is ignored when using Unix sockets; the socket path determines the destination.

## HTTP Versions

### `--http VERSION`

Force a specific HTTP version.

### HTTP/1.1

```sh
fetch --http 1 example.com
```

- Uses HTTP/1.1 protocol
- Single request per connection
- No header compression
- Useful for debugging or legacy servers

### HTTP/2

```sh
fetch --http 2 example.com
```

- Used after automatic HTTP/3 does not win, unless a version is forced
- Multiplexed streams
- Header compression (HPACK)
- Required for gRPC
- Automatically uses h2c (HTTP/2 over cleartext) for gRPC requests with `http://` URLs, enabling plaintext HTTP/2 connections to local development servers without TLS

### HTTP/3 (QUIC)

```sh
fetch --http 3 example.com
```

- Uses QUIC transport (UDP-based)
- Reduced latency
- Better handling of packet loss
- Not all servers support HTTP/3

### Version Detection

For direct HTTPS requests, the default mode starts normal address resolution and
HTTPS/SVCB discovery together. A valid `h3` service candidate and cached
`Alt-Svc` candidate can race TCP/TLS setup. The request is sent only once on
the transport that wins. Fresh HTTPS/SVCB candidates take precedence over
cached DNS candidates. Proxies and Unix-socket requests use TCP only.

If HTTP/3 does not win, `fetch` negotiates HTTP/2 through ALPN and falls back
to HTTP/1.1 when needed. Authenticated DNS discovery errors are not silently
downgraded. Use `--http 1` or `--http 2` to disable HTTP/3 discovery and
racing. Use `--http 3` to require HTTP/3; it never falls back to TCP.

Automatic HTTP/3 alternatives are stored in a bounded persistent cache under
`os.UserCacheDir()/fetch/http3`. Entries are scoped by HTTPS origin and resolver
identity. Each origin keeps at most four candidates, the cache keeps at most
1,024 shards, and entries expire after at most seven days. DNS TTL, DoH `Age`,
and `Alt-Svc` `ma` values provide shorter expiry when available. Cache files
are hashed, locked, symlink-safe, and updated atomically. Cache failures do not
block a request.

## TLS Configuration

### Encrypted ClientHello

`--ech off` is the default and does not perform ECH discovery. `--ech auto`
performs HTTPS/SVCB discovery with address resolution and uses a validated
advertised ECH configuration when a TCP-compatible candidate is available.
Authenticated discovery failures are fatal; authenticated no-data results may
fall back. `--ech on` requires an advertised usable configuration, requires
TLS 1.3, rejects explicit HTTP/3, and uses TCP during automatic version
selection. Explicit TLS 1.2 bounds are rejected. ECH is not available through
proxies or cleartext HTTP/2. Real ECH uses Go's `crypto/tls`; auto mode sends a
fresh randomized GREASE configuration when discovery has no usable config and
falls back to ordinary TLS after a verified rejection. WSS and `--inspect-tls`
use the same host-scoped discovery and report whether real ECH was accepted,
rejected, or followed by fallback at `-v` and above. HTTP/3 inspection fails closed when a
rejected handshake does not expose certificate state for verification, unless
`--insecure` is explicit. At `-vvv`, fetch warns once when discovery
uses system/plaintext DNS or encrypted DNS without certificate verification.

### TLS Version Bounds

`--min-tls VERSION` sets the minimum acceptable TLS version. `--tls VERSION` is kept as an alias for `--min-tls`:

```sh
fetch --min-tls 1.2 example.com  # Require TLS 1.2+
fetch --tls 1.3 example.com      # Require TLS 1.3+
```

`--max-tls VERSION` sets the maximum acceptable TLS version:

```sh
fetch --min-tls 1.2 --max-tls 1.3 example.com  # Allow TLS 1.2 through 1.3
fetch --min-tls 1.2 --max-tls 1.2 example.com  # Require exactly TLS 1.2
```

| Value | Protocol                    |
| ----- | --------------------------- |
| `1.2` | TLS 1.2 (supported minimum) |
| `1.3` | TLS 1.3 (most secure)       |

### Insecure Mode

`--insecure` accepts invalid TLS certificates:

```sh
fetch --insecure https://self-signed.example.com
```

**Warning**: Only use for development/testing. Never in production.

### Custom CA Certificate

`--ca-cert` specifies a custom CA certificate:

```sh
fetch --ca-cert /path/to/ca.crt https://internal.example.com
```

Use cases:

- Internal PKI with private CA
- Development with self-signed certificates
- Corporate environments with SSL inspection

### TLS Certificate Inspection

`--inspect-tls` performs a TLS handshake only (no HTTP request is made) and provides a focused view of the server certificate and its verification. This makes it useful as a standalone diagnostic tool:

```sh
fetch --inspect-tls example.com
```

The default output uses the structured diagnostic view. It shows separate connection and certificate sections with the remote address, negotiated TLS, verification status, leaf certificate, issuer, exact validity window, serial number, public-key description, signature algorithm, SHA-256 fingerprint, server and verified chains, all parsed SAN types, OCSP status and timestamps, SCT count, SNI, resolver provenance, and ECH details. The `-v` flag has no effect in TLS inspection mode. Use `-vv` for AIA, CRL, policy, and other niche X.509 details. OCSP staple status checks the matching certificate and response signature, but not responder authorization or freshness. QUIC reports `cipher suite unavailable` only when the transport does not expose it.

Inspection completes the handshake even when certificate verification fails. It returns a nonzero status for a verification failure unless `--insecure` is explicit; `--insecure` reports the failure as ignored and returns success. Expiry is color-coded in the certificate view: red if expired or less than 7 days remaining, yellow if less than 30 days, green otherwise. The inspection result is written to stdout. Warnings and errors are written to stderr, so the result can be redirected or piped without diagnostic output.

HTTP-only flags (e.g. `--data`, `--timing`, `--grpc`) are ignored with a warning when used with `--inspect-tls`.

When combined with `--http 3`, TLS inspection uses a QUIC handshake and offers `h3` ALPN instead of dialing TCP. Custom DNS, address-family racing, and `--connect-timeout` apply to both paths. QUIC closes the inspection connection before rendering the result.

```sh
# Check server chain and verified path
fetch --inspect-tls example.com

# Inspect certificates even if invalid
fetch --inspect-tls --insecure expired.badssl.com

# Inspect the HTTP/3 QUIC/TLS path
fetch --inspect-tls --http 3 example.com
```

### Configuration File

```ini
# Require TLS 1.2 minimum
min-tls = 1.2

# Internal server with private CA
[internal.company.com]
ca-cert = /etc/pki/internal-ca.crt

# Development server (insecure)
[dev.localhost]
insecure = true
```

## Compression

Use `--compress` to select response compression negotiation and streaming
decoding:

```sh
fetch --compress auto example.com
fetch --compress br example.com
fetch --compress gzip example.com
fetch --compress zstd example.com
fetch --compress off example.com
```

The modes send these automatic `Accept-Encoding` values:

- `auto`: `gzip, br, zstd`
- `br` (or `brotli`): `br`
- `gzip`: `gzip`
- `zstd`: `zstd`
- `off`: no automatic encoding header

Supported response encodings are decoded as they stream. Stacked encodings
are decoded in reverse order. `--compress off` preserves encoded response
bytes, including when writing to a file. An explicit `Accept-Encoding` header
is never replaced. Use `--no-encode` as a compatibility alias for
`--compress off`.

## Range Requests

### `-r, --range RANGE`

Request specific byte ranges (partial content):

```sh
# First 1KB
fetch -r 0-1023 example.com/file.bin

# Last 500 bytes
fetch -r -500 example.com/file.bin

# Skip first 1000 bytes
fetch -r 1000- example.com/file.bin
```

### Multiple Ranges

```sh
fetch -r 0-499 -r 1000-1499 example.com/file.bin
```

This sets the header:

```
Range: bytes=0-499, 1000-1499
```

### Use Cases

- Resume interrupted downloads
- Download specific portions of large files
- Video seeking
- Parallel downloads

## Redirect Control

### `--redirects NUM`

Set maximum number of automatic redirects:

```sh
# Disable redirects
fetch --redirects 0 example.com

# Allow up to 10 redirects
fetch --redirects 10 example.com
```

### Verbose Redirect Tracking

```sh
fetch -v --redirects 5 example.com
```

Shows each redirect hop with status codes.

Redirects preserve non-POST methods and replayable bodies for 301 and 302, and 307 or 308 preserve the method and body. A 301 or 302 changes POST to GET, while a 303 changes requests to GET except HEAD. A redirect whose effective request has a body and whose status/method semantics preserve that body is refused before a cross-origin destination request is sent. This rule is based on body presence, not only on PUT, PATCH, or custom methods, so body-bearing GET, HEAD, DELETE, OPTIONS, POST, and custom methods are covered. There is no cross-origin body-replay opt-in. Requests with one-shot bodies fail when a redirect needs a replay. Credentials, credential-like custom headers (including names with authentication, token, key, secret, password, credential, signature, private, or client-ID components), and an explicit Host value are retained only on the same origin. Matching uses complete header-name components and case boundaries, including compound names such as `X-ApiKey`, so ordinary names such as `X-Keyboard-Layout` and `X-KeyboardLayout` are not classified as credentials. Code that generates an otherwise unclassified credential header must mark it with `client.MarkCredentialHeaders`. Once a redirect crosses an origin boundary, those values are not restored even if a later redirect returns to the original origin. When mTLS is configured with `--cert`, redirects crossing an origin boundary are refused before the destination TLS handshake; same-origin redirects remain allowed. Destination names are resolved again with the configured DNS server.

## Request Timeout

### `-t, --timeout SECONDS`

Set a timeout for the entire request:

```sh
fetch --timeout 30 example.com
fetch --timeout 2.5 example.com  # Decimal seconds
```

The timeout covers:

- DNS resolution
- Connection establishment
- TLS handshake
- Request/response transfer

### `--connect-timeout SECONDS`

Set a timeout for just the connection phase (DNS resolution, TCP connect, TLS handshake):

```sh
fetch --connect-timeout 5 example.com
fetch --connect-timeout 5 --timeout 30 example.com  # Both timeouts
```

This is useful for fast-failing on unreachable hosts while allowing large responses to transfer slowly. The connect timeout is independent of `--timeout` — both can be set simultaneously, and `--timeout` still caps the entire request.

### Configuration File

```ini
# Global timeout
timeout = 30

# Connect timeout for fast-fail on unreachable hosts
connect-timeout = 5

# Longer timeout for slow API
[slow-api.example.com]
timeout = 120
```

## Combining Options

Complex requests often combine multiple advanced options:

```sh
fetch \
  --dns-server https://1.1.1.1/dns-query \
  --proxy socks5://localhost:9050 \
  --min-tls 1.3 \
  --timeout 60 \
  --http 2 \
  -v \
  https://example.onion/api
```

### Configuration File Example

```ini
# Global settings
timeout = 30
min-tls = 1.2
dns-server = 8.8.8.8

# Internal services
[internal.company.com]
proxy = http://internal-proxy:8080
ca-cert = /etc/pki/internal-ca.crt
insecure = false

# Development environment
[localhost]
insecure = true
timeout = 5

# High-security API
[secure-api.example.com]
min-tls = 1.3
timeout = 60
```

## Cookie Sessions

### `-S, --session NAME`

Persistent cookie storage across invocations using named sessions.

### Basic Usage

```sh
# First request — server sets cookies, they get saved
fetch --session api https://example.com/login -j '{"user":"me"}'

# Second request — saved cookies are sent automatically
fetch --session api https://example.com/dashboard
```

### Session Isolation

Different session names maintain separate cookie stores:

```sh
fetch --session prod https://api.example.com/login
fetch --session staging https://staging.example.com/login
```

### Configuration File

Set session names per-host so you don't need `--session` every time:

```ini
# Global default session
session = default

# Per-host session names
[api.example.com]
session = api-prod

[staging.example.com]
session = api-staging
```

### Session File Storage

Sessions are stored as JSON in the user's cache directory:

- **Linux**: `~/.cache/fetch/sessions/<NAME>.json`
- **macOS**: `~/Library/Caches/fetch/sessions/<NAME>.json`

### Behavior Details

- **Expired cookies**: Cookies with an explicit expiry in the past are filtered out on load.
- **Session cookies** (no explicit expiry): Persist across invocations since the session is explicitly named.
- **Cookie domain matching**: Delegated to Go's `net/http/cookiejar`, which implements RFC 6265.
- **Atomic writes**: Session files use owner-only permissions, an operation lock, an exclusive temporary file, and an atomic rename. Saves merge additions, updates, and deletions with the latest file so concurrent fetch processes do not lose cookie changes.
- **Session limits**: Session files are capped at 2 MiB and serialized cookie data at 1 MiB. A session holds at most 2,048 cookies and 64 cookies per domain; cookie names and values are capped at 256 and 4,096 bytes. New cookies that exceed a name/value limit are rejected. Count and serialized-size pressure evicts the oldest cookies deterministically, with a bounded warning.
- **WebSockets**: Named-session cookies are sent with WebSocket handshakes and handshake cookie changes are saved after the session ends.
- **Dry-run**: Dry-run loads sessions without writing them, including when the session file is corrupted.
- **Name validation**: Only `[a-zA-Z0-9_-]` characters are allowed to prevent path traversal.

## Debugging Network Issues

### Timing Waterfall

`--timing` (or `-T`) displays a timing waterfall chart after the response, showing how time was spent across DNS resolution, TCP connection, TLS handshake, time to first byte, and body download:

```sh
fetch --timing https://example.com
```

The chart adapts to the request: TLS is omitted for HTTP, TCP is omitted for HTTP/3 (QUIC), and DNS/TCP/TLS are omitted when the connection is reused. Combine with `-vvv` for both inline debug text and the waterfall summary.

Can also be configured in the [configuration file](configuration.md):

```ini
timing = true
```

### Verbose Output

```sh
fetch -v example.com    # Response headers
fetch -vv example.com   # Request + response headers with direction prefixes
fetch -vvv example.com  # DNS + TLS details with direction prefixes
```

### Dry Run

Preview the request without sending:

```sh
fetch --dry-run -m POST -j '{"test": true}' example.com
```

### Testing Connectivity

```sh
# Test with specific DNS
fetch --dns-server 8.8.8.8 -v example.com

# Test with explicit HTTP version
fetch --http 1 -v example.com

# Test TLS configuration
fetch --min-tls 1.3 -vvv example.com
```

## See Also

- [Documentation index](index.md) - Complete user and maintainer guide index
- [CLI Reference](cli-reference.md) - Complete option reference
- [Authentication](authentication.md) - mTLS and other auth methods
- [Configuration](configuration.md) - Configuration file options
- [Article extraction](article.md) - Readable Markdown output
- [HAR recording](har.md) - Final-exchange capture
- [Updates and installation](updates.md) - Verified release artifacts
- [Troubleshooting](troubleshooting.md) - Network debugging
