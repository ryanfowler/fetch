# Advanced Features

This guide covers advanced networking, protocol, and TLS options in `fetch`.

## Custom DNS Resolution

### `--dns-server`

Use a custom DNS server instead of the system resolver.

### UDP DNS

Specify an IP address with optional port, or use the explicit `udp://` scheme:

```sh
# Google DNS
fetch --dns-server 8.8.8.8 example.com

# Cloudflare DNS with custom port
fetch --dns-server 1.1.1.1:53 example.com
fetch --dns-server udp://1.1.1.1:53 example.com

# IPv6 DNS server
fetch --dns-server "[2001:4860:4860::8888]:53" example.com
```

UDP DNS queries advertise EDNS(0) and retry truncated responses over TCP.

### DNS over TCP

Use the `tcp://` scheme for plain DNS over TCP. This avoids UDP truncation
entirely because responses are streamed with a 2-byte length prefix.

```sh
fetch --dns-server tcp://1.1.1.1 example.com
fetch --dns-server tcp://1.1.1.1:53 example.com
```

### DNS over TLS (DoT)

Use the `tls://` or `dot://` scheme for DNS over TLS. The default port is 853.
Both IP addresses and hostnames are accepted; hostnames are resolved with the
system resolver and used for TLS server name verification.

```sh
fetch --dns-server tls://1.1.1.1 example.com
fetch --dns-server dot://dns.google example.com
fetch --dns-server tls://dns.google:853 example.com
```

### DNS over QUIC (DoQ)

Use the `quic://` or `doq://` scheme for DNS over QUIC. The default port is 853. Both IP addresses and hostnames are accepted.

```sh
fetch --dns-server quic://1.1.1.1 example.com
fetch --dns-server doq://dns.adguard-dns.com example.com
```

### DNS-over-HTTPS (DoH)

Use an HTTPS URL for encrypted DNS queries. `fetch` uses RFC 8484
`application/dns-message` requests for generic DoH endpoints and falls back to
Google-style JSON DoH responses for compatibility.

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

Request-only CLI flags warn that no HTTP request will be sent and those flags have no effect when used with `--inspect-dns`; config-file defaults do not trigger this warning.

The output shows the resolver backend, A, AAAA, CNAME, TXT, MX, NS, SOA, SRV, CAA, SVCB, and HTTPS records when present, address count, record count, lookup duration, and per-record TTLs. UDP DNS inspection advertises EDNS(0) and retries truncated UDP responses over TCP; if TCP fallback cannot complete the lookup, `fetch` warns that the results are incomplete and exits with a non-zero status.

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

HTTPS proxy TLS is configured separately from origin TLS. The proxy handshake
uses platform verification, and origin `--ca-cert`, `--cert`/`--key`, and
`--insecure` settings do not apply to the proxy.

### SOCKS5 Proxy

```sh
fetch --proxy socks5://localhost:1080 example.com
```

### Authenticated Proxy

```sh
fetch --proxy http://user:password@proxy.example.com:8080 example.com
```

### Environment Variables

`fetch` respects standard proxy environment variables:

```sh
export HTTP_PROXY="http://proxy.example.com:8080"
export HTTPS_PROXY="http://proxy.example.com:8080"
export ALL_PROXY="socks5://proxy.example.com:1080"
export NO_PROXY="localhost,127.0.0.1,192.168.0.0/16,.internal.com"

fetch example.com  # Uses proxy from environment
```

Proxy variables also support lowercase forms: `http_proxy`, `https_proxy`,
`all_proxy`, and `no_proxy`. Uppercase names are checked before lowercase names
for each variable, except uppercase `HTTP_PROXY` is ignored when
`REQUEST_METHOD` is set.

Proxy precedence is: an explicit `--proxy` or configured `proxy = ...` value,
then scheme-specific environment variables (`HTTP_PROXY` for HTTP requests and
`HTTPS_PROXY` for HTTPS requests), then `ALL_PROXY`, then the system proxy
configuration. `NO_PROXY`/`no_proxy` entries may be hosts, domains, IP
addresses, CIDR ranges, ports, or `*`.

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

Force a specific HTTP version. `--http1`, `--http2`, and `--http3` are aliases
for `--http 1`, `--http 2`, and `--http 3`.

When `--http` is unset, direct HTTPS requests use DNS HTTPS/SVCB records to
discover `h3`. With `--dns-server`, HTTPS-record discovery uses that custom UDP
or DoH resolver. Without `--dns-server`, it uses the platform resolver,
matching normal address lookup. HTTPS-record discovery and normal A/AAAA lookup
run in parallel. `fetch` starts the TCP/TLS path as soon as normal DNS produces
a usable address, and a usable `h3` candidate that is discovered before TCP/TLS
wins races QUIC setup against it. The request is sent once on the winning
transport. If HTTPS-record discovery is too slow, fails, is unsupported by the
OS resolver, or returns no usable `h3` record, HTTPS uses the normal ALPN path
and offers `h2` then `http/1.1`. Proxy and Unix socket requests also use the
normal ALPN path.

`fetch` also remembers recent HTTP/3 alternatives learned from HTTPS/SVCB
records and `Alt-Svc: h3=...` response headers in a bounded per-origin cache
under the user cache directory. Cached alternatives are scoped to the resolver
that learned them, expire with DNS TTL or `Alt-Svc` `ma`, and are only used for
the same automatic direct HTTPS path. Prompt fresh HTTPS/SVCB results are tried
before cached entries, while cached entries can race slower HTTPS-record
discovery so a learned `Alt-Svc` alternative can be used on later requests.

Setting `--http 1`, `--http 2`, or `--http 3` forces that protocol; it does not
set a version cap. Use `--http 1` or `--http 2` to opt out of automatic HTTP/3.

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
fetch --http2 example.com
```

- Forces HTTP/2
- Multiplexed streams
- Header compression (HPACK)
- Required for gRPC
- Plain `http://` URLs are only supported with forced HTTP/2 for gRPC requests,
  where `fetch` uses h2c (HTTP/2 over cleartext) for local development servers
  without TLS

### HTTP/3 (QUIC)

```sh
fetch --http 3 example.com
```

- Forces QUIC transport (UDP-based)
- Does not fall back to TCP when QUIC fails
- Not all servers support HTTP/3

### Version Detection

By default, `fetch` negotiates the best available version:

1. Uses DNS HTTPS/SVCB records from the platform resolver, or from
   `--dns-server` when set, to discover `h3` candidates for direct HTTPS
2. Reuses fresh cached HTTP/3 alternatives learned from prior HTTPS/SVCB or
   `Alt-Svc` responses
3. Resolves A and AAAA in parallel and starts TCP/TLS as soon as an address is
   usable
4. Races QUIC setup against TCP/TLS when a usable `h3` candidate is discovered
   before TCP/TLS wins
5. Otherwise offers HTTP/2 via ALPN
6. Falls back to HTTP/1.1 if needed

## TLS Configuration

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

| Value | Protocol                      |
| ----- | ----------------------------- |
| `1.2` | TLS 1.2 (recommended minimum) |
| `1.3` | TLS 1.3 (most secure)         |

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

`--inspect-tls` performs a TLS handshake only (no HTTP request is made) and provides a focused view of the TLS certificate chain, useful as a standalone diagnostic tool:

```sh
fetch --inspect-tls example.com
```

Output includes:

- **TLS version and cipher suite** (e.g., TLS 1.3: TLS_AES_256_GCM_SHA384)
- **ALPN negotiated protocol** (e.g., h2)
- **Certificate chain** with tree visualization and expiry status
- **Subject Alternative Names** (DNS names and IP addresses)
- **OCSP staple status** (good, revoked, or unknown)

Expiry is color-coded: red if expired or less than 7 days remaining, yellow if less than 30 days, green otherwise.

Request-only CLI flags (e.g. `--data`, `--timing`, `--grpc`) warn that no HTTP request will be sent and those flags have no effect when used with `--inspect-tls`; config-file defaults do not trigger this warning.

`--dns-server` applies to TLS inspection too, so certificate diagnostics can use
the same UDP or DNS-over-HTTPS resolver override as normal requests. When
combined with `--http 3`, TLS inspection uses a QUIC handshake and offers `h3`
ALPN instead of dialing TCP.

```sh
# Check certificate chain
fetch --inspect-tls example.com

# Inspect certificates even if invalid
fetch --inspect-tls --insecure expired.badssl.com

# Inspect the HTTP/3 QUIC/TLS path
fetch --inspect-tls --http 3 example.com

# Inspect with a custom DNS resolver
fetch --inspect-tls --dns-server 1.1.1.1 example.com
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

### `--compress MODE`

Control automatic compression negotiation:

```sh
fetch --compress auto example.com
fetch --compress br example.com
fetch --compress gzip example.com
fetch --compress zstd example.com
fetch --compress off example.com
```

By default, `fetch`:

- Sends `Accept-Encoding: gzip, br, zstd` header
- Automatically decompresses responses

Compression modes:

- `auto` requests gzip, brotli, or zstd and decompresses any of those response encodings
- `br`/`brotli` requests and decompresses brotli only
- `gzip` requests and decompresses gzip only
- `zstd` requests and decompresses zstd only
- `off` sends no automatic `Accept-Encoding` header and leaves compressed response bodies untouched

Output files receive decoded/decompressed bodies by default too. Use
`--compress off` for byte-for-byte downloads of `.gz`, `.br`, or `.zst` assets.

For SSE (`text/event-stream`) responses in `auto` mode, `fetch` retries without
`Accept-Encoding` when the server replies with compressed content. This avoids
common buffering behavior that prevents events from appearing as they arrive.

Using `off` is useful when:

- Testing compression behavior
- Server has compression bugs
- You want to see raw compressed data
- You need a byte-for-byte output-file download

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
- Streamed response bodies such as SSE, NDJSON, and gRPC streams

Timeouts from CLI flags, `--from-curl`, and configuration files are enforced for
streaming responses. Omit `--timeout` or use a larger value for long-lived event
streams.

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
- **Cookie domain matching**: Delegated to the Rust cookie store, which implements RFC 6265 behavior.
- **Atomic writes**: Session files are written atomically (temp file + rename) to avoid corruption.
- **Name validation**: Only `[a-zA-Z0-9_-]` characters are allowed to prevent path traversal.

## Debugging Network Issues

### Timing Waterfall

`--timing` (or `-T`) displays a timing waterfall chart after the response, showing how time was spent across DNS resolution, TCP connection setup, TLS handshake, time to first byte, and body download:

```sh
fetch --timing https://example.com
```

The chart adapts to the request: TLS is omitted for plaintext HTTP, HTTP/3 reports connection setup as QUIC, and connection phases are omitted when an existing pooled connection is reused. Combine with `-vvv` for both inline debug text and the waterfall summary.

Can also be configured in the [configuration file](configuration.md):

```ini
timing = true
```

### Verbose Output

```sh
fetch -v example.com    # Response headers
fetch -vv example.com   # Request + response headers with direction prefixes
fetch -vv --sort-headers example.com  # Sort displayed headers by name
fetch -vvv example.com  # DNS + TLS details with direction prefixes
```

### Dry Run

Preview the request without sending:

```sh
fetch --dry-run -j '{"test": true}' example.com
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

- [CLI Reference](cli-reference.md) - Complete option reference
- [Authentication](authentication.md) - mTLS and other auth methods
- [Configuration](configuration.md) - Configuration file options
- [Troubleshooting](troubleshooting.md) - Network debugging
