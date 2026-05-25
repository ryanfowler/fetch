# Advanced Features

This guide covers advanced networking, protocol, and TLS options in `fetch`.

## Custom DNS Resolution

### `--dns-server`

Use a custom DNS server instead of the system resolver.

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

Use HTTPS URL for encrypted DNS queries:

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

The output shows the resolver backend, A, AAAA, CNAME, TXT, MX, NS, SOA, SRV, CAA, SVCB, and HTTPS records when present, address count, record count, lookup duration, and per-record TTLs.

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
export NO_PROXY="localhost,127.0.0.1,.internal.com"

fetch example.com  # Uses proxy from environment
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

- Default behavior (HTTP/2 preferred with fallback)
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

By default, `fetch` negotiates the best available version:

1. Attempts HTTP/2 via ALPN
2. Falls back to HTTP/1.1 if needed

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

HTTP-only flags (e.g. `--data`, `--timing`, `--grpc`) are ignored with a warning when used with `--inspect-tls`.

When combined with `--http 3`, TLS inspection uses a QUIC handshake and offers `h3` ALPN instead of dialing TCP.

```sh
# Check certificate chain
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

### `--compress MODE`

Control automatic compression negotiation:

```sh
fetch --compress auto example.com
fetch --compress gzip example.com
fetch --compress zstd example.com
fetch --compress off example.com
```

By default, `fetch`:

- Sends `Accept-Encoding: gzip, zstd` header
- Automatically decompresses responses

Compression modes:

- `auto` requests gzip or zstd and decompresses either response encoding
- `gzip` requests and decompresses gzip only
- `zstd` requests and decompresses zstd only
- `off` sends no automatic `Accept-Encoding` header and leaves compressed response bodies untouched

Using `off` is useful when:

- Testing compression behavior
- Server has compression bugs
- You want to see raw compressed data

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

`--timing` (or `-T`) displays a timing waterfall chart after the response, showing how time was spent across DNS resolution, connection establishment, time to first byte, and body download:

```sh
fetch --timing https://example.com
```

The chart adapts to the request: Connect represents the full connector phase and may include TCP plus TLS. DNS and Connect are omitted when the connection is reused. Combine with `-vvv` for both inline debug text and the waterfall summary.

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

- [CLI Reference](cli-reference.md) - Complete option reference
- [Authentication](authentication.md) - mTLS and other auth methods
- [Configuration](configuration.md) - Configuration file options
- [Troubleshooting](troubleshooting.md) - Network debugging
