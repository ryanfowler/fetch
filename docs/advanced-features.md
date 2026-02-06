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

### Minimum TLS Version

`--tls VERSION` sets the minimum acceptable TLS version:

```sh
fetch --tls 1.2 example.com  # Require TLS 1.2+
fetch --tls 1.3 example.com  # Require TLS 1.3
```

| Value | Protocol                      |
| ----- | ----------------------------- |
| `1.0` | TLS 1.0 (legacy)              |
| `1.1` | TLS 1.1 (deprecated)          |
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

### Configuration File

```ini
# Require TLS 1.2 minimum
tls = 1.2

# Internal server with private CA
[internal.company.com]
ca-cert = /etc/pki/internal-ca.crt

# Development server (insecure)
[dev.localhost]
insecure = true
```

## Compression

### `--no-encode`

Disable automatic compression negotiation:

```sh
fetch --no-encode example.com
```

By default, `fetch`:

- Sends `Accept-Encoding: gzip, zstd` header
- Automatically decompresses responses

Disabling is useful when:

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

### Configuration File

```ini
# Global timeout
timeout = 30

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
  --tls 1.3 \
  --timeout 60 \
  --http 2 \
  -v \
  https://example.onion/api
```

### Configuration File Example

```ini
# Global settings
timeout = 30
tls = 1.2
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
tls = 1.3
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
- **Atomic writes**: Session files are written atomically (temp file + rename) to avoid corruption.
- **Name validation**: Only `[a-zA-Z0-9_-]` characters are allowed to prevent path traversal.

## Debugging Network Issues

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
fetch --tls 1.3 -vvv example.com
```

## See Also

- [CLI Reference](cli-reference.md) - Complete option reference
- [Authentication](authentication.md) - mTLS and other auth methods
- [Configuration](configuration.md) - Configuration file options
- [Troubleshooting](troubleshooting.md) - Network debugging
