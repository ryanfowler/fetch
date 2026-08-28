# CLI Reference

Complete reference for all `fetch` command-line options. This file is embedded
in the Go binary and is displayed by `fetch -v --help`.

See also [the documentation index](index.md), [limits and safety](limits.md),
and the dedicated [article](article.md), [HAR](har.md), [updates](updates.md),
and [Agent Skill](agent-skill.md) guides.

## Usage

```
fetch [OPTIONS] [URL]
```

## URL Handling

When no scheme is provided, `fetch` defaults to HTTPS for hostnames. `localhost` and all IP literals default to HTTP. Dry-run output includes the normalized absolute URL. If a schemeless HTTPS connection fails during setup, `fetch` suggests the equivalent `http://` URL for plaintext services.

```sh
fetch example.com          # https://example.com
fetch localhost:3000       # http://localhost:3000
fetch http://example.com   # Force HTTP
```

A timeout value of `0` disables that deadline. `--timeout 0` removes the
request deadline, and `--connect-timeout 0` removes the connection setup
deadline.

## HTTP Method

### `-m, --method METHOD`

Specify the HTTP method. Default: `GET`, or `POST` when a request-body flag is used without an explicit method.

**Alias**: `-X`

```sh
fetch -m POST example.com
fetch -X DELETE example.com/resource/123
```

## Headers and Query Parameters

### `-H, --header NAME:VALUE`

Set custom headers. Can be used multiple times.

```sh
fetch -H "Authorization: Bearer token" example.com
fetch -H "X-Custom: value" -H "Accept: application/json" example.com
```

### `-q, --query KEY=VALUE`

Append query parameters to the URL in input order. Duplicate parameters are preserved. Can be used multiple times.

```sh
fetch -q page=1 -q limit=50 example.com
```

## Request Body Options

Body options are mutually exclusive - only one can be used per request.

### `-d, --data [@]VALUE`

Send a raw request body. Content-Type is auto-detected when using file references.

```sh
fetch -d 'Hello, world!' -m PUT example.com
fetch -d @data.txt -m PUT example.com
fetch -d @- -m PUT example.com < data.txt
```

### `-j, --json [@]VALUE`

Send a JSON request body. Sets `Content-Type: application/json`.

```sh
fetch -j '{"hello": "world"}' -m POST example.com
fetch -j @data.json -m POST example.com
```

### `-x, --xml [@]VALUE`

Send an XML request body. Sets `Content-Type: application/xml`.

```sh
fetch -x '<Tag>value</Tag>' -m PUT example.com
fetch -x @data.xml -m PUT example.com
```

### `-f, --form KEY=VALUE`

Send a URL-encoded form body. Can be used multiple times.

```sh
fetch -f username=john -f password=secret -m POST example.com/login
```

### `-F, --multipart NAME=[@]VALUE`

Send a multipart form body. Use `@` prefix for file uploads. Can be used multiple times.

```sh
fetch -F hello=world -F file=@document.pdf -m POST example.com/upload
```

### `-e, --edit`

Open an editor to modify the request body before sending. Uses `VISUAL` or `EDITOR` environment variables.

```sh
fetch --edit -m PUT example.com
```

## Authentication

Authentication options are mutually exclusive.

### `--basic USER:PASS`

HTTP Basic Authentication.

```sh
fetch --basic username:password example.com
```

### `--digest USER:PASS`

HTTP Digest Authentication. Uses a bounded RFC 7616 challenge-response handshake. Supports MD5, MD5-sess, SHA-256, SHA-256-sess, SHA-512-256, and SHA-512-256-sess, with no qop or qop=auth challenges.

```sh
fetch --digest username:password example.com
```

### `--bearer TOKEN`

HTTP Bearer Token Authentication.

```sh
fetch --bearer mysecrettoken example.com
```

### `--aws-sigv4 REGION/SERVICE`

Sign requests with AWS Signature V4. Requires `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables. If `AWS_SESSION_TOKEN` is set, it is sent and signed as `x-amz-security-token`.

```sh
fetch --aws-sigv4 us-east-1/s3 s3.amazonaws.com/bucket/key
```

### `--cert PATH`

Client certificate file for mTLS. PEM format.

```sh
fetch --cert client.crt --key client.key example.com
```

### `--key PATH`

Client private key file for mTLS. Required if `--cert` is a certificate-only file.

```sh
fetch --cert client.crt --key client.key example.com
```

## Output Options

### `-o, --output PATH`

Write response body to a file. Use `-` for stdout (bypasses binary detection).

```sh
fetch -o response.json example.com/api/data
fetch -o - example.com/file.bin > output.bin
```

### `-O, --remote-name`

Write response body to current directory using the filename from the URL.

**Alias**: `--output-current-dir`

```sh
fetch -O example.com/path/to/file.txt  # Creates ./file.txt
```

### `-J, --remote-header-name`

Use filename from `Content-Disposition` header. Requires `-O`. The extended
`filename*` parameter is preferred. Unsafe or malformed names fall back to the
URL filename with a warning.

```sh
fetch -O -J example.com/download
```

### `--clobber`

Overwrite existing output file (default behavior is to fail if file exists).

```sh
fetch -o output.json --clobber example.com/data
```

### `--copy`

Copy the response body to the system clipboard. The response is still printed
to stdout normally. Works with all response types including streaming responses
(SSE, NDJSON, gRPC). Responses exceeding 1 MiB are not copied to the clipboard.

Requires a clipboard command to be available on the system:

- **macOS**: `pbcopy` (built-in)
- **Linux/Wayland**: `wl-copy`
- **Linux/X11**: `xclip` or `xsel`
- **Windows**: `clip.exe` (built-in)

```sh
fetch --copy example.com/api/data
fetch --copy -o response.json example.com/api/data
```

### `--discard`

Discard the response body. Useful for checking status codes, viewing headers (with `-v`), or measuring timing (with `--timing`) without printing the response body.

Cannot be combined with `--output`, `--remote-name`, or `--copy`.

```sh
fetch --discard example.com
fetch --discard -v example.com              # View headers only
fetch --discard --timing example.com        # Measure timing only
```

## Formatting Options

### `--format OPTION`

Control response formatting. Values: `auto`, `on`, `off`.

Markdown rendered on a terminal uses clickable OSC 8 hyperlinks when the
terminal supports them. Terminal prose wraps to the detected terminal width,
capped at 100 columns by default. Non-terminal output does not contain OSC 8
hyperlink escapes.

```sh
fetch --format off example.com   # Disable formatting
fetch --format on example.com    # Force formatting
```

### `--article`

Extract a readable HTML/XHTML page as Markdown with YAML frontmatter. Markdown
responses (`text/markdown` and `text/x-markdown`) pass through after a `url`
frontmatter field. Article mode buffers at most 16 MiB of decoded content and
does not execute JavaScript. On terminals, embedded article images are fetched
and rendered unless `--image off` is set. Output files and pipes retain image
links in the raw Markdown. It cannot be combined with `--discard`,
`--remote-name`, or `--remote-header-name`.

The frontmatter fields are `title`, `byline`, `site_name`, `published_time`,
`lang`, `dir`, `length`, `excerpt`, and `url` when available. String values use
JSON quoting, which is also valid YAML. The final URL after redirects is used
for link resolution and the `url` field.

Output files and pipes receive raw, uncolored Markdown. `--format`, `--color`,
and `--pager` control only terminal presentation.

```sh
fetch --article https://example.com/story
fetch --article -o story.md https://example.com/story
```

### `--compress MODE`

Select content-encoding negotiation and streaming decoding: `auto`, `br`
(alias `brotli`), `gzip`, `zstd`, or `off`. `auto` advertises `gzip, br, zstd`;
the other enabled modes advertise only their selected encoding. `off` sends
no automatic encoding header and preserves encoded response bytes. An
explicit `Accept-Encoding` header is never replaced. The compatibility flag
`--no-encode` is equivalent to `--compress off`; selecting conflicting
explicit modes is an error.

### `--ech MODE`

Configure Encrypted ClientHello with `auto`, `on`, or `off`. The default is
`off`. `auto` discovers HTTPS/SVCB records with address resolution and uses a
validated advertised ECH configuration when one is available. Authenticated
DNS discovery failures are not silently downgraded. `on` requires a usable
advertised configuration, rejects explicit HTTP/3, and uses TCP with automatic
HTTP version selection. ECH requires TLS 1.3; explicit TLS 1.2 bounds are a
configuration error. WSS and TLS inspection use the same ECH discovery and
handshake reporting. ECH is not available through proxies or cleartext HTTP/2.
See [Encrypted ClientHello](ech.md) for discovery and downgrade rules.

### `--har PATH`

Record the final HTTP exchange in a HAR 1.2 sidecar at `PATH`. Standard output
(`-`) is not a valid HAR destination. The sidecar contains request headers,
cookies, credentials, and captured bodies. Protect it as sensitive data.

Request and response bodies are captured up to 16 MiB each. UTF-8 text is stored
as text and binary data as base64 while within the limit. For larger bodies,
the captured payload is omitted entirely and the HAR adds the comment `Body
omitted by fetch because it exceeds the 16 MiB HAR capture limit`. HAR records
the final exchange after redirects and retries. It is not
available for WebSocket sessions, DNS/TLS inspection, gRPC discovery, or
`--dry-run`, and it cannot use the response output path.

### `--color OPTION`

Control colored output. Values: `auto`, `on`, `off`.

**Alias**: `--colour`

```sh
fetch --color off example.com
```

### `--image OPTION`

Control image rendering. Values: `auto`, `external`, or `off`. `auto` uses
built-in decoders only. `external` allows bounded `vips`, `magick`, and
`ffmpeg` adapters after built-in decoding. The legacy `native` spelling
remains accepted as an alias for `auto`.

- `auto` - Use only built-in decoders (JPEG, PNG, TIFF, WebP)
- `external` - Try built-in decoders, then bounded external adapters
- `off` - Disable image rendering

```sh
fetch --image auto example.com/image.png
fetch --image off example.com/photo.jpg
```

### `--pager MODE`

Choose pager behavior with `auto`, `on`, or `off`. `--no-pager` remains a
compatibility alias for `--pager off`.

### `--sort-headers`

Accepted for compatibility. The Go implementation keeps deterministic
alphabetical header rendering, so this option is currently a no-op.

### `--ws-message-mode MODE`

Set WebSocket input handling to `auto`, `text`, or `binary`. This option is
valid only with a `ws://` or `wss://` URL. Text lines, interactive entries, and
incoming messages are bounded to 16 MiB; binary stdin is streamed in bounded
chunks. See [WebSocket](websocket.md).

### WebTransport options

`--webtransport URL` opens an HTTPS WebTransport session over HTTP/3 and direct
UDP. The default `--wt-mode stream` uses one reliable bidirectional stream.
`--wt-mode datagram` uses unreliable datagrams. Use `--wt-datagram-mode
lines|binary` to split piped input, and repeat `--wt-protocol PROTOCOL` to offer
application protocols. Received datagrams are compact JSON Lines records with
base64 data. WebTransport does not support proxies, redirects, retries,
formatting, HAR, output files, Unix sockets, or Digest authentication. EOF on
datagram input does not close the session; use Ctrl+C when the peer remains
open. `--dry-run` does not access the network or consume stdin.

## Agent Skill Options

### `--skill`

Print the portable Agent Skill without requiring a URL.

### `--install-skill [AGENT]` / `--uninstall-skill [AGENT]`

Manage the portable skill for `auto`, `agents`, `codex`, `claude`, `gemini`,
`pi`, or `all`. Use `--scope user|project` to select the destination and
`--force` to permit replacement/removal of modified files. `--scope` and
`--force` require an install or uninstall operation.

### `--no-pager`

Disable piping output to a pager (`less`).

```sh
fetch --no-pager example.com
```

## Sessions

### `-S, --session NAME`

Use a named session for persistent cookie storage across invocations. Cookies set by servers are saved to disk and automatically sent on subsequent requests using the same session name.

Session names must contain only alphanumeric characters, hyphens, and underscores (`[a-zA-Z0-9_-]`).

```sh
# First request — server sets cookies, they get saved
fetch --session api example.com/login -j '{"user":"me"}'

# Second request — saved cookies are sent automatically
fetch --session api example.com/dashboard
```

Session files are stored in the user's cache directory:

- **Linux**: `~/.cache/fetch/sessions/<NAME>.json`
- **macOS**: `~/Library/Caches/fetch/sessions/<NAME>.json`

Session files are limited to 2 MiB, and serialized cookie data is limited to
1 MiB. Each session can contain up to 2,048 cookies (64 per domain); cookie
names and values are limited to 256 and 4,096 bytes. Cookies rejected or
evicted by these limits produce a bounded warning.

Can also be configured per-host in the [configuration file](configuration.md).

## Network Options

### `--connect-timeout SECONDS`

Timeout for the connection phase (DNS resolution, TCP connect, TLS handshake) in seconds. Accepts decimal values. Independent of `--timeout`, which covers the entire request.

```sh
fetch --connect-timeout 5 example.com
fetch --connect-timeout 5 --timeout 30 example.com
```

### `-t, --timeout SECONDS`

Request timeout in seconds. Accepts decimal values.

```sh
fetch --timeout 30 example.com
fetch --timeout 2.5 example.com
```

### `--redirects NUM`

Maximum automatic redirects. Default: `10`. Use `0` to disable.

```sh
fetch --redirects 0 example.com   # Don't follow redirects
fetch --redirects 10 example.com
```

Credential-bearing headers, including custom headers with authentication-like
names, are sent only within the initial origin. Header-name matching uses
complete components rather than substrings. They are removed before a
cross-origin redirected request and are not restored if a later redirect
returns to the original origin.

When `--cert` configures mTLS, a redirect crossing a scheme, host, or port
boundary is refused before connecting to the destination. Same-origin
redirects remain allowed.

Request bodies are also protected at origin boundaries. A redirect is refused
with an error before any bytes are sent to the destination when the effective
redirected request has a body and the status/method semantics preserve that
body. This rule is based on body presence, not a fixed list of methods, so it
also covers body-bearing GET, HEAD, DELETE, OPTIONS, POST, and custom methods.
There is no cross-origin body-replay opt-in. A 301 or 302 POST and every
non-HEAD 303 are changed to GET without a body, so those redirects remain
allowed.

### `--retry NUM`

Maximum number of retries for transient failures. Default: `0` (no retries).
The value must be between `0` and `100`.

Retries occur on connection errors and retryable status codes (429, 502, 503, 504) for GET, HEAD, OPTIONS, and TRACE requests. Non-retryable errors (4xx, TLS certificate errors) are not retried. PUT and DELETE are not retried by default: although HTTP describes them as idempotent, individual APIs may implement side effects that are unsafe to repeat. POST, PATCH, PUT, DELETE, and custom methods require the explicit `--retry-unsafe` opt-in. Uses exponential backoff with jitter between attempts.

All attempts, redirects, response reads, bounded drains, and retry delays share one `--timeout` wall-clock budget. A request body must be replayable before a retry starts. Only the final attempt's response body is written to stdout. Retry notifications are printed to stderr (suppressed with `--silent`).

```sh
fetch --retry 3 example.com
fetch --retry 2 --retry-delay 0.5 example.com
```

### `--retry-unsafe`

Opt in to automatic retries for methods other than GET, HEAD, OPTIONS, and
TRACE. This includes POST, PATCH, PUT, DELETE, and custom methods. Use it only
when the endpoint is known to tolerate replay, or when the request carries an
application-level idempotency guarantee such as a validated `Idempotency-Key`.
The option does not add an idempotency key or otherwise make a request safe.

```sh
fetch --method POST --data '{"action":"create"}' --retry 2 --retry-unsafe example.com/actions
```

Digest authentication is a separate challenge-response mechanism. A Digest
401 challenge can replay the request once (and a stale nonce can cause one
additional bounded replay) when `--digest` is enabled, including for an unsafe
method; `--retry-unsafe` does not control those authentication replays.

### `--retry-delay SECONDS`

Initial delay between retries in seconds. Default: `1`. Accepts decimal values.

The actual delay uses exponential backoff (delay doubles each attempt, capped at 30s) with ±25% jitter. If the server sends a `Retry-After` header, that value is used when it exceeds the computed delay and is capped at 30 seconds. A warning is printed when a server value is clamped. The request stops without sleeping when the remaining timeout cannot accommodate the delay.

```sh
fetch --retry 3 --retry-delay 2 example.com
fetch --retry 3 --retry-delay 0.5 example.com
```

### `--dns-server ENDPOINT`

Use a custom DNS resolver. Supported endpoints are bare UDP addresses, or
`udp://`, `tcp://`, `tls://`/`dot://`, `quic://`/`doq://`, and `https://`
(DNS-over-HTTPS) endpoints. UDP and TCP default to port 53. DoT and DoQ
default to 853. DoH uses the URL port and requires HTTPS.

```sh
fetch --dns-server 8.8.8.8 example.com
fetch --dns-server tcp://1.1.1.1:53 example.com
fetch --dns-server dot://dns.example example.com
fetch --dns-server https://1.1.1.1/dns-query example.com
```

Endpoints reject userinfo, fragments, invalid ports, and paths or queries on
non-DoH transports. Resolver endpoint parsing occurs during CLI/config
validation, before any network request. The configured resolver is shared by
HTTP/1.1, HTTP/2, forced HTTP/3, gRPC, WebSocket, TLS inspection, and update
traffic. Address candidates use Happy Eyeballs while preserving resolver
family preference. TCP and DoT queries use one operation-scoped pipelined
connection. DoQ uses one verified QUIC connection per resolver operation and
one bidirectional stream per DNS query. Hostname endpoints use a nonrecursive
platform bootstrap and negotiate the standard `doq` ALPN.

### `--inspect-dns`

Inspect DNS resolution for the URL hostname only (no HTTP request is made). Without `--dns-server`, it queries the nameservers listed in the system resolver configuration (`/etc/resolv.conf`) directly, including on macOS. It reports every record type (A, AAAA, CNAME, TXT, MX, NS, SOA, SRV, CAA, SVCB, and HTTPS) with per-record TTLs, but does not apply macOS scoped, per-interface, VPN, or `/etc/resolver` routing. On platforms without a usable resolver file (notably Windows), or when the name is resolved only through OS mechanisms (the hosts file, NSS modules, or mDNS), it uses the platform resolver for A and AAAA records without per-record TTLs. If direct DNS returns no address records, platform-resolver addresses are added while any records already returned by direct DNS remain visible. With an explicit resolver it queries the same record types concurrently. The output includes resolver security, record counts, and duration. If one query fails, successful records remain visible, a warning identifies the incomplete record types, and the command exits with status 1.

```sh
fetch --inspect-dns example.com
fetch --inspect-dns --dns-server https://1.1.1.1/dns-query example.com
```

### `--proxy PROXY`

Route request through a proxy.

```sh
fetch --proxy http://localhost:8080 example.com
fetch --proxy socks5://localhost:1080 example.com
```

### `--resolve [+]HOST:PORT:IP[,IP]`

Connect to the supplied IP address for a matching host and port while keeping
the URL host as the HTTP Host header and TLS SNI. Repeat the option or provide
comma-separated addresses to provide multiple candidates. A `*` host acts as
a fallback for any host. A leading `+` is accepted for curl compatibility.

```sh
fetch --resolve example.com:443:127.0.0.1 https://example.com
fetch --resolve '*:443:192.0.2.10' https://example.com
```

### `--unix PATH`

Make request over a Unix domain socket. Unix-like systems only.

```sh
fetch --unix /var/run/docker.sock http://unix/containers/json
```

## TLS Options

### `--tls VERSION`

Minimum TLS version. This is an alias for `--min-tls`. Values: `1.2`, `1.3`.

```sh
fetch --tls 1.3 example.com
```

### `--min-tls VERSION`

Minimum TLS version. Values: `1.2`, `1.3`.

```sh
fetch --min-tls 1.2 example.com
```

### `--max-tls VERSION`

Maximum TLS version. Values: `1.2`, `1.3`. Combine with `--min-tls` to allow a bounded range or require an exact TLS version.

```sh
fetch --min-tls 1.2 --max-tls 1.2 example.com
```

### `--inspect-tls`

Inspect the TLS certificates by performing a TLS handshake only (no HTTP request is made). The handshake does not stop for certificate errors. Inspection then verifies the peer certificate with the configured hostname, system and custom roots, and peer intermediates. The default output shows the remote address, negotiated TLS, cipher, key exchange, ALPN, verification status, leaf certificate, SANs, OCSP staple status, and connection timing. Use `-v` for exact certificate fields, the server and verified chains, all SAN types, OCSP timestamps, SCT count, SNI, resolver provenance, and ECH details. OCSP staple status checks the matching certificate and response signature, but not responder authorization or freshness. Use `-vv` for AIA, CRL, policy, and other niche X.509 details. The inspection result is written to stdout; warnings and errors are written to stderr. Certificate verification failure returns a nonzero status unless `--insecure` is explicit; `--insecure` marks the failure as ignored and returns success. Requires an HTTPS URL. With `--http 3`, inspection uses a QUIC handshake and offers `h3` ALPN. HTTP-only flags (e.g. `--data`, `--timing`, `--grpc`) are ignored with a warning.

```sh
fetch --inspect-tls example.com
fetch --inspect-tls --http 3 example.com
fetch --inspect-tls --insecure expired.badssl.com
```

### `--insecure`

Accept invalid TLS certificates. In `--inspect-tls` mode, verification still runs and reports its result, but a verification failure is ignored for the exit status. Use with caution.

```sh
fetch --insecure https://self-signed.example.com
```

### `--ca-cert PATH`

Custom CA certificate file.

```sh
fetch --ca-cert ca-cert.pem example.com
```

## HTTP Version

### `--http VERSION`

Force specific HTTP version. Values: `1`, `2`, `3`.

- `1` - HTTP/1.1
- `2` - Force HTTP/2; direct HTTPS may otherwise try automatic HTTP/3 first
- `3` - HTTP/3 (QUIC)

When `--http 2` is used with an `http://` URL for gRPC requests, `fetch` automatically uses h2c (HTTP/2 over cleartext) to connect without TLS.

```sh
fetch --http 1 example.com
fetch --http 3 example.com
fetch --grpc --http 2 http://localhost:50051/pkg.Svc/Method  # uses h2c
```

The compatibility aliases `--http1`, `--http2`, and `--http3` select the
corresponding version without a value argument.

## Compression

### `--no-encode`

Disable automatic content-encoding negotiation and decoding. This is
equivalent to `--compress off`.

```sh
fetch --no-encode example.com
```

## Range Requests

### `-r, --range RANGE`

Request specific byte ranges. Can be used multiple times.

```sh
fetch -r 0-1023 example.com/file.bin
fetch -r 0-499 -r 1000-1499 example.com/file.bin
```

## Verbosity

### `-v, --verbose`

Increase output verbosity. Can be stacked.

- `-v` - Show response headers
- `-vv` - Show request and response headers with `> ` / `< ` prefixes
- `-vvv` - Show DNS and TLS details with `> ` / `< ` / `* ` prefixes

Diagnostic URLs and headers redact userinfo, sensitive query values, standard
credential headers, and credential-like custom header names. Query-key matching
is case-insensitive and covers names containing `key`, `token`, `secret`,
`password`, `credential`, `signature`, `authorization`, or `session`; names are
retained.

```sh
fetch -v example.com
fetch -vvv example.com
```

### `-T, --timing`

Display a timing waterfall chart after the response. Shows DNS, TCP, TLS, TTFB, and body download phases as a proportional bar chart. Works independently of verbosity. Phases that don't apply (e.g., TLS for HTTP, TCP for HTTP/3, DNS/TCP/TLS for reused connections) are omitted.

```sh
fetch --timing https://example.com
fetch -T https://example.com
fetch --timing -vvv https://example.com   # Both debug text and waterfall
```

### `-s, --silent`

Suppress verbose output. Only errors shown on stderr.

```sh
fetch -s example.com
```

### `--ignore-status`

Don't use HTTP status code for exit code. Always exit 0 on successful request.

```sh
fetch --ignore-status example.com/not-found
```

## WebSocket

Use `ws://` or `wss://` URL schemes to open a WebSocket connection:

```sh
fetch ws://echo.websocket.events
fetch wss://echo.websocket.events -d "hello"
```

Use `--ws-interactive auto|on|off` to control the terminal prompt.

Use `--ws-message-mode auto|text|binary` to select message types. See
[WebSocket documentation](websocket.md) for message limits, close handling,
proxy/TLS behavior, and unsupported options.

## gRPC Options

### `--grpc`

Enable gRPC mode. Automatically sets HTTP/2, POST method, and gRPC headers. When no local proto schema is provided, `fetch` automatically tries gRPC reflection before falling back to generic protobuf handling.

```sh
fetch --grpc https://localhost:50051/package.Service/Method
```

### `--grpc-list`

List available gRPC services. Uses reflection when a URL is provided, or runs offline when `--proto-file` / `--proto-desc` is provided.

```sh
fetch --grpc-list https://localhost:50051
fetch --grpc-list --proto-desc service.pb
```

### `--grpc-describe NAME`

Describe a gRPC service, method, or message. Accepts `package.Service`, `package.Service/Method`, `package.Service.Method`, and full message names.

```sh
fetch --grpc-describe grpc.health.v1.Health https://localhost:50051
fetch --grpc-describe grpc.health.v1.Health/Check --proto-desc service.pb
```

### `--proto-file PATH`

Compile `.proto` file(s) for gRPC requests or offline discovery. Requires `protoc`. Can specify multiple comma-separated paths.

```sh
fetch --grpc --proto-file service.proto -j '{"field": "value"}' localhost:50051/pkg.Svc/Method
```

### `--proto-desc PATH`

Use a pre-compiled descriptor set file instead of `--proto-file`.

```sh
# Generate descriptor:
protoc --descriptor_set_out=service.pb --include_imports service.proto

# Use descriptor:
fetch --grpc --proto-desc service.pb -j '{"field": "value"}' localhost:50051/pkg.Svc/Method
```

### `--proto-import PATH`

Add import paths for proto compilation. Use with `--proto-file`.

```sh
fetch --grpc --proto-file service.proto --proto-import ./proto localhost:50051/pkg.Svc/Method
```

Plaintext servers are supported via `h2c` (HTTP/2 over cleartext) when using an `http://` URL with HTTP/2. This works for `--grpc` and reflection-based discovery (`--grpc-list`, `--grpc-describe`).

## Configuration

### `-c, --config PATH`

Specify configuration file path.

```sh
fetch --config ~/.config/fetch/custom.conf example.com
```

## Curl Compatibility

### `--from-curl COMMAND`

Execute a curl command using fetch. Parses a curl command string and translates its flags into the equivalent fetch options. The `curl` prefix is optional.

Cannot be combined with other request-specifying flags (URL, `--method`, `--header`, `--data`, auth flags, etc.). Meta flags like `--dry-run`, `--color`, `--format`, `--no-pager`, and `--timing` can still be used.

```sh
# Basic GET
fetch --from-curl 'curl https://example.com'

# POST with JSON
fetch --from-curl 'curl -X POST -H "Content-Type: application/json" -d {"key":"value"} https://example.com'

# With authentication
fetch --from-curl 'curl -u user:pass https://example.com'

# Follow redirects with retry
fetch --from-curl 'curl -L --max-redirs 5 --retry 3 https://example.com'

# Preview without sending
fetch --dry-run --from-curl 'curl -X PUT -d @data.json https://example.com'

# Without the curl prefix
fetch --from-curl 'https://example.com'
```

**Supported curl flags:**

| Category                   | Curl Flags                                                                                                                         |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Request                    | `-X`, `-H`, `-d`, `--data-raw`, `--data-binary`, `--data-urlencode`, `--json`, `-F`, `-T`, `-I`, `-G`                              |
| Auth                       | `-u`, `--digest`, `--aws-sigv4`, `--oauth2-bearer`                                                                                 |
| TLS                        | `-k`, `--cacert`, `-E`/`--cert`, `--key`, `--tlsv1.x`, `--tls-max`, `--ech hard                                                    | true | auto | false` |
| Output                     | `-o`, `-O`, `-J`                                                                                                                   |
| Network                    | `-L`, `--max-redirs`, `-m`/`--max-time`, `--connect-timeout`, `-x`, `--unix-socket`, `--doh-url`, `--resolve`, `--retry`, `--retry-delay`, `--retry-unsafe`, `-r` |
| HTTP version               | `-0`, `--http1.1`, `--http2`, `--http3`                                                                                            |
| Headers                    | `-A`, `-e`, `-b`                                                                                                                   |
| Verbosity                  | `-v`, `-s`                                                                                                                         |
| Protocol                   | `--proto` (restricts allowed protocols; errors if URL scheme is not allowed)                                                       |
| Default-compatible no-ops  | `--compressed`, `-S`/`--show-error`, `--fail-with-body`, `--no-keepalive`                                                          |
| Presentation compatibility | `-#`/`--progress-bar`, `--no-progress-meter`                                                                                       |

**Notes:**

- `-b`/`--cookie` only supports inline cookie strings (e.g., `-b 'name=value'`). Cookie jar files are not supported and will return an error.
- A single `-d @filename` or `-d @-` body streams through fetch's native request-body path. Composite data bodies and `--data-urlencode @filename` are materialized for curl compatibility and capped at 16 MiB.
- `--data-urlencode` supports `@filename` and `name@filename` forms for reading and URL-encoding file contents. File bytes are encoded before any text conversion.
- `-n`/`--netrc` is not supported. Use `--basic`, `--bearer`, or an explicit `Authorization` header instead.
- Semantic curl flags that fetch cannot faithfully translate, such as `-f`/`--fail`, `-N`/`--no-buffer`, `--proto-default`, and `--proto-redir`, return an error instead of being ignored.

Unknown curl flags return an error.

## Utility Options

### `-h, --help`

Print concise help information. Use `-v --help` for the full Markdown
reference. The detailed form uses the configured pager when appropriate.
`--pager on` forces paging, `--pager off` disables it, and `NO_PAGER` disables
automatic paging.

### `-V, --version`

Print version.

### `--buildinfo`

Print build information as JSON. The output includes the fetch version, Go
version and build settings. Add
`-v` to include module dependency versions. Metadata commands read
configuration on a best-effort basis; an invalid config does not prevent help,
version, or build information output.

### `--check-update`

Check the latest GitHub release without downloading or replacing the executable.
The command uses bounded HTTPS requests and carries only operational proxy, DNS,
CA, and timeout settings.

Automatic checks run only for a validated normal request. They use the platform
user cache interval and start a detached, silent updater child. The child does
not inherit interactive standard input or terminal signals. Automatic failures
are non-fatal to the request. Metadata-only commands, skill management,
dry-runs, and updater children do not start another automatic check.

### `--update`

Update fetch binary in place. The selected archive must have a matching SHA-256
sidecar. Metadata is limited to 1 MiB, checksums to 1 KiB, and archives to 128
MiB. The archive is streamed to a temporary file and verified before extraction.
Use with `--dry-run` to validate release metadata, asset selection, checksum
availability, and executable preflight. Dry-run downloads bounded release
metadata and the checksum sidecar, but does not download the executable archive
or replace the binary. It does not update the automatic-check timestamp.

### `--complete SHELL`

Output shell completion scripts. Values: `bash`, `fish`, `powershell`, `zsh`.
The scripts and dynamic candidates are generated from the same option registry
as CLI help. See [Shell completion](completions.md).

```sh
echo 'eval "$(fetch --complete bash)"' >> ~/.bashrc
fetch --complete zsh > ~/.zshrc.d/_fetch
fetch --complete fish > ~/.config/fish/completions/fetch.fish
```

### `--dry-run`

Print request information without sending. The normalized absolute URL, method,
redacted headers, and at most 1,024 body bytes are shown. A preview never
consumes stdin or changes sessions, output files, HAR files, updater metadata,
or skill installations. When used with `--update`, checks release metadata and
destination preflight without downloading or installing.

```sh
fetch --dry-run -m POST -j '{"test": true}' example.com
fetch --update --dry-run
```

## Unsupported combinations and safety notes

- `--article` cannot be combined with WebSockets, gRPC, DNS/TLS inspection,
  `--discard`, `--remote-name`, or `--remote-header-name`.
- `--har` cannot be used with WebSockets, DNS/TLS inspection, gRPC discovery,
  dry-run, standard output, or the response output path. It supports unary gRPC
  only.
- WebSockets require HTTP/1.1. They reject HTTP/2 and HTTP/3 forcing, Digest,
  retries, retry delays, redirects, output, remote names, clipboard, clobber,
  discard, range, compression controls (`--compress` and `--no-encode`),
  `--ignore-status`, article, gRPC, and gRPC discovery options before connecting.
- Explicit HTTP/3 cannot use a proxy or Unix socket. Forced HTTP/3 never falls
  back to TCP.
- `--ech on` cannot use explicit HTTP/3 or TLS 1.2 bounds. ECH is not used
  through proxies or cleartext HTTP/2.
- `--sort-headers` is accepted as a compatibility no-op. Go's normal HTTP
  stack uses deterministic header serialization and does not preserve input wire
  order.

See [Limits and safety](limits.md) for all body, protocol, archive, and
subprocess caps.

## Environment Variables

| Variable                      | Description                                            |
| ----------------------------- | ------------------------------------------------------ |
| `AWS_ACCESS_KEY_ID`           | AWS access key for `--aws-sigv4`                       |
| `AWS_SECRET_ACCESS_KEY`       | AWS secret key for `--aws-sigv4`                       |
| `AWS_SESSION_TOKEN`           | Optional temporary AWS session token for `--aws-sigv4` |
| `VISUAL` / `EDITOR`           | Editor for `--edit` option                             |
| `HTTPS_PROXY` / `https_proxy` | HTTPS/WSS proxy URL                                    |
| `HTTP_PROXY` / `http_proxy`   | HTTP/WS proxy URL                                      |
| `ALL_PROXY` / `all_proxy`     | Fallback proxy URL                                     |
| `NO_PROXY` / `no_proxy`       | Hosts, domains, IPs, CIDR ranges, or ports             |

## File References

Many options support file references with the `@` prefix:

- `@filename` - Read content from file
- `@-` - Read content from stdin
- `@~/path` - Home directory expansion

```sh
fetch -j @data.json -m POST example.com
echo '{"test": true}' | fetch -j @- -m POST example.com
```
