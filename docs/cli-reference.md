# CLI Reference

Complete reference for all `fetch` command-line options.

## Usage

```
fetch [OPTIONS] [URL]
```

## URL Handling

When no scheme is provided, `fetch` defaults to HTTPS for hostnames. `localhost`
and all IP literals default to HTTP. If a schemeless hostname defaults to HTTPS
and the connection fails during setup, `fetch` suggests the equivalent
`http://` URL for plaintext services.

```sh
fetch example.com          # https://example.com
fetch localhost:3000       # http://localhost:3000
fetch 192.168.1.1:8080     # http://192.168.1.1:8080
fetch 1.1.1.1              # http://1.1.1.1
fetch http://example.com   # Force HTTP
```

## HTTP Method

### `-m, --method METHOD`

Specify the HTTP method. Default: `GET`, or `POST` when a request-body flag is
used and `--method` is omitted.

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

Append query parameters to the URL. Can be used multiple times.

```sh
fetch -q page=1 -q limit=50 example.com
```

## Request Body Options

Payload source options are mutually exclusive - only one of `--data`, `--json`,
`--xml`, `--form`, or `--multipart` can be used per request. These options, and
`--edit`, default the request method to `POST` when `--method` is omitted; use
`-m`/`--method` to send the body with another method.

### `-d, --data [@]VALUE`

Send a raw request body. Content-Type is auto-detected when using file references.

```sh
fetch -d 'Hello, world!' -m PUT example.com
fetch -d @data.txt -m PUT example.com
fetch -d @- example.com < data.txt
```

### `-j, --json [@]VALUE`

Send a JSON request body. Sets `Content-Type: application/json`.

```sh
fetch -j '{"hello": "world"}' example.com
fetch -j @data.json example.com
```

### `-x, --xml [@]VALUE`

Send an XML request body. Sets `Content-Type: application/xml`.

```sh
fetch -x '<Tag>value</Tag>' example.com
fetch -x @data.xml -m PUT example.com
```

### `-f, --form KEY=VALUE`

Send a URL-encoded form body. Can be used multiple times.

```sh
fetch -f username=john -f password=secret example.com/login
```

### `-F, --multipart NAME=[@]VALUE`

Send a multipart form body. Use `@` prefix for file uploads. Can be used multiple times.

```sh
fetch -F hello=world -F file=@document.pdf example.com/upload
```

### `-e, --edit`

Open an editor to modify the request body before sending. Uses `VISUAL` or `EDITOR` environment variables.

```sh
fetch --edit example.com
```

## Authentication

Authentication options are mutually exclusive.

### `--basic USER:PASS`

HTTP Basic Authentication.

```sh
fetch --basic username:password example.com
```

### `--digest USER:PASS`

HTTP Digest Authentication. Uses a challenge-response handshake to avoid sending credentials in plain text.
Supports challenges without `qop` and challenges with `qop=auth`; unsupported digest parameters are reported as diagnostics.

```sh
fetch --digest username:password example.com
```

### `--bearer TOKEN`

HTTP Bearer Token Authentication.

```sh
fetch --bearer mysecrettoken example.com
```

### `--aws-sigv4 REGION/SERVICE`

Sign requests with AWS Signature V4. Requires `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables. Temporary credentials can also set `AWS_SESSION_TOKEN`.

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
TLS requests reject `--key` without a client certificate.

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

Output files receive the decoded response body by default. If the response uses
`Content-Encoding` for a `.gz`, `.br`, or `.zst` asset, use `--compress off` for
byte-for-byte downloads.

### `-O, --remote-name`

Write response body to current directory using the filename from the URL.

**Alias**: `--output-current-dir`

```sh
fetch -O example.com/path/to/file.txt  # Creates ./file.txt
```

### `-J, --remote-header-name`

Use filename from `Content-Disposition` header. Requires `-O`. If the response
does not include a usable header filename, fetch warns and falls back to the URL
filename.

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

Do not print the response body. Useful for checking status codes, viewing headers (with `-v`), or measuring timing (with `--timing`) without writing the body to stdout.

`--discard` still reads the response body to completion. Use `-m HEAD` when you want to ask the server to avoid transferring a response body.

Cannot be combined with `--output`, `--remote-name`, or `--copy`.

```sh
fetch --discard example.com
fetch --discard -v example.com              # View headers only
fetch --discard --timing example.com        # Measure timing only
fetch -m HEAD example.com                   # Avoid body transfer when supported
```

## Formatting Options

### `--format OPTION`

Control response formatting. Values: `auto`, `on`, `off`.

```sh
fetch --format off example.com   # Disable formatting
fetch --format on example.com    # Force formatting
```

### `--color OPTION`

Control colored output. Values: `auto`, `on`, `off`.

**Alias**: `--colour`

```sh
fetch --color off example.com
```

### `--image OPTION`

Control image rendering. Values: `auto`, `external`, `off`.

- `auto` - Try optimal terminal protocol with built-in decoders
- `external` - Allow external adapters for additional formats
- `off` - Disable image rendering

```sh
fetch --image external example.com/photo.avif
fetch --image off example.com/photo.jpg
```

### `--pager MODE`

Control piping response body output to a pager. Values:

- `auto` - Use the pager when stdout is a terminal (default)
- `on` - Force pager use
- `off` - Disable the pager

```sh
fetch --pager off example.com
```

When paging is enabled, fetch uses `$PAGER` if it is set. Set `NO_PAGER` to
disable the default `auto` pager. If `$PAGER` is unset, fetch falls back to
`less -FIRX`; when `$LESS` is set, fetch runs `less` without adding its default
flags so your `LESS` options apply. `$PAGER` is split with POSIX shell-style
quoting, but fetch launches the pager directly and does not interpret shell
operators such as pipes or redirects.

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

Can also be configured per-host in the [configuration file](configuration.md).

## Network Options

### `--connect-timeout SECONDS`

Timeout for the connection phase (DNS resolution, TCP connect, TLS handshake) in seconds. Accepts decimal values. Independent of `--timeout`, which covers the entire request.

```sh
fetch --connect-timeout 5 example.com
fetch --connect-timeout 5 --timeout 30 example.com
```

### `-t, --timeout SECONDS`

Request timeout in seconds. Accepts decimal values. The timeout covers the full
request, including response body streaming; it is also enforced for SSE, NDJSON,
and gRPC streams.

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

### `--retry NUM`

Maximum number of retries for transient failures. Default: `0` (no retries).

Retries occur on connection errors and retryable status codes (429, 502, 503, 504). Non-retryable errors (4xx, TLS certificate errors) are not retried. Uses exponential backoff with jitter between attempts.

Only the final attempt's response body is written to stdout. Retry notifications are printed to stderr (suppressed with `--silent`).

```sh
fetch --retry 3 example.com
fetch --retry 2 --retry-delay 0.5 example.com
```

### `--retry-delay SECONDS`

Initial delay between retries in seconds. Default: `1`. Accepts decimal values.

The actual delay uses exponential backoff (delay doubles each attempt) with ±25% jitter. The effective delay is capped at 30 seconds. If the server sends a `Retry-After` header, that value is used when it exceeds the computed delay, but it is also capped at 30 seconds. A warning is emitted when `Retry-After` is clamped unless `--silent` is enabled. An overall `--timeout` remains the final upper bound.

```sh
fetch --retry 3 --retry-delay 2 example.com
fetch --retry 3 --retry-delay 0.5 example.com
```

### `--dns-server IP[:PORT]|URL`

Use a custom DNS server. Supports UDP DNS, DNS over TCP, DNS over TLS (DoT),
DNS over QUIC (DoQ), and DNS-over-HTTPS (DoH) for requests and DNS/TLS
inspection. Bare `IP[:PORT]` values use UDP DNS, which advertises EDNS(0) and
retries truncated responses over TCP. DoH URLs are queried with RFC 8484
wire-format requests, with Google-style JSON DoH retained as a compatibility
fallback.

```sh
fetch --dns-server 8.8.8.8 example.com
fetch --dns-server 1.1.1.1:53 example.com
fetch --dns-server udp://1.1.1.1:53 example.com
fetch --dns-server tcp://1.1.1.1 example.com
fetch --dns-server tls://dns.google example.com
fetch --dns-server dot://dns.google:853 example.com
fetch --dns-server quic://dns.adguard-dns.com example.com
fetch --dns-server doq://dns.adguard-dns.com example.com
fetch --dns-server https://1.1.1.1/dns-query example.com
```

### `--inspect-dns`

Inspect DNS resolution for the URL hostname only (no HTTP request is made). Displays the resolver backend, A, AAAA, CNAME, TXT, MX, NS, SOA, SRV, CAA, SVCB, and HTTPS records when present, along with per-record TTLs, address count, record count, and lookup duration. Supports all `--dns-server` transports. UDP DNS inspection advertises EDNS(0) and retries truncated UDP responses over TCP; if TCP fallback cannot complete the lookup, `fetch` warns that the results are incomplete and exits with a non-zero status. Request-only CLI flags warn that no HTTP request will be sent and those flags have no effect; config-file defaults do not trigger this warning.

```sh
fetch --inspect-dns example.com
fetch --inspect-dns --dns-server https://1.1.1.1/dns-query example.com
fetch --inspect-dns --dns-server tls://dns.google example.com
```

### `--proxy PROXY`

Route request through a proxy.

```sh
fetch --proxy http://localhost:8080 example.com
fetch --proxy https://secure-proxy.example.com:8443 example.com
fetch --proxy socks5://localhost:1080 example.com
```

HTTPS proxy TLS uses platform verification by default. Origin TLS flags such as
`--ca-cert`, `--cert`, `--key`, and `--insecure` do not apply to the proxy
handshake.

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

### `--ech MODE`

Encrypted Client Hello mode. Values: `auto`, `on`, `off`. Default: `off`.

- **`auto`** — Use ECH if the server advertises it via DNS HTTPS/SVCB records.
  Falls back to GREASE ECH when no real config is found. If the server
  rejects the offer, the connection proceeds gracefully.
- **`on`** — Require ECH. Errors if the server doesn't advertise ECH in DNS,
  and fails if the server rejects the offer.
- **`off`** — Never use ECH.

ECH requires TLS 1.3 and is incompatible with `--min-tls 1.2`.

```sh
fetch --ech auto example.com
fetch --ech on cloudflare.com
```

See [Encrypted Client Hello](ech.md) for details.

### `--inspect-tls`

Inspect the TLS certificate chain by performing a TLS handshake only (no HTTP request is made). Displays the TLS version, cipher suite, ALPN protocol, full certificate chain with expiry status, Subject Alternative Names (SANs), and OCSP staple status. Requires an HTTPS URL. With `--http 3`, inspection uses a QUIC handshake and offers `h3` ALPN. Request-only CLI flags (e.g. `--data`, `--timing`, `--grpc`) warn that no HTTP request will be sent and those flags have no effect; config-file defaults do not trigger this warning.

```sh
fetch --inspect-tls example.com
fetch --inspect-tls --http 3 example.com
fetch --inspect-tls --dns-server 1.1.1.1 example.com
fetch --inspect-tls --insecure expired.badssl.com
```

### `--insecure`

Accept invalid TLS certificates. Use with caution.

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

Force a specific HTTP protocol version. Values: `1`, `2`, `3`.
Aliases: `--http1`, `--http2`, `--http3`.

- `1` - HTTP/1.1
- `2` - HTTP/2
- `3` - HTTP/3 (QUIC)

When `--http` is unset, direct HTTPS requests use DNS HTTPS/SVCB records to
discover `h3` endpoints. With `--dns-server`, HTTPS-record discovery uses that
custom UDP or DoH resolver. Without `--dns-server`, it uses the platform
resolver, matching normal address lookup. This discovery is opportunistic and
does not delay the normal address lookup or TCP/TLS setup: `fetch` starts
TCP/TLS as soon as normal DNS produces a usable address, while a usable `h3`
record discovered before TCP/TLS wins races QUIC setup against it. The request
is sent once on the winning transport. If HTTPS-record discovery is too slow,
fails, is unsupported by the OS resolver, or returns no usable `h3` record,
HTTPS offers `h2` then `http/1.1` through ALPN. Proxy and Unix socket requests
also use the normal ALPN path.

`--http 1`, `--http 2`, and `--http 3` force that protocol instead of setting
a maximum version. `--http 2` with a plain `http://` URL is only supported for
gRPC requests, where `fetch` uses h2c (HTTP/2 over cleartext) for local
plaintext servers. Use `--http 1` or `--http 2` to opt out of automatic
HTTP/3; forced `--http 3` remains strict and does not fall back to TCP.

```sh
fetch --http 1 example.com
fetch --http2 example.com
fetch --http 3 example.com
fetch --grpc --http 2 http://localhost:50051/pkg.Svc/Method  # uses h2c
```

## Compression

### `--compress MODE`

Control response compression negotiation. Values: `auto`, `br`/`brotli`, `gzip`, `zstd`, `off`.

- `auto` - request gzip, brotli, or zstd compression (default)
- `br`/`brotli` - request brotli compression only
- `gzip` - request gzip compression only
- `zstd` - request zstd compression only
- `off` - disable automatic compression negotiation and decompression

Output files also receive decoded/decompressed bodies by default. Use
`--compress off` for byte-for-byte downloads of `.gz`, `.br`, or `.zst` assets.

In `auto` mode, compressed SSE (`text/event-stream`) responses are retried
without `Accept-Encoding` so streaming events can be delivered promptly instead
of being buffered by compression.

```sh
fetch --compress br example.com
fetch --compress gzip example.com
fetch --compress off example.com
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
- `--sort-headers` - Sort displayed request/response headers alphabetically by name

```sh
fetch -v example.com
fetch -vv --sort-headers example.com
fetch -vvv example.com
```

### `-T, --timing`

Display a timing waterfall chart after the response. Shows DNS, TCP, TLS, TTFB, and body download phases as a proportional bar chart. HTTP/3 reports connection setup as QUIC. Works independently of verbosity. Phases that don't apply (e.g., TLS for plaintext HTTP or connection phases for reused connections) are omitted.

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

HTTP 4xx/5xx responses exit nonzero by default; use `--ignore-status` to keep
the exit code at 0 when the request completes.

```sh
fetch --ignore-status example.com/not-found
```

Interrupted requests, such as Ctrl-C/SIGINT, exit 130.

## WebSocket

Use `ws://` or `wss://` URL schemes to open a WebSocket connection:

```sh
fetch ws://echo.websocket.events
fetch wss://echo.websocket.events -d "hello"
```

Use `--ws-interactive auto|on|off` to control the terminal prompt.

Use `--ws-message-mode auto|text|binary` to control whether outgoing messages
are sent as text or binary WebSocket frames.

Piped text/auto input is line-delimited and capped at 16 MiB per line; use
`--ws-message-mode binary` for larger raw streams.

Incoming WebSocket server frames and assembled messages are capped at 16 MiB.

See [WebSocket documentation](websocket.md) for details.

## gRPC Options

### `--grpc`

Enable gRPC mode. Automatically sets HTTP/2, POST method, and gRPC headers, including `grpc-accept-encoding: gzip`. When no local proto schema is provided, `fetch` automatically tries gRPC reflection before falling back to generic protobuf handling. Gzip-compressed gRPC response messages are decompressed before protobuf formatting.

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

Cannot be combined with other request-specifying flags (URL, `--method`, `--header`, `--data`, auth flags, etc.). Meta flags like `--dry-run`, `--color`, `--format`, `--pager`, and `--timing` can still be used.

```sh
# Basic GET
fetch --from-curl 'curl https://example.com'

# POST with JSON
fetch --from-curl "curl -X POST -H 'Content-Type: application/json' -d '{\"key\":\"value\"}' https://example.com"

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
| TLS                        | `-k`, `--cacert`, `-E`/`--cert`, `--key`, `--tlsv1.2`, `--tlsv1.3`, `--tls-max`                                                    |
| Output                     | `-o`, `-O`, `-J`                                                                                                                   |
| Network                    | `-L`, `--max-redirs`, `-m`/`--max-time`, `--connect-timeout`, `-x`, `--unix-socket`, `--doh-url`, `--retry`, `--retry-delay`, `-r` |
| HTTP version               | `-0`, `--http1.1`, `--http2`, `--http3`                                                                                            |
| Headers                    | `-A`, `-e`, `-b`                                                                                                                   |
| Verbosity                  | `-v`, `-s`                                                                                                                         |
| Protocol                   | `--proto` (restricts allowed protocols; errors if URL scheme is not allowed)                                                       |
| Default-compatible no-ops  | `--compressed`, `-S`/`--show-error`, `--fail-with-body`, `--no-keepalive`                                                          |
| Presentation compatibility | `-#`/`--progress-bar`, `--no-progress-meter`                                                                                       |

**Notes:**

- `-b`/`--cookie` only supports inline cookie strings (e.g., `-b 'name=value'`). Cookie jar files are not supported and will return an error.
- A single `-d @filename` or `-d @-` body streams through fetch's native request body path. Composite data bodies and `--data-urlencode @filename` are materialized for curl compatibility and are capped at 16 MiB.
- `--data-urlencode` supports `@filename` and `name@filename` forms for reading and URL-encoding file contents.
- `-n`/`--netrc` is not supported. Use `--basic`, `--bearer`, or an explicit `Authorization` header instead.
- Semantic curl flags that `fetch` cannot faithfully translate, such as `-f`/`--fail`, `-N`/`--no-buffer`, `--proto-default`, and `--proto-redir`, return an error instead of being ignored.

Unknown curl flags return an error.

## Utility Options

### `-h, --help`

Print help information. Use `-v --help` or `--verbose --help` for the detailed,
colorized CLI reference. Detailed help follows `--pager`; use `--pager off` to
print directly and `--color off` to disable color.

### `-V, --version`

Print version.

### `--buildinfo`

Print build information. Use `-v --buildinfo` to include dependency details.

### `--update`

Update fetch binary in place. Use with `--dry-run` to check for updates without installing.
See [Updates](updates.md) for release source, verification, permissions,
background auto-update behavior, and cache/lock files.

### Agent skill options

The fetch Agent Skill is embedded in the binary and can be installed offline.
Choose an agent-specific location or the interoperable `agents` location:

| Target | User scope | Project scope |
| --- | --- | --- |
| `agents` (default) | `~/.agents/skills/fetch` | `.agents/skills/fetch` |
| `codex` | `~/.codex/skills/fetch` | `.codex/skills/fetch` |
| `claude` | `~/.claude/skills/fetch` | `.claude/skills/fetch` |
| `gemini` | `~/.gemini/skills/fetch` | `.gemini/skills/fetch` |
| `pi` | `~/.pi/agent/skills/fetch` | `.pi/skills/fetch` |

```sh
fetch --skill                                # print SKILL.md
fetch --install-skill [agents|codex|claude|gemini|pi|all]
fetch --uninstall-skill [agents|codex|claude|gemini|pi|all]
```

User scope is the default; use `--scope project` for the project locations
shown above. Install and uninstall commands show every destination before
changing it and ask for confirmation when attached to a terminal. `--dry-run`
previews changes and `--force` permits replacing or removing a locally modified
installation. No agent configuration files are changed and installation
performs no network requests.

Each installed copy contains `.fetch-skill.json`, recording the skill version,
fetch version, and hashes used to detect local modifications. `all` means the
five locations listed above; it does not probe and write to additional
directories.

### `--complete SHELL`

Output shell completion scripts. Values: `bash`, `fish`, `zsh`.

```sh
echo 'eval "$(fetch --complete bash)"' >> ~/.bashrc
fetch --complete zsh > ~/.zshrc.d/_fetch
fetch --complete fish > ~/.config/fish/completions/fetch.fish
```

### `--dry-run`

Print request information without sending, including the normalized absolute
URL. When used with `--update`, checks for the latest version without
installing.

```sh
fetch --dry-run -j '{"test": true}' example.com
fetch --update --dry-run
```

## Environment Variables

| Variable                | Description                                               |
| ----------------------- | --------------------------------------------------------- |
| `AWS_ACCESS_KEY_ID`     | AWS access key for `--aws-sigv4`                          |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key for `--aws-sigv4`                          |
| `AWS_SESSION_TOKEN`     | AWS session token for temporary `--aws-sigv4` credentials |
| `PAGER`                 | Pager command for response bodies when paging is enabled  |
| `LESS`                  | Options for `less`; disables fetch's default `less` flags |
| `NO_PAGER`              | Disable the default `auto` pager when set                 |
| `VISUAL` / `EDITOR`     | Editor for `--edit` option                                |
| `HTTP_PROXY`            | HTTP proxy URL                                            |
| `HTTPS_PROXY`           | HTTPS proxy URL                                           |
| `ALL_PROXY`             | Fallback proxy URL for any request scheme                 |
| `NO_PROXY`              | Hosts, domains, IPs, or CIDR ranges to bypass proxy       |

Proxy variables also support lowercase forms: `http_proxy`, `https_proxy`,
`all_proxy`, and `no_proxy`. Uppercase names are checked before lowercase names
for each variable, except uppercase `HTTP_PROXY` is ignored when
`REQUEST_METHOD` is set.

Proxy precedence is: an explicit `--proxy` or configured `proxy = ...` value,
then scheme-specific environment variables (`HTTP_PROXY` for HTTP requests and
`HTTPS_PROXY` for HTTPS requests), then `ALL_PROXY`, then the system proxy
configuration. `NO_PROXY`/`no_proxy` applies to environment proxies and may use
hosts, domains, IP addresses, CIDR ranges, ports, or `*`.

## File References

Many options support file references with the `@` prefix:

- `@filename` - Read content from file
- `@-` - Read content from stdin
- `@~/path` - Home directory expansion

```sh
fetch -j @data.json example.com
echo '{"test": true}' | fetch -j @- example.com
```
