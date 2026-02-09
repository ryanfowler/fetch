# CLI Reference

Complete reference for all `fetch` command-line options.

## Usage

```
fetch [OPTIONS] [URL]
```

## URL Handling

When no scheme is provided, `fetch` defaults to HTTPS. Loopback addresses (`localhost`, `127.0.0.1`) default to HTTP.

```sh
fetch example.com          # https://example.com
fetch localhost:3000       # http://localhost:3000
fetch http://example.com   # Force HTTP
```

## HTTP Method

### `-m, --method METHOD`

Specify the HTTP method. Default: `GET`.

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

### `--bearer TOKEN`

HTTP Bearer Token Authentication.

```sh
fetch --bearer mysecrettoken example.com
```

### `--aws-sigv4 REGION/SERVICE`

Sign requests with AWS Signature V4. Requires `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables.

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

Use filename from `Content-Disposition` header. Requires `-O`.

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

Control image rendering. Values: `auto`, `native`, `off`.

- `auto` - Try optimal protocol, fallback to external tools
- `native` - Use only built-in decoders (JPEG, PNG, TIFF, WebP)
- `off` - Disable image rendering

```sh
fetch --image native example.com/image.png
fetch --image off example.com/photo.jpg
```

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

Maximum automatic redirects. Use `0` to disable.

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

The actual delay uses exponential backoff (delay doubles each attempt, capped at 30s) with ±25% jitter. If the server sends a `Retry-After` header, that value is used when it exceeds the computed delay.

```sh
fetch --retry 3 --retry-delay 2 example.com
fetch --retry 3 --retry-delay 0.5 example.com
```

### `--dns-server IP[:PORT]|URL`

Use custom DNS server. Supports UDP DNS and DNS-over-HTTPS.

```sh
fetch --dns-server 8.8.8.8 example.com
fetch --dns-server 1.1.1.1:53 example.com
fetch --dns-server https://1.1.1.1/dns-query example.com
```

### `--proxy PROXY`

Route request through a proxy.

```sh
fetch --proxy http://localhost:8080 example.com
fetch --proxy socks5://localhost:1080 example.com
```

### `--unix PATH`

Make request over a Unix domain socket. Unix-like systems only.

```sh
fetch --unix /var/run/docker.sock http://unix/containers/json
```

## TLS Options

### `--tls VERSION`

Minimum TLS version. Values: `1.0`, `1.1`, `1.2`, `1.3`.

```sh
fetch --tls 1.3 example.com
```

### `--inspect-tls`

Inspect the TLS certificate chain by performing a TLS handshake only (no HTTP request is made). Displays the TLS version, cipher suite, ALPN protocol, full certificate chain with expiry status, Subject Alternative Names (SANs), and OCSP staple status. Requires an HTTPS URL. HTTP-only flags (e.g. `--data`, `--timing`, `--grpc`) are ignored with a warning.

```sh
fetch --inspect-tls example.com
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

Force specific HTTP version. Values: `1`, `2`, `3`.

- `1` - HTTP/1.1
- `2` - HTTP/2 (default preference)
- `3` - HTTP/3 (QUIC)

```sh
fetch --http 1 example.com
fetch --http 3 example.com
```

## Compression

### `--no-encode`

Disable automatic gzip/zstd compression.

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

See [WebSocket documentation](websocket.md) for details.

## gRPC Options

### `--grpc`

Enable gRPC mode. Automatically sets HTTP/2, POST method, and gRPC headers.

```sh
fetch --grpc https://localhost:50051/package.Service/Method
```

### `--proto-file PATH`

Compile `.proto` file(s) for JSON-to-protobuf conversion. Requires `protoc`. Can specify multiple comma-separated paths.

```sh
fetch --grpc --proto-file service.proto -j '{"field": "value"}' localhost:50051/pkg.Svc/Method
```

### `--proto-desc PATH`

Use pre-compiled descriptor set file instead of `--proto-file`.

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

| Category | Curl Flags |
|---|---|
| Request | `-X`, `-H`, `-d`, `--data-raw`, `--data-binary`, `--data-urlencode`, `--json`, `-F`, `-T`, `-I`, `-G` |
| Auth | `-u`, `--aws-sigv4`, `--oauth2-bearer` |
| TLS | `-k`, `--cacert`, `-E`/`--cert`, `--key`, `--tlsv1.x` |
| Output | `-o`, `-O`, `-J` |
| Network | `-L`, `--max-redirs`, `-m`/`--max-time`, `--connect-timeout`, `-x`, `--unix-socket`, `--doh-url`, `--retry`, `--retry-delay`, `-r` |
| HTTP version | `-0`, `--http1.1`, `--http2`, `--http3` |
| Headers | `-A`, `-e`, `-b` |
| Verbosity | `-v`, `-s` |
| Protocol | `--proto` (restricts allowed protocols; errors if URL scheme is not allowed) |
| No-ops | `--compressed`, `-S`, `-N`, `--no-keepalive`, `-#`, `--no-progress-meter`, `-n`, `-f`, `--fail-with-body`, `--proto-default`, `--proto-redir` |

**Notes:**
- `-b`/`--cookie` only supports inline cookie strings (e.g., `-b 'name=value'`). Cookie jar files are not supported and will return an error.
- `--data-urlencode` supports `@filename` and `name@filename` forms for reading and URL-encoding file contents.

Unknown curl flags return an error.

## Utility Options

### `-h, --help`

Print help information.

### `-V, --version`

Print version.

### `--buildinfo`

Print detailed build information.

### `--update`

Update fetch binary in place. Use with `--dry-run` to check for updates without installing.

### `--complete SHELL`

Output shell completion scripts. Values: `bash`, `fish`, `zsh`.

```sh
echo 'eval "$(fetch --complete bash)"' >> ~/.bashrc
fetch --complete zsh > ~/.zshrc.d/_fetch
fetch --complete fish > ~/.config/fish/completions/fetch.fish
```

### `--dry-run`

Print request information without sending. When used with `--update`, checks for the latest version without installing.

```sh
fetch --dry-run -m POST -j '{"test": true}' example.com
fetch --update --dry-run
```

## Environment Variables

| Variable                | Description                      |
| ----------------------- | -------------------------------- |
| `AWS_ACCESS_KEY_ID`     | AWS access key for `--aws-sigv4` |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key for `--aws-sigv4` |
| `VISUAL` / `EDITOR`     | Editor for `--edit` option       |
| `HTTPS_PROXY`           | HTTPS proxy URL                  |
| `HTTP_PROXY`            | HTTP proxy URL                   |
| `NO_PROXY`              | Hosts to bypass proxy            |

## File References

Many options support file references with the `@` prefix:

- `@filename` - Read content from file
- `@-` - Read content from stdin
- `@~/path` - Home directory expansion

```sh
fetch -j @data.json -m POST example.com
echo '{"test": true}' | fetch -j @- -m POST example.com
```
