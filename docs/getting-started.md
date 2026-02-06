# Getting Started

This guide will help you install `fetch` and make your first HTTP request.

## Installation

### Installation Script (Recommended)

For macOS or Linux, use the installation script:

```sh
curl -fsSL https://raw.githubusercontent.com/ryanfowler/fetch/main/install.sh | bash
```

### Homebrew

For macOS or Linux, install with [Homebrew](https://brew.sh):

```sh
brew install ryanfowler/tap/fetch
```

### Building from Source

If you have Go installed:

```sh
go install github.com/ryanfowler/fetch@latest
```

### Pre-built Binaries

Download binaries for your operating system from the [GitHub releases page](https://github.com/ryanfowler/fetch/releases).

### Verify Installation

```sh
fetch --version
```

## Making Your First Request

Make a GET request by providing a URL:

```sh
fetch httpbin.org/json
```

The response body is automatically formatted and syntax-highlighted:

```
HTTP/2.0 200 OK

{
  "slideshow": {
    "author": "Yours Truly",
    "title": "Sample Slide Show"
  }
}
```

When no scheme is provided, `fetch` defaults to HTTPS:

```sh
fetch example.com        # Uses https://example.com
fetch 192.168.1.1:8080   # Uses https://192.168.1.1:8080
```

Loopback addresses default to HTTP for local development:

```sh
fetch localhost:3000     # Uses http://localhost:3000
fetch 127.0.0.1:8080     # Uses http://127.0.0.1:8080
```

You can always specify the scheme explicitly:

```sh
fetch http://example.com   # Force HTTP
fetch https://localhost    # Force HTTPS for localhost
```

## Understanding the Output

`fetch` separates its output into two streams:

1. **Status line** (stderr) - The HTTP version, status code, and status text
2. **Response body** (stdout) - The response content, automatically formatted

This separation means you can pipe the body to other tools or redirect it to a file without the status line getting in the way:

```sh
# Save just the response body to a file
fetch httpbin.org/json > response.json

# Pipe to jq for further processing
fetch httpbin.org/json | jq '.slideshow.title'
```

### Auto-formatting

`fetch` automatically detects the content type and formats the response with syntax highlighting. Supported formats include:

- **JSON** - Pretty-printed with syntax highlighting
- **XML / HTML** - Indented and highlighted
- **CSS** - Formatted and highlighted
- **CSV** - Column-aligned table output
- **Images** - Rendered directly in supported terminals
- **Protobuf / msgpack** - Decoded and displayed as JSON
- **SSE / NDJSON** - Streamed line-by-line

See [Output Formatting](output-formatting.md) for details.

## Inspecting Requests and Responses

`fetch` provides three levels of verbosity to help you debug HTTP requests, plus a dry-run mode to preview requests without sending them.

### `-v` - Response Headers

Show the full response headers alongside the body:

```sh
fetch -v httpbin.org/json
```

```
HTTP/2.0 200 OK
access-control-allow-credentials: true
access-control-allow-origin: *
content-length: 429
content-type: application/json
date: Thu, 05 Feb 2026 00:33:27 GMT
server: gunicorn/19.9.0

{
  "slideshow": {
    "author": "Yours Truly",
    ...
  }
}
```

### `-vv` - Request and Response Headers

Show the outgoing request headers followed by the response:

```sh
fetch -vv httpbin.org/json
```

```
> GET /json HTTP/1.1
> accept: application/json,application/vnd.msgpack,application/xml,image/webp,*/*
> accept-encoding: gzip, zstd
> host: httpbin.org
> user-agent: fetch/v0.17.3
>
< HTTP/2.0 200 OK
< access-control-allow-credentials: true
< access-control-allow-origin: *
< content-length: 429
< content-type: application/json
< date: Thu, 05 Feb 2026 00:33:27 GMT
< server: gunicorn/19.9.0
<

{
  "slideshow": {
    "author": "Yours Truly",
    ...
  }
}
```

The `> ` and `< ` prefixes indicate outgoing request and incoming response lines.

### `-vvv` - DNS, TLS, and Timing Details

Show the full connection lifecycle including DNS resolution, TCP connect, TLS handshake, and time-to-first-byte:

```sh
fetch -vvv httpbin.org/json
```

```
> GET /json HTTP/1.1
> accept: application/json,application/vnd.msgpack,application/xml,image/webp,*/*
> accept-encoding: gzip, zstd
> host: httpbin.org
> user-agent: fetch/v0.17.3
>
* DNS: httpbin.org (2.7ms)
*   3.210.41.225
*   3.223.36.72
* TCP: 3.210.41.225:443 (81.9ms)
* TLS 1.2: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (176.6ms)
*   ALPN: h2
*   Resumed: no
* Certificate:
*   Subject: CN=httpbin.org
*   Issuer: CN=Amazon RSA 2048 M03,O=Amazon,C=US
*   Valid: 2025-07-20 to 2026-08-17
* TTFB: 87.9ms
*
< HTTP/2.0 200 OK
< ...
```

The `> `, `< `, and `* ` prefixes make the direction of data instantly clear: outgoing request lines, incoming response lines, and informational/connection details.

This is useful for diagnosing latency issues, verifying TLS configuration, and understanding connection behavior.

### `--dry-run` - Preview Without Sending

Preview the exact request that would be sent without actually making the HTTP call:

```sh
fetch --dry-run -vv -j '{"hello":"world"}' -m POST httpbin.org/post
```

```
> POST /post HTTP/1.1
> accept: application/json,application/vnd.msgpack,application/xml,image/webp,*/*
> accept-encoding: gzip, zstd
> content-length: 17
> content-type: application/json
> host: httpbin.org
> user-agent: fetch/v0.17.3
>
{"hello":"world"}
```

Combine `--dry-run` with `-vv` to see the full request including headers and body before sending it.

## Common Tasks

### Changing the HTTP Method

```sh
fetch -m POST httpbin.org/post
fetch -X DELETE httpbin.org/delete
```

### Sending JSON Data

The `-j` flag sets the request body and automatically adds `Content-Type: application/json`:

```sh
fetch -j '{"name": "test", "value": 42}' -m POST httpbin.org/post
```

### Adding Headers and Query Parameters

Add custom headers with `-H` and query parameters with `-q`:

```sh
fetch -H "X-Custom: value" httpbin.org/get
fetch -q name=test -q page=1 httpbin.org/get
```

Query parameters are URL-encoded and appended to the URL automatically.

### Sending Form Data

```sh
fetch -f name=test -f value=42 -m POST httpbin.org/post
```

See [Request Bodies](request-bodies.md) for multipart forms and file uploads.

### Authentication

`fetch` has built-in support for common authentication methods:

```sh
fetch --bearer TOKEN httpbin.org/bearer
fetch --basic user:pass httpbin.org/basic-auth/user/pass
```

See [Authentication](authentication.md) for AWS Signature V4 and other options.

### Saving Responses

Save the response body to a file:

```sh
fetch -o response.json httpbin.org/json
```

Use `-O` to save using the filename from the URL:

```sh
fetch -O httpbin.org/image/png
```

### Viewing Images

`fetch` can render images directly in terminals that support inline images (Kitty, iTerm2), with a block-character fallback for other terminals.

```sh
fetch httpbin.org/image/png
```

See [Image Rendering](image-rendering.md) for details.

## Sessions

Sessions let you persist cookies across multiple requests. This is useful for interacting with APIs that use cookie-based authentication:

```sh
# Log in - cookies are saved to the "myapi" session
fetch -S myapi -j '{"user":"me","pass":"secret"}' -m POST httpbin.org/cookies/set/token/abc123

# Subsequent requests automatically include the saved cookies
fetch -S myapi httpbin.org/cookies
```

## Updating

Update `fetch` to the latest version:

```sh
fetch --update
```

Or enable automatic updates in your [configuration file](configuration.md):

```ini
auto-update = true
```

## Shell Completions

Generate shell completion scripts:

```sh
# Bash
echo 'eval "$(fetch --complete bash)"' >> ~/.bashrc

# Zsh
fetch --complete zsh > ~/.zshrc.d/fetch-completion.zsh

# Fish
fetch --complete fish > ~/.config/fish/completions/fetch.fish
```

## Next Steps

- **[CLI Reference](cli-reference.md)** - Complete list of all command-line options
- **[Configuration](configuration.md)** - Set up a configuration file for persistent settings
- **[Authentication](authentication.md)** - Learn about authentication options
- **[Request Bodies](request-bodies.md)** - Send JSON, XML, forms, and files
- **[Output Formatting](output-formatting.md)** - Formatting and syntax highlighting details
- **[Image Rendering](image-rendering.md)** - Rendering images in the terminal
