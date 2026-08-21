# fetch

This file provides guidance to AI agents when working with code in this repository. Keep this file updated after making changes.

## Project Overview

`fetch` is a modern HTTP(S) client CLI written in Go. It features automatic response formatting (JSON, XML, YAML, HTML, CSS, CSV, Markdown, protobuf, msgpack), readable article extraction, image rendering in terminals, gRPC support with reflection/discovery and JSON-to-protobuf conversion, and authentication (Basic, Digest, Bearer, AWS SigV4).

The repository currently targets Go 1.26.7 in `go.mod` and GitHub Actions.

## Common Commands

```bash
# Run all tests
go test -v ./...

# Run specific package tests
go test -v ./internal/format
go test -v ./integration

# Run a single test
go test -v ./internal/cli -run TestParseFlagAWS

# Build the binary
go build -o bin/fetch .

# Format code (CI will fail if not formatted)
gofmt -s -w .

# Verify modules
go mod tidy && go mod verify

# Run linter (CI uses staticcheck)
staticcheck ./...

# Format other files
prettier -w .
```

## Architecture

### Entry Point

`main.go` orchestrates the CLI: parses arguments via `internal/cli`, loads config via `internal/config`, and delegates to `internal/fetch.Fetch()`.

### Key Packages

- **internal/article** - Bounded readability extraction, YAML frontmatter, and HTML-to-Markdown rendering.
- **internal/aws** - AWS Signature V4 request signing.
- **internal/body** - Lazy request-body sources and single-read response tee pipelines, including replay, bounded preview/materialization, and exact file checks.
- **internal/cli** - Command-line argument parsing. `App` struct holds all parsed options.
- **internal/client** - HTTP client wrapper and HTTP version-specific transport setup.
- **internal/complete** - Shell completion implementation.
- **internal/config** - INI-format config file parsing with host-specific overrides.
- **internal/core** - Shared types (`Printer`, `Color`, `Format`, `HTTPVersion`), timeout budgets, checked arithmetic, bounded readers/buffers, resource limits, and error categories.
- **internal/curl** - Curl command parser for `--from-curl` flag. Tokenizes and parses curl command strings into an intermediate `Result` struct.
- **internal/digest** - HTTP Digest Authentication challenge parsing and response computation (RFC 7616).
- **internal/fetch** - Core HTTP request execution. `fetch.go:Fetch()` is the main entry point that builds requests, handles gRPC framing/reflection/discovery, and routes to formatters.
- **internal/fileutil** - Shared file helpers, including cross-platform atomic replacement for temp-file write flows.
- **internal/format** - Response body formatters (JSON, XML, YAML, HTML, CSS, CSV, msgpack, protobuf, SSE, NDJSON). Each formatter writes colored output to a `Printer`.
- **internal/grpc** - gRPC framing, headers, and status code handling.
- **internal/image** - Terminal image rendering (Kitty, iTerm2 inline, block-character fallback).
- **internal/image** - Multipart form implementation.
- **internal/har** - Bounded HAR 1.2 final-exchange recording with streaming body capture and atomic output.
- **internal/proto** - Protocol buffer compilation and message handling for gRPC support.
- **internal/pager** - Shell-free `$PAGER` parsing and bounded pager process lifecycle for help and response output.
- **internal/resolver** - Shared DNS resolution and dialing for system DNS, UDP DNS, and DNS-over-HTTPS across HTTP, HTTP/3, gRPC, and TLS inspection.
- **internal/session** - Named cookie sessions with persistent storage across invocations.
- **internal/update** - Check for updates, download from Github, and self-update.
- **internal/ws** - WebSocket message loop (read, write, bidirectional coordination).

### Request Flow

1. CLI args parsed (`cli.Parse`) → `App` struct
2. Config file merged (`config.GetFile`)
3. `fetch.Request` built from merged config
4. If gRPC: load local proto schema or resolve it via reflection, setup descriptors, convert JSON→protobuf, frame message

## Recent Notes

- `--grpc-list` and `--grpc-describe` provide grpcurl-style discovery using reflection or local descriptor files.
- `--grpc` now automatically tries gRPC reflection when no local schema is supplied.
- Plaintext loopback gRPC servers are supported via `h2c` for both calls and discovery.
- `--inspect-dns` resolves the URL hostname without making an HTTP request, showing common DNS record types, resolver backend, duration, and per-record TTLs from direct UDP or DoH responses.
- `--inspect-tls --http 3` performs QUIC/TLS inspection with `h3` ALPN instead of the TCP TLS path.
- `--tls` remains a compatibility alias for setting the minimum TLS version; prefer `--min-tls` in new docs/examples, and use `--max-tls` to cap negotiation or combine min/max for an exact TLS version.
- WebSocket terminal sessions use the interactive prompt by default and can be controlled with `--ws-interactive auto|on|off`; output-file/clipboard/retry flags are rejected because the WebSocket path streams through the message loop instead of the normal response pipeline.
- Metadata-only commands (`--help`, `--version`, `--buildinfo`) perform best-effort config parsing for presentation settings, but config errors and background auto-updates cannot block them.
- Schemeless hostnames default to HTTPS, while `localhost` and all IP literals default to HTTP. Body-producing flags infer POST unless the method is explicit, dry-run shows the normalized absolute URL, and failed schemeless HTTPS connection setup suggests the equivalent HTTP URL when safe.
- Article mode decodes and extracts at most 16 MiB of content, uses the final URL for link resolution, and never executes JavaScript.
- Shared timeout budgets and resource-bound helpers live in `internal/core`; finite child operations must reuse the parent budget's absolute deadline, while zero or absent timeouts remain unlimited.
- Request replayability is explicit: one-shot sources such as stdin are rejected before retry or Digest replay, regular files are reopened with identity/length checks, and dry-run previews do not consume request bytes. Digest supports all RFC 7616 MD5/SHA-256/SHA-512-256 algorithms and their -sess variants, no qop, and qop=auth; malformed or unsupported challenges are errors, and stale nonces are retried once.
- AWS SigV4 reads `AWS_SESSION_TOKEN`, signs `x-amz-security-token`, preserves duplicate query parameters and literal plus signs during canonicalization, and converts URL userinfo to redacted Basic authorization before signing.
- Response files and HAR sidecars use exclusive temporary files, atomic commits, best-effort durability sync, and cross-platform sanitization for server-provided filenames; symlink destinations are rejected.
- HAR recording captures one final exchange, preserves duplicate headers, captures decoded response bodies up to 16 MiB, and never changes the normal streaming pipeline. HAR files can contain credentials and sensitive bodies.
- Brotli response decoding uses the decoder-only `github.com/google/brotli/go/brotli` module; tests use fixed Brotli fixtures.
- SSE and NDJSON use bounded, chunk-safe streaming parsers; automatic compression retries compressed SSE once for safe GET/HEAD requests.
- `-v --help` renders the embedded Markdown CLI reference and uses the configured pager. Pager commands are parsed without a shell, and `NO_PAGER` disables automatic paging.
- Build information includes target OS/architecture and Go settings; dependency versions appear with `--buildinfo -v`. Ctrl-C exits with status 130, and broken-pipe output exits cleanly.
5. HTTP client executes request
6. Response formatted based on Content-Type and output to stdout (optionally via pager)

Retryable requests replay bodies by calling `req.GetBody` when available, reopening file-backed bodies directly when possible, and only spooling the original body to a temp file as a final fallback for one-shot streams. This avoids holding large uploads in memory and keeps retries working for closable bodies like `*os.File`.
Multipart `-F` request bodies are produced by a replayable factory with a stable boundary; request construction sets `req.GetBody` so 307/308 redirects can resend them without relying on retry/digest spooling.
Redirect handling preserves non-POST methods and replayable bodies for 301/302, applies strict origin credential boundaries, preserves same-origin custom Host values, and resolves each redirected destination through the configured DNS backend.

### Content Type Detection

`internal/fetch/fetch.go:getContentType()` maps MIME types to formatters. Supported types include JSON, XML, YAML, HTML, CSS, CSV, msgpack, protobuf, gRPC, SSE, NDJSON, and images.

## Testing

- Unit tests: `*_test.go` files alongside source in each package
- Integration tests: `integration/integration_test.go` (comprehensive end-to-end tests)
- CI runs tests on Ubuntu, macOS, and Windows

## Docs

High level documentation exists in the README. All detailed documentation exists in the `docs/` directory, and should be kept up-to-date with any code changes.

The `--edit` workflow accepts `VISUAL`/`EDITOR` values with flags and also preserves executable paths that contain spaces, even when those paths are not shell-quoted. Request-body files are validated before opening, streamed from replayable regular-file sources, and checked for replacement, resizing, and premature EOF; multipart header parameters are sanitized and replay with a stable boundary.
