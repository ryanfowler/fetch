# fetch

This file provides guidance to AI agents when working with code in this repository. Keep this file updated after making changes.

## Project Overview

`fetch` is a modern HTTP(S) client CLI written in Go. It features automatic response formatting (JSON, XML, YAML, HTML, CSS, CSV, Markdown, protobuf, msgpack), readable article extraction, image rendering in terminals, gRPC support with reflection/discovery and JSON-to-protobuf conversion, and authentication (Basic, Digest, Bearer, AWS SigV4).

The repository currently targets Go 1.27.0 in `go.mod` and GitHub Actions.

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
- **internal/grpc** - gRPC framing, headers, and status code handling. Schema-less binary calls
  remain usable when reflection is unavailable; JSON conversion requires a
  descriptor, streaming conversion preserves decoder look-ahead, dry-run
  conversion is bounded to 16 MiB, and unary HAR bodies are base64 encoded.
- **internal/image** - Terminal image rendering (Kitty, iTerm2 inline, block-character fallback).
- **internal/image** - Multipart form implementation.
- **internal/har** - Bounded HAR 1.2 final-exchange recording with streaming body capture and atomic output.
- **internal/proto** - Protocol buffer compilation and message handling for gRPC support.
- **internal/pager** - Shell-free `$PAGER` parsing and bounded pager process lifecycle for help and response output.
- **internal/resolver** - Shared DNS resolution and dialing for system DNS, UDP, pipelined TCP, DNS-over-TLS, DNS-over-QUIC, and DNS-over-HTTPS across HTTP, HTTP/3, gRPC, and TLS inspection.
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
- `--grpc` now automatically tries gRPC reflection when no local schema is supplied. Schema-less binary calls remain sendable when reflection fails, while JSON conversion requires a descriptor; streaming JSON conversion preserves decoder look-ahead, dry-run conversion is bounded to 16 MiB, and unary gRPC HAR bodies are base64 encoded with trailers preserved.
- Plaintext loopback gRPC servers are supported via `h2c` for both calls and discovery.
- `--inspect-dns` resolves the URL hostname without making an HTTP request. The platform resolver shows A/AAAA records without TTLs; an explicit UDP, pipelined TCP/DoT, DoQ, or DoH resolver queries all supported inspection types concurrently, shows resolver security, duration, and per-record TTLs, and preserves successful records with exit status 1 when a query fails. TCP, DoT, and DoQ inspection queries share one bounded operation-scoped connection.
- `--inspect-tls --http 3` performs QUIC/TLS inspection with `h3` ALPN instead of the TCP TLS path.
- Curl import translates supported flags without silently dropping semantics: a single `-d @file` or `-d @-` streams through the replayable body path, composite data and `--data-urlencode` materialization is capped at 16 MiB, and unsupported security/transport flags return clear errors.
- TLS configuration is centralized for HTTP, gRPC, WebSocket, encrypted DNS, and inspection: only TLS 1.2/1.3 are accepted, custom CA files extend system roots, and merged client certificates/keys are validated after config scopes combine. `--tls` remains a compatibility alias for setting the minimum TLS version; prefer `--min-tls` in new docs/examples, and use `--max-tls` to cap negotiation or combine min/max for an exact TLS version.
- ECH validates HTTPS/SVCB ECHConfigLists, preserves DNS priority, applies `off|auto|on` policy before transport setup, performs real ECH and randomized GREASE with Go `crypto/tls`, retries valid server configs once within the connect budget, rejects explicit TLS 1.2 bounds and hard ECH with HTTP/3, and does not silently ignore ECH through proxies or cleartext HTTP/2.
- WebSocket terminal sessions use the interactive prompt by default and can be controlled with `--ws-interactive auto|on|off`; output-file/clipboard/retry flags are rejected because the WebSocket path streams through the message loop instead of the normal response pipeline. WebSocket reads enforce a 16 MiB message cap, interactive queues and history use byte bounds, piped EOF performs a bounded normal close handshake, and cancellation closes the connection and input source.
- Metadata-only commands (`--help`, `--version`, `--buildinfo`) perform best-effort config parsing for presentation settings, but config errors and background auto-updates cannot block them.
- Schemeless hostnames default to HTTPS, while `localhost` and all IP literals default to HTTP. Body-producing flags infer POST unless the method is explicit, dry-run shows the normalized absolute URL, and failed schemeless HTTPS connection setup suggests the equivalent HTTP URL when safe.
- Article mode decodes and extracts at most 16 MiB of content, uses the final URL for link resolution, and never executes JavaScript.
- Shared timeout budgets and resource-bound helpers live in `internal/core`; finite child operations must reuse the parent budget's absolute deadline, while zero or absent timeouts remain unlimited.
- Request replayability is explicit: one-shot sources such as stdin are rejected before retry or Digest replay, regular files are reopened with identity/length checks, and dry-run previews do not consume request bytes. Digest supports all RFC 7616 MD5/SHA-256/SHA-512-256 algorithms and their -sess variants, no qop, and qop=auth; malformed or unsupported challenges are errors, and stale nonces are retried once.
- AWS SigV4 reads `AWS_SESSION_TOKEN`, signs `x-amz-security-token`, preserves duplicate query parameters and literal plus signs during canonicalization, and converts URL userinfo to redacted Basic authorization before signing.
- Named sessions use 0700 directories and 0600 files, lock saves with bounded crash recovery, merge changes from the latest on-disk state, and persist cookies from WebSocket handshakes without modifying sessions during dry-run.
- Response files and HAR sidecars use exclusive temporary files, atomic commits, best-effort durability sync, and cross-platform sanitization for server-provided filenames; symlink destinations are rejected.
- HAR recording captures one final exchange, preserves duplicate headers, captures decoded response bodies up to 16 MiB, and never changes the normal streaming pipeline. HAR files can contain credentials and sensitive bodies.
- Brotli response decoding uses the decoder-only `github.com/google/brotli/go/brotli` module; tests use fixed Brotli fixtures.
- DNS-over-HTTPS sends bounded RFC 8484 wire queries first, falls back to bounded JSON only for clear protocol incompatibility, adjusts TTLs for `Age`, and never falls back after transport, TLS, timeout, or malformed-wire failures. DNS answers authorize owners through bounded CNAME chains, and DoH JSON records use the same owner validation. HTTPS/SVCB records use strict parameter/value validation, reject reserved or compressed wire forms, preserve unknown optional parameters, and reject malformed RRsets atomically. Service discovery follows bounded AliasMode chains, resolves service targets, supplements address hints with target A/AAAA results, and exposes authenticated failure classes so verified DNS errors cannot be silently downgraded.
- A and AAAA lookups run concurrently across custom DNS transports, keep the first usable family preference with a bounded sibling grace period, deduplicate stable address order, and interleave later dial candidates without changing the preferred family. All resolver-backed network modes use the same resolver-aware Happy Eyeballs dialer; update downloads carry only operational resolver, proxy, CA, and connect-timeout policy. Self-update metadata, checksums, and archives are bounded, archives require mandatory SHA-256 sidecars, and verification occurs before extraction. Unix tar.gz and Windows zip extraction accepts only a root fetch executable, rejects links, sparse, and traversal entries, validates the staged binary, and replaces it atomically with bounded lock and cleanup behavior.
- Resolver-aware dialing is centralized in `internal/client/dialer.go`: it shares one DNS/TCP/TLS budget, returns the winning address and timings, supports custom attempt strategies for proxies and Unix sockets, and closes completed losing candidates without a background drain goroutine.
- Automatic HTTP/3 candidates use a bounded persistent cache under the user cache directory. Cache keys include the normalized HTTPS origin and resolver provenance; shards are hashed, locked, atomic, symlink-safe, capped at four candidates per origin and 1,024 shards, and never block a request when cache I/O fails. HTTP/3 uploads and response bodies use explicit lifecycle wrappers: body errors reset streams and remain observable, request budgets cancel unread responses, and failed automatic candidates are suppressed without making Alt-Svc maintenance delay response delivery.
- Proxy selection uses explicit configuration, scheme-specific environment variables, `ALL_PROXY`, then direct connection. Uppercase variables win, CGI `HTTP_PROXY` is ignored, and `NO_PROXY` supports wildcard, host/domain, IP, CIDR, IDNA, and port matching without treating malformed entries as a global bypass. HTTP, HTTPS, SOCKS5, and SOCKS5H share the HTTP transport layer; proxy TLS is verified separately from origin TLS, and SOCKS5 resolves destinations locally while SOCKS5H sends hostnames to the proxy.
- System HTTPS/SVCB discovery uses `resolvectl` on Linux when available, then a bounded `/etc/resolv.conf` fallback that skips malformed nameservers and honors `rotate`, `attempts`, and `timeout`.
- SSE and NDJSON use bounded, chunk-safe streaming parsers; automatic compression retries compressed SSE once for safe GET/HEAD requests.
- `-v --help` renders the embedded Markdown CLI reference and uses the configured pager. Pager commands are parsed without a shell, and `NO_PAGER` disables automatic paging.
- Build information includes target OS/architecture and Go settings; dependency versions appear with `--buildinfo -v`. Ctrl-C exits with status 130, and broken-pipe output exits cleanly.
- Release archives are Go-built for Linux, macOS, and Windows targets with `CGO_ENABLED=0`; Unix archives have lowercase SHA-256 sidecars. `install.sh` verifies the sidecar before bounded extraction, stages inside the destination, validates `--version`, and atomically renames the staged executable without following symlink targets.
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
