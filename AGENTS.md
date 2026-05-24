# fetch

This file provides guidance to AI agents when working with code in this repository. Keep this file updated after making changes.

## Project Overview

`fetch` is a modern HTTP(S) client CLI. The primary implementation is now the
Rust Cargo binary named `fetch`; the Go implementation remains in the repository
as the behavioral reference and to host the existing integration harness. It
features automatic response formatting (JSON, XML, YAML, HTML, CSS, CSV,
protobuf, msgpack), image rendering in terminals, gRPC support with
reflection/discovery and JSON-to-protobuf conversion, and authentication (Basic,
Digest, Bearer, AWS SigV4).

## Common Commands

After making any code or documentation changes, AI agents must run:

```bash
cargo fmt
cargo clippy --locked --all-targets --all-features -- -D warnings
```

```bash
# Run Rust unit tests
cargo test --all-features

# Run the Rust integration suite against the Rust binary
cargo test --all-features --test integration -- --test-threads=1

# Run a focused Rust test
cargo test --all-features image::tests

# Build the Rust binary
cargo build --release

# Format code (CI will fail if not formatted)
cargo fmt
gofmt -s -w .

# Lint
cargo clippy --locked --all-targets --all-features -- -D warnings
staticcheck ./...

# Verify Go harness/reference modules
go mod tidy && go mod verify

# Format other files
prettier -w .

# Run a focused Rust integration test
cargo test --all-features --test integration request_construction_and_data_sources
```

## Architecture

### Entry Point

`src/main.rs` is intentionally thin and delegates to `src/app.rs`, which parses
CLI arguments via `src/cli.rs`, loads config via `src/config`, dispatches
metadata/update/DNS/TLS inspection modes, and executes requests via `src/http`.

The legacy Go entry point in `main.go` still orchestrates the reference CLI and
is kept for parity comparisons while the Rust binary is primary.

### Key Packages

- **internal/aws** - AWS Signature V4 request signing.
- **internal/cli** - Command-line argument parsing. `App` struct holds all parsed options.
- **internal/client** - HTTP client wrapper and HTTP version-specific transport setup.
- **internal/complete** - Shell completion implementation.
- **internal/config** - INI-format config file parsing with host-specific overrides.
- **internal/core** - Shared types (`Printer`, `Color`, `Format`, `HTTPVersion`) and utilities.
- **internal/curl** - Curl command parser for `--from-curl` flag. Tokenizes and parses curl command strings into an intermediate `Result` struct.
- **internal/digest** - HTTP Digest Authentication challenge parsing and response computation (RFC 7616).
- **internal/fetch** - Core HTTP request execution. `fetch.go:Fetch()` is the main entry point that builds requests, handles gRPC framing/reflection/discovery, and routes to formatters.
- **internal/fileutil** - Shared file helpers, including cross-platform atomic replacement for temp-file write flows.
- **internal/format** - Response body formatters (JSON, XML, YAML, HTML, CSS, CSV, msgpack, protobuf, SSE, NDJSON). Each formatter writes colored output to a `Printer`.
- **internal/grpc** - gRPC framing, headers, and status code handling.
- **internal/image** - Terminal image rendering (Kitty, iTerm2 inline, block-character fallback).
- **internal/multipart** - Multipart form implementation.
- **internal/proto** - Protocol buffer compilation and message handling for gRPC support.
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
- Rust `--inspect-tls` renders the Go-style verified certificate chain when verification succeeds, appending omitted trusted roots or replacing server-sent cross-signed roots with the matching platform/custom trusted root for expiry display; `--insecure` keeps the raw peer chain.
- `--tls` remains a compatibility alias for setting the minimum TLS version; prefer `--min-tls` in new docs/examples, and use `--max-tls` to cap negotiation or combine min/max for an exact TLS version.
- WebSocket terminal sessions use the interactive prompt by default and can be controlled with `--ws-interactive auto|on|off`; output-file/clipboard/retry flags are rejected because the WebSocket path streams through the message loop instead of the normal response pipeline.
- Metadata-only commands (`--help`, `--version`, `--buildinfo`) perform best-effort config parsing for presentation settings, but config errors and background auto-updates cannot block them.
- Rust formatting code has a central `core::Printer`/`PrinterHandle` and ANSI `Sequence` abstraction mirroring the Go printer design; JSON/NDJSON write through the printer directly, other formatter/progress style helpers route escape emission through the shared sequence writer, and stderr metadata/inspection/error/warning renderers now use the same printer for request/response headers, `--inspect-dns`/`--inspect-tls`, and Go-style bold red/yellow labels.
- Rust error rendering now mirrors Go `PrinterTo`-style rich diagnostics for common CLI/config errors, styling labels, flags/options, invalid values, file paths, and config line context while preserving plain-text `Display` output.
- Rust `-vvv` output prints config, DNS, TCP, and TTFB debug metadata through the central printer, including color policy and the blank response-header separator before formatted bodies.
- Rust `--timing` now enables DNS pre-resolution timing and wraps reqwest's connector service so the waterfall includes DNS, TCP, TTFB, and Body phases instead of only response/body timing. reqwest does not currently expose a Go `httptrace`-style separate TLS handshake duration, so Rust reports the combined TCP/TLS connector phase as TCP timing.
- GitHub Actions are Rust-primary: CI has one Ubuntu check job for Cargo fmt/clippy/unit tests plus Go formatting/module/staticcheck validation, and one OS matrix job that builds and runs the Rust integration suite once on each supported runner. Release builds Cargo archives named for the self-updater, and Dependabot tracks Cargo, Go modules, and Actions. Release builds must set `FETCH_VERSION` from the release tag so the compiled binary reports the published version.
- Rust default config discovery keeps Go parity on Windows by honoring `XDG_CONFIG_HOME/fetch/config` and `HOME/.config/fetch/config` before falling back to `AppData/fetch/config`; Windows mTLS integration fixtures use RSA test certificates to stay compatible with reqwest/rustls platform verification.
5. HTTP client executes request
6. Response formatted based on Content-Type and output to stdout (optionally via pager)

Retryable requests replay bodies by calling `req.GetBody` when available, reopening file-backed bodies directly when possible, and only spooling the original body to a temp file as a final fallback for one-shot streams. This avoids holding large uploads in memory and keeps retries working for closable bodies like `*os.File`.
Multipart `-F` request bodies are produced by a replayable factory with a stable boundary; request construction sets `req.GetBody` so 307/308 redirects can resend them without relying on retry/digest spooling.

### Content Type Detection

`internal/fetch/fetch.go:getContentType()` maps MIME types to formatters. Supported types include JSON, XML, YAML, HTML, CSS, CSV, msgpack, protobuf, gRPC, SSE, NDJSON, and images.

## Testing

- Rust unit tests live alongside modules in `src/`.
- Rust integration tests live in `tests/integration.rs` and run the compiled Rust binary via Cargo.
- The legacy Go integration harness remains under `integration/` as a parity reference during migration.
- The Go `*_test.go` files remain as the behavioral reference; translated coverage and not-applicable cases are tracked in `MIGRATION.md`.
- CI runs Rust/Go checks once on Ubuntu and runs the Rust integration harness once on each supported GitHub Actions runner: Ubuntu, macOS, and Windows.

## Docs

High level documentation exists in the README. All detailed documentation exists in the `docs/` directory, and should be kept up-to-date with any code changes.

The `--edit` workflow accepts `VISUAL`/`EDITOR` values with flags and also preserves executable paths that contain spaces, even when those paths are not shell-quoted.

## Rust Migration Notes

- `MIGRATION.md` tracks the package map, dependency choices, test map, parity checklist, and current known gaps.
- The Rust skeleton currently covers a minimal reqwest/rustls HTTP path, URL normalization/default-scheme behavior for loopback and non-loopback hosts, Go-shaped help descriptions and common CLI parse errors, regular request construction for methods/headers/query params/direct data content types, `--edit` request-body editing, translated content-type sniffing tests, `--from-curl` parsing/application including `--http3`, shell completion registration/dynamic completions, Basic/Bearer auth, Digest auth including redirected challenged requests, AWS SigV4 auth, multipart form/file uploads with 307 replay, output filename/clobber handling, response output streaming with temp-file atomic install, gzip/zstd decode, and progress summaries, range request parsing/header behavior, redirect limit/no-follow behavior, timeout validation/error wording, runtime fetch error/help-footer parity for representative HTTP failures, top-level signal cancellation/error parity, manual gzip/zstd response decoding, Go-shaped JSON/NDJSON/XML/YAML/HTML/CSS/CSV/Markdown/MessagePack formatting with charset transcoding for text responses, terminal image rendering with Unix PTY block/iTerm2 inline/Kitty protocol coverage and Go-compatible image terminal environment detection, terminal-target color auto/on/off policy and CSV terminal-width dispatch, Server-Sent Events formatting, schema-less protobuf wire formatting, descriptor-backed unframed `application/protobuf` formatting in `--grpc` mode, gRPC framed response unframing/stream formatting, schema-less gRPC request defaults/framing/status handling, descriptor-backed gRPC/protobuf calls and reflection, `--proto-file` compilation through external `protoc`, proto schema missing-file validation, regular HTTP version selection including reqwest/rustls HTTP/3 prior knowledge with redirect/retry/session/proxy-rejection integration coverage, regular HTTP TLS min/max enforcement through reqwest/rustls, HTTP/HTTPS/SOCKS proxy support through CLI/config/env/from-curl including Go-style invalid proxy syntax errors, config default search plus request-option config parsing/merging including duplicate host-section replacement and proxy syntax validation with file/line context, config-time TLS PEM validation, config `key`/`cert` source behavior, config-vs-`--tls` alias precedence, config-backed bool/count source tracking for CLI and `--from-curl`, explicit presentation config for `color`/`format`, Rust-native `--buildinfo` metadata with Go-style formatting policy, HTTP timing waterfalls, `-vv`/`-vvv` request/debug metadata, non-interactive WebSocket mode plus interactive line-editor/cursor/wrapping/screen-rendering/runtime support with Unix PTY integration coverage, named cookie sessions with static public-suffix rejection parity, fileutil atomic replacement helpers, progress size/bar/spinner helpers, Unix socket transport, DNS-over-HTTPS and UDP DNS request resolution, `--inspect-dns` over DoH/UDP/system resolver fallback, regular HTTP mTLS/client certificate handling plus certificate-validation no-retry/`--insecure` hint behavior, TCP and QUIC/HTTP3 `--inspect-tls` inspection with TLS min/max enforcement plus TCP stapled OCSP status rendering, the integration-covered self-update path plus Unix update locking/hardening/progress unit coverage, Windows zip artifact unpacking tests, Windows self-replace/self-delete helper logic, and the retry path for retryable statuses/timeouts with `Retry-After` and Go-style backoff/jitter.
- The Rust integration harness now covers the primary CLI/error handling, request construction, config merge/default search, auth, redirect/range/status/session/copy/discard handling, response formatting, output-file, retry, timing, regular HTTP/3, descriptor-backed gRPC/protobuf client-streaming and `--proto-file` compilation, plaintext h2c and TLS gRPC reflection discovery/calls/unavailable errors, regular HTTP mTLS, top-level SIGINT request cancellation, self-update, Unix PTY image/WebSocket behavior, and `--from-curl` flows against the Cargo-built binary. The legacy Go integration suite is kept as the behavioral reference for future drift audits and platform-specific hardening.
- `MIGRATION.md` tracks documented non-blocking gaps such as rustls's lack of TLS 1.0/1.1 negotiation, QUIC inspection cipher-suite visibility, broader cross-platform PTY/resize coverage, and runtime validation of Windows running-executable update replacement.
