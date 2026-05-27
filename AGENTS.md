# fetch

This file provides guidance to AI agents when working with code in this repository. Keep this file updated after making changes.

## Project Overview

`fetch` is a modern HTTP(S) client CLI implemented as the Rust Cargo binary
named `fetch`. It features automatic response formatting (JSON, XML, YAML,
HTML, CSS, CSV, protobuf, msgpack), image rendering in terminals, gRPC support
with reflection/discovery and JSON-to-protobuf conversion, and authentication
(Basic, Digest, Bearer, AWS SigV4).

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

# Lint
cargo clippy --locked --all-targets --all-features -- -D warnings

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

### Key Packages

- **src/auth** - Basic, Bearer, Digest, and AWS Signature V4 authentication helpers.
- **src/cli** - Command-line argument parsing, shell completion, and `--from-curl` support.
- **src/config** - INI-format config file parsing with host-specific overrides.
- **src/core.rs** - Shared printer, color, format, and terminal utilities.
- **src/dns** - DNS-over-HTTPS, UDP DNS, system resolver fallback, and `--inspect-dns`.
- **src/format** - Response body formatters for JSON, XML, YAML, HTML, CSS, CSV, Markdown, msgpack, protobuf, SSE, NDJSON, gRPC, and images.
- **src/grpc** - gRPC framing, reflection, status handling, and protobuf request/response support.
- **src/http** - Core HTTP request construction and execution, multipart uploads, output routing, retries, proxies, TLS, Unix sockets, and timing.
- **src/image** - Terminal image rendering (Kitty, iTerm2 inline, block-character fallback).
- **src/output** - Response output, progress summaries, and atomic output-file writes.
- **src/proto** - Protocol buffer descriptor loading, compilation, and dynamic message handling.
- **src/session.rs** - Named cookie sessions with persistent storage across invocations.
- **src/tls** - TCP and QUIC/TLS inspection.
- **src/update.rs** - Check for updates, download release artifacts, and self-update.
- **src/websocket** - WebSocket message loop and interactive terminal prompt.

### Request Flow

1. CLI args parsed via `src/cli.rs` into an `App` struct
2. Config file merged via `src/config`
3. HTTP request built from merged config and CLI state
4. If gRPC: load local proto schema or resolve it via reflection, setup descriptors, convert JSON→protobuf, frame message
5. HTTP client executes request
6. Response formatted based on Content-Type and output to stdout (optionally via pager)

## Recent Notes

- `--grpc-list` and `--grpc-describe` provide grpcurl-style discovery using reflection or local descriptor files.
- `--grpc` now automatically tries gRPC reflection when no local schema is supplied.
- Plaintext loopback gRPC servers are supported via `h2c` for both calls and discovery.
- Formatted gRPC responses with `Content-Type: application/grpc+proto` stream through `FrameDecoder`, writing each complete message immediately while preserving trailers.
- Client-streaming and bidi gRPC calls stream JSON input into framed protobuf request bodies instead of materializing the whole stream up front.
- `--inspect-dns` resolves the URL hostname without making an HTTP request, showing common DNS record types, resolver backend, duration, and per-record TTLs from direct UDP or DoH responses.
- `--inspect-tls --http 3` performs QUIC/TLS inspection with `h3` ALPN instead of the TCP TLS path.
- Rust `--inspect-tls` renders a verified certificate chain when verification succeeds, appending omitted trusted roots or replacing server-sent cross-signed roots with the matching platform/custom trusted root for expiry display; `--insecure` keeps the raw peer chain.
- `--tls` remains a compatibility alias for setting the minimum TLS version; prefer `--min-tls` in new docs/examples, and use `--max-tls` to cap negotiation or combine min/max for an exact TLS version.
- Rust TLS version options accept only TLS 1.2 and TLS 1.3; legacy TLS 1.0/1.1 values are rejected consistently for CLI flags, config, WebSocket, and inspection paths.
- WebSocket terminal sessions use the interactive prompt by default and can be controlled with `--ws-interactive auto|on|off`; output-file/clipboard/retry flags are rejected because the WebSocket path streams through the message loop instead of the normal response pipeline.
- `wss://` WebSocket handshakes build a rustls client config so `--ca-cert`, `--cert`/`--key`, `--insecure`, and TLS min/max settings apply; plain `ws://` rejects TLS flags. WebSocket requests use a custom dialer so `--dns-server` works for direct connections, and `--proxy` supports HTTP CONNECT plus SOCKS5/SOCKS5H tunnels before the WebSocket/TLS handshake.
- Metadata-only commands (`--help`, `--version`, `--buildinfo`) perform best-effort config parsing for presentation settings, but config errors and background auto-updates cannot block them.
- Rust formatting code has a central `core::Printer`/`PrinterHandle` and ANSI `Sequence` abstraction; JSON/NDJSON write through the printer directly, other formatter/progress style helpers route escape emission through the shared sequence writer, and stderr metadata/inspection/error/warning renderers use the same printer for request/response headers and `--inspect-dns`/`--inspect-tls`.
- Rust error rendering uses rich diagnostics for common CLI/config errors, styling labels, flags/options, invalid values, file paths, and config line context while preserving plain-text `Display` output.
- Rust `-vvv` output prints config, DNS, TCP, and TTFB debug metadata through the central printer, including color policy and the blank response-header separator before formatted bodies.
- Rust `--timing` enables DNS pre-resolution timing and wraps reqwest's connector service so the waterfall includes DNS, TCP, TTFB, and Body phases. reqwest does not currently expose a separate TLS handshake duration, so Rust reports the combined TCP/TLS connector phase as TCP timing.
- Rust response body paging is controlled by `--pager auto|on|off` or `pager = ...`; `auto` routes terminal stdout through `less -FIRX`, `on` forces the pager, and `off` disables it. Image responses and output-file writes bypass the pager.
- Custom/pre-resolved DNS observes timeout budgets before the reqwest client is built: `--connect-timeout` bounds DNS resolution when set, otherwise DNS uses the remaining `--timeout` budget, and DoH lookup clients receive the same budget.
- Custom/pre-resolved DNS is scoped to the request URL; manual redirects that change scheme, host, or port rebuild the reqwest client and resolve the redirect target so `--dns-server`, `-vvv`, and `--timing` stay aligned with the actual target.
- Custom UDP DNS uses random query IDs and applies a 5s per-query receive timeout when no request/connect timeout is available, so unresponsive UDP resolvers cannot hang indefinitely.
- GitHub Actions run Cargo fmt, clippy, unit tests, and the Rust integration suite. Release builds Cargo archives named for the self-updater, Linux GNU binaries are built with a prebuilt `cargo-zigbuild` against an explicit glibc 2.28 floor, Windows release binaries use the static MSVC CRT, and each archive is uploaded with a SHA-256 sidecar. The release workflow also composes target-specific `RUSTFLAGS` with `--cfg reqwest_unstable`, which is required while reqwest HTTP/3 support is enabled. The release workflow supports manual dry runs via `workflow_dispatch`, uploading archives as workflow artifacts unless explicitly told to upload to an existing GitHub Release. Release builds set `FETCH_VERSION` from the release tag/manual version so the compiled binary reports the published or test version; `Cargo.toml` intentionally remains `0.0.0` unless crate publishing becomes a goal. Local builds derive `FETCH_VERSION` from a matching `v*` git tag, then `git describe`, then `v0.0.0-dev`.
- Rust default config discovery on Windows honors `XDG_CONFIG_HOME/fetch/config` and `HOME/.config/fetch/config` before falling back to `AppData/fetch/config`; Windows mTLS integration fixtures use RSA test certificates to stay compatible with reqwest/rustls platform verification.
- `--copy` tees decoded response bodies to the system clipboard for both stdout and output-file responses, using platform clipboard commands (`pbcopy`, `wl-copy`, `xclip`, `xsel`, or `clip.exe`) and skipping clipboard writes when the decoded body exceeds 1 MiB.
- Output-file downloads keep `*.download` temp files behind a drop guard so cancellation paths such as Ctrl-C clean up partial files; Unix atomic installs also sync the parent directory after rename/link updates for stronger crash durability.
- Response bodies that appear binary are not written to stdout when stdout is a terminal unless output is explicitly forced with `--output -`; this guard applies to both buffered formatting fallback output and raw streaming paths such as `--format off`.
- Image rendering defaults (`auto`) use built-in Rust decoders only; external adapters (`vips`, `magick`, `ffmpeg`) require `--image external` or `image = external` and run with bounded stdin/stdout/stderr and timeout handling.
- Response compression negotiation is controlled by `--compress auto|br|gzip|zstd|off` or `compress = ...`; `brotli` is accepted as an alias for `br`, `auto` requests and decodes gzip/brotli/zstd, single-algorithm modes only request/decode that algorithm, and `off` leaves compressed bodies untouched.
- Formatted SSE responses stream incrementally to stdout with terminal color when enabled, rendering events as `event:`/`data:` blocks while formatting JSON data. Auto-compressed SSE responses are retried without `Accept-Encoding` so intermediaries do not buffer events; request timeouts from flags, curl commands, or config remain enforced.
- Digest authentication retries drain oversized 401 challenge bodies with a fixed bound; on Windows, and for responses whose advertised body exceeds the discard bound, the authenticated retry is sent before the partially drained challenge response is dropped so the local TCP abort from abandoning the first response cannot poison the follow-up request.
- `--sort-headers` or `sort-headers = true` sorts displayed request/response headers alphabetically by name in verbose output without changing the actual request header order.
- Default HTTP requests send `Accept: application/json, */*;q=0.5`, preferring JSON while allowing any other response type as a lower-priority fallback.
- `--basic` and `--digest` credentials preserve exact bytes around the first colon; leading/trailing spaces in usernames or passwords are significant and are not trimmed after CLI or `--from-curl` parsing.
- The HTTP/2/3 environment-proxy guard mirrors reqwest `NO_PROXY` matching for hosts, domains, IP literals, CIDR ranges, and `*` so env proxies do not incorrectly block direct private-network requests.

Retryable requests use replayable request bodies so retries and 307/308 redirects can resend data without holding unrelated state.
Multipart `-F` request bodies are produced with a stable boundary so redirected requests preserve the original body shape.
Rust request uploads use a replayable body descriptor instead of a universal `Vec<u8>`: literal/form/edit/gRPC bodies remain buffered when required, while `@file`, `@-`, JSON/XML file inputs, and multipart file parts stream into reqwest bodies. File and multipart sources can be reopened for retries and 307/308 redirects; stdin streams once and reports an error if a replay is required.

### Content Type Detection

`src/format/content_type.rs` maps MIME types to formatters. Supported types include JSON, XML, YAML, HTML, CSS, CSV, msgpack, protobuf, gRPC, SSE, NDJSON, Markdown, and images.

## Testing

- Rust unit tests live alongside modules in `src/`.
- Rust integration tests live in `tests/integration.rs` and run the compiled Rust binary via Cargo.
- CI runs Rust checks once on Ubuntu and runs the Rust integration harness once on each supported GitHub Actions runner: Ubuntu, macOS, and Windows.

## Docs

High level documentation exists in the README. All detailed documentation exists in the `docs/` directory, and should be kept up-to-date with any code changes.

The `--edit` workflow accepts `VISUAL`/`EDITOR` values with flags and also preserves executable paths that contain spaces, even when those paths are not shell-quoted.
