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
cargo test --all-features --test cli --test formatting --test grpc --test http --test network --test terminal --test update --test websocket -- --test-threads=1

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
cargo test --all-features --test http request_construction_and_data_sources
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
- gRPC calls and reflection advertise `grpc-accept-encoding: gzip`; response frames with the compressed flag are decompressed with the response `grpc-encoding` before protobuf decoding, with unsupported encodings reported by name.
- gRPC standard request headers, status extraction from headers/trailers, and full framed-body reads live under `src/grpc`; request execution and reflection should reuse those helpers instead of duplicating protocol handling.
- gRPC reflection framed-body reads apply reflection-specific decoded-byte and message-count limits before retaining messages; keep reflection discovery bounded even when servers send many individually valid frames.
- Formatted SSE, NDJSON, and gRPC stdout streaming share `src/http/mod.rs`'s formatter callback driver for decoded reads, clipboard capture, byte counting, trailer extraction, and flushes; keep per-format parsing inside the callbacks. Formatted NDJSON caps each pending unterminated record at `MAX_BUFFERED_RESPONSE_BYTES`.
- Client-streaming and bidi gRPC calls stream JSON input into framed protobuf request bodies instead of materializing the whole stream up front; stdin-backed gRPC JSON streams use the shared incremental parser behind a blocking stdin bridge, discard leading whitespace before each message, cap pending incomplete JSON at `framing::MAX_MESSAGE_SIZE`, and Windows pipe stdin is peeked before reads so complete request messages can be sent before EOF without byte-at-a-time reads.
- Custom UDP DNS queries advertise EDNS(0) and retry truncated responses over TCP.
- `--inspect-dns` resolves the URL hostname without making an HTTP request, showing common DNS record types, resolver backend, duration, and per-record TTLs from direct UDP or DoH responses. UDP inspection queries retry truncated UDP responses over TCP; if TCP fallback cannot complete the lookup, render a warning about incomplete results and exit non-zero instead of silently omitting that record type.
- `--inspect-tls --http 3` performs QUIC/TLS inspection with `h3` ALPN instead of the TCP TLS path.
- `--inspect-tls` honors `--dns-server` for both TCP and QUIC inspection, resolving domain targets through the configured UDP or DoH resolver before the TLS handshake.
- Rust `--inspect-tls` renders a verified certificate chain when verification succeeds, appending omitted trusted roots or replacing server-sent cross-signed roots with the matching platform/custom trusted root for expiry display; `--insecure` keeps the raw peer chain.
- `--tls` remains a compatibility alias for setting the minimum TLS version; prefer `--min-tls` in new docs/examples, and use `--max-tls` to cap negotiation or combine min/max for an exact TLS version.
- Rust TLS version options accept only TLS 1.2 and TLS 1.3; legacy TLS 1.0/1.1 values are rejected consistently for CLI flags, config, WebSocket, and inspection paths.
- Rustls is built with `aws-lc-rs` and `prefer-post-quantum`; keep post-quantum key exchange preference enabled unless there is a concrete compatibility or provider reason to disable it.
- TLS inspection keeps its custom verifier for certificate display and OCSP capture, but Rustls protocol-version selection and PEM/client-auth material parsing should stay centralized in `src/tls/mod.rs`.
- Default HTTPS requests should preserve the old reqwest-style protocol preference by offering `h2` and `http/1.1` through ALPN, dispatching to hyper HTTP/2 when `h2` is negotiated and falling back to HTTP/1.1 otherwise. Explicit `--http 1`, `--http 2`, and `--http 3` remain forced protocol selections.
- The custom transport should preserve reqwest's safe default retries for HTTP/2/3 protocol NACKs such as remote `REFUSED_STREAM`, remote `GOAWAY(NO_ERROR)`, and HTTP/3 connection timeout signals, but only when the request body can be replayed.
- WebSocket terminal sessions use the interactive prompt by default and can be controlled with `--ws-interactive auto|on|off`; output-file/clipboard/retry flags are rejected because the WebSocket path streams through the message loop instead of the normal response pipeline.
- WebSocket requests require HTTP/1.1 for the upgrade handshake; reject explicit `--http 2` and `--http 3` instead of silently performing an HTTP/1.1 upgrade.
- Non-interactive WebSocket stdin connects before reading piped input, streams lines through a bounded bridge while receiving messages concurrently, preserves empty lines as empty text messages, and closes the send half on stdin EOF while continuing to read server messages. `--ws-message-mode auto|text|binary` controls outgoing frame type; `auto` sends invalid UTF-8 payloads as binary, and `binary` streams piped stdin as raw byte chunks.
- Non-interactive WebSocket text output writes through locked stdout, flushes after each received message, and treats `BrokenPipe` as normal downstream termination. Incoming binary frames write raw bytes to non-terminal stdout; terminal stdout keeps a binary guard instead of printing unsafe payloads.
- `wss://` WebSocket handshakes build a rustls client config so `--ca-cert`, `--cert`/`--key`, `--insecure`, and TLS min/max settings apply; plain `ws://` rejects TLS flags. WebSocket requests use a custom dialer so `--dns-server` works for direct connections and local target resolution through plain `socks5://` proxies; `socks5h://` keeps target DNS resolution remote. `--proxy` supports HTTP CONNECT plus SOCKS5/SOCKS5H tunnels before the WebSocket/TLS handshake. HTTP proxy userinfo sends `Proxy-Authorization: Basic`, including username-only URLs as an empty-password credential. `--connect-timeout` bounds WebSocket DNS, TCP, proxy negotiation, and TLS setup, capped by the remaining `--timeout` budget when both are set.
- WebSocket handshakes honor `--session` and configured `session = ...` by sending matching stored cookies during the upgrade and persisting `Set-Cookie` headers from successful handshake responses.
- HTTPS proxy TLS is configured separately from origin TLS: origin `--ca-cert`, `--cert`/`--key`, and `--insecure` do not apply to proxy handshakes. Proxy TLS should continue to use platform verification by default and must not receive origin client auth.
- HTTP client setup computes the effective explicit/env/system proxy decision, including `NO_PROXY`, before target DNS pre-resolution for `--dns-server`, `--timing`, and `-vvv`; skip local target DNS whenever the selected proxy resolves targets remotely, and only pre-resolve proxied target hosts for plain `socks5://`.
- Metadata-only commands (`--help`, `--version`, `--buildinfo`) perform best-effort config parsing for presentation settings, but config errors and background auto-updates cannot block them.
- Rust formatting code has a central `core::Printer`/`PrinterHandle` and ANSI `Sequence` abstraction; JSON/NDJSON write through the printer directly, formatter/progress/timing/inspection helpers route escape emission through the shared printer, and stderr metadata/error/warning renderers use the same printer for request/response headers and `--inspect-dns`/`--inspect-tls`. Production renderers should expose printer-oriented `*_to(..., &mut core::Printer)` entry points where practical; boolean color wrappers are test-only compatibility helpers.
- CLI stdout paths that are not already using a stream/pager writer should use `core::write_stdout` or another checked writer instead of `print!`/`println!`, including metadata, completion, gRPC discovery, and WebSocket message output.
- Rust stdio terminal detection and color/format auto policy are centralized in `src/core.rs`; prefer `core::stdio()`, `core::color_enabled`, and `core::format_enabled` over direct `IsTerminal` checks or local auto-policy helpers.
- The fetch-owned HTTP transport lives in `src/http/transport.rs`, using hyper-util's pooled client for HTTP/1.1 and HTTP/2, h3/quinn for HTTP/3, and rustls/aws-lc-rs for TLS. Shared network dialing for DNS-aware TCP, HTTP CONNECT, SOCKS5/SOCKS5H, and proxy auth lives in `src/net.rs`; HTTP, WebSocket, DoH, and update code should reuse those helpers instead of duplicating dialer code.
- Rust error rendering uses rich diagnostics for common CLI/config errors, styling labels, flags/options, invalid values, file paths, and config line context while preserving plain-text `Display` output.
- Rust `-vvv` output prints config, DNS, TCP, TLS/QUIC, and TTFB debug metadata through the central printer, including color policy and the blank response-header separator before formatted bodies.
- Rust `--timing` enables DNS pre-resolution timing and transport connection timing so the waterfall includes DNS, TCP, TLS/QUIC, TTFB, and Body phases. The direct transport owns DNS/TCP/TLS/QUIC setup, so keep new timing instrumentation in `src/http/transport.rs` and `src/net.rs`.
- `src/main.rs` runs the Tokio runtime on an explicitly larger stack thread, and the top-level app future in `src/app.rs` is heap-pinned before the shutdown-signal `tokio::select!`; do not move it back to `tokio::pin!` or the default process main stack because the combined async request/WebSocket/inspection state can overflow Windows' smaller main-thread stack even for metadata commands.
- Rust response body paging is controlled by `--pager auto|on|off` or `pager = ...`; `auto` routes terminal stdout through `less -FIRX`, `on` forces the pager, and `off` disables it. Image responses and output-file writes bypass the pager.
- Timeout duration parsing, Go-style duration formatting, elapsed request budgets, connect/DNS timeout caps, and shared `request timed out after ...` errors live in `src/duration.rs`; HTTP, WebSocket, DNS inspection, and TLS inspection paths should reuse `TimeoutBudget` instead of recomputing remaining time locally, and response body deadlines should preserve the original request timeout diagnostic.
- HTTP retries keep the original `--timeout` operation deadline across attempts, cap retry sleeps to the remaining budget, refresh per-request timeouts before each send, and use best-effort byte/time-bounded drains for retry cleanup responses.
- Custom/pre-resolved DNS observes timeout budgets before the transport client is built: `--connect-timeout` bounds DNS resolution when set, otherwise DNS uses the remaining `--timeout` budget, and DoH lookup clients receive the same budget.
- Custom/pre-resolved DNS is scoped to the request URL; manual redirects that change scheme, host, or port rebuild the transport client and resolve the redirect target so `--dns-server`, `-vvv`, and `--timing` stay aligned with the actual target.
- Custom/pre-resolved DNS runs A and AAAA lookups concurrently for both UDP and DoH, preserving any successful records when the other family fails.
- DNS diagnostics keep transport socket addresses and displayed DNS addresses in resolver order, with display-only stable deduping. HTTP/3 chooses its preferred/fallback address family from the first resolved address, matching TCP `connect_first`.
- DNS fallback paths share the top-level lookup timeout budget: DoH RFC 8484 POST and JSON fallback requests use one `TimeoutBudget`, and truncated UDP responses use the remaining budget for TCP fallback instead of restarting the timeout.
- Custom UDP DNS uses random query IDs and applies a 5s per-query receive timeout when no request/connect timeout is available, so unresponsive UDP resolvers cannot hang indefinitely.
- DoH lookups use the main HTTP transport client's ALPN-negotiated pool so concurrent HTTPS query types share an HTTP/2 connection when the resolver supports `h2`, falling back to HTTP/1.1 only when needed. Avoid regressing to one TLS connection per A/AAAA query.
- DoH responses are capped at 1 MiB while buffering; oversized responses must fail with a DNS error instead of growing memory without bound.
- DoH resolver URLs are queried with RFC 8484 `application/dns-message` POST requests first, falling back to Google-style JSON DoH for compatibility; keep the same response size cap on both paths.
- DNS implementation details are centralized under `src/dns`: `custom.rs` owns `--dns-server` dispatch, `wire.rs` owns DNS packet encoding/parsing, and `doh.rs` owns DoH querying. Request, TLS, WebSocket, and inspection code should reuse those helpers instead of branching on DoH vs UDP locally.
- HTTP request and DoH HTTPS connections use rustls' platform verifier to match the old reqwest path and avoid loading native roots into a Rust store during request/DNS timing; request-path TLS config still needs to preserve `--ca-cert`, mTLS, `--insecure`, and TLS min/max behavior.
- GitHub Actions run Cargo fmt, clippy, unit tests, and the Rust integration suite. Release builds Cargo archives named for the self-updater, Linux GNU binaries are built with a prebuilt `cargo-zigbuild` against an explicit glibc 2.28 floor, Windows release binaries use the static MSVC CRT, and each archive is uploaded with a SHA-256 sidecar. The release workflow supports manual dry runs via `workflow_dispatch`, uploading archives as workflow artifacts unless explicitly told to upload to an existing GitHub Release. Release builds set `FETCH_VERSION` from the release tag/manual version so the compiled binary reports the published or test version; `Cargo.toml` intentionally remains `0.0.0` unless crate publishing becomes a goal. Local builds derive `FETCH_VERSION` from a matching `v*` git tag, then `git describe`, then `v0.0.0-dev`. Build info marks `vcs.modified` from tracked Git changes only, ignoring untracked files such as local Zig caches.
- Rust is pinned to 1.96.0 via `rust-toolchain.toml`; keep `Cargo.toml`'s `rust-version` and GitHub Actions toolchain setup aligned with that version.
- Rust default config discovery on Windows honors `XDG_CONFIG_HOME/fetch/config` and `HOME/.config/fetch/config` before falling back to `AppData/fetch/config`; Windows mTLS integration fixtures use RSA test certificates to stay compatible with rustls platform verification.
- `--copy` tees decoded response bodies to the system clipboard for both stdout and output-file responses, using platform clipboard commands (`pbcopy`, `wl-copy`, `xclip`, `xsel`, or `clip.exe`) and skipping clipboard writes when the decoded body exceeds 1 MiB.
- Clipboard command execution is bounded while stdin is written and while waiting for exit; `--copy` kills a clipboard backend that does not finish within the short wait timeout and reports a warning instead of hanging indefinitely.
- Named session saves take a per-session advisory lock, reload the latest JSON, and merge only local cookie creates/updates/deletes before atomic replacement so concurrent `--session` invocations preserve distinct cookie changes. Session saves use a short bounded lock wait and report a warning instead of hanging indefinitely when another process keeps the session lock.
- Explicit self-updates use a bounded update-lock wait capped by the request timeout or the fixed update-lock timeout; background auto-update checks keep using nonblocking lock acquisition.
- Output-file downloads keep `*.download` temp files behind a drop guard so cancellation paths such as Ctrl-C clean up partial files; Unix atomic installs also sync the parent directory after rename/link updates for stronger crash durability.
- Self-updates stream release artifacts while calculating SHA-256 on the fly: `.tar.gz`/`.tgz` artifacts unpack directly into the update temp directory through a bounded reader, while `.zip` artifacts stream to a temp archive file first because zip extraction needs seekable input. Non-Windows replacement copies the new executable into the target directory before calling `fileutil::atomic_replace_file` so Unix parent-directory syncs are preserved.
- Response bodies that appear binary are not written to stdout when stdout is a terminal unless output is explicitly forced with `--output -`; this guard applies to both buffered formatting fallback output and raw streaming paths such as `--format off`.
- Image rendering defaults (`auto`) use built-in Rust decoders only; external adapters (`vips`, `magick`, `ffmpeg`) require `--image external` or `image = external` and run with bounded stdin/stdout/stderr and timeout handling.
- MessagePack `str` values and string map keys validate UTF-8 before JSON formatting; invalid `str` bytes return `MsgPackError`, while `bin` values continue to render as base64 JSON strings. Empty string map keys are valid and preserved.
- Response compression negotiation is controlled by `--compress auto|br|gzip|zstd|off` or `compress = ...`; `brotli` is accepted as an alias for `br`, `auto` requests and decodes gzip/brotli/zstd, single-algorithm modes only request/decode that algorithm, and `off` leaves compressed bodies untouched.
- Formatted SSE responses stream incrementally to stdout with terminal color when enabled, rendering events as `event:`/`data:` blocks while formatting JSON data. Auto-compressed SSE responses are retried without `Accept-Encoding` so intermediaries do not buffer events; request timeouts from flags, curl commands, or config remain enforced.
- Formatted NDJSON responses stream incrementally to stdout when formatting is enabled, splitting decoded bytes on newlines, formatting each record with the JSON-line formatter, and flushing after each record.
- Digest authentication retries use bounded cleanup for 401 challenge bodies. Challenge responses that may be abandoned before EOF are retried through a fresh client before the first response is dropped so a local TCP abort from abandoning that response cannot poison the follow-up request. Unsupported or malformed Digest challenges surface an explicit diagnostic before the body replay check.
- `--sort-headers` or `sort-headers = true` sorts displayed request/response headers alphabetically by name in verbose output without changing the actual request header order.
- Default HTTP requests send `Accept: application/json, */*;q=0.5`, preferring JSON while allowing any other response type as a lower-priority fallback.
- Request `Content-Length` inference is centralized in `src/http/mod.rs` and only runs when neither `Content-Length` nor `Transfer-Encoding` was supplied, keeping verbose/dry-run output aligned with the sent request and avoiding invalid mixed framing.
- `--basic` and `--digest` credentials preserve exact bytes around the first colon; leading/trailing spaces in usernames or passwords are significant and are not trimmed after CLI or `--from-curl` parsing.
- `--from-curl` should only no-op curl flags that already match fetch defaults or curl presentation-only progress flags. Unsupported semantic flags such as `-n`/`--netrc`, `-f`/`--fail`, `-N`/`--no-buffer`, `--proto-default`, and `--proto-redir` return clear diagnostics instead of being ignored.
- The HTTP/2/3 environment-proxy guard implements `NO_PROXY` matching for hosts, domains, IP literals, CIDR ranges, and `*` so env proxies do not incorrectly block direct private-network requests.

Retryable requests use replayable request bodies so retries and 307/308 redirects can resend data without holding unrelated state.
Multipart `-F` request bodies are produced with a stable boundary so redirected requests preserve the original body shape.
Rust request uploads use a replayable body descriptor instead of a universal `Vec<u8>`: literal/form/edit/gRPC bodies remain buffered when required, while `@file`, `@-`, JSON/XML file inputs, and multipart file parts stream into hyper request bodies. File and multipart sources can be reopened for retries and 307/308 redirects; stdin streams once and reports an error if a replay is required.

### Content Type Detection

`src/format/content_type.rs` centralizes MIME policy, mapping MIME types to response formatter kinds, preferred file extensions, and request-body default Content-Types for `@file` and multipart file parts. Supported formatter types include JSON, XML, YAML, HTML, CSS, CSV, msgpack, protobuf, gRPC, SSE, NDJSON, Markdown, and images.

## Testing

- Rust unit tests live alongside modules in `src/`.
- Rust integration tests live in focused files under `tests/`, with shared
  harness code in `tests/support/mod.rs`, and run the compiled Rust binary via
  Cargo.
- CI runs Rust checks once on Ubuntu and runs the Rust integration harness once on each supported GitHub Actions runner: Ubuntu, macOS, and Windows.

## Docs

High level documentation exists in the README. All detailed documentation exists in the `docs/` directory, and should be kept up-to-date with any code changes.

The `--edit` workflow accepts `VISUAL`/`EDITOR` values with flags and also preserves executable paths that contain spaces, even when those paths are not shell-quoted.
