# Go to Rust Migration

This document tracks the incremental rewrite of `fetch` from Go to Rust. The Rust Cargo binary is now the primary implementation; the Go code remains in the repository as the behavioral reference and to host the existing integration suite.

## Repository Analysis Notes

- `README.md`, `docs/`, `AGENTS.md`, `go.mod`, `main.go`, `internal/`, and `integration/` have been inspected for the initial map.
- No `CLAUDE.md` file is present in this checkout.
- The current Go entry point parses CLI arguments, merges config, handles metadata/completion/update/inspection modes, then builds a `fetch.Request` for `internal/fetch`.
- The integration suite is `integration/integration_test.go`; it runs the compiled CLI as a subprocess against local HTTP, TLS, gRPC, WebSocket, Unix socket, and update test servers.

## Package and Module Map

| Go package/path | Responsibility | Existing tests | Proposed Rust path | Rust crates needed | Known behavioral risks |
| --- | --- | --- | --- | --- | --- |
| `main.go` | Signal handling, CLI/config orchestration, metadata commands, update dispatch, DNS/TLS inspection dispatch, top-level exit codes | `main_test.go` | `src/main.rs`, `src/app.rs`, `src/error.rs` | `tokio`, `anyhow`, `thiserror`, `serde_json` | Exact error presentation, help/version/buildinfo output, signal cancellation semantics |
| `internal/aws` | AWS Signature V4 request signing and canonicalization | `internal/aws/sigv4_test.go` | `src/auth/aws_sigv4.rs` | `hmac`, `sha2`, `time`, `url`; manual hex encoding | Signer is ported and matches Go AWS test vectors; Rust `HeaderValue` rejects newline-containing header values, so that exact Go header-canonicalization case is represented with spaces/tabs only |
| `internal/cli` | Custom CLI parser, flag metadata/help, URL normalization, flag exclusivity, curl import application | `internal/cli/cli_test.go` | `src/cli.rs`, `src/cli/from_curl.rs` | `clap`, `url`, custom curl tokenizer/parser | Common help/error surfaces are ported; remaining risk is exact clap formatting for less-common parse errors and repeatable flag presentation |
| `internal/client` | HTTP client construction, HTTP/1.1/2/3 transports, redirect policy, proxies, Unix sockets, TLS config, gzip/zstd decoding, request construction | `internal/client/*_test.go` | `src/http/mod.rs`, `src/tls/mod.rs` | `reqwest` with `rustls-tls`, `rustls`, `rustls-pemfile`, `flate2`, `zstd`, `hyper`, `hyper-rustls`, `h2`, `quinn`/`h3` if reqwest HTTP/3 is insufficient | Reqwest automatic behavior can alter redirects, headers, decompression, proxy handling, and HTTP version negotiation |
| `internal/complete` | Shell completion rendering | `internal/complete/complete_test.go` | `src/cli/completion.rs` | Custom renderer using local flag metadata | Completion output is ported; the Rust static flag metadata must stay in sync with future CLI flag changes |
| `internal/config` | INI-like config parser, host/wildcard precedence, value parsers, TLS cert/key loading | `internal/config/*_test.go` | `src/config/mod.rs` | `rustls-pemfile`, `x509-parser`, `dirs`, `url` | File parse errors include exact file/line formatting; host merge order must remain stable |
| `internal/core` | Shared enums, TTY detection, ANSI printer, content-type detection for request bodies, common errors/build info | No standalone test file; used by many tests | `src/core.rs`, `src/output/printer.rs`, `src/error.rs` | `anstream`/`anstyle`, `is-terminal`, `mime_guess` | Color auto-detection, ANSI output, and error rendering are observable |
| `internal/curl` | `--from-curl` tokenizer and curl flag parser | `internal/curl/curl_test.go` | `src/cli/from_curl.rs` | Custom parser | Parser/application slice is ported for the Go-supported curl flags; downstream features such as HTTP/3 still depend on their own Rust ports |
| `internal/digest` | HTTP Digest auth challenge parsing and response generation | `internal/digest/digest_test.go` | `src/auth/digest.rs` | `md-5`, `sha2`, `rand`; manual hex encoding | Basic HTTP Digest and redirected challenged-request slices are ported; random cnonce prevents exact Authorization header comparison |
| `internal/dnsinspect` | DNS inspection command rendering and record normalization | `internal/dnsinspect/dnsinspect_test.go` | `src/dns/inspect.rs` | `hickory-resolver`, `hickory-proto`, `tokio` | TTL extraction, DoH generic RDATA normalization, and concurrent lookup ordering |
| `internal/fetch` | Core request execution, retries, dry-run, output routing, formatting, clipboard, gRPC reflection setup, timing waterfall, WebSocket dispatch | `internal/fetch/*_test.go` | `src/http/request.rs`, `src/http/retry.rs`, `src/output/mod.rs`, `src/timing/mod.rs`, `src/grpc/reflection.rs` | `reqwest`, `tokio`, `bytes`, `arboard`, `futures-util` | Most observable behavior lives here: status-to-exit-code mapping, verbose output, retry replay, body size limits |
| `internal/fileutil` | Cross-platform atomic replace/write helpers | `internal/fileutil/replace_test.go` | `src/fileutil.rs` | `tempfile`, `fs4` if locking is needed | Windows replace semantics and preserving file permissions |
| `internal/format` | Format registry and formatters for JSON, XML, YAML, HTML, CSS, CSV, Markdown, MessagePack, Protobuf, SSE, NDJSON, gRPC streams, sniffing | `internal/format/*_test.go` | `src/format/*` | `serde_json`, `quick-xml`, local tokenizers/renderers, `prost-reflect`, `unicode-width` if terminal-width gaps require it | Current formatters have custom pretty-printing and ANSI coloring; crate defaults may not match |
| `internal/grpc` | gRPC frame encoding/decoding, status parsing, gRPC headers | `internal/grpc/*_test.go` | `src/grpc/framing.rs`, `src/grpc/status.rs` | `bytes`, `thiserror`, `percent-encoding` | Frame errors and max size messages are asserted |
| `internal/image` | Terminal image rendering, emulator detection, external adapters, EXIF orientation | No package tests in current tree | `src/image/mod.rs` | `image`, `base64`, `libc`; external `vips`/`magick`/`ffmpeg` adapters | Terminal protocols are environment-sensitive; Unix PTY coverage now verifies block, iTerm2 inline, and Kitty output on Unix/cgo platforms |
| `internal/multipart` | Replayable multipart body factory with stable boundary and file content-type detection | `internal/multipart/multipart_test.go` | `src/http/multipart.rs` | Custom byte body builder | Ported as an owned-byte body factory to match current reqwest replay needs; large-file streaming remains a future optimization |
| `internal/progress` | Progress bar/spinner readers, size/duration formatting, native progress escape emission | `internal/progress/progress_test.go` | `src/output/progress.rs` | Custom `std::io`/thread wrapper; no new crate | Response-output streaming/progress and self-update artifact progress are wired; exact terminal color/TTY policy remains broader core parity work |
| `internal/proto` | `protoc` compilation, descriptor-set loading, dynamic schema lookup, JSON<->protobuf conversion | `internal/proto/*_test.go` | `src/proto/*` | `prost`, `prost-types`, `prost-reflect`, `prost-build` or external `protoc` invocation | Dynamic JSON/protobuf behavior must match Go protobuf reflection |
| `internal/resolver` | System/UDP/DoH resolution and shared dialing hooks | `internal/resolver/resolver_test.go` | `src/dns/resolver.rs` | `hickory-resolver`, `hickory-proto`, `reqwest` for DoH | Custom resolver integration with reqwest/hyper and timing traces |
| `internal/session` | Named persistent cookie sessions with RFC cookie behavior and JSON storage | `internal/session/session_test.go` | `src/session.rs` | `cookie_store`, `cookie`, `psl`, `serde_json`, `time`, `url` | Integration-backed persistence is ported; public-suffix parity now depends on the static `psl` crate list staying current with Go's `x/net/publicsuffix` data |
| `internal/tlsinspect` | TLS-only certificate-chain inspection including ALPN and QUIC/TLS path | `internal/tlsinspect/tlsinspect_test.go` | `src/tls/inspect.rs` | `rustls`, `tokio-rustls`, `webpki-roots`, `rustls-native-certs`, `quinn`, local DER/OCSP status parser | Verified-chain root selection, ALPN choice, expiry wording, OCSP behavior |
| `internal/update` | Self-update metadata, release lookup, archive unpacking, atomic replacement | `internal/update/*_test.go` | `src/update.rs` | `reqwest`, `tar`, `flate2`, `zip`, `tempfile` | Updating the running executable differs by OS; path traversal checks are security-sensitive |
| `internal/ws` | WebSocket connection loop, stdin/stdout streaming, interactive terminal prompt/editor | `internal/ws/*_test.go` | `src/websocket/*` | `tokio-tungstenite`, `futures-util`, `tokio` channels/time, `libc`/`windows-sys` for raw terminal mode | PTY/end-to-end terminal coverage, resize polling cadence, signal handling, and close-code handling |
| `integration` | End-to-end CLI behavior through subprocesses and local test servers | `integration/integration_test.go`, `integration/pty_unix_test.go` | `tests/integration.rs` now hosts the Rust subprocess harness for primary CI coverage; the Go harness remains as the behavioral reference while transport-heavy cases finish porting | Existing Go deps plus `cargo`; Rust-side subprocess tests use the Cargo-built binary and local Rust test servers | Stateful tests make global side-by-side parity comparison unsafe |

## Dependency Map

| Go dependency | Current use | Rust equivalent | Reasoning |
| --- | --- | --- | --- |
| `github.com/coder/websocket` | WebSocket server/client and close handling | `tokio-tungstenite` + `tungstenite` | Async Tokio-compatible WebSocket implementation with header/control-frame support |
| `github.com/goccy/go-yaml` | YAML tokenization/formatting | Custom token-preserving highlighter | The Go formatter writes lexer token origins back out so comments, anchors, tags, document markers, and scalar spelling stay intact; serde YAML parsers are still candidates if a later feature needs a semantic YAML tree |
| `github.com/klauspost/compress` | gzip/zstd decoding and test archive compression | `flate2`, `zstd` | Mature Rust gzip/zstd crates; the Rust client disables reqwest transparent decoding and decodes manually so `Content-Encoding` remains visible for verbose output |
| `github.com/mattn/go-runewidth` | Terminal display width | `unicode-width` | Standard Rust display-width crate |
| `github.com/quic-go/quic-go` | HTTP/3 and QUIC/TLS inspection | `reqwest` HTTP/3 feature with `h3`/`h3-quinn`/`quinn`; direct `quinn` for inspection | Rustls-native QUIC stack; avoid OpenSSL/native-tls while keeping regular requests on the reqwest client path |
| `github.com/tinylib/msgp` | MessagePack formatting | Local MessagePack-to-JSON parser | The Go formatter converts MessagePack to JSON before applying JSON formatting; the Rust slice mirrors that path locally and avoids adding a dependency while current parity coverage is bounded |
| `github.com/yuin/goldmark` | Markdown tokenization/formatting | Local Markdown terminal renderer | The Go formatter renders a normalized terminal-oriented Markdown shape with preserved list markers, front-matter YAML delegation, fenced-code formatter delegation, and custom ANSI styling; the Rust slice mirrors that observable output locally instead of pulling in a generic HTML/CommonMark renderer |
| `golang.org/x/crypto` | Cryptographic helpers | `sha2`, `hmac`, `md-5`, `rand` | Focused Rust crypto crates; no native TLS dependency. Digest uses `md-5`, `sha2`, and `rand`; AWS SigV4 uses `hmac` and `sha2` |
| `golang.org/x/image` | Image decoders and drawing | `image`, optional format features | Rust image crate covers common decoders/resizing |
| `golang.org/x/net` | HTTP/2, DNS/httpguts, HTML tokenizer, public suffix list | `h2`, `hyper`, `http`, `html5ever`, `psl`, custom validation | Need split replacements because Go x/net spans unrelated areas; `psl` provides the static public suffix list for session-cookie Domain rejection |
| `golang.org/x/sys` | OS/terminal syscalls | `std::io::IsTerminal`, local `libc`/`windows-sys` calls where needed | Cross-platform terminal and low-level OS behavior without adding broad platform abstractions |
| `golang.org/x/term` | Raw terminal and size handling | `libc` termios on Unix, `windows-sys` console mode on Windows, existing `core::terminal_size` | Keeps the WebSocket prompt local and avoids adding a terminal abstraction crate while matching the existing low-level OS dependencies |
| `golang.org/x/text` | Charset decoding | `encoding_rs` | WHATWG charset label lookup and decoding for response formatting; the current Rust stdout path buffers before formatting, so a streaming transcoder is not needed yet |
| `google.golang.org/protobuf` | Dynamic descriptors and protobuf JSON conversion | `prost`, `prost-types`, `prost-reflect` | Dynamic descriptor/message support for gRPC |
| `github.com/clipperhouse/uax29/v2` indirect | Unicode text segmentation via dependencies | `unicode-segmentation` if needed | Rust equivalent for grapheme/word segmentation |
| `github.com/philhofer/fwd` indirect | MessagePack dependency | `rmp` transitive | No direct Rust choice needed unless implementing low-level MessagePack |
| `github.com/quic-go/qpack` indirect | HTTP/3 QPACK | `h3`/`h3-quinn` transitive | Let the selected HTTP/3 stack provide QPACK |

Baseline Rust crates for the skeleton are `clap`, `tokio`, `reqwest` with `default-features = false` and `rustls-tls`, `anyhow`, `thiserror`, `serde`, `serde_json`, `url`, and `mime`. `serde_json` now enables `preserve_order` and `arbitrary_precision` so the JSON/NDJSON formatter preserves Go decoder-observable object order and numeric lexemes. The XML formatter uses `quick-xml` as a streaming parser so formatting can mirror Go's `encoding/xml` token flow without building a full DOM. The YAML formatter uses a local token-preserving highlighter instead of `serde_yml`/`serde_yaml` because the observable Go behavior preserves comments, anchors, tags, document markers, scalar spelling, and original layout. The CSS formatter uses a local tokenizer/pretty-printer rather than adding a parser crate because the Go formatter is token-level and intentionally lenient. The HTML formatter also uses a local tokenizer rather than adding `html5ever` because the Go implementation formats directly from `golang.org/x/net/html` tokens and the tested behavior is token-shape oriented rather than DOM oriented. The Markdown formatter uses a local terminal renderer rather than `pulldown-cmark` because the Go formatter's public output includes normalized Markdown markers, front-matter YAML delegation, code-block delegation to existing formatters, and exact ANSI styling that is simpler to preserve directly. The MessagePack formatter uses a local core MessagePack parser rather than adding `rmpv`/`rmp-serde`; it mirrors the Go path by converting MessagePack to compact JSON first and then reusing the Rust JSON formatter. The CSV formatter currently uses a local lenient parser and display-width helper rather than adding `csv`/`unicode-width`; revisit that choice if broader terminal-width behavior exposes a parity gap. The terminal image renderer uses the `image` crate with only common decoder features enabled (`jpeg`, `png`, `tiff`, `webp`) plus local EXIF-orientation parsing, ANSI block/iTerm2/Kitty writers, and subprocess fallbacks to `vips`, `magick`, or `ffmpeg`; this keeps rendering local and does not affect the rustls-only HTTP path. The retry slice adds `httpdate` to parse HTTP-date `Retry-After` values exactly through the HTTP-date grammar rather than hand-rolling date parsing; retry sleeping remains on Tokio and request bodies remain owned bytes for cheap replay. The reqwest feature set now also enables `system-proxy` so the Rust client can honor `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` without enabling native TLS; this pulls in proxy/system-configuration support, not OpenSSL. The reqwest `socks` feature is enabled for SOCKS4/SOCKS5 proxy URLs while preserving `default-features = false`, so SOCKS support stays on the same reqwest/rustls path and does not introduce native TLS. Regular HTTP/3 requests use reqwest's unstable `http3` feature with `.cargo/config.toml` setting `--cfg reqwest_unstable`; this brings in `h3`, `h3-quinn`, and `quinn` while still using rustls and keeping default/native TLS disabled. The WebSocket slice adds `tokio-tungstenite` with rustls/webpki roots and `futures-util` for Tokio-compatible WebSocket streams without enabling native TLS. The session slice adds direct `cookie_store`/`cookie` dependencies to expose RFC cookie matching, request `Cookie` header generation, and response `Set-Cookie` persistence through reqwest's cookie provider, plus `psl` for static public suffix matching equivalent to Go's `x/net/publicsuffix` rejection path. The fileutil and terminal-policy slices use `windows-sys` for direct `MoveFileExW` and console-buffer-size bindings on Windows, matching the Go packages without adding a broad platform abstraction. The progress slice uses custom `std::io::Read` wrappers and counter-based async download hooks plus a small render thread/printer abstraction, avoiding a progress-bar dependency so the exact Go output shape stays under local control; response output reuses the existing `fileutil` helper for Go-style temp-file atomic install and streams the reqwest body through a blocking reader bridge so gzip/zstd decoding can stay streaming without adding a new async compression dependency. The gRPC response/status slice adds direct `http`, `http-body-util`, and `percent-encoding` dependencies so the Rust response path can collect trailers from reqwest bodies and decode `Grpc-Message` values without native TLS. The descriptor-backed gRPC/protobuf slice adds `prost`, `prost-types`, and `prost-reflect` with its `serde` feature for dynamic descriptor pools, proto JSON conversion, reflected schemas, and schema-aware gRPC response formatting; `--proto-file` compilation shells out to the user-installed `protoc` like the Go implementation rather than pulling in a Rust code-generation build step. The DNS-over-HTTPS request-resolution slice reuses `reqwest`, `serde_json`, and `url` to match the Go JSON DoH endpoint behavior. The UDP DNS request-resolution and `--inspect-dns` slices implement the limited DNS packet encode/decode locally, avoiding a resolver crate while matching the current Go-tested A/AAAA request-resolution and DNS-inspection record surfaces. The mTLS slice uses reqwest's rustls-backed `Certificate` and `Identity` types so custom CA roots and client certificates stay on the rustls path without adding native TLS or OpenSSL. The regular HTTP TLS min/max slice uses reqwest's rustls-backed `min_tls_version` and `max_tls_version` builder settings, preserving the rustls-only client path and avoiding native TLS/OpenSSL. The TCP TLS inspection slice adds direct `rustls`, `tokio-rustls`, and `webpki-roots` usage so `--inspect-tls` can perform a handshake without issuing an HTTP request; direct rustls features are pinned to the `ring` provider to avoid accidentally enabling both rustls crypto providers. TLS inspection now also uses `rustls-native-certs` to load platform root certificates as DER for rustls trust roots and display metadata, matching Go's verified-chain root rendering without using native-tls or OpenSSL for the handshake. The OCSP status slice captures stapled responses through a rustls verifier wrapper and parses the Go-rendered `good`/`revoked`/`unknown` status surface locally, avoiding a new parser crate. The QUIC TLS inspection slice adds `quinn` with `runtime-tokio` and `rustls-ring` for `--inspect-tls --http 3`, preserving the rustls-only TLS stack and avoiding native TLS/OpenSSL while negotiating `h3` ALPN over QUIC. The self-update slice adds `tar` for Unix `.tar.gz` release artifacts, `zip` with deflate support for Windows `.zip` release artifacts, continues to download with reqwest/rustls, reuses the existing `time` dependency for Go-shaped RFC3339 update metadata timestamps, uses direct `libc` for Unix `flock` update-lock parity, and uses `windows-sys` for Windows self-replace/self-delete handles plus `LockFileEx`/`UnlockFileEx` lock parity.

The WebSocket interactive runtime reuses Tokio `sync` channels/time, Unix `libc` termios, Windows console mode via `windows-sys`, and the existing terminal-size helper instead of adding a terminal abstraction crate.

## Test Map

| Go test area | Rust target |
| --- | --- |
| `main_test.go` | `src/app.rs` unit tests for inspection ignored-flag warnings and metadata-mode behavior |
| `internal/aws/sigv4_test.go` | `src/auth/aws_sigv4.rs` unit tests preserving Go test names where practical |
| `internal/cli/cli_test.go` | `src/cli.rs` and `src/cli/from_curl.rs` unit tests plus integration coverage where subprocess behavior matters |
| `internal/client/*_test.go` | `src/http/mod.rs`, `src/tls/mod.rs` unit tests plus integration coverage |
| `internal/complete/complete_test.go` | `src/cli/completion.rs` unit/snapshot tests |
| `internal/config/*_test.go` | `src/config/mod.rs` unit tests |
| `internal/curl/curl_test.go` | `src/cli/from_curl.rs` unit tests |
| `internal/digest/digest_test.go` | `src/auth/digest.rs` unit tests |
| `internal/dnsinspect/dnsinspect_test.go` | `src/dns/inspect.rs` unit tests |
| `internal/fetch/*_test.go` | `src/http/request.rs`, `src/http/retry.rs`, `src/output/*`, `src/grpc/reflection.rs`, `src/timing/mod.rs` unit tests |
| `internal/fileutil/replace_test.go` | `src/fileutil.rs` unit tests |
| `internal/format/*_test.go` | `src/format/*` unit tests plus formatter dispatch integration cases |
| `internal/grpc/*_test.go` | `src/grpc/framing.rs`, `src/grpc/status.rs` unit tests |
| `internal/multipart/multipart_test.go` | `src/http/multipart.rs` unit tests |
| `internal/progress/progress_test.go` | `src/output/progress.rs` unit tests |
| `internal/proto/*_test.go` | `src/proto/*` unit tests |
| `internal/resolver/resolver_test.go` | `src/dns/resolver.rs` unit tests |
| `internal/session/session_test.go` | `src/session.rs` unit tests |
| `internal/tlsinspect/tlsinspect_test.go` | `src/tls/inspect.rs` unit tests |
| `internal/update/*_test.go` | `src/update.rs` unit tests |
| `internal/ws/*_test.go` | `src/websocket/*` unit tests |
| `integration/integration_test.go`, `integration/pty_unix_test.go` | Legacy end-to-end parity reference; `tests/integration.rs` is the Rust-native Cargo integration harness for primary CI coverage |

All current Go `*_test.go` files are covered by the map above. The documented
not-applicable or intentionally different cases are: Go's newline-containing AWS
header canonicalization unit case because Rust HTTP header types reject newline
bytes, Go's low-level retry temp-spool/seekable-body tests because Rust request
bodies are owned bytes before replay, TLS 1.0/1.1 negotiation because the
required rustls stack does not support those deprecated protocol versions, QUIC
TLS cipher-suite display because Quinn does not expose it, and runtime Windows
self-update replacement validation in this macOS workspace.

## Feature Parity Checklist

- [x] URL parsing and default scheme behavior
- [x] HTTP methods
- [x] Headers
- [x] Query parameters
- [x] Request bodies
- [x] JSON/XML/form/multipart/file uploads
- [x] Redirects including no-follow, default/max limits, verbose hop status, and retry exclusion on redirect-limit errors
- [x] `--from-curl` tokenizer/parser/application for request/header/body/auth/network flags
- [x] Retry on 429/502/503/504 and per-attempt timeouts with replayed owned bodies, `Retry-After`, and Go-style exponential backoff/jitter
- [x] Range request flag parsing/normalization and `Range` header emission
- [x] HTTP/HTTPS proxies via `--proxy`, config files, `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` with `NO_PROXY`, and `--from-curl`, with Go-style HTTP/2+ rejection
- [x] SOCKS proxies
- [x] Compression/decompression including gzip, zstd, stacked encodings, and `aws-chunked`
- [x] HTTP/1.1, HTTP/2, and HTTP/3 behavior for the regular HTTP client (`--http 1`, `--http 2`, and `--http 3`)
- [x] Unix socket transport on Unix platforms through reqwest's Unix socket connector
- [x] DNS-over-HTTPS request resolution for regular HTTP requests through `--dns-server http(s)://...`
- [x] UDP DNS request resolution for regular HTTP requests through `--dns-server <IP[:PORT]>`
- [x] `--inspect-dns` for IP literals, system resolver fallback, UDP DNS servers, DoH servers, TTL display, record sorting/deduplication, generic CAA/SVCB/HTTPS RDATA normalization, and ignored-flag warnings
- [x] Regular HTTP/3 request behavior using reqwest/rustls HTTP/3 prior knowledge, custom CA roots, method/header/query/body propagation, redirects, retries, sessions, and Go-style plain-HTTP/proxy rejection
- [x] TCP TLS inspection with `--inspect-tls` for HTTPS/WSS, custom CA roots, `--insecure`, client certificates, HTTP/1 vs HTTP/2 ALPN, certificate chain/SAN/expiry output, stapled OCSP status output, and ignored-flag warnings
- [x] Regular HTTP TLS min/max options via `--tls`, `--min-tls`, and `--max-tls` on the reqwest/rustls path
- [x] QUIC/HTTP/3 TLS inspection with `--inspect-tls --http 3`, `h3` ALPN, custom CA roots, `--insecure`, client certificates, and certificate chain rendering
- [x] Inspection-path TLS min/max enforcement for TCP and QUIC/HTTP3 `--inspect-tls`
- [x] Legacy TLS 1.0/1.1 negotiation limitation documented for the rustls path
- [x] Regular HTTP certificate validation options and failure behavior (`--ca-cert`, `--insecure`, certificate-error no-retry, and the Go-style `--insecure` hint)
- [x] mTLS/client certificates for regular HTTP requests with `--ca-cert`, `--cert`, and `--key`
- [x] Basic auth
- [x] Digest auth
- [x] Bearer auth
- [x] AWS SigV4 auth
- [x] Config file loading and precedence
- [x] Presentation config for explicit config files (`color`/`format`) and metadata best-effort behavior
- [x] Config default search plus request option parsing/merging for headers, query params, retry, timeouts, redirects, HTTP version, sessions, verbosity, and boolean request controls
- [x] Environment variables for config search, editor selection, AWS credentials, proxies, sessions, updates, build metadata, image terminal detection, and integration harness overrides
- [x] Named cookie sessions with JSON persistence, `FETCH_INTERNAL_SESSIONS_DIR`, expiry filtering, isolated session names, and invalid-name rejection
- [x] Output formatting and syntax highlighting for supported response formats, including charset transcoding before text formatting
- [x] Output files, `-O`, `-J`, clobber checks, and filename sanitization
- [x] JSON formatting
- [x] XML formatting
- [x] YAML formatting
- [x] HTML formatting
- [x] CSS formatting
- [x] CSV formatting
- [x] Markdown formatting
- [x] MessagePack formatting
- [x] Schema-less Protobuf wire-format response formatting and gRPC response stream unframing
- [x] Schema-aware gRPC Protobuf JSON formatting from descriptor/reflection schemas
- [x] Descriptor-backed unframed `application/protobuf` response formatting in `--grpc` mode
- [x] Local `.proto` compilation via `protoc` for gRPC request/discovery schema loading
- [x] Server-Sent Events formatting
- [x] NDJSON formatting
- [x] Image rendering behavior
- [x] Terminal detection/color/TTY behavior
- [x] WebSocket non-interactive support for `ws://`/`wss://`, data and piped stdin text messages, bearer/basic/AWS handshake auth headers, JSON-line text-frame formatting, verbose `101` metadata, dry-run effective `GET`, and the `--timing` warning
- [x] WebSocket interactive terminal prompt/TUI parity
- [x] gRPC integration support for framed unary/streaming responses, client streaming, local descriptor sets, reflection list/describe, reflection-backed JSON calls, and h2c loopback servers
- [x] gRPC framed response formatting for `application/grpc+proto` without descriptors
- [x] Minimal schema-less gRPC request defaults/framing and response status handling
- [x] HTTP timing waterfall and `-vvv` config/DNS/TCP/TTFB debug text
- [x] Error handling and exit codes
- [x] Timeout/connect-timeout validation and request timeout error wording
- [x] Shell completion registration and dynamic bash/fish/zsh completion output
- [x] Help descriptions and common parser error output parity
- [x] Version output and buildinfo formatting parity, with Rust-native build settings/dependency metadata replacing Go-specific build info fields
- [x] Initial content-type sniffing unit tests ported to Rust

## Integration Harness Plan

- Default integration command builds `target/debug/fetch` with Cargo and runs the existing Go integration assertions against that binary.
- `FETCH_BIN=/path/to/fetch go test -v ./integration` overrides the binary. This allows running the same suite against the Go binary or Rust binary.
- A global side-by-side parity mode is not safe for the current suite because many tests mutate local server counters, session files, output files, and update binaries. Add case-level parity helpers later for pure request/response cases that can be safely duplicated.
- Output normalization may be needed for timestamps, random multipart boundaries, retry timing, terminal capabilities, and Go-vs-Rust help formatting.

## Implemented So Far

- Added Cargo project with package/binary name `fetch`.
- Added thin async `src/main.rs` and top-level `src/app.rs`.
- Added `clap`-based CLI skeleton with the existing flag surface represented.
- Ported the Go CLI help descriptions into the Rust clap metadata and normalized common clap parse errors to the Go parser surfaces: unknown flags, missing flag arguments, values passed to boolean flags, mutually exclusive flags, and `--ws-interactive` invalid values no longer emit clap usage blocks.
- Added a minimal `reqwest` + `rustls` HTTP execution path covering simple requests, basic/bearer auth, data/json/xml/form bodies, headers, ranges, output files, status-to-exit-code mapping, and parse-error normalization for initial parity.
- Ported the URL normalization/default-scheme slice from `internal/cli` and `internal/client`: scheme-less non-loopback hosts default to HTTPS, loopback hosts including `localhost`, `127.0.0.0/8`, and IPv6 `::1` default to HTTP, WebSocket schemes are rewritten for the regular request path like Go's `parseURL`, and URL parsing now relies on URL host extraction instead of string splitting so query-only and bracketed IPv6 hosts are classified correctly.
- Added translated Rust coverage for Go's `TestIsLoopback` cases plus default-scheme regression tests for IPv6 loopback, loopback hosts with query strings, non-loopback HTTPS defaults, and `ws://`/`wss://` rewriting.
- Ported `internal/format/contenttype.go` and `internal/format/contenttype_test.go` into `src/format/content_type.rs`.
- Ported the `internal/curl` tokenizer/parser into `src/cli/from_curl.rs` with translated Rust unit tests for tokenization, common curl flags, auth, retry/network options, `--json`, `--proto`, cookie-file rejection, `--data-urlencode`, and data/upload conflicts.
- Added app-layer Rust tests for `--from-curl` data-urlencode file expansion, `-G` query appending, curl redirect defaults, exclusivity with a positional URL, and `--proto` scheme rejection.
- Added Rust `--from-curl` application in `src/app.rs`, including exclusivity checks, curl data materialization, `-G` query appending, `--proto` restrictions, convenience headers, auth mapping, redirect defaults, and retry/verbosity/silent mapping.
- Tightened Basic/Bearer auth parity: direct `--basic` and `--from-curl -u/--user` credentials now reject missing-colon values with the Go `ValueError` wording, trim username/password around the first colon like `core.CutTrimmed`, share the same normalized Basic header path across HTTP/WebSocket/gRPC reflection, and preserve Bearer tokens exactly. The integration harness now covers valid Basic, invalid Basic format, valid Bearer, and `--from-curl` Basic auth against the Rust binary.
- Added the shared Rust retry loop in `src/http/mod.rs` for retryable status codes and reqwest timeout/connect errors; request bodies are replayed from owned bytes for each attempt.
- Ported Go retry helper behavior into Rust: `Retry-After` integer/date parsing, exponential backoff capped at 30s with +/-25% jitter, Go-shaped retry delay formatting, retryable-status tests, and owned-body replay coverage. The Go temp-file/seekable-stream `newReplayableBody` tests are not applicable to the Rust request model because request bodies are materialized as owned bytes before retry/digest/grpc handling.
- Added verbose response metadata output needed by current `-v`/retry integration coverage.
- Ported `internal/digest` into `src/auth/digest.rs`, including challenge parsing, MD5/MD5-sess/SHA-256/SHA-512-256 response generation, qop handling, quoted parameter parsing, and combined `WWW-Authenticate` challenge extraction.
- Wired Digest auth into the Rust HTTP path: unauthenticated first request, 401 Digest challenge parsing, replayed body, and challenged request with computed `Authorization`.
- Added translated Rust tests for Digest challenge parsing, response construction, hash output, unsupported qop/algorithm handling, combined challenge extraction, CLI digest parsing/conflicts, and digest credential validation.
- Ported Digest challenge retry behavior after redirects from `internal/fetch/retry.go`: the Rust redirect policy now records redirect statuses so a 401 challenge after a redirect is signed and replayed with the method/body Go would have used for the challenged request, including POST -> 303 -> GET with an empty body.
- Added a Rust unit test for Go redirect method/body transformation before Digest retry, plus an integration case asserting POST -> 303 -> Digest challenge uses the protected URL, GET method, and empty body.
- Ported `internal/aws` into `src/auth/aws_sigv4.rs`, including environment-loaded credentials at sign time, canonical URI/query/header construction, payload hashing, S3 `UNSIGNED-PAYLOAD` for stdin bodies, HMAC signing keys, and Authorization header construction.
- Wired AWS SigV4 into the Rust HTTP path before each request attempt so retry attempts are freshly signed with the current request body and headers.
- Added translated Rust tests for AWS SigV4 S3 test vectors, canonical path handling, host header handling, header value canonicalization, S3 unsigned payload behavior, config parsing, CLI parse behavior, and `--from-curl --aws-sigv4` application.
- Ported `internal/multipart` into `src/http/multipart.rs`, including stable per-request boundaries, text fields, file fields, basename-only filenames, file validation, extension/sniffed file content types, and replayable owned body bytes for redirects/retries.
- Wired multipart request bodies into the Rust HTTP path and verified 307 redirect replay through the existing integration suite.
- Added translated Rust tests for JSON/PDF/JPEG multipart file content types, basename-only filenames, stable replayed bodies, and missing-file/directory validation.
- Ported the output filename slice from `internal/fetch/output.go` into `src/output/mod.rs`, including direct `-o`, stdout `-o -`, `-O` URL filename inference, `-O -J` `Content-Disposition` filename handling, basename sanitization, hostname fallback, and `--clobber` file-exists behavior.
- Added translated Rust tests for `sanitizeFilename`, output overwrite/clobber behavior, direct stdout handling, URL-derived names, `Content-Disposition` names, path traversal sanitization, invalid content-disposition fallback, hostname fallback, and quoted/RFC 5987 filename parsing.
- Ported the `--range` parser behavior from `internal/cli/app.go`, including suffix/open-ended/bounded ranges, whitespace normalization, signed/malformed range rejection, and validation of ranges imported through `--from-curl`.
- Added translated Rust tests for accepted byte ranges, malformed range rejection, and `invalid range end` error wording.
- Ported redirect policy behavior into the Rust reqwest client path: `--redirects 0` now returns the 30x response without following, default/custom redirect limits use Go-compatible error text, redirect-limit errors are not retried, and `-vv` prints redirect hop status lines needed by integration coverage.
- Added a Rust unit assertion for the Go-compatible redirect-limit error string.
- Ported timeout flag validation and request timeout error wording: negative timeout values now reach Rust validation instead of being treated as unknown flags by `clap`, and request timeout errors render as `request timed out after <duration>` like the Go CLI.
- Added Rust tests for negative numeric timeout parsing and Go-style duration formatting.
- Ported gzip/zstd response decoding behavior from `internal/client`: reqwest transparent decoding is disabled, `Accept-Encoding: gzip, zstd` is still requested by default, response bodies are decoded manually only when fetch requested compression, `Content-Encoding` remains visible for verbose output, stacked encodings are decoded in reverse order, and `aws-chunked` is ignored like Go.
- Added translated Rust tests for splitting multiple `Content-Encoding` values, stacked gzip/zstd decoding, `aws-chunked` plus gzip, unsupported stacked encodings, no-decode behavior when fetch did not request compression, and gzip decoder error prefixing.
- Ported the Server-Sent Events formatter from `internal/format/sse.go` into `src/format/sse.rs`, including comments, event names, multi-line data assembly, BOM/CR/LF handling, EOF dispatch, JSON event-data formatting, and `--format on` dispatch for `text/event-stream`.
- Added translated Rust tests for EOF dispatch without a trailing blank line, no duplicate final event with a trailing blank line, CRLF/BOM handling, and the integration-format output shape.
- Ported regular HTTP version selection from `internal/config`/`internal/client`: direct `--http` values are validated like Go, `--http 1` forces reqwest's HTTP/1 path, and `--http 2` forces HTTP/2 while preserving the Go transport's `http2: unsupported scheme` failure for plain HTTP URLs outside gRPC/h2c mode.
- Added Rust tests for accepted/rejected `--http` values, the plain HTTP/2 error boundary, and the HTTP/3 HTTPS/plain-HTTP/Unix-socket boundaries.
- Ported regular HTTP/3 request execution through reqwest's rustls-backed HTTP/3 prior-knowledge path: explicit `--http 3` now sends requests over QUIC, sets reqwest requests to `HTTP/3.0`, preserves the existing method/header/query/body/output pipeline, supports custom CA roots, and keeps Go-style proxy/Unix-socket/plain-HTTP rejection surfaces.
- Added HTTP/3 hardening integration coverage shared by the Rust binary and Go reference binary for 307 redirect body replay, 503 retry body replay, named-session cookie persistence, and explicit proxy rejection.
- Ported the terminal image rendering slice from `internal/image`: native PNG/JPEG/TIFF/WebP decode, 8192-dimension rejection, local EXIF orientation handling, external adapter fallback through `vips`/`magick`/`ffmpeg`, block-character fallback rendering, iTerm2 inline images, Kitty graphics protocol chunks, emulator detection, and `--image` validation/`--image off` dispatch.
- Added Unix/cgo PTY integration coverage for compiled-binary terminal image rendering: the Go harness serves a generated PNG, attaches stdout/stderr/stdin to a pseudo-terminal with no pixel dimensions, and asserts both Rust and Go emit ANSI half-block image output instead of raw PNG bytes.
- Completed the environment-variable parity audit for product and harness variables currently used by Go: config search (`HOME`, `XDG_CONFIG_HOME`, `AppData`), editor selection (`VISUAL`, `EDITOR`, `PATH`, `PATHEXT`), AWS credentials, proxy environment variables including CGI `REQUEST_METHOD` handling, session/update internals, build metadata, terminal/image detection, and integration harness overrides are represented in Rust or documented as test-only.
- Tightened image truecolor environment parity: Rust block image rendering now mirrors Go's `COLORTERM=truecolor|24bit` behavior and the Windows-only `WT_SESSION` / `ConEmuANSI=ON` truecolor fallback. Added a unit test that covers these branches from non-Windows workspaces.
- Ported the presentation subset of `internal/config`: explicit `--config` files now parse and merge global/host-specific `color` and `format` settings with CLI precedence, validate wildcard host sections, and apply best-effort config parsing for metadata commands.
- Added a Go-shaped JSON formatter with optional ANSI color so `format = on` plus `color = on` produces colored JSON output like the Go CLI's presentation path.
- Added translated Rust tests for presentation config parsing, invalid value errors, wildcard validation, exact/wildcard host precedence, CLI-over-config precedence, and colored JSON formatting.
- Ported metadata build-info presentation parity: `--buildinfo` now honors Go's default pretty JSON formatting, `--format off` emits compact JSON without a newline, `--color on` colors formatted JSON, and the Rust-native payload includes `fetch`, `rust`, `settings`, and Cargo.lock dependency metadata. Go-only build-info fields (`go`, Go module settings) are intentionally replaced with Rust equivalents.
- Extended the Rust `internal/config` port beyond presentation settings: default config search now checks `$XDG_CONFIG_HOME/fetch/config` then `$HOME/.config/fetch/config` on Unix and `%AppData%/fetch/config` on Windows, explicit config paths are absolutized after `~/` expansion, host/global precedence is preserved, repeated `header`/`query`/`ca-cert` values merge before CLI values, config-time PEM validation is performed for `ca-cert`/`cert`/`key`, config/from-curl `key` values without a paired `cert` are ignored after direct CLI required-flag validation like Go, direct `--tls` is treated as an explicit minimum TLS source when merging config, and request options such as `header`, `query`, `retry`, `retry-delay`, `timeout`, `connect-timeout`, `redirects`, `http`, `session`, `ignore-status`, `insecure`, `no-encode`, `no-pager`, `copy`, `silent`, `timing`, and `verbosity` are parsed with Go-style validation.
- Added translated Rust config tests for header validation, non-negative retry parsing, finite non-overflowing duration parsing, wildcard and host matching, successful Go config file cases, CLI-over-config precedence for explicitly supplied retry defaults and the `--tls` alias, repeated-value merge order, config-time TLS PEM file validation/error surfaces, direct-CLI-only `--key` required-flag validation, default config search candidates, and request-option application.
- Ported config source tracking for config-backed boolean/count options that clap stores as defaults: `copy`, `ignore-status`, `insecure`, `no-encode`, `no-pager`, `silent`, `timing`, and `verbosity` now preserve direct CLI or `--from-curl` values when a lower-priority config file explicitly sets the option to `false` or `0`, matching Go's pointer-backed `Config.Merge` semantics.
- Tightened host-section config parity: duplicate host sections now replace the previous section like Go's `File.Hosts[host] = config` parse path, invalid wildcard section cases and invalid key/value line errors are covered by translated Rust tests, host matching covers case-insensitive exact/wildcard/deep wildcard/no-match/empty-host cases, and the integration harness now asserts duplicate host sections against both Rust and the Go reference binary.
- Ported the HTTP/HTTPS proxy slice from `internal/client` and `main.go`: explicit `--proxy` URLs now configure reqwest's proxy layer and override environment proxies, standard proxy environment variables are honored for HTTP/HTTPS/ALL with `NO_PROXY`, config and `--from-curl` proxy values flow through the same path, and proxies are rejected when the effective HTTP version is HTTP/2 or HTTP/3 like the Go app.
- Added Rust proxy boundary tests for HTTP/2/HTTP/3 rejection and integration coverage for explicit proxy use, config-provided proxy, environment proxy, `--from-curl --proxy`, and the HTTP/2 rejection error.
- Enabled reqwest's `socks` feature and ported SOCKS proxy behavior for explicit `--proxy` and `--from-curl --proxy socks5://...` values. The existing proxy wiring now accepts SOCKS URLs without enabling native TLS, and the integration harness includes a local SOCKS5 proxy that verifies the Rust binary connects through the proxy rather than directly.
- Added a targeted Rust test proving SOCKS proxy URLs are accepted by the compiled reqwest feature set, plus integration coverage for direct CLI and curl-imported SOCKS5 proxy use.
- Ported `internal/complete` into `src/cli/completion.rs`: `--complete bash|fish|zsh` now emits the Go registration scripts, dynamic completion requests parse the trailing `-- ...` token stream, long/short flag completions use Go-shaped flag metadata, value completions cover enumerated options, and path completions cover file-valued flags plus `@file` body forms.
- Added translated Rust completion tests for bash/fish flag and value completions, shell registration/unsupported-shell errors, `--flag=value` completion prefixes, short aliases, and completion-specific extra-arg parsing; the integration harness now asserts bash registration, fish dynamic flag completion, bash dynamic value completion, and unsupported-shell output against the Rust binary.
- Tightened the JSON/NDJSON formatter parity from `internal/format/json.go` and `internal/format/ndjson.go`: strings now use Go-compatible escaping including DEL/control characters, keys use Go-style blue+bold color placement while values use green string coloring, object order and number lexemes are preserved via `serde_json` features, and `application/x-ndjson` dispatches through the formatter when `--format on`.
- Added translated Rust tests for `escapeJSONString`, `FormatJSONLine`, invalid/trailing JSON, streaming NDJSON values, object-order preservation, and numeric lexeme preservation; the integration harness now asserts formatted `application/x-ndjson` output against the Rust binary.
- Ported the CSV formatter from `internal/format/csv.go` into `src/format/csv.rs`: delimiter detection covers comma/tab/semicolon/pipe, parsing is lenient for ragged rows and lazy quotes, horizontal output aligns display widths, vertical output preserves Go-style row separators, and header/value ANSI coloring matches the existing formatter conventions.
- Added translated Rust tests for CSV formatting, delimiter detection, total-width calculation, vertical rendering, CJK display widths, ragged rows, extra columns, and color output; the integration harness now asserts formatted `text/csv` output against the Rust binary.
- Ported the Go `core.Printer` target-stream color policy into the Rust response/output path: `color = auto` now follows the stdout/stderr terminal status for formatted response bodies and progress rendering, `--color on` forces ANSI, and `--color off` disables it.
- Added the Rust `core::Printer`/`PrinterHandle` abstraction with Go-style ANSI `Sequence` emission, buffering, discard/flush helpers, and per-target color policy. JSON/NDJSON now writes through the central printer, and the other response formatter/progress style helpers route ANSI emission through the shared sequence writer instead of duplicating escape strings locally.
- Extended the central printer path to stderr metadata and inspection output: verbose request/response headers, status lines, redirect hops, `--inspect-dns`, and `--inspect-tls` now use Go-shaped ANSI styling for `--color on` and terminal `auto` color, including Go's dim `* ` informational prefixes for inspection output.
- Ported Go-style error/warning label rendering onto the same Rust printer: top-level CLI/runtime errors, certificate-validation `--insecure` hints, gRPC status errors, DNS inspection errors, and module warnings now use bold red `error` / bold yellow `warning` labels and bold flag hints when color is enabled.
- Wired Rust CSV response formatting to stdout terminal column detection, so terminal-width-triggered vertical CSV layout is now reachable through the CLI path rather than only through formatter unit tests.
- Added Rust tests for central printer buffering/color behavior, Go-style color auto/on/off behavior, error/warning label styling, parse-error color recovery, DNS/TLS inspection color rendering, OCSP status color rendering, and response-format CSV terminal-width dispatch; the integration harness now asserts `-vv --color on`, `--inspect-dns --color on`, `--inspect-tls --color on`, and colored parse/runtime CLI errors against the Rust binary.
- Ported the XML formatter from `internal/format/xml.go` into `src/format/xml.rs`: streaming XML parsing, indentation, empty-element expansion, declarations, comments, doctype directives, entity re-escaping, local tag/attribute names, and tag/attribute/text ANSI coloring now match the Go formatter shape used by the CLI.
- Added translated Rust tests for valid/malformed XML, exact element/attribute output, declarations/comments/directives, entity and character escaping, and color output; the integration harness now asserts formatted `application/xml` output and sniffed XML output against the Rust binary.
- Ported the YAML formatter from `internal/format/yaml.go` into `src/format/yaml.rs`: the Rust path preserves the original token text and layout for non-colored output, highlights mapping keys, string scalars, comments, tags, anchors, aliases, directives, merge keys, and document markers, and keeps syntax errors on obvious unterminated quote boundaries as formatter fallbacks.
- Added translated Rust tests for the Go YAML fixture set, output containment, structure preservation, quoted-scalar errors, and color output; the integration harness now asserts formatted `application/x-yaml` output against the Rust binary.
- Ported the CSS formatter from `internal/format/css.go` into `src/format/css.rs`: byte-oriented tokenization, selector/at-rule/declaration pretty-printing, comments, functions, nested at-rule bodies, keyframes, custom properties, missing-semicolon handling, top-level rule blank lines, and Go-shaped ANSI colors now match the Go formatter shape.
- Added translated Rust tests for CSS formatter/tokenizer coverage and an integration harness case that asserts formatted `text/css` output against the Rust binary.
- Ported the HTML formatter from `internal/format/html.go` into `src/format/html.rs`: doctype/comment/start/end/self-closing tokens, block and void element handling, inline text spacing, raw script text, `<pre>`/`<textarea>` whitespace preservation, attribute escaping, Go-shaped ANSI colors, and embedded `<style>` CSS formatting now match the Go formatter surface.
- Added translated Rust tests for the Go HTML formatter cases, attribute escaping, embedded CSS handling, color output, and an integration harness case that asserts formatted `text/html` output against the Rust binary.
- Ported the Markdown formatter from `internal/format/markdown.go` into `src/format/markdown.rs`: headings, blockquotes, lists, horizontal rules, fenced and indented code blocks, inline emphasis/code/links/images/autolinks, strikethrough, tables, CRLF normalization, front-matter YAML delegation, and fenced-code delegation to JSON/YAML/XML/HTML/CSS formatters now match the Go formatter surface covered by tests.
- Added translated Rust tests for the Go Markdown formatter cases, output-shape assertions, color styling, front-matter extraction/rendering, code-block delegation, block spacing, tables, multi-line links/code spans, and an integration harness case that asserts formatted `text/markdown` output against the Rust binary.
- Ported the MessagePack formatter from `internal/format/msgpack.go` into `src/format/msgpack.rs`: core MessagePack scalar/array/map/bin/extension values convert to compact JSON and then flow through the existing Rust JSON formatter, preserving formatted output and ANSI coloring behavior.
- Added translated Rust tests for the Go MessagePack unit case, nested values, numeric map keys, invalid UTF-8 replacement, malformed input rejection, color output, and an integration harness case that asserts formatted `application/vnd.msgpack` output against the Rust binary.
- Ported response charset transcoding from `internal/fetch/charset.go` into the Rust stdout formatting path: non-UTF-8 charsets are decoded before text formatter dispatch, UTF-8/ASCII/unknown charsets remain byte-for-byte unchanged, and image/MessagePack/Protobuf/gRPC binary formats skip charset conversion like Go.
- Added translated Rust tests for charset decoder no-op/known-label behavior, byte transcoding for ISO-8859-1 and Windows-1252, binary-format skip behavior, and charset-aware JSON formatting. The integration harness now asserts `application/json; charset=iso-8859-1` formatting against both Rust and the Go reference binary.
- Ported the HTTP timing waterfall surface from `internal/fetch/waterfall.go`: `--timing` now renders a waterfall after the response body is consumed, omits the `Body` phase for HEAD/empty bodies, works with `--discard`, and `-vvv` prints config, DNS, TCP, and TTFB debug lines through the central printer.
- Added translated Rust tests for timing duration formatting, waterfall labels/glyphs, omitted body phases, and zero-duration rendering.
- Added Go-style `-vv` request header metadata output so the existing verbosity integration case passes alongside `-vvv` timing debug output.
- Ported the non-interactive WebSocket path into `src/websocket/mod.rs`: WebSocket URLs now dispatch outside the regular HTTP pipeline, coerce non-GET methods to the effective GET upgrade with the Go warning, propagate headers/auth into the handshake, send `-d`/`-j` bodies as initial text messages, send piped stdin line-by-line, print text/binary frames, format JSON text frames as Go-style JSON lines, print verbose `101` upgrade metadata, support dry-run request metadata, and warn that `--timing` is unsupported.
- Added translated Rust tests for Go-style JSON-line formatting and WebSocket URL/header/signing/method helpers.
- Ported the WebSocket interactive helper/rendering layer from `internal/ws`: line-editor rune operations, escape-sequence cursor/delete handling, cursor-row response extraction/detection, message-text sanitization, display-width wrapping/fitting for wide runes, interactive message row counting, scroll-region setup/teardown, status/separator/input-line drawing, sent/received message wrapping, binary indicators, and JSON text-message formatting now live in `src/websocket/interactive.rs` with translated and targeted unit tests.
- Wired the WebSocket interactive terminal runtime into the Rust WebSocket path: `auto` now enters the prompt when stdin/stdout/stderr are terminals, `on` keeps the Go terminal requirement, `off` stays non-interactive, terminal-too-small falls back to read-only mode, raw terminal mode is restored on exit, DSR cursor-row detection preserves pending typed bytes, stdin/server/resize events are coordinated through the prompt loop, send failures restore the editor text, and initial `-d`/`-j` messages render as sent prompt messages.
- Added Unix/cgo PTY integration coverage for the compiled Rust binary's WebSocket interactive path: the Go harness runs `fetch` with stdin/stdout/stderr attached to a pseudo-terminal, answers the cursor-position probe, sends a typed message through the prompt, verifies the WebSocket server receives it, and asserts the TUI renders the echoed response.
- Ported the named cookie session slice into `src/session.rs`: session names are validated like Go, `FETCH_INTERNAL_SESSIONS_DIR` is honored, cookies are loaded from/saved to Go-shaped JSON files, expired cookies are filtered, host-only/domain/path/secure/http-only/same-site attributes are persisted, corrupted session files warn and start fresh, and the store is wired into reqwest's cookie provider so separate CLI invocations share cookies.
- Added translated Rust tests for valid/invalid session names, load/save round trips, expired-cookie filtering, foreign-domain and top-level public suffix rejection, host-only reload behavior, deletion cookies, and corrupted session files.
- Ported Go's full public-suffix session-cookie Domain policy using the static `psl` crate: multi-label public suffixes such as `github.io` are rejected when set from subdomains, and the RFC exception where the request host exactly equals the public suffix is converted to host-only before persistence/reload. Added Rust unit coverage and a Rust/Go integration parity case using the existing UDP DNS override.
- Ported regular HTTP Unix socket transport by wiring `--unix` into reqwest's Unix socket connector on Unix platforms while preserving the existing request/format/output pipeline.
- Added a Rust unit boundary test for the Unix socket builder path and verified the existing integration test against a real Unix-domain HTTP server.
- Ported the schema-less protobuf wire formatter from `internal/format/protobuf.go` into `src/format/protobuf.rs`, including varint/fixed32/fixed64/bytes fields, nested message detection, printable string escaping, and binary byte rendering.
- Ported gRPC frame parsing from `internal/grpc/framing.go` into `src/grpc/framing.rs` and wired `application/grpc+proto` response formatting through `src/format/grpc.rs` for unary and streaming framed responses.
- Added Go-style proto schema file existence validation in the Rust app layer for `--proto-file`, comma-separated `--proto-file` values, `--proto-desc`, and `--proto-import` so missing schemas fail before descriptor/protoc loading.
- Ported `internal/grpc/status.go` into `src/grpc/status.rs`, including code names, `grpc error: ...` display text, and percent-decoded `Grpc-Message` handling.
- Added minimal schema-less `--grpc` execution behavior: default method `POST`, default HTTP/2 selection unless `--http` overrides it, standard gRPC headers, empty/raw request-body framing, trailer/header `Grpc-Status` checks after body consumption, and Go-compatible non-OK gRPC exit/status output.
- Ported the regular request-construction parity slice from `internal/client`/`internal/cli`: direct `--method` values flow through the reqwest path with GET as the default, direct `--header` validation now preserves Go's empty-value support and invalid-name error shape, `Host` and custom headers remain observable through integration, `--query` parameters are merged and re-encoded like Go's `url.Values.Encode` including sorted keys and `+` spaces, and direct `--data` bodies now get Go-style content-type detection from filename extensions or sniffed bytes.
- Added translated/targeted Rust tests for method defaults/custom methods, header empty values and invalid names, Go-style query sorting/encoding, direct data body content-type detection, and Go-shaped `@file` missing-file/directory errors. The integration harness now asserts method/header/query/body/content-type behavior through the Rust binary.
- Ported the `--edit` request-body workflow from `internal/fetch/edit.go` into `src/http/edit.rs`: `VISUAL`/`EDITOR` precedence, Go-style editor argument splitting, preservation of unquoted executable paths containing spaces, fallback editor lookup, content-type-specific temp file extensions, existing body prefill, empty-body aborts, editor start/exit error wording, temp cleanup, and replayable owned edited bodies. The HTTP path now applies the effective body content type before editing and edits before gRPC framing, matching the Go request construction order.
- Added translated Rust tests for Go's `TestSplitArgs` and `TestFindEditor` cases plus request editing success, empty-body abort, editor exit-code errors, and content-type extension policy. The integration harness now uses the Go test binary as a cross-platform fake editor and asserts `--edit --json` edited request bodies plus empty-edited-body errors against the Rust binary.
- Ported the JSON DNS-over-HTTPS resolver slice from `internal/resolver/doh.go` into `src/dns/doh.rs`, including A/AAAA lookups, NXDOMAIN/rcode errors, TTL-preserving records, DoH query parameter replacement, IP-literal bypass, and reqwest resolver overrides for regular HTTP requests.
- Ported the regular HTTP UDP resolver slice from `internal/resolver/udp.go` into `src/dns/resolver.rs`: `--dns-server <IP[:PORT]>` values are parsed like Go, A/AAAA lookups run through the configured UDP server, IP literals bypass DNS, TTL metadata is parsed for unit parity, NXDOMAIN rcodes surface in lookup errors, and resolved addresses are injected into reqwest through `resolve_to_addrs` on the existing rustls client path.
- Added Rust UDP resolver tests for A/AAAA lookup, TTL parsing, IP-literal bypass, NXDOMAIN errors, and Go-compatible DNS server address parsing. The integration harness now includes a local UDP DNS server and verifies that the Rust binary can fetch `http://fetch-dns.test:<port>` through `--dns-server <udp addr>`.
- Ported `internal/dnsinspect` into `src/dns/inspect.rs`: `--inspect-dns` now runs outside the HTTP request pipeline, renders to stderr like Go, handles IP literals without a query, uses `/etc/resolv.conf` UDP targets or system resolver fallback, queries all Go-inspected record types concurrently through DoH or UDP, deduplicates records with the lowest TTL, normalizes generic CAA/SVCB/HTTPS RDATA, sorts rendered records, and warns about ignored request/auth/TLS/output flags.
- Added translated Rust DNS inspection tests for DoH rendering and TTLs, IP literals, concurrent record queries, duplicate CNAME TTL collapsing, UDP TTL parsing, default resolver fallback, resolver-target loopback avoidance, render sorting/TTL display, TTL/CAA formatting, generic HTTPS/CAA RDATA normalization, NXDOMAIN failures, and ignored-flag warning order. The integration harness now asserts `--inspect-dns --dns-server <local DoH URL>` output against the Rust binary.
- Ported the regular HTTP mTLS/client certificate slice into `src/tls/mod.rs`: CLI-provided CA roots are loaded into reqwest's rustls trust store, separate or combined client cert/key PEM files become reqwest identities, Go-style file-not-found and missing-key errors are preserved, and `--key` now emits the Go-compatible required-flag error instead of clap's default.
- Ported regular HTTP TLS version bounds from `internal/client`: `--tls`, `--min-tls`, and `--max-tls` are validated with Go-compatible values, default regular HTTP connections explicitly use TLS 1.2 as the minimum, and reqwest/rustls enforces configured min/max versions. Reqwest TLS source errors are expanded with Go-style `tls:` context when the lower-level rustls source would otherwise hide it from the CLI.
- Added translated Rust tests for TLS version parsing/defaults, config/direct-CLI TLS validation, and Go-style TLS request error hints. The integration harness now asserts a TLS 1.3-only server succeeds with exact `--min-tls 1.3 --max-tls 1.3` and fails when capped at `--max-tls 1.2`.
- Ported regular HTTP certificate-validation failure behavior from `internal/fetch`: Rust now classifies reqwest/rustls certificate verification failures, does not retry them, and prints the Go-style `If you absolutely trust the server, try '--insecure'.` hint. The integration harness now asserts a self-signed TLS server fails without retries, succeeds with `--insecure`, and the same case passes against the Go reference binary.
- Tightened regular HTTP runtime error presentation from `internal/fetch`: DNS override lookup failures, redirect-limit failures, request timeouts, and final reqwest transport errors now use a runtime error variant so they print like Go `fetch.Fetch` errors without the CLI `For more information` help footer. The integration harness now asserts that DoH NXDOMAIN, timeout, and redirect-limit failures preserve that no-help runtime surface against both Rust and the Go reference binary.
- Added top-level Tokio signal handling for SIGINT, SIGHUP, and SIGTERM on Unix, plus Ctrl-C on non-Unix, so interrupted Rust requests exit with code 1 and a Go-style `received signal: ...` runtime error instead of being terminated by the default process signal action.
- Ported the TCP `--inspect-tls` path into `src/tls/inspect.rs`: HTTPS/WSS URL validation, direct rustls handshake without an HTTP request, custom CA roots, `--insecure`, client certificates, HTTP/1 vs HTTP/2 ALPN selection, certificate chain/SAN/expiry rendering, and Go-style ignored-flag warnings.
- Ported stapled OCSP status rendering for TCP `--inspect-tls`: the Rust path captures the rustls verifier's OCSP response, parses the response status locally, and renders Go-style `OCSP: good|revoked|unknown (stapled)` output. The integration harness now staples a locally generated OCSP response and asserts the Rust binary renders it.
- Ported the QUIC `--inspect-tls --http 3` path into `src/tls/inspect.rs`: host/port resolution, Quinn/rustls QUIC handshakes without issuing an HTTP request, `h3` ALPN, custom CA roots, `--insecure`, client certificates, certificate chain rendering, and Go-style integration coverage with a local quic-go listener.
- Ported inspection-path TLS min/max enforcement: `--inspect-tls` now applies `--tls`/`--min-tls`/`--max-tls` when building direct rustls configs, TCP inspection fails against TLS 1.3-only servers when capped at TLS 1.2, HTTP/3 inspection rejects TLS ranges that exclude TLS 1.3, and direct rustls handshake errors include Go-style `tls:` context.
- Tightened `--inspect-tls` certificate-chain rendering to mirror Go's `ConnectionState.VerifiedChains` behavior: after verified handshakes, Rust appends an omitted trusted root or replaces a server-sent cross-signed root with the matching platform/custom trusted root so root expiry output reflects the validated chain. In `--insecure` mode, Rust keeps the raw peer chain like Go.
- Added Rust unit tests for verified-chain root replacement, omitted-root appending, and `--insecure` peer-chain fallback. A live check against `openfeed.ryanfowler.ca` now renders `GTS Root R4` with the trusted-root 2036 expiry instead of the server-sent cross-sign 2028 expiry.
- Ported descriptor-backed gRPC/protobuf support into `src/proto/mod.rs` and `src/grpc/reflection.rs`: `--proto-desc` loading, service/method/message lookup, JSON-to-protobuf conversion with unknown-field discard, client-streaming request framing from adjacent JSON objects, schema-aware gRPC response JSON formatting, local `--grpc-list`/`--grpc-describe`, TLS reflection, plaintext h2c reflection, actionable reflection-unavailable errors, and reflection-backed JSON unary calls.
- Wired descriptor-backed unframed `application/protobuf` response formatting for `--grpc` calls: when a local/reflected method response descriptor is available and the server replies with a plain protobuf body instead of `application/grpc+proto`, Rust now emits Go-style proto-JSON using proto field names, applies the existing JSON color path, and falls back to the raw body if descriptor decoding fails.
- Ported `--proto-file` compilation via external `protoc`: temporary descriptor-set generation, default proto-file directory imports, explicit `--proto-import` paths, multiple/comma-separated proto files, Go-compatible `protoc not found` and `protoc failed: ...` errors, and reuse of the descriptor-backed gRPC request/discovery path.
- Translated the remaining `internal/proto` descriptor/message/schema unit coverage into Rust tests, including descriptor-set file/byte loading, empty/invalid descriptor sets, message/service/method lookup, message/service listing, dynamic JSON-to-protobuf, protobuf-to-JSON, compact JSON, round trips, nested messages, and protoc error surfaces.
- Ported `internal/fileutil` into `src/fileutil.rs`: Unix `rename` replacement, Unix hard-link install for create-new semantics, Windows `MoveFileExW` replacement/install semantics through `windows-sys`, and translated tests for replacement, successful create-new install, and existing-target refusal. Session persistence now uses this helper for atomic replacement.
- Ported `internal/progress` into `src/output/progress.rs`: Go-compatible byte-size and duration formatting, progress bar and spinner `Read` passthrough wrappers, counter-based async progress hooks, render/start callbacks, native progress escape emission, no-color render shapes, final download summaries, and translated unit tests.
- Wired response output files through Go-style streaming temp-file writes and atomic install, using the progress helpers to emit non-silent `Downloaded ...` summaries for non-TTY stderr and terminal bar/spinner summaries for TTY stderr. The Rust path streams reqwest body frames into the output writer, preserves response trailers for gRPC status checks, and applies streaming gzip/zstd/`aws-chunked` decoding before writing output files. The integration suite now asserts the output-file summary surface and decoded gzip/zstd output files.
- Ported the integration-covered self-update path into `src/update.rs`: latest-release lookup via `FETCH_INTERNAL_UPDATE_URL`, platform/architecture artifact matching, Unix `.tar.gz` unpacking without preserving archive mtimes, in-place replacement, dry-run messages, update success/changelog output, metadata-command suppression, and background `--auto-update 0s` spawning.
- Ported the self-update hardening/unit-test slice from `internal/update`: Go-style `vX.Y.Z` tag detection for changelog refs, RFC3339 `metadata.json` last-attempt writes with atomic replacement, boolean/duration auto-update cadence parsing, Unix `flock` update locking for blocking `--update` and nonblocking auto-update checks, Unix replacement permission probing, and Unix tar.gz path-traversal/directory/truncation archive tests.
- Wired self-update artifact downloads through the progress helpers: terminal stderr receives Go-shaped bar/spinner progress based on `Content-Length`, non-TTY/silent update behavior remains quiet, and the line is cleared after download completion.
- Ported the Windows self-update release artifact selection/unpack slice from `internal/update/update_windows.go`: Windows assets now resolve to `fetch-<version>-windows-<arch>.zip`, zip archives are decoded with deflate support, directory entries and parent directories are created, regular files truncate existing destination files, and archive entries with parent traversal, absolute Unix paths, Windows drive prefixes, or leading backslash paths are rejected before extraction.
- Added translated Rust tests for the Go Windows zip archive path traversal cases, explicit directory entries, destination-file truncation, and Windows artifact URL matching.
- Ported the Windows self-update running-executable replacement slice from `internal/update/update_windows.go`: Rust now uses the Go-style temp/relocated/self-delete executable suffixes, copies the downloaded binary into place before renaming, rolls back when replacing the new executable fails, schedules the relocated old executable for deletion through a self-delete helper process with an inherited parent-process handle and `DELETE_ON_CLOSE`, handles `FETCH_INTERNAL_UPDATE_SELF_DELETE` at process startup, and uses `LockFileEx`/`UnlockFileEx` for Windows update-lock parity.
- Added Rust tests for the Windows self-delete environment payload parsing and Go-style temp executable suffix planning. The current macOS workspace does not have the `x86_64-pc-windows-msvc` Rust standard library installed, so `cargo check --target x86_64-pc-windows-msvc --all-features` could not compile the Windows-only cfg path here; this should be covered by Windows CI or a local Windows-target toolchain.
- Updated the Go integration harness to build the Rust binary by default and support `FETCH_BIN`.
- Updated repository build/release surfaces so the Rust binary is the primary implementation: README/docs/source-install instructions now use Cargo, CI runs Rust fmt/clippy/tests plus the Go integration harness against the Rust binary, and release artifacts are built from Cargo for Linux, macOS, and Windows targets.
- Added a Rust-native subprocess integration harness in `tests/integration.rs` and moved CI's primary integration step to `cargo test --locked --all-features --test integration -- --test-threads=1`. The new harness covers the primary CLI parse/error, completion, verbose/color output, request body construction, config merge/default search, Basic/Bearer/AWS/Digest auth, redirect/range/status/session/copy/discard handling, formatter dispatch/sniffing, output-file modes, retry body replay, timing waterfalls, regular HTTP/3 request/redirect/retry/session/proxy cases, descriptor-backed gRPC/protobuf client-streaming and `protoc`-compiled `--proto-file` cases, plaintext h2c and TLS gRPC reflection discovery/calls/unavailable errors, regular HTTP mTLS client-certificate cases, top-level SIGINT request cancellation, the integration self-update flow, Unix PTY image/WebSocket cases, and `--from-curl` flows against the Cargo-built `fetch` binary. The Go integration harness remains as the reference for future drift audits and platform-specific hardening.
- Added `/target` to `.gitignore`.

## Commands

```bash
# Rust formatting/lint/tests
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features

# Existing integration suite, now targeting the Rust binary by default
go test -v ./integration

# Run integration suite against an explicit binary
FETCH_BIN=/absolute/path/to/fetch go test -v ./integration

# Current Go reference commands
go test -v ./...
staticcheck ./...
```

## Current Known Gaps

- The Rust implementation is the integration-tested CLI path. Remaining differences are documented non-blocking gaps or platform hardening items rather than currently failing parity tests in this macOS workspace.
- Shell completion registration/dynamic completions, help descriptions, help line-width coverage, and common CLI parse errors are ported. Remaining CLI presentation differences include clap's repeatable `-v` help spelling (`--verbose...`) and any less-common parser errors not yet covered by translated tests.
- Remaining platform hardening that still needs dedicated runtime coverage includes Windows self-update execution on an actual Windows target and broader cross-platform PTY/resize coverage for terminal behavior.
- Response-output streaming progress summaries and atomic temp-file install are ported, including streaming gzip/zstd decoding for output files.
- `--from-curl` now parses and applies the Go-supported curl flags, including `--http3` now that regular HTTP/3 request execution is ported.
- Digest auth integration passes for direct CLI use, request bodies, `--from-curl`, and challenge responses after 303 redirects where the challenged request must be replayed as GET without the original body.
- AWS SigV4 integration passes for direct CLI use and body hashing. The Go unit test that canonicalizes a newline-containing header value is not exactly portable because `reqwest`/`http` rejects newline bytes in header values; the Rust test covers the same canonicalization path with leading/trailing spaces and tabs.
- Multipart integration passes for regular uploads and 307 redirect replay. The Rust implementation currently materializes multipart bodies into owned bytes; this preserves replay behavior but is less memory-efficient than the Go streaming pipe for large files.
- Output file integration passes for direct output, `-O`, `-J`, file-exists errors, `--clobber`, path traversal sanitization, Go-style final download summaries, temp-file atomic install, and decoded gzip/zstd output files.
- Range request integration passes for valid ranges, invalid range rejection, and multiple `Range` header values.
- Redirect integration passes for no-follow, default follow, max redirect errors, `-vv` redirect hop output, and no-retry redirect-limit behavior.
- Timeout integration passes for request timeout wording, valid connect timeout, invalid negative connect timeout, and retry on per-attempt timeout.
- Error handling and exit-code parity now covers CLI parse/validation errors with help footers, runtime fetch errors without help footers, HTTP status class exit codes, certificate-validation hints/no-retry behavior, timeout/connect-timeout wording, gRPC status errors, update/discard/copy/output errors, and top-level signal cancellation. The integration suite now asserts SIGINT request cancellation against both Rust and the Go reference binary.
- Compression integration passes for gzip, zstd, `aws-chunked` stacked encodings, and `--no-encode`.
- Server-Sent Events integration passes for `text/event-stream` with `--format on`.
- JSON and NDJSON formatting integration passes for sniffed JSON, direct CLI `--format`/`--color` behavior, colored config-driven JSON, `application/x-ndjson` with `--format on`, and non-UTF-8 charset transcoding before text formatter dispatch.
- HTTP version integration passes for regular HTTP requests: `--http 1` succeeds against the local HTTP/1 server and `--http 2` fails with the Go-compatible `http2:` error.
- HTTP/HTTPS/SOCKS proxy integration passes for direct `--proxy`, config files, environment variables, `--from-curl`, invalid proxy syntax errors, and HTTP/2 rejection.
- Request-body integration passes for direct data/JSON/XML/file/form/multipart bodies and `--edit` body editing, including the empty-edited-body abort path.
- Shell completion integration passes for bash registration, fish/bash dynamic completions, and unsupported-shell errors.
- Config integration passes for explicit `--config` files with `color`/`format`, metadata commands that ignore invalid config but still apply valid presentation settings, config-provided request headers/query/retry settings, config-time TLS PEM validation, parse-time proxy URL validation with file/line context, config/from-curl `key` without `cert` source behavior, direct `--tls` alias precedence over config `min-tls`, config-backed boolean/count source precedence for CLI and `--from-curl`, and default Unix/XDG config search.
- Metadata command integration passes for help/version/buildinfo best-effort config behavior. `--buildinfo` now follows Go's formatted-vs-compact output policy while reporting Rust-native compiler/settings/dependency fields instead of Go runtime/module fields.
- HTTP timing integration passes for `--timing`, `-T`, HEAD requests, retries, `--discard --timing`, `-vvv` config/DNS/TCP/TTFB debug text and color, and the WebSocket unsupported-warning path. Rust `--timing` enables DNS pre-resolution timing and wraps reqwest's connector service to report DNS and TCP phases before TTFB; reqwest does not currently expose a separate Go `httptrace`-style TLS handshake duration.
- Non-interactive WebSocket integration passes for echoing `-d` messages, scheme dispatch, verbose upgrade metadata, JSON text-frame formatting, piped stdin, bearer auth headers, gRPC exclusivity, non-GET method warnings, dry-run effective GET output, SIGINT exit, and the `--timing` warning.
- Session integration passes for persisted cookies across invocations, expired cookie suppression, isolated session names, and invalid session-name rejection.
- Unix socket integration passes on Unix platforms with `--unix <socket> http://unix/`.
- Schema-less protobuf, descriptor-backed unframed protobuf in `--grpc` mode, and gRPC framed response formatting integration passes for `application/protobuf`, `application/grpc+proto`, and streaming framed protobuf responses with `--format on`.
- Proto schema missing-file validation passes for `--proto-file` and `--proto-desc`, including the Go-compatible `file '<path>' does not exist` error surface.
- Schema-less gRPC status integration passes for framed responses that end with a non-OK `Grpc-Status` trailer; the Rust path now emits the Go-style `grpc error: INTERNAL: ...` message and exits non-zero.
- Descriptor-backed gRPC integration passes for local descriptor-set client streaming, local descriptor-set list/describe, TLS reflection list/describe/calls, plaintext h2c reflection and calls, reflection-unavailable errors, JSON-to-protobuf request conversion, and schema-aware protobuf JSON response output.
- `--proto-file` integration passes for protoc-compiled local schemas, including local `--grpc-list` discovery and gRPC client-streaming JSON conversion.
- DNS-over-HTTPS request resolution integration passes for `--dns-server http(s)://...`, including NXDOMAIN/no-such-host exit behavior. UDP DNS request resolution integration passes for `--dns-server <IP[:PORT]>` against a local DNS server. `--inspect-dns` passes translated unit coverage plus local-DoH integration coverage.
- Regular HTTP certificate validation integration passes for custom CA roots, `--insecure`, certificate verification failures, the `--insecure` hint, and no-retry behavior for certificate errors. Regular HTTP mTLS integration passes for separate cert/key files, combined cert+key files, missing client certificates, missing private keys, and missing cert/key file errors.
- Regular HTTP TLS min/max integration passes for TLS 1.2/1.3 through reqwest/rustls. Legacy TLS 1.0/1.1 values are still accepted for Go-compatible parsing/config surfaces, but they are no longer advertised in help or completions because the Rust TLS stack does not negotiate those deprecated protocol versions. Legacy-only ranges such as `--min-tls 1.0 --max-tls 1.1` now fail early on the Rust path with an implementation-neutral unsupported-range error instead of attempting a native-TLS/OpenSSL fallback.
- TLS inspection integration passes for both TCP and QUIC/HTTP3 `--inspect-tls` cases, including inspection-path TLS min/max enforcement, stapled OCSP status rendering for TCP, and Go-style verified-chain root rendering for TCP/QUIC peer chains. The remaining TLS inspection gap is QUIC cipher-suite rendering because Quinn's public handshake data exposes ALPN and peer identity but not the negotiated rustls cipher suite.
- Regular HTTP/3 request execution now passes local quic-go integration coverage for method/header/query/body propagation, custom CA roots, `HTTP/3.0` status output, 307 redirect body replay, 503 retry body replay, named-session cookie persistence, and Go-style plain-HTTP/proxy rejection. Remaining HTTP/3 hardening areas are lower-priority audits for reqwest unstable-feature behavior changes and less common redirect/retry/session edge cases over real QUIC servers.
- WebSocket interactive prompt/TUI runtime is ported: raw mode, DSR cursor detection, scroll-region prompt rendering, input editing/submission, server-message rendering, resize handling, initial message rendering, and send-failure recovery are implemented. Unix/cgo PTY integration now verifies the compiled Rust binary's explicit interactive prompt send/echo path; remaining hardening is cross-platform PTY coverage and resize/terminal-edge cases.
- Current config parity is complete for the Go `Config.Set` key surface: default search, explicit path handling, global/host/wildcard precedence, duplicate host-section replacement, `colour` alias support, request-option parsing/merging, config-time TLS PEM validation, proxy syntax validation with file/line context, `key`/`cert` source behavior, `--tls` alias precedence, invalid section/key-value errors, and clap-derived boolean/count source tracking are now ported. Future config additions should update `CliConfigSources` when a clap default cannot be distinguished from an explicit CLI value.
- Session persistence uses `cookie_store` for RFC domain/path/expiry matching and `psl` for Go-style public suffix Domain rejection, including multi-label public suffixes and the host-only exact-host exception.
- JSON, NDJSON, XML, YAML, HTML, CSS, CSV, Markdown, MessagePack, and terminal image rendering now pass translated/unit coverage and targeted integration dispatch cases. Environment-variable handling for image emulator detection and truecolor fallback matches the Go policy, including empty emulator variables, Windows Terminal, and ConEmu truecolor branches. Target-stream color auto/on/off, stderr metadata/inspection/error/warning color rendering, and TTY-width-triggered CSV vertical dispatch are wired and unit-tested; Unix/cgo PTY coverage now verifies terminal image block fallback, iTerm2 inline image protocol output, Kitty graphics protocol output, and WebSocket interactive rendering. Remaining terminal hardening is broader cross-platform PTY/resize coverage.
- Descriptor-backed unframed `application/protobuf` response formatting now matches the Go-observable path for `--grpc` calls with a method response descriptor, including proto field names and raw-body fallback on descriptor decode failure. A truly standalone regular-HTTP `--proto-desc`/`--proto-file` formatting mode is not present in the Go CLI and is not being introduced during the parity migration.
- Self-update integration passes on Unix with the local test release server. The Rust update path now has Go-shaped metadata timestamp writes, auto-update cadence parsing, Unix update locking, Unix no-write-permission probing, terminal artifact download progress, translated Unix tar archive hardening tests, translated Windows zip artifact selection/unpack tests, and a port of the Windows running-executable self-replace/self-delete plus update-lock path from `internal/update/update_windows.go`. The remaining gap is runtime validation on a Windows target; this macOS workspace only has the `aarch64-apple-darwin` Rust target installed.
- Retry integration coverage passes, and the Go retry helper unit coverage for exponential backoff, `Retry-After`, delay formatting, retryable statuses, and owned-body replay has been translated. The Go low-level `newReplayableBody` temp-spool/seekable-file tests are documented as not applicable to the Rust owned-byte request body model.
- The existing Go test command may need `GOCACHE`/`GOMODCACHE` pointed at a writable directory in sandboxed environments.

## Current Validation Baseline

- `cargo fmt` passes.
- `cargo clippy --all-targets --all-features -- -D warnings` passes.
- `cargo test --all-features` passes: 488 Rust unit tests plus 38 Rust integration tests.
- `cargo test --all-features --test integration -- --test-threads=1` passes: 38 Rust integration tests.
- `cargo build --release --locked` passes for the host target.
- `env HOME=/private/tmp/fetch-empty-home XDG_CONFIG_HOME=/private/tmp/fetch-empty-config FETCH_BIN=/Users/ryanfowler/code/fetch/target/debug/fetch GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod go test -count=1 -v ./integration` passes against the Rust binary.
- GitHub Actions workflow YAML parses after switching CI/release build steps to Cargo.
- Targeted CLI help/error parity tests now pass against both Rust and Go binaries through the same integration harness:

```bash
cargo test --all-features help_output_includes_go_descriptions_and_stays_under_80_columns
cargo test --all-features clap_parse_errors_are_rendered_like_go_parser
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration \
  -run 'TestMain/^(help|invalid flag|conflicting flags|missing flag argument|flag with disallowed value)$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go build -o /private/tmp/fetch-go .
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod FETCH_BIN=/private/tmp/fetch-go \
  go test -count=1 -v ./integration \
  -run 'TestMain/^(help|invalid flag|conflicting flags|missing flag argument|flag with disallowed value)$'
```

- Targeted terminal image PTY parity tests now pass against both Rust and Go binaries through the same integration harness:

```bash
cargo test --all-features image::tests
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration \
  -run '^TestImageRendering(PTY|InlinePTY|KittyPTY)$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod FETCH_BIN=/private/tmp/fetch-go \
  go test -count=1 -v ./integration \
  -run '^TestImageRendering(PTY|InlinePTY|KittyPTY)$'
```
- Targeted integration smoke against the Rust binary passes:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration \
  -run 'TestMain/^(help|no_url|too_many_args|invalid_flag|conflicting_flags|basic_auth|bearer_auth|data|form|ignore_status|sniff_json_without_content-type|sniff_xml_without_content-type|sniff_html_without_content-type|no_sniff_plain_text_without_content-type)$'
```

- Targeted `--from-curl` integration tests now pass against the Rust binary:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration -run 'TestMain/^from-curl'
```

- Targeted terminal color/CSV-width policy tests now pass:

```bash
cargo test --all-features color_enabled_matches_go_auto_policy
cargo test --all-features formatted_stdout_uses_go_color_auto_target_policy
cargo test --all-features formatted_stdout_auto_follows_stdout_terminal_like_go
cargo test --all-features formatted_stdout_passes_terminal_width_to_csv_like_go
cargo test --all-features error_and_warning_helpers_match_go_label_styles
cargo test --all-features parse_error_color_setting_is_recovered_like_go_partial_app
cargo test --all-features test_render_colors_dns_output_like_go
cargo test --all-features render_with_color_colors_tls_metadata_like_go
cargo test --all-features render_ocsp_status_matches_go_stapled_status_line
cargo test --all-features image::tests
go test -count=1 -v ./internal/format -run 'CSV|Json|JSON|Color'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration \
  -run 'TestMain/^(config_color|cli_color_and_format_flags|csv_formatting|ndjson_formatting|charset-aware_json_formatting|xml_formatting|yaml_formatting|html_formatting|markdown_formatting|msgpack_formatting|css_formatting)$'
go test -v ./integration -run 'TestMain/^(verbosity|inspect dns|inspect-tls)$'
go test -v ./integration -run 'TestMain/^(no url|invalid flag)$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/fetch -run 'Charset|Transcode'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod FETCH_BIN=/private/tmp/fetch-go \
  go test -count=1 -v ./integration -run 'TestMain/^charset-aware_json_formatting$'
```

- Targeted config source-precedence tests now pass against the Rust binary:

```bash
cargo test --all-features apply_file_treats_tls_alias_as_cli_min_tls_source_like_go
cargo test --all-features apply_file_preserves_bool_and_count_sources_when_config_sets_false
cargo test --all-features config_or_curl_key_without_direct_cert_does_not_trip_required_flag
cargo test --all-features client_identity_key_without_cert_is_ignored_after_cli_validation
cargo test --all-features config::tests
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration \
  -run 'TestMain/^config_(key_without_cert_is_ignored|min-tls_does_not_override_cli_tls_alias|source_precedence_from-curl_insecure|duplicate_host_section_replaces_previous_section)$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration -run 'TestMain/^from-curl_key_without_cert_is_ignored$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/config ./internal/cli -run 'TestParseFile|TestFromCurl|TestTLSFlags'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod FETCH_BIN=/private/tmp/fetch-go \
  go test -count=1 -v ./integration \
  -run 'TestMain/^config_duplicate_host_section_replaces_previous_section$'
```

- Targeted retry integration tests now pass against the Rust binary:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration -run 'TestMain/^retry'
```

- Targeted regular HTTP runtime error presentation tests now pass against both Rust and Go binaries through the same integration harness:

```bash
cargo test --all-features http::tests::exit_code_maps_status_classes
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration \
  -run 'TestMain/^(dns over https|timeout|redirects)$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go build -o /private/tmp/fetch-go .
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod FETCH_BIN=/private/tmp/fetch-go \
  go test -count=1 -v ./integration \
  -run 'TestMain/^(dns over https|timeout|redirects)$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration \
  -run 'TestMain/^request ctrl-c reports signal$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod FETCH_BIN=/private/tmp/fetch-go \
  go test -count=1 -v ./integration \
  -run 'TestMain/^request ctrl-c reports signal$'
```

- Targeted retry helper translation tests now pass:

```bash
cargo test --all-features retry
cargo test --all-features compute_delay
cargo test --all-features owned_request_body_clone_replays_without_go_temp_spool
go test -count=1 -v ./internal/fetch -run 'Retry|Backoff|RetryAfter|Replay|Body'
go test -count=1 -v ./integration -run 'TestMain/^retry|TestMain/^no_retry'
```

- Targeted WebSocket integration tests now pass against the Rust binary:

```bash
go test -count=1 -v ./integration \
  -run 'TestMain/^(websocket_echo_with_data_flag|websocket_scheme_auto-detection|websocket_verbose_shows_upgrade|websocket_json_formatting|websocket_piped_stdin|websocket_auth_header_sent|websocket_exclusive_with_grpc|websocket_non-GET_method_warns|websocket_dry-run|websocket_dry-run_non-GET_shows_effective_GET|websocket_ctrl-c_exits|timing_waterfall_websocket_warning)$'
```

- Targeted WebSocket interactive helper/runtime translation tests now pass:

```bash
cargo test --all-features websocket::interactive::tests::
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/ws
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration -run '^TestWebSocketInteractivePTY$'
```

- Targeted session integration tests now pass against the Rust binary:

```bash
cargo test --all-features session::tests::
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/session
go test -count=1 -v ./integration -run 'TestMain/^session$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go build -o /private/tmp/fetch-go .
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod FETCH_BIN=/private/tmp/fetch-go \
  go test -v ./integration -run 'TestMain/^session$/^public suffix domain cookies are rejected$'
```

- Targeted Unix socket integration now passes against the Rust binary:

```bash
go test -count=1 -v ./integration -run 'TestMain/^unix_socket$'
```

- Targeted DNS-over-HTTPS integration now passes against the Rust binary:

```bash
go test -count=1 -v ./integration -run 'TestMain/^dns_over_https$'
```

- Targeted UDP DNS request-resolution integration now passes against the Rust binary:

```bash
go test -count=1 -v ./integration -run 'TestMain/^udp dns server$'
```

- Targeted DNS inspection integration now passes against the Rust binary:

```bash
go test -count=1 -v ./integration -run 'TestMain/^inspect dns$'
```

- Targeted mTLS integration now passes against the Rust binary:

```bash
go test -count=1 -v ./integration -run 'TestMain/^mtls$'
```

- Targeted regular HTTP TLS min/max integration now passes against the Rust binary:

```bash
go test -count=1 -v ./integration -run 'TestMain/^tls version bounds$'
```

- Targeted legacy TLS/rustls limitation tests now pass:

```bash
cargo test --all-features legacy_tls
cargo test --all-features inspection_protocol_versions_document_rustls_legacy_limit
```

- Targeted regular HTTP certificate-validation tests now pass against both Rust and Go binaries through the same integration harness:

```bash
cargo test --all-features certificate_validation_messages_match_go_error_classes
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration \
  -run 'TestMain/^certificate validation failure suggests insecure and is not retried$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go build -o /private/tmp/fetch-go .
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod FETCH_BIN=/private/tmp/fetch-go \
  go test -count=1 -v ./integration \
  -run 'TestMain/^certificate validation failure suggests insecure and is not retried$'
```

- Targeted inspection-path TLS min/max tests now pass:

```bash
cargo test --all-features tls::inspect::tests::inspection_protocol_versions
cargo test --all-features inspect_http3_rejects_tls12_only_config_like_quic_tls
go test -count=1 -v ./integration -run 'TestMain/^tls version bounds$'
```

- Targeted TLS inspection integration now passes against the Rust binary:

```bash
cargo test --all-features tls::inspect::tests::
cargo test --all-features display_chain
go test -count=1 -v ./internal/tlsinspect
go test -count=1 -v ./integration -run 'TestMain/^inspect-tls$'
cargo run -- --inspect-tls openfeed.ryanfowler.ca --color off
```

- Targeted QUIC/HTTP3 TLS inspection tests now pass against the Rust binary:

```bash
cargo test --all-features inspect_http3_uses_quic_and_h3_alpn
go test -count=1 -v ./integration -run 'TestMain/^inspect-tls http3$'
```

- Targeted regular HTTP/3 request tests now pass against the Rust binary:

```bash
cargo test --all-features http3
go test -count=1 -v ./integration -run 'TestMain/^http3'
FETCH_BIN=/private/tmp/fetch-go go test -count=1 -v ./integration -run 'TestMain/^http3'
```

- Targeted terminal image rendering tests now pass:

```bash
cargo test --all-features image
cargo test --all-features image_off_returns_raw_image_bytes
cargo test --all-features validate_image_flag_matches_go_choices
go test -count=1 -v ./integration -run 'TestMain/^image off$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration -run '^TestImageRenderingPTY$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod FETCH_BIN=/private/tmp/fetch-go \
  go test -count=1 -v ./integration -run '^TestImageRenderingPTY$'
```

- Targeted protobuf/gRPC response formatting and gRPC status integration now passes against the Rust binary:

```bash
cargo test --all-features protobuf_response
cargo test --all-features protobuf_descriptor_decode_failure
cargo test --all-features protobuf_to_json_uses_proto_field_names_like_go
go test -count=1 -v ./integration \
  -run 'TestMain/^(protobuf_response_formatting|grpc_response_unframing|grpc_streaming_response|grpc_streaming_error_status)$'
```

- Targeted descriptor-backed gRPC client streaming and reflection integration now passes against the Rust binary:

```bash
go test -count=1 -v ./integration \
  -run 'TestMain/^grpc_client_streaming$|TestMain/^grpc_reflection_discovery_and_calls$'
```

- Targeted `internal/proto` translation and `--proto-file` compilation tests now pass:

```bash
cargo test --all-features proto::tests::
go test -count=1 -v ./internal/proto
go test -count=1 -v ./integration \
  -run 'TestMain/^grpc_client_streaming$/^proto-file compiles local schema$'
```

- Targeted `internal/fileutil` translation tests now pass:

```bash
cargo test --all-features fileutil::tests::
go test -count=1 -v ./internal/fileutil
```

- Targeted `internal/progress` translation tests now pass:

```bash
cargo test --all-features output::progress::tests::
go test -count=1 -v ./internal/progress
```

- Targeted response-output progress/atomic install tests now pass:

```bash
cargo test --all-features output::tests::write_output
go test -count=1 -v ./internal/fetch -run 'TestWriteOutputToFile|TestGetOutputValue'
go test -count=1 -v ./integration -run 'TestMain/^output$'
go test -count=1 -v ./integration \
  -run 'TestMain/^output$|TestMain/^(gzip_compression|zstd_compression)$'
```

- Targeted self-update integration now passes against the Rust binary:

```bash
cargo test --all-features update::tests::
cargo test --all-features update::tests::test_unpack_zip
go test -count=1 -v ./internal/update
go test -count=1 -v ./integration -run 'TestMain/^update$'
```

Windows-target compile validation was attempted with:

```bash
cargo check --target x86_64-pc-windows-msvc --all-features
```

It could not run in the current macOS workspace because the `x86_64-pc-windows-msvc` Rust standard library target is not installed.

- Targeted proto schema missing-file validation integration now passes against the Rust binary:

```bash
go test -count=1 -v ./integration \
  -run 'TestMain/^(proto-file_requires_protoc|proto-desc_file_not_found)$'
```

- Targeted Basic/Bearer auth translation and integration tests now pass:

```bash
cargo test --all-features basic_auth
cargo test --all-features bearer_auth
cargo test --all-features basic_header
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/cli \
  -run 'TestDigestFlag|TestAWSSigv4CredentialsAreNotLoadedDuringParse|TestFromCurlAWSSigv4CredentialsAreNotLoadedDuringParse'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration \
  -run 'TestMain/^(basic auth|basic auth invalid format|bearer auth|from-curl with basic auth)$'
```

- Targeted URL/default-scheme translation and integration tests now pass:

```bash
cargo test --all-features default_scheme
cargo test --all-features test_is_loopback
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/client -run TestIsLoopback
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration -run 'TestMain/^default scheme loopback$'
```

- Targeted request-construction translation and integration tests now pass:

```bash
cargo test --all-features method_defaults
cargo test --all-features apply_headers
cargo test --all-features apply_query
cargo test --all-features request_body
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/cli \
  -run 'TestHeaderFlag|TestLongFlagExplicitEmptyValue'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/config -run TestParseHeader
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration \
  -run 'TestMain/^(data|request construction|host header)$'
```

- Targeted `--edit` request-body translation and integration tests now pass:

```bash
cargo test --all-features edit
go test -count=1 -v ./internal/fetch -run 'TestSplitArgs|TestFindEditor'
go test -count=1 -v ./integration -run 'TestMain/^edit request body$'
```

- Targeted Digest integration tests now pass against the Rust binary:

```bash
cargo test --all-features digest_challenge_after_redirect_uses_go_redirect_method_and_body
go test -count=1 -v ./internal/fetch -run 'TestDoOnceDigestAfterRedirectUsesChallengedRequest'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration -run 'TestMain/.*digest'
```

- Targeted AWS SigV4 integration tests now pass against the Rust binary:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration -run 'TestMain/.*AWS|TestMain/.*aws'
```

- Targeted multipart integration tests now pass against the Rust binary:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration \
  -run 'TestMain/.*multipart|TestMain/.*form file|TestMain/.*form field'
```

- Targeted output filename integration tests now pass against the Rust binary:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration \
  -run 'TestMain/^(output-current-dir|remote-name_ignores_content-disposition|remote-header-name_uses_content-disposition|remote-header-name_requires_remote-name|file_exists_error|direct_output_file_exists_error|clobber_overwrites_existing_file|path_traversal_blocked_in_content-disposition)$'
```

- Targeted range request integration now passes against the Rust binary:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration -run 'TestMain/^range_request$'
```

- Targeted redirect integration now passes against the Rust binary:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration \
  -run 'TestMain/^redirects$|TestMain/^no_retry_on_redirect_limit_exceeded$'
```

- Targeted timeout integration now passes against the Rust binary:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration \
  -run 'TestMain/^(timeout|connect_timeout|connect_timeout_invalid|retry_on_per-attempt_timeout)$'
```

- Targeted compression integration now passes against the Rust binary:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration -run 'TestMain/^(gzip_compression|zstd_compression)$'
```

- Targeted Server-Sent Events integration now passes against the Rust binary:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration -run 'TestMain/^server_sent_events$'
```

- Targeted JSON/NDJSON formatter translation and integration tests now pass:

```bash
cargo test --all-features format::json
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/format \
  -run 'TestFormatJSONLine|TestFormatJSONLineInvalid|TestFormatJSONLineTrailingData|TestEscapeJSONString'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration -run 'TestMain/^ndjson formatting$'
```

- Targeted CSV formatter translation and integration tests now pass:

```bash
cargo test --all-features format::csv
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/format \
  -run 'TestFormatCSV|TestDetectDelimiter|TestCalculateTotalWidth|TestVertical|TestUnicodeDisplayWidth'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration -run 'TestMain/^csv formatting$'
```

- Targeted XML formatter translation and integration tests now pass:

```bash
cargo test --all-features format::xml
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/format \
  -run 'TestFormatXML|TestEscapeXMLString'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration \
  -run 'TestMain/^xml formatting$|TestMain/^sniff xml without content-type$'
```

- Targeted YAML formatter translation and integration tests now pass:

```bash
cargo test --all-features format::yaml
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/format -run 'TestFormatYAML'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration -run 'TestMain/^yaml formatting$'
```

- Targeted HTML formatter translation and integration tests now pass:

```bash
cargo test --all-features format::html
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/format -run 'TestFormatHTML|TestEscapeHTMLAttrValue'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration \
  -run 'TestMain/^(html formatting|sniff html without content-type)$'
```

- Targeted Markdown formatter translation and integration tests now pass:

```bash
cargo test --all-features format::markdown
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/format -run TestFormatMarkdown
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration -run 'TestMain/^markdown formatting$'
```

- Targeted MessagePack formatter translation and integration tests now pass:

```bash
cargo test --all-features format::msgpack
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/format -run TestFormatMsgPack
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration -run 'TestMain/^msgpack formatting$'
```

- Targeted CSS formatter translation and integration tests now pass:

```bash
cargo test --all-features format::css
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/format -run 'TestFormatCSS|TestCSSTokenizer'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration -run 'TestMain/^css formatting$'
```

- Targeted HTTP version integration now passes against the Rust binary:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration -run 'TestMain/^http_version$'
```

- Targeted proxy integration now passes against the Rust binary:

```bash
go test -count=1 -v ./integration -run 'TestMain/^proxy'
```

- Targeted SOCKS proxy integration now passes against the Rust binary:

```bash
cargo test --all-features proxy
go test -count=1 -v ./integration -run 'TestMain/^socks proxy$'
```

- Targeted shell completion translation and integration tests now pass:

```bash
cargo test --all-features cli::completion
cargo test --all-features extra_args
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./internal/complete
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -count=1 -v ./integration -run 'TestMain/^shell completion$'
```

- Targeted config and metadata integration now passes against the Rust binary:

```bash
cargo test --all-features build_info
cargo test --all-features config::tests::parse_file_rejects_invalid_proxy_value_like_go
cargo test --all-features config::tests::validate_proxy_flag_matches_go_cli_behavior
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration \
  -run 'TestMain/^(config_color|config_request_options|config_TLS_PEM_validation|config_key_without_cert_is_ignored|config_min-tls_does_not_override_cli_tls_alias|config_invalid_proxy_preserves_file_context|default_config_search|metadata_commands_use_best-effort_config|help|no_url|too_many_args|invalid_flag|invalid_proxy_flag|conflicting_flags)$'
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod FETCH_BIN=/private/tmp/fetch-go \
  go test -count=1 -v ./integration \
  -run 'TestMain/^(config invalid proxy preserves file context|invalid proxy flag|metadata commands use best-effort config)$'
```

- Targeted HTTP timing/verbosity integration now passes against the Rust binary, including colored `-vvv` config/DNS/TCP/TTFB metadata:

```bash
env GOCACHE=/private/tmp/fetch-gocache GOMODCACHE=/private/tmp/fetch-gomod \
  go test -v ./integration \
  -run 'TestMain/^(timing_waterfall|timing_waterfall_short_flag|timing_waterfall_without_debug_text|timing_waterfall_with_debug|timing_waterfall_HEAD_request|timing_waterfall_with_retry|discard|verbosity)$'
```

- Latest full `go test -count=1 -v ./integration` against the Rust binary passes.
