# fetch

Guidance for AI agents working in this repo. Keep this file current when behavior or workflow changes.

## Snapshot

`fetch` is a Rust terminal-native API client (`cargo` binary: `fetch`) for HTTP requests, streaming, WebSockets, gRPC/reflection/protobuf, DNS/TLS inspection, timing, auth (Basic/Digest/Bearer/AWS SigV4), rich response formatting (JSON/XML/YAML/HTML/CSS/CSV/Markdown/msgpack/protobuf/SSE/NDJSON/images), and self-update/session workflows.

## Commands

Rust code changes:

```bash
cargo fmt
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features --lib --bins
```

Then run the narrowest relevant test, e.g.:

```bash
cargo test --locked --all-features --test http request_construction_and_data_sources
cargo test --locked --all-features image::
```

Full CI-equivalent before PRs, shared transport/request/response changes, or unclear scope:

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features --lib --bins
cargo test --locked --all-features --test cli --test formatting --test grpc --test http --test network --test terminal --test update --test websocket
```

The integration test suite uses `TcpListener::bind("127.0.0.1:0")` and
`UdpSocket::bind("127.0.0.1:0")` for all test servers, so tests are safe to run in
parallel. If transient "Connection refused" errors occur from port reuse races, add
`-- --test-threads=1` to force sequential execution. The `TestServer` and
`H3TestServer` use `mpsc` channels instead of polling for request notification.

Docs-only changes: skip Cargo unless examples/generated CLI output changed; format changed docs only:

```bash
prettier -w README.md docs/**/*.md AGENTS.md
```

Release/package/update validation only:

```bash
cargo build --release --locked
```

## Architecture Map

| Area | Files | Notes |
| --- | --- | --- |
| Entry | `src/main.rs`, `src/app.rs`, `src/cli.rs` | `main` uses a larger-stack Tokio thread; `app` heap-pins the top-level future. Do not revert. |
| Core IO | `src/core.rs`, `src/output`, `src/fileutil.rs` | Central printer/color/format/stdout policy, atomic writes, `~/` expansion, cross-platform locks. Prefer `core::write_stdout`, `core::stdio`, `core::color_enabled`, `core::format_enabled`; avoid direct `print!`/`println!` and ad-hoc terminal checks. |
| Config | `src/config` | INI with host overlays. Config-backed options belong in `config_options!`; duplicate host sections are errors. Metadata commands parse config best-effort only. |
| HTTP | `src/http`, `src/http/response`, `src/http/transport`, `src/net.rs` | Request building/execution, response orchestration, retries, proxies, TLS, Unix sockets, timing. Transport code owns DNS/TCP/TLS/QUIC setup; reuse `src/net.rs` dialing/proxy helpers. |
| DNS | `src/dns` | Custom UDP/TCP/TLS/QUIC/DoH resolvers, inspection, HTTPS/SVCB, EDNS/truncation fallback. Reuse `custom.rs`, `wire.rs`, `doh.rs`; inspection orchestration/rendering stays under `src/dns/inspect*`. |
| TLS | `src/tls` | Shared rustls config, client auth, min/max TLS, ECH, inspection. Inspection orchestration in `inspect.rs`; cert/DER/render helpers stay split. |
| Formatting | `src/format`, `src/format/content_type.rs`, `src/image` | MIME-to-formatter policy, streaming formatters, built-in image defaults; external image adapters only for `--image external`/config and must be bounded. |
| gRPC/protobuf | `src/grpc`, `src/proto` | Framing/status/reflection, local schema/discovery/conversion/JSON streams. Reuse standard gRPC headers/status/framed-body helpers. |
| WebSocket | `src/websocket` | Interactive and non-interactive message loops; custom dialer for DNS/proxy/TLS. |
| Auth/session/update | `src/auth`, `src/session.rs`, `src/update`, `install.sh` | Auth helpers; locked cookie sessions; HTTPS self-update with checksum/archive validation and no origin-specific TLS overrides. |
| Tests | `tests/`, `tests/support/` | Integration tests run the compiled binary; support code is split by domain. `run_fetch` isolates HTTP/3 cache by default. `TestServer`/`H3TestServer` use `mpsc` channel notification (not polling). `wait_for_requests` blocks via `recv_timeout` on the notification channel. |

Request flow: CLI parse → config merge → request build (gRPC may load/reflect schema and frame protobuf) → transport execute → response format/output/pager/clipboard.

## Invariants & Implementation Notes

### Transport, DNS, TLS, HTTP/3

- Direct HTTPS can opportunistically discover HTTP/3 via HTTPS/SVCB `h3`; proxy, Unix socket, explicit `--http`, gRPC, and WebSocket paths bypass auto-H3. Explicit `--http 1|2|3` forces a version, not a cap.
- Auto-H3 must not delay normal TCP/TLS: start SVCB discovery in parallel, race QUIC only if a usable candidate appears before TCP/TLS wins, and share the started `--connect-timeout` budget across branches. Use `net::race_staggered`/`AbortOnDropJoin` for per-address races.
- HTTP/3 alternatives are cached as bounded sharded JSON under `http3/<prefix>/<hash>.json`, scoped by normalized origin + resolver key, storing alternative authorities (not IPs), expiring by SVCB TTL/Alt-Svc `ma` with a hard cap. Never use for proxy, Unix socket, IP literal, non-HTTPS, explicit `--http`, gRPC, or WebSocket. Do not learn Alt-Svc from `--insecure` responses.
- Preserve reqwest-like safe retries for HTTP/2/3 protocol NACKs (`REFUSED_STREAM`, `GOAWAY(NO_ERROR)`, HTTP/3 connection timeout) only when the request body is replayable.
- Custom/direct DNS is scoped per request URL and redirect target. A/AAAA run concurrently and may proceed once one family succeeds; preserve successful records if the other fails, resolver order in diagnostics, IPv6 scope IDs, and Happy Eyeballs staggering.
- `--dns-server` schemes: bare/`udp://IP[:PORT]`, `tcp://`, `tls://`/`dot://` (853), `quic://`/`doq://` (853). TLS/QUIC resolver hostnames resolve via system DNS and provide SNI/verification.
- UDP DNS advertises EDNS(0), randomizes IDs, falls back to TCP on truncation using the remaining timeout, and uses a 5s receive timeout when no request/connect timeout exists. DoH uses RFC8484 POST first, JSON fallback, shared `DohClient` for concurrent families, main transport pooling, and a 1 MiB response cap.
- Timeout handling lives in `src/duration.rs`; use `TimeoutBudget` for HTTP/WebSocket/DNS/TLS, cap sleeps/work to remaining budget, and preserve the original request-timeout diagnostic.
- TLS versions are only 1.2/1.3. `--tls` aliases min TLS; prefer `--min-tls`/`--max-tls` in docs. rustls uses `aws-lc-rs` with post-quantum preference enabled.
- ECH: flags `--ech auto|on|off`, `--ech-config`, `--ech-grease`, `--ech-hard-fail`; ECH comes from HTTPS/SVCB key 5 or explicit config, requires TLS 1.3, and is fetched even when remote-resolving proxies skip A/AAAA. DNS inspection prints `ECH=<base64>`.
- Request/DoH HTTPS/`wss://` use rustls platform verification while preserving request-path CA, mTLS, `--insecure`, and TLS min/max. HTTPS proxy TLS is separate and must not inherit origin CA/client auth/`--insecure`.

### Requests, bodies, retries, curl

- Request `Content-Length` inference is centralized in `src/http/mod.rs` and only runs when neither `Content-Length` nor `Transfer-Encoding` was supplied.
- Body-producing flags (`--data`, `--json`, `--xml`, `--form`, `--multipart`, `--edit`) infer `POST` unless `--method` is explicit; explicit methods (including GET with body) win.
- Retryable uploads use replayable body descriptors, not one universal `Vec<u8>`: file/multipart sources reopen for retries/307/308; stdin streams once and errors if replay is required. Multipart boundaries are stable; multipart part headers/content type/length are resolved when built.
- Digest auth retries use bounded cleanup for 401 bodies and retry through a fresh client before dropping an abandoned challenge body; malformed/unsupported challenges fail before replay checks.
- `--basic`/`--digest` preserve exact bytes around the first colon; do not trim spaces.
- `--from-curl` should no-op only defaults/presentation flags. Unsupported semantic flags (`-n`, `--netrc`, `-f`, `--fail`, `-N`, `--no-buffer`, `--proto-default`, `--proto-redir`, etc.) must diagnose clearly. Single `-d @file`/`@-` uses native streaming; composite data/materialized `--data-urlencode @file` caps at 16 MiB.
- Schemeless URLs default to HTTPS for hostnames and HTTP for `localhost`/IP literals; dry-run shows normalized absolute URL and HTTPS plaintext failures suggest `http://`.
- Default request `Accept` is `application/json, */*;q=0.5`. `--sort-headers` sorts displayed headers only.

### Response/output/formatting

- Response handling split: `stdout.rs` terminal/pager policy; `stream.rs` decoded streaming, shared sink copy, formatter callback driver, trailers/byte counts/clipboard/broken-pipe handling; `formatters.rs` buffered/streaming body formatting; `metadata.rs` timing/clipboard/status metadata.
- SSE, NDJSON, and gRPC formatted stdout streaming share the `stream.rs` callback driver. Keep per-format parsing in callbacks; NDJSON pending records cap at `MAX_BUFFERED_RESPONSE_BYTES`.
- Binary-looking bodies are not written to terminal stdout unless forced with `--output -`, for both buffered fallback and raw streaming (`--format off`).
- `--compress auto|br|gzip|zstd|off` controls negotiation/decoding (`brotli` aliases `br`). Output files receive decoded bodies by default; document `--compress off` for byte-for-byte compressed downloads.
- Auto-compressed SSE retries without `Accept-Encoding` only for safe methods (`GET`/`HEAD`); unsafe methods warn and keep the original response.
- Pager: `--pager auto|on|off`; `NO_PAGER` disables auto fallback; `$PAGER` is shell-split but launched directly; `$LESS` suppresses fallback flags. Images/output files bypass pager.
- `--copy` tees decoded stdout/output-file bodies to platform clipboard commands, skips >1 MiB, and bounds stdin/write/wait, killing hung backends with a warning.
- Content type policy belongs in `src/format/content_type.rs`; update README/docs when user-visible formats or MIME behavior change.

### gRPC/protobuf

- `--grpc-list`/`--grpc-describe` use reflection or local descriptors; `--grpc` auto-reflects when no local schema is supplied. Plaintext loopback h2c is gRPC-only.
- gRPC requests advertise `grpc-accept-encoding: gzip`; compressed response frames use `grpc-encoding` and unsupported encodings report by name.
- Reflection framed-body reads are bounded by decoded bytes and message count. Client/bidi streaming should stream incremental JSON into framed protobuf without materializing full input; stdin uses the shared incremental parser, whitespace skipping, `framing::MAX_MESSAGE_SIZE`, and Windows pipe peeking.
- `application/grpc+proto` formatted responses stream complete frames immediately while preserving trailers.

### WebSocket

- Requires HTTP/1.1 upgrade; reject explicit `--http 2|3`. Output-file/clipboard/retry flags are invalid because the path streams through the message loop.
- Interactive prompt default is controlled by `--ws-interactive auto|on|off`.
- Non-interactive stdin connects before reading piped input, sends lines concurrently with receive, preserves empty text lines, closes send half at EOF, and continues receiving. `--ws-message-mode auto|text|binary`; `auto` sends invalid UTF-8 as binary, `binary` streams raw chunks.
- Text output locks stdout, flushes per message, and treats broken pipe as normal. Incoming binary writes raw bytes only to non-terminal stdout; terminals use a guard. Incoming frames/messages are capped at 16 MiB.
- URL userinfo becomes Basic auth on the stripped URL unless explicit auth headers/options override. `wss://` honors request TLS options; `ws://` rejects TLS flags. DNS/proxy/connect timeout behavior mirrors HTTP, with SOCKS5H resolving remotely and plain SOCKS5 locally. Sessions send/persist cookies on successful handshakes.

### Inspection, sessions, update, platform

- `--inspect-dns` resolves without HTTP, shows common records/backend/duration/TTLs, retries truncated UDP over TCP, and exits non-zero with a warning if fallback cannot complete a record type.
- `--inspect-tls --http 3` uses QUIC/TLS with `h3`; inspection honors `--dns-server`. Verified chain rendering may append/replace trusted roots for expiry display; `--insecure` shows raw peer chain.
- Session saves lock per session, reload latest JSON, merge only local cookie changes, atomically replace, and warn on bounded lock wait. Update locks use `fileutil::FileLock`; background checks are nonblocking.
- Self-update metadata/artifact/checksum/redirect URLs require HTTPS except internal test overrides; update networking must not inherit origin-specific TLS/version/Unix-socket config, but may keep proxy/DNS/timeouts/verbosity/custom CA. Artifacts stream with SHA-256; tar extracts streaming, zip uses temp archive; Unix replacement preserves atomic parent-dir sync.
- `install.sh` verifies `.sha256`; completion install is opt-in (`--completions` or `FETCH_INSTALL_COMPLETIONS=1`) and must not auto-edit shell startup files by default.
- Ctrl-C/SIGINT exits 130, including streaming modes. Output downloads keep `*.download` temps under a drop guard.
- Rust is pinned to 1.96.0 (`rust-toolchain.toml`); keep `Cargo.toml` rust-version and CI aligned. Windows config search prefers XDG/HOME paths before AppData; Windows mTLS fixtures use RSA certs.
- GitHub Actions run fmt/clippy/unit/integration. Release builds archive names for self-updater, Linux GNU uses `cargo-zigbuild` with glibc 2.28 floor, Windows uses static MSVC CRT, archives get SHA-256 sidecars, `FETCH_VERSION` comes from release tag/manual version (local: matching `v*`, then `git describe`, then `v0.0.0-dev`), and `vcs.modified` ignores untracked files.

## Docs

README is high-level; detailed docs are under `docs/`. Keep docs and generated CLI output aligned with code. The `--edit` workflow accepts `VISUAL`/`EDITOR` values with flags and preserves executable paths containing spaces even when unquoted.
