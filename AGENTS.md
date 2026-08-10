# fetch development guide

Repository-specific guidance for AI agents. Update this file only when the development workflow, architecture, or non-obvious implementation constraints change. User-facing behavior belongs in `README.md`, `docs/`, and tests.

## Workflow

- Inspect nearby code and tests before editing; preserve unrelated working-tree changes.
- Prefer existing abstractions and patterns over parallel implementations.
- Add or update tests for behavior changes. Update docs when flags, defaults, output, configuration, or examples change.
- During development, run the narrowest relevant test first, for example:

```bash
cargo test --locked --all-features --test http request_construction_and_data_sources
cargo test --locked --all-features image::
cargo test --locked --all-features --test install
```

## Validation

For Rust changes, run before completion:

```bash
cargo fmt
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features --lib --bins
```

Run the full CI-equivalent suite before PRs and for shared transport/request/response changes or unclear scope:

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features --lib --bins
cargo test --release --locked --all-features --test cli --test formatting --test grpc --test har --test http --test install --test network --test terminal --test update --test websocket -- --test-threads=2
```

For docs-only changes, skip Cargo unless examples or generated CLI output changed:

```bash
prettier -w README.md "docs/**/*.md" "**/AGENTS.md"
```

For release/package/update validation only:

```bash
cargo build --release --locked
```

Report the checks run and any checks not run.

## Architecture

| Area                  | Main code                                                      | Integration tests                          |
| --------------------- | -------------------------------------------------------------- | ------------------------------------------ |
| Entry and CLI         | `src/main.rs`, `src/app.rs`, `src/cli.rs`                      | `tests/cli.rs`                             |
| Config and core IO    | `src/config/`, `src/core.rs`, `src/output/`, `src/fileutil.rs` | `tests/cli.rs`, `tests/terminal.rs`        |
| HTTP and transport    | `src/http/`, `src/net.rs`                                      | `tests/http.rs`, `tests/network.rs`        |
| DNS and TLS           | `src/dns/`, `src/tls/`                                         | `tests/network.rs`                         |
| Formatting and images | `src/format/`, `src/image/`                                    | `tests/formatting.rs`, `tests/terminal.rs` |
| gRPC and protobuf     | `src/grpc/`, `src/proto/`                                      | `tests/grpc.rs`                            |
| WebSocket             | `src/websocket/`                                               | `tests/websocket.rs`                       |
| Auth and sessions     | `src/auth/`, `src/session.rs`                                  | `tests/http.rs`                            |
| Update and skills     | `src/update/`, `src/skill.rs`, `install.sh`, `skills/fetch/`   | `tests/update.rs`, `tests/install.rs`      |

Request flow: CLI parse → config merge → request construction → transport → response formatting/output.

Read the nearest scoped guide before changing these areas:

- `src/http/AGENTS.md`
- `src/dns/AGENTS.md`
- `src/grpc/AGENTS.md` and `src/proto/AGENTS.md`
- `src/websocket/AGENTS.md`
- `src/update/AGENTS.md`
- `tests/AGENTS.md`

## Cross-cutting rules

- Preserve the spawned Tokio runtime in `src/main.rs`; stack-heavy entry futures must not move back to the process main thread.
- Use `core::write_stdout`, `core::stdio`, `core::color_enabled`, and `core::format_enabled`; avoid direct `print!`/`println!` and ad-hoc terminal checks.
- Use `TimeoutBudget` from `src/duration.rs` for timeout-aware HTTP, WebSocket, DNS, and TLS work. Cap sleeps and nested operations to the remaining budget.
- Reuse dialing, proxy, and address-racing helpers in `src/net.rs`. Do not create subsystem-specific copies.
- Bound all externally controlled buffering and preserve streaming where the surrounding path streams.
- Preserve request-body replayability semantics across authentication retries, transport retries, and 307/308 redirects; stdin is not replayable.
- Keep HTTPS proxy TLS configuration separate from origin TLS configuration.
- Use atomic file helpers and cross-platform locks for persistent state. Downloads must retain their temporary-file drop guards.
- Config-backed options belong in `config_options!`. Metadata commands parse config best-effort.
- Content-type-to-formatter policy belongs in `src/format/content_type.rs`.
- Skill installation remains offline and embedded; do not add network downloads or agent-configuration edits.
- Ctrl-C/SIGINT exits with status 130, including streaming modes.
- Rust is pinned in `rust-toolchain.toml`; keep it aligned with `Cargo.toml` and CI.
