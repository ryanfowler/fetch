# HTTP development notes

Applies to `src/http/` and its submodules.

- Transport code owns DNS/TCP/TLS/QUIC setup. Reuse `src/net.rs` dialing, proxy, timeout, and address-racing helpers.
- Automatic HTTP/3 discovery applies only to eligible direct HTTPS requests. It must not delay normal TCP/TLS and must share the already-started connect-timeout budget.
- Keep HTTP/3 cache entries bounded, origin/resolver scoped, authority-based, and expiring. Never learn Alt-Svc from insecure responses.
- Retry protocol NACKs only when safe and when the request body is replayable.
- Body descriptors must preserve replay behavior: files and multipart sources reopen; stdin streams once and errors if replay becomes necessary.
- `Content-Length` inference stays centralized in `src/http/mod.rs` and runs only when neither `Content-Length` nor `Transfer-Encoding` was supplied.
- Digest authentication validates challenges before replay checks and cleans up abandoned 401 bodies with bounded work.
- Keep request/DoH/WebSocket origin TLS settings separate from HTTPS proxy TLS settings.
- Response responsibilities remain split between `response/stdout.rs`, `response/stream.rs`, `response/formatters.rs`, and `response/metadata.rs`.
- SSE, NDJSON, and gRPC stdout streaming use the shared callback driver. Keep parsing format-specific and buffering bounded.
- Do not emit binary-looking bodies to terminal stdout unless the user explicitly forces stdout output.
- Put MIME selection policy in `src/format/content_type.rs`; update user documentation for visible format or MIME changes.
