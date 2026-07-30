# WebSocket development notes

Applies to `src/websocket/` and its submodules.

- WebSocket handshakes require HTTP/1.1. Keep explicit HTTP/2 and HTTP/3 rejection at validation boundaries.
- Reuse HTTP networking semantics for DNS, proxies, TLS, and connect-timeout budgeting; SOCKS5H resolves remotely while SOCKS5 resolves locally.
- Non-interactive mode connects before consuming piped stdin, sends and receives concurrently, closes only the send half at EOF, and continues receiving.
- Preserve empty text lines and automatic binary handling for invalid UTF-8.
- Keep incoming frames and messages bounded. Never write incoming binary data to terminal stdout.
- Lock and flush text stdout per message; treat broken pipes as normal termination.
- Keep origin TLS options on `wss://`; reject TLS options for `ws://`.
- Preserve session cookie loading and persistence around successful handshakes.
