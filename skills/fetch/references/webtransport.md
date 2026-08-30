## WebTransport

Use `--webtransport` with an `https://` URL. It selects HTTP/3 over direct
UDP; do not use WebSocket flags or WebSocket message semantics.

The default `--wt-mode stream` opens one reliable bidirectional stream. `-d`,
`-j`, and piped input are raw bytes sent after the handshake. Stream output is
raw when redirected and terminal-safe when displayed.

`--wt-mode datagram` sends datagrams. `--wt-datagram-mode lines` sends one
line per datagram, and `binary` sends 1 KiB chunks. Received datagrams are
compact JSON Lines records containing `sequence`, `length`, and base64 `data`.
Oversized outgoing datagram errors include the current underlying QUIC limit.
Input EOF does not close a datagram session; cancellation or peer closure does.

Repeat `--wt-protocol` for application protocol offers. WebTransport v1 does
not support proxies, redirects, retries, output files, `--format`, HAR, or
Digest authentication. `--dry-run` is network-free and does not consume
stdin.
