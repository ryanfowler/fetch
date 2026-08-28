# WebTransport

Use `fetch --webtransport https://host/path` to open a WebTransport session.
WebTransport uses HTTP/3 over a direct UDP connection. It does not support
proxies, Unix sockets, redirects, retries, output files, formatting, or
Digest authentication.

The default mode is one reliable bidirectional stream. `-d` and `-j` are sent
after the session handshake, followed by piped standard input. The stream is
closed for writing at EOF, but fetch continues to read until the peer closes.
Stream output is raw bytes when stdout is redirected and is escaped when it is
a terminal.

Use `--wt-mode datagram` for unreliable datagrams. `--wt-datagram-mode lines`
sends one datagram per line; `binary` sends 1 KiB chunks. Received datagrams
are JSON Lines records with `sequence`, `length`, and base64 `data` fields.
Datagram input ending does not close the session. Use Ctrl+C when the peer does
not close it.

Repeat `--wt-protocol` to advertise application protocols. Protocols are
validated and sent in offer order. `--dry-run` prints the CONNECT metadata and
does not resolve DNS, open UDP, or consume standard input.

This implementation uses WebTransport draft-16. Use HTTPS and TLS 1.3-capable
HTTP/3 servers.
