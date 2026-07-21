# WebSocket

`fetch` supports WebSocket connections for real-time bidirectional communication.

## Basic Usage

Connect using `ws://` or `wss://` URL schemes:

```sh
fetch ws://echo.websocket.events
fetch wss://echo.websocket.events
```

## Sending Messages

### Initial Message

Use `-d` or `-j` to send a single message on connect:

```sh
fetch ws://echo.websocket.events -d "hello"
fetch ws://echo.websocket.events -j '{"type": "subscribe", "channel": "updates"}'
```

By default, outgoing messages are sent as text when the payload is valid UTF-8
and as binary when it is not. Use `--ws-message-mode text|binary|auto` to force
the frame type:

```sh
fetch ws://api.example.com/upload -d @payload.bin --ws-message-mode binary
```

### Piped Input

Pipe lines from stdin. `fetch` sends each line as a separate text message. It
also sends empty lines:

```sh
echo "hello" | fetch ws://echo.websocket.events
printf "msg1\nmsg2\n" | fetch ws://echo.websocket.events
```

`fetch` connects before it reads piped input. It streams each line as the line
arrives. After stdin reaches EOF, it prints server messages until the server
closes the connection.

With `--ws-message-mode auto`, piped input is still line-delimited, but a line
that is not valid UTF-8 is sent as a binary message. With `--ws-message-mode
binary`, piped input is streamed as raw byte chunks and newline bytes are
preserved.

Text and auto stdin modes cap each line at 16 MiB before a newline. Use
`--ws-message-mode binary` for larger messages or raw byte streams without line
delimiters.

If stdin, stdout, and stderr are terminals, `fetch` opens an interactive prompt.
Type a message and press Enter to send it. Press Ctrl+C or Ctrl+D to exit.

Control this behavior with `--ws-interactive`:

```sh
# Automatically use the prompt when attached to a terminal
fetch ws://api.example.com/stream --ws-interactive auto

# Require the prompt, failing if stdio is not a terminal
fetch ws://api.example.com/stream --ws-interactive on

# Disable the prompt and stream server messages to stdout
fetch ws://api.example.com/stream --ws-interactive off
```

## Output

- **Text messages**: `fetch` writes text messages to stdout. On a terminal, it
  automatically formats JSON messages.
- **Binary messages**: `fetch` writes raw bytes if stdout is redirected or
  piped. On a terminal, it gives a warning and does not print binary-looking
  data.
- **Formatting**: Use `--format on` to force JSON formatting, or `--format off` to disable it.

Incoming server frames and assembled messages are capped at 16 MiB. Larger
messages fail with a WebSocket message size diagnostic instead of being printed.

```sh
# Force JSON formatting
fetch ws://api.example.com/stream --format on

# Disable formatting
fetch ws://api.example.com/stream --format off
```

## Verbose Output

Use `-v` flags to see connection details:

```sh
# Show response status and headers
fetch -v ws://echo.websocket.events -d "hello"

# Show request and response headers with prefixes
fetch -vv ws://echo.websocket.events -d "hello"
```

## Authentication

Header-based authentication options work with WebSocket connections. `fetch`
sends the headers during the HTTP upgrade handshake. It converts URL
credentials to a Basic `Authorization` header and removes them from the
handshake URL.

WebSocket requests do not support Digest authentication (`--digest`). Digest
authentication requires a challenge and a retry before the upgrade completes.

```sh
fetch --bearer mytoken ws://api.example.com/ws
fetch --basic user:pass ws://api.example.com/ws
fetch ws://user:pass@api.example.com/ws
fetch -H "Authorization: Bearer mytoken" ws://api.example.com/ws
```

## Subprotocols

Specify WebSocket subprotocols with the `Sec-WebSocket-Protocol` header:

```sh
fetch -H "Sec-WebSocket-Protocol: graphql-ws" wss://api.example.com/graphql
```

## Network Options

WebSocket connections honor `--dns-server` for direct TCP connections and for
local target resolution through plain `socks5://` proxies. Use `socks5h://` to
make the SOCKS proxy resolve the target hostname.

## Timeout

The `--timeout` flag applies to the WebSocket handshake only. The connection stays open until the server closes or stdin EOF:

```sh
fetch --timeout 5 ws://api.example.com/ws
```

Use `--connect-timeout` to limit WebSocket connection setup. The limit applies
to custom DNS resolution, the TCP connection, proxy CONNECT or SOCKS
negotiation, and TLS handshakes. If both timeout flags are set, the remaining
`--timeout` value limits the connect timeout:

```sh
fetch --connect-timeout 2 --timeout 10 wss://api.example.com/ws
```

## Limitations

- WebSocket requires HTTP/1.1 for the upgrade handshake. Using `--http 2` or `--http 3` with WebSocket is not supported.
- WebSocket (`ws://` / `wss://`) cannot be combined with `--grpc`, `--form`, `--multipart`, `--xml`, `--edit`, output-file/clipboard flags, or retry flags.
- The pager is disabled for WebSocket output.

## See Also

- [CLI Reference](cli-reference.md#websocket)
- [Authentication](authentication.md)
- [Advanced Features](advanced-features.md)
