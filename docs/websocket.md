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

### Piped Input

Pipe lines from stdin — each line is sent as a separate text message. Empty lines are preserved, and both LF and CRLF endings are accepted:

```sh
echo "hello" | fetch ws://echo.websocket.events
printf "msg1\nmsg2\n" | fetch ws://echo.websocket.events
```

Use `--ws-message-mode` to select the message type:

```sh
# Auto-detect the initial payload; piped input remains line-delimited text
fetch --ws-message-mode auto ws://api.example.com/ws -d "hello"
# Require UTF-8 text for the initial payload and piped input
fetch --ws-message-mode text ws://api.example.com/ws
# Stream stdin as bounded binary WebSocket messages, preserving newlines
cat payload.bin | fetch --ws-message-mode binary ws://api.example.com/ws
```

The initial payload and each text line are limited to 16 MiB. Binary stdin uses bounded reusable chunks. After stdin reaches EOF, `fetch` sends a normal close frame and waits for the peer close response while receiving in-flight messages. Cancellation closes the connection and input source.

When stdin/stdout/stderr are terminals, `fetch` opens an interactive prompt. Type a message and press Enter to send it. Empty entries are valid messages. Ctrl+D performs a normal close handshake; Ctrl+C cancels the connection. Interactive history is byte-bounded.

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

- **Text messages**: Written to stdout. JSON messages are automatically formatted when connected to a terminal.
- **Binary messages**: A `[binary N bytes]` indicator is printed to stderr.
- **Formatting**: Use `--format on` to force JSON formatting, or `--format off` to disable it.

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

All authentication options work with WebSocket connections — headers are sent during the HTTP upgrade handshake:

```sh
fetch --bearer mytoken ws://api.example.com/ws
fetch --basic user:pass ws://api.example.com/ws
fetch -H "Authorization: Bearer mytoken" ws://api.example.com/ws
```

## Subprotocols

Specify WebSocket subprotocols via the `Sec-WebSocket-Protocol` header:

```sh
fetch -H "Sec-WebSocket-Protocol: graphql-ws" wss://api.example.com/graphql
```

## Timeout

The `--timeout` flag applies to the WebSocket handshake only. The connection stays open until the server closes or the operation is canceled:

```sh
fetch --timeout 5 ws://api.example.com/ws
```

## Limitations

- WebSocket requires HTTP/1.1 for the upgrade handshake. Forcing HTTP/2 or HTTP/3 is rejected; HTTP/1.1 remains supported.
- WebSocket uses the normal proxy, DNS, TLS, ECH, and session-cookie configuration.
- WebSocket (`ws://` / `wss://`) cannot be combined with `--grpc`, `--form`, `--multipart`, `--xml`, `--edit`, output-file/clipboard flags, Digest authentication, redirects, ranges, compression flags, or retry flags.
- Incoming WebSocket messages are limited to 16 MiB.
- Binary messages are written byte-for-byte to a pipe or redirected stdout. A terminal receives only a safe size indicator.
- The pager and image rendering do not apply to WebSocket output; fetch warns when these options are selected.
