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

Pipe lines from stdin — each line is sent as a separate text message:

```sh
echo "hello" | fetch ws://echo.websocket.events
printf "msg1\nmsg2\n" | fetch ws://echo.websocket.events
```

When stdin is not piped (i.e. running from a terminal), `fetch` operates in read-only mode — it listens for server messages until the connection closes or Ctrl+C is pressed.

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

The `--timeout` flag applies to the WebSocket handshake only. The connection stays open until the server closes or stdin EOF:

```sh
fetch --timeout 5 ws://api.example.com/ws
```

## Limitations

- WebSocket requires HTTP/1.1 for the upgrade handshake. Using `--http 3` with WebSocket is not supported.
- WebSocket (`ws://` / `wss://`) cannot be combined with `--grpc`, `--form`, `--multipart`, `--xml`, or `--edit`.
- Binary message content is not displayed; only a size indicator is shown.
- The pager is disabled for WebSocket output.
