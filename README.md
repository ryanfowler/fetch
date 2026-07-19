# fetch

A terminal API client for requests, streams, and network debugging.

![Example of fetch with an image and JSON responses](./assets/example.png)

`fetch` combines formatted HTTP responses with WebSockets, gRPC, DNS and TLS
inspection, request timing, authentication, sessions, and terminal-native image
rendering.

## Features

- HTTP/1.1, HTTP/2, HTTP/3, WebSockets, and gRPC with reflection
- Automatic formatting for JSON, XML, YAML, HTML, CSV, Markdown, MessagePack,
  Protocol Buffers, SSE, NDJSON, and images
- JSON, XML, forms, multipart uploads, files, stdin, and editor-based bodies
- Basic, Digest, Bearer, AWS SigV4, and mutual TLS authentication
- DNS, TLS certificate, and request timing diagnostics
- Proxies, custom DNS, cookie sessions, configuration, and self-update workflows

## Quick Start

Install on macOS or Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/ryanfowler/fetch/main/install.sh | bash
```

Or use Homebrew or Cargo:

```sh
brew install ryanfowler/tap/fetch
cargo install --git https://github.com/ryanfowler/fetch --locked
```

Make a request:

```sh
fetch httpbin.org/json
```

Send JSON (body options infer `POST`):

```sh
fetch -j '{"name":"Ada"}' https://httpbin.org/post
```

Inspect a connection or call a reflected gRPC method:

```sh
fetch -vvv https://example.com
fetch --grpc -j '{"service":""}' \
  http://127.0.0.1:50051/grpc.health.v1.Health/Check
```

`fetch -h` shows concise help. Use `fetch -v -h` for the complete, colorized
command menu.

## Output

Response bodies go to stdout; status, headers, timing, warnings, and errors go
to stderr. This keeps pipelines clean:

```sh
fetch example.com/api | jq .
```

Terminal output is formatted automatically. Redirected output is unformatted by
default, and binary responses are protected from accidental terminal output.
See [Output Formatting](docs/output-formatting.md) for pager, color, binary,
clipboard, and file behavior.

Use `--har request.har` to record the final HTTP exchange as a HAR 1.2 sidecar
without changing normal response output. HAR files can contain credentials,
cookies, and bodies and should be treated as sensitive data.

## Documentation

Start with the **[documentation index](docs/README.md)**, or jump directly to:

- **[Getting Started](docs/getting-started.md)** — installation and common tasks
- **[CLI Reference](docs/cli-reference.md)** — every command-line option
- **[Configuration](docs/configuration.md)** — global and per-host settings
- **[Request Bodies](docs/request-bodies.md)** — JSON, forms, multipart, and files
- **[Authentication](docs/authentication.md)** — supported authentication methods
- **[Troubleshooting](docs/troubleshooting.md)** — diagnostics and exit codes

## License

`fetch` is released under the [MIT License](LICENSE).
