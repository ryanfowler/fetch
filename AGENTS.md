# fetch

This file provides guidance to AI agents when working with code in this repository. Keep this file updated after making changes.

## Project Overview

`fetch` is a modern HTTP(S) client CLI written in Go. It features automatic response formatting (JSON, XML, YAML, HTML, CSS, CSV, protobuf, msgpack), image rendering in terminals, gRPC support with JSON-to-protobuf conversion, and authentication (Basic, Bearer, AWS SigV4).

## Common Commands

```bash
# Run all tests
go test -v ./...

# Run specific package tests
go test -v ./internal/format
go test -v ./integration

# Run a single test
go test -v ./internal/cli -run TestParseFlagAWS

# Build the binary
go build -o bin/fetch .

# Format code (CI will fail if not formatted)
gofmt -s -w .

# Verify modules
go mod tidy && go mod verify

# Run linter (CI uses staticcheck)
staticcheck ./...

# Format other files
prettier -w .
```

## Architecture

### Entry Point

`main.go` orchestrates the CLI: parses arguments via `internal/cli`, loads config via `internal/config`, and delegates to `internal/fetch.Fetch()`.

### Key Packages

- **internal/aws** - AWS Signature V4 request signing.
- **internal/cli** - Command-line argument parsing. `App` struct holds all parsed options.
- **internal/client** - HTTP client wrapper with custom DNS resolver support.
- **internal/complete** - Shell completion implementation.
- **internal/config** - INI-format config file parsing with host-specific overrides.
- **internal/core** - Shared types (`Printer`, `Color`, `Format`, `HTTPVersion`) and utilities.
- **internal/curl** - Curl command parser for `--from-curl` flag. Tokenizes and parses curl command strings into an intermediate `Result` struct.
- **internal/fetch** - Core HTTP request execution. `fetch.go:Fetch()` is the main entry point that builds requests, handles gRPC framing, and routes to formatters.
- **internal/format** - Response body formatters (JSON, XML, YAML, HTML, CSS, CSV, msgpack, protobuf, SSE, NDJSON). Each formatter writes colored output to a `Printer`.
- **internal/grpc** - gRPC framing, headers, and status code handling.
- **internal/image** - Terminal image rendering (Kitty, iTerm2 inline, block-character fallback).
- **internal/image** - Multipart form implementation.
- **internal/proto** - Protocol buffer compilation and message handling for gRPC support.
- **internal/session** - Named cookie sessions with persistent storage across invocations.
- **internal/update** - Check for updates, download from Github, and self-update.
- **internal/ws** - WebSocket message loop (read, write, bidirectional coordination).

### Request Flow

1. CLI args parsed (`cli.Parse`) → `App` struct
2. Config file merged (`config.GetFile`)
3. `fetch.Request` built from merged config
4. If gRPC: load proto schema, setup descriptors, convert JSON→protobuf, frame message
5. HTTP client executes request
6. Response formatted based on Content-Type and output to stdout (optionally via pager)

### Content Type Detection

`internal/fetch/fetch.go:getContentType()` maps MIME types to formatters. Supported types include JSON, XML, YAML, HTML, CSS, CSV, msgpack, protobuf, gRPC, SSE, NDJSON, and images.

## Testing

- Unit tests: `*_test.go` files alongside source in each package
- Integration tests: `integration/integration_test.go` (comprehensive end-to-end tests)
- CI runs tests on Ubuntu, macOS, and Windows

## Docs

High level documentation exists in the README. All detailed documentation exists in the `docs/` directory, and should be kept up-to-date with any code changes.
