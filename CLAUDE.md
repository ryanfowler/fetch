# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Build and Run
- `go build -o fetch .` - Build the binary
- `go run . [args]` - Run the application directly
- `go install github.com/ryanfowler/fetch@latest` - Install from source

### Testing
- `go test ./...` - Run all tests
- `go test ./internal/...` - Run internal package tests
- `go test -v ./internal/cli/...` - Run CLI tests with verbose output
- `go test ./integration/...` - Run integration tests

### Code Quality
- `go fmt ./...` - Format all Go code
- `go vet ./...` - Run static analysis
- `go mod tidy` - Clean up module dependencies

## Architecture Overview

### Core Components

The application follows a layered architecture:

1. **Entry Point** (`main.go`): Handles signal management, CLI parsing, config loading, and auto-updates
2. **CLI Layer** (`internal/cli/`): Command-line argument parsing and validation with comprehensive flag definitions
3. **Core Layer** (`internal/core/`): Shared types, constants, and utilities including Color, Format, Verbosity enums
4. **Configuration** (`internal/config/`): Configuration file parsing and merging with CLI options
5. **Fetch Engine** (`internal/fetch/`): HTTP request execution, response handling, and output formatting
6. **Client** (`internal/client/`): HTTP client creation and configuration
7. **Specialized Modules**:
   - `internal/aws/`: AWS Signature V4 authentication
   - `internal/format/`: Response formatting for JSON, XML, NDJSON, SSE
   - `internal/image/`: Terminal image rendering support
   - `internal/multipart/`: Multipart form handling
   - `internal/update/`: Binary self-update functionality
   - `internal/complete/`: Shell completion support

### Key Design Patterns

- **Configuration Precedence**: CLI flags > domain-specific config > global config
- **Content Type Detection**: Automatic response formatting based on Content-Type headers
- **Modular Authentication**: Pluggable auth systems (Basic, Bearer, AWS SigV4)
- **Terminal-Aware Output**: Automatic color/formatting based on terminal detection
- **Error Handling**: Custom error types with pretty printing support

### Request Processing Flow

1. Parse CLI arguments (`cli.Parse`)
2. Load and merge configuration files (`config.GetFile`)
3. Create HTTP client with appropriate settings (`client.NewClient`)
4. Build HTTP request with auth, headers, body (`client.NewRequest`)
5. Execute request with optional debugging/dry-run (`fetch.Fetch`)
6. Format response based on content type (`formatResponse`)
7. Stream output to stdout or file with optional pager

### Configuration System

The config system supports:
- Global settings in `~/.config/fetch/config` (Unix) or `%AppData%\fetch\config` (Windows)
- Host-specific sections in config files
- Auto-update configuration with interval control
- All CLI options available as config file settings

### Testing Strategy

- Unit tests for individual components
- Integration tests in `integration/` directory
- CLI parsing tests with edge cases
- Configuration merging tests