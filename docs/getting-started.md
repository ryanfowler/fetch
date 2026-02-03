# Getting Started

This guide will help you install `fetch` and make your first HTTP request.

## Installation

### Installation Script (Recommended)

For macOS or Linux, use the installation script:

```sh
curl -fsSL https://raw.githubusercontent.com/ryanfowler/fetch/main/install.sh | bash
```

### Building from Source

If you have Go installed:

```sh
go install github.com/ryanfowler/fetch@latest
```

### Pre-built Binaries

Download binaries for your operating system from the [GitHub releases page](https://github.com/ryanfowler/fetch/releases).

### Verify Installation

```sh
fetch --version
```

## Making Your First Request

Make a GET request by providing a URL:

```sh
fetch example.com
```

When no scheme is provided, `fetch` defaults to HTTPS:

```sh
fetch example.com        # Uses https://example.com
fetch 192.168.1.1:8080   # Uses https://192.168.1.1:8080
```

Loopback addresses default to HTTP for local development:

```sh
fetch localhost:3000     # Uses http://localhost:3000
fetch 127.0.0.1:8080     # Uses http://127.0.0.1:8080
```

You can always specify the scheme explicitly:

```sh
fetch http://example.com   # Force HTTP
fetch https://localhost    # Force HTTPS for localhost
```

## Understanding the Output

When you make a request, `fetch` displays:

1. **Status line** (to stderr) - Shows the HTTP version, status code, and status text
2. **Response body** (to stdout) - Automatically formatted based on content type

```
HTTP/1.1 200 OK

{
  "name": "example",
  "value": 42
}
```

The response body is automatically formatted and syntax-highlighted for supported content types like JSON, XML, HTML, and more.

## Common Options

### Change HTTP Method

```sh
fetch -m POST example.com
fetch -X DELETE example.com/resource/123
```

### Add Headers

```sh
fetch -H "Authorization: Bearer token" example.com
fetch -H "X-Custom: value" -H "Accept: application/json" example.com
```

### Send JSON Data

```sh
fetch -j '{"name": "test"}' -m POST example.com/api
```

### View Request and Response Headers

```sh
fetch -v example.com     # Show response headers
fetch -vv example.com    # Show request and response headers
fetch -vvv example.com   # Show DNS and TLS details
```

## Updating

Update `fetch` to the latest version:

```sh
fetch --update
```

Or enable automatic updates in your [configuration file](configuration.md):

```ini
auto-update = true
```

## Shell Completions

Generate shell completion scripts:

```sh
# Bash
echo 'eval "$(fetch --complete bash)"' >> ~/.bashrc

# Zsh
fetch --complete zsh > ~/.zshrc.d/fetch-completion.zsh

# Fish
fetch --complete fish > ~/.config/fish/completions/fetch.fish
```

## Next Steps

- **[CLI Reference](cli-reference.md)** - Complete list of all command-line options
- **[Configuration](configuration.md)** - Set up a configuration file for persistent settings
- **[Authentication](authentication.md)** - Learn about authentication options
- **[Request Bodies](request-bodies.md)** - Send JSON, XML, forms, and files
