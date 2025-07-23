# Configuration Guide

This guide provides comprehensive documentation for configuring `fetch` using a configuration file.

## Configuration File Format

`fetch` uses an INI-like configuration file format that supports both global and host-specific settings.

### File Locations

`fetch` searches for configuration files in the following order:

1. **Specified path**: The file location specified with the `-c` or `--config` flag
2. **Windows**: `%AppData%\fetch\config`
3. **Unix-like systems**:
   - `$XDG_CONFIG_HOME/fetch/config` (if `XDG_CONFIG_HOME` is set)
   - `$HOME/.config/fetch/config` (fallback)

### Configuration Precedence

Settings are applied in the following order of precedence (highest to lowest):

1. **Command line flags** - Override all other settings
2. **Domain-specific configuration** - Host-specific settings in config file
3. **Global configuration** - Global settings in config file
4. **Default values** - Built-in application defaults

This allows you to set global defaults and override them per-domain or per-command as needed.

### File Structure

Configuration files use a simple key-value format with optional sections:

```ini
# Global settings
option = value

# Host-specific settings
[example.com]
option = host_specific_value
```

## Available Configuration Options

### Auto-Update Options

#### `auto-update`
**Type**: Boolean or duration interval
**Default**: `false` (disabled)

Enable or disable automatic updates, or set the minimum interval between update checks.

```ini
# Enable auto-update with default 24-hour interval
auto-update = true

# Disable auto-update
auto-update = false

# Custom update interval
auto-update = 4h
auto-update = 30m
auto-update = 1d
```

### Output Control Options

#### `color` / `colour`
**Type**: String
**Values**: `auto`, `off`, `on`
**Default**: `auto`

Control colored output in the terminal.

```ini
# Automatically detect terminal color support
color = auto

# Always disable colors
color = off

# Always enable colors
color = on
```

#### `format`
**Type**: String
**Values**: `auto`, `off`, `on`
**Default**: `auto`

Control automatic formatting of response bodies (JSON, XML, etc.).

```ini
# Automatically detect and format supported content types
format = auto

# Disable all formatting
format = off

# Always attempt formatting
format = on
```

#### `image`
**Type**: String
**Values**: `auto`, `native`, `off`
**Default**: `auto`

Control image rendering in the terminal.

```ini
# Try optimal protocol, fallback to external tools
image = auto

# Use only built-in decoders (jpeg, png, tiff, webp)
image = native

# Disable image rendering
image = off
```

#### `no-pager`
**Type**: Boolean
**Default**: `false`

Disable piping output through a pager like `less`.

```ini
# Disable pager
no-pager = true

# Enable pager (default)
no-pager = false
```

#### `silent`
**Type**: Boolean
**Default**: `false`

Suppress verbose output. Only warnings and errors are written to stderr.

```ini
# Enable silent mode
silent = true

# Normal output (default)
silent = false
```

#### `verbosity`
**Type**: Integer
**Values**: `0` or greater
**Default**: `0`

Set the verbosity level for debug output.

```ini
# Normal output (default)
verbosity = 0

# Verbose - show response headers
verbosity = 1

# Extra verbose - show request and response headers
verbosity = 2

# Debug - show DNS and TLS details
verbosity = 3
```

### Network Options

#### `ca-cert`
**Type**: CA certificate path
**Default**: System default

Use a custom CA cert pool.

```ini
# Set to filepath to cert file
ca-cert = ca-cert.pem
```

#### `dns-server`
**Type**: IP address with optional port, or HTTPS URL
**Default**: System default

Use a custom DNS server for hostname resolution.

```ini
# Use Google DNS
dns-server = 8.8.8.8

# Use Cloudflare DNS with custom port
dns-server = 1.1.1.1:53

# Use IPv6 DNS server
dns-server = [2001:4860:4860::8888]:53

# Use DNS-over-HTTPS
dns-server = https://1.1.1.1/dns-query
dns-server = https://dns.google/dns-query
```

#### `proxy`
**Type**: URL
**Default**: None

Route requests through the specified proxy server.

```ini
# HTTP proxy
proxy = http://proxy.example.com:8080

# HTTPS proxy
proxy = https://secure-proxy.example.com:8080

# SOCKS5 proxy
proxy = socks5://localhost:1080
```

#### `timeout`
**Type**: Number (seconds)
**Default**: System default

Set a timeout for HTTP requests. Accepts decimal values.

```ini
# 30 second timeout
timeout = 30

# 2.5 second timeout
timeout = 2.5
```

#### `redirects`
**Type**: Integer
**Default**: System default

Set the maximum number of automatic redirects to follow.

```ini
# Disable redirects
redirects = 0

# Allow up to 10 redirects
redirects = 10
```

#### `http`
**Type**: String
**Values**: `1`, `2`
**Default**: `2`

Specify the highest allowed HTTP version.

```ini
# Force HTTP/1.1
http = 1

# Allow HTTP/2 (default)
http = 2
```

#### `tls`
**Type**: String
**Values**: `1.0`, `1.1`, `1.2`, `1.3`
**Default**: System default

Specify the minimum TLS version to use.

```ini
# Require TLS 1.2 or higher
tls = 1.2

# Require TLS 1.3
tls = 1.3
```

#### `insecure`
**Type**: Boolean
**Default**: `false`

Allow connections to servers with invalid TLS certificates.

```ini
# Allow invalid certificates (not recommended)
insecure = true

# Require valid certificates (default)
insecure = false
```

#### `no-encode`
**Type**: Boolean
**Default**: `false`

Disable automatic gzip compression for requests and responses.

```ini
# Disable compression
no-encode = true

# Enable compression (default)
no-encode = false
```

### Request Options

#### `header`
**Type**: String (name:value format)
**Repeatable**: Yes

Set custom HTTP headers. Can be specified multiple times.

```ini
# Single header
header = X-API-Key: your-api-key

# Multiple headers
header = X-Custom-Header: value1
header = Authorization: Bearer token
header = User-Agent: MyApp/1.0
```

#### `query`
**Type**: String (key=value format)
**Repeatable**: Yes

Append query parameters to requests. Can be specified multiple times.

```ini
# Single query parameter
query = api_version=2

# Multiple query parameters
query = page=1
query = limit=50
query = sort=name
```

#### `ignore-status`
**Type**: Boolean
**Default**: `false`

Don't determine exit code from HTTP status. Always exit with code 0.

```ini
# Ignore HTTP status for exit code
ignore-status = true

# Use HTTP status for exit code (default)
ignore-status = false
```

## Host-Specific Configuration

You can configure different settings for specific hosts or domains using sections:

```ini
# Global settings apply to all requests
timeout = 30
color = auto

# Settings for api.example.com
[api.example.com]
timeout = 10
header = X-API-Key: secret-key-for-api
query = version=2

# Settings for internal.company.com
[internal.company.com]
insecure = true
proxy = http://internal-proxy:8080
header = Authorization: Bearer internal-token

# Settings for slow.example.com
[slow.example.com]
timeout = 120
redirects = 0
```

### Host Section Rules

- Section names should be the exact hostname (without protocol or path)
- Host-specific settings override global settings
- Command-line flags override both global and host-specific settings
- Multiple headers and query parameters are merged (host-specific first, then global)

## Configuration Examples

### Basic Global Configuration

```ini
# Enable colored output and formatting
color = on
format = on

# Set reasonable timeouts
timeout = 30
redirects = 5

# Enable auto-update checks every 12 hours
auto-update = 12h

# Add common headers
header = User-Agent: fetch/1.0
```

### API Development Configuration

```ini
# Global API settings
format = on
color = on
timeout = 10

# Development API
[api.dev.example.com]
header = X-API-Key: dev-key-here
header = X-Environment: development
query = debug=1

# Production API (more restrictive)
[api.example.com]
header = X-API-Key: prod-key-here
timeout = 30
redirects = 3
```

### Enterprise/Corporate Configuration

```ini
# Corporate proxy settings
proxy = http://corporate-proxy.company.com:8080

# Internal services (allow self-signed certificates)
[internal.company.com]
insecure = true

# External APIs (strict security)
[external-api.vendor.com]
tls = 1.2
timeout = 60
header = X-Company-ID: company-identifier
```

## Configuration File Validation

`fetch` validates configuration files when loading them and will report errors with specific line numbers:

```
config file '/home/user/.config/fetch/config': line 15: invalid option: 'invalid-option'
```

Common validation errors include:
- Invalid option names
- Invalid values for specific options (e.g., `color = invalid`)
- Malformed key=value pairs
- Empty host section names `[]`

## Best Practices

1. **Use host-specific sections** for API keys and service-specific settings
2. **Set reasonable timeouts** to avoid hanging requests
3. **Use global settings** for common preferences like colors and formatting
4. **Keep sensitive data secure** - configuration files may contain API keys
5. **Test configurations** with dry-run mode: `fetch --dry-run example.com`
6. **Use comments** to document complex configurations
7. **Enable auto-update** for security and feature updates
