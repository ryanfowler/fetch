# Usage Guide

This guide provides comprehensive documentation for using `fetch`, a modern HTTP client for the command line.

## Basic Usage

To make a GET request to a URL:

```sh
fetch example.com
```

## Authentication Options

### AWS Signature V4

**Flag**: `--aws-sigv4 REGION/SERVICE`

Sign the request using [AWS Signature V4](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html).

Requires: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables.

```sh
fetch --aws-sigv4 us-east-1/s3 example.com
```

### Basic Authentication

**Flag**: `--basic USER:PASS`

Enable HTTP Basic Authentication.

```sh
fetch --basic username:password example.com
```

### Bearer Token

**Flag**: `--bearer TOKEN`

Enable HTTP Bearer Token Authentication.

```sh
fetch --bearer mysecrettoken example.com
```

## Request Body Options

Body options generally accept values in the format: `[@]VALUE`

- A value without `@` prefix is sent directly
- A value prefixed with `@` sends a file at the given path
- A value of `@-` sends data read from stdin

### Raw Request Body

**Flag**: `-d, --data [@]VALUE`

Send a raw request body.

```sh
fetch -d 'Hello, world!' -m PUT example.com
fetch -d @data.txt -m PUT example.com
fetch -d @- -m PUT example.com < data.txt
```

### JSON Request Body

**Flag**: `-j, --json [@]VALUE`

Send a JSON request body. Automatically sets the `Content-Type` header to `application/json`.

```sh
fetch -j '{"hello":"world"}' -m PUT example.com
fetch -j @data.json -m PUT example.com
```

### XML Request Body

**Flag**: `-x, --xml [@]VALUE`

Send an XML request body. Automatically sets the `Content-Type` header to `application/xml`.

```sh
fetch -x '<Tag>value</Tag>' -m PUT example.com
fetch -x @data.xml -m PUT example.com
```

### URL-Encoded Form Body

**Flag**: `-f, --form KEY=VALUE`

Send a URL-encoded form body. Can be used multiple times to add multiple fields.

```sh
fetch -f hello=world -f name=value -m POST example.com
```

### Multipart Form Body

**Flag**: `-F, --multipart NAME=[@]VALUE`

Send a multipart form body. Can be used multiple times to add multiple fields.

```sh
fetch -F hello=world -F data=@/path/to/file.txt -m POST example.com
fetch -F "file=@image.png" -F "description=My image" -m POST example.com
```

### Editor Integration

**Flag**: `-e, --edit`

Edit the request body with an editor before sending. Uses `VISUAL` or `EDITOR` environment variables, or falls back to well-known editors.

```sh
fetch --edit -m PUT example.com
```

## General Request Options

### HTTP Method

**Flag**: `-m, --method METHOD` (alias: `-X`)

Specify the HTTP method to use. Default is GET.

```sh
fetch -m POST example.com
fetch -X DELETE example.com
```

### Custom Headers

**Flag**: `-H, --header NAME:VALUE`

Set custom headers on the request. Can be used multiple times.

```sh
fetch -H "x-custom-header: value" -H "Authorization: Bearer token" example.com
```

### Query Parameters

**Flag**: `-q, --query KEY=VALUE`

Append query parameters to the URL. Can be used multiple times.

```sh
fetch -q hello=world -q page=2 example.com
```

### Range Requests

**Flag**: `-r, --range RANGE`

Set the [Range](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range) request header. Can be used multiple times for multiple ranges.

```sh
fetch -r 0-1023 example.com
fetch -r 0-499 -r 1000-1499 example.com
```

### Redirects

**Flag**: `--redirects NUM`

Set the maximum allowed automatic redirects. Use `0` to disable redirects.

```sh
fetch --redirects 0 example.com
fetch --redirects 10 example.com
```

### Timeout

**Flag**: `-t, --timeout SECONDS`

Set a timeout for the entire request in seconds. Accepts decimal values.

```sh
fetch --timeout 30 example.com
fetch --timeout 2.5 example.com
```

### Custom DNS Server

**Flag**: `--dns-server IP[:PORT]|URL`

Use a custom DNS server. Can be either:
- IP address with optional port for UDP DNS
- HTTPS URL for DNS-over-HTTPS

```sh
fetch --dns-server 8.8.8.8 example.com
fetch --dns-server 1.1.1.1:53 example.com
fetch --dns-server https://1.1.1.1/dns-query example.com
```

### Proxy

**Flag**: `--proxy PROXY`

Route the request through the specified proxy.

```sh
fetch --proxy http://localhost:8080 example.com
fetch --proxy socks5://localhost:1080 example.com
```

### Unix Socket

**Flag**: `--unix PATH`

Make the request over a Unix domain socket. Only available on Unix-like systems.

```sh
fetch --unix /var/run/docker.sock http://unix/containers/json
fetch --unix /var/run/service.sock http://unix/api/status
```

### TLS Options

**Flag**: `--insecure`

Allow for invalid TLS certificates from the server.

```sh
fetch --insecure https://self-signed.example.com
```

**Flag**: `--tls VERSION`

Specify the minimum TLS version to use. Must be one of: `1.0`, `1.1`, `1.2`, `1.3`.

```sh
fetch --tls 1.3 example.com
```

### HTTP Version

**Flag**: `--http VERSION`

Specify the highest allowed HTTP version. Must be `1` or `2`. Default is `2`.

```sh
fetch --http 1 example.com
```

### Compression

**Flag**: `--no-encode`

Disable automatic gzip request/response compression.

```sh
fetch --no-encode example.com
```

### Custom CA Certificate

**Flag**: `--ca-cert`

Use a custom CA certificate.

```sh
fetch --ca-cert ca-cert.pem example.com
```

## Output Options

### Output to File

**Flag**: `-o, --output PATH`

Write the response body to the specified file. Truncates existing files.

```sh
fetch -o response.json example.com/api/data
fetch -o ~/downloads/file.zip example.com/file.zip
```

### Output to Current Directory

**Flag**: `-O, --output-current-dir`

Write the response body to the current directory using the filename from the URL.

```sh
fetch -O example.com/path/to/file.txt
# Creates ./file.txt
```

### Colored Output

**Flag**: `--color OPTION` (alias: `--colour`)

Set whether output should be colored. Options: `auto`, `off`, `on`.

```sh
fetch --color off example.com
fetch --colour on example.com
```

### Formatted Output

**Flag**: `--format OPTION`

Set whether output should be formatted. Options: `auto`, `off`, `on`.

```sh
fetch --format off example.com
fetch --format on example.com
```

### Image Rendering

**Flag**: `--image OPTION`

Set how images should be rendered in the terminal. Options: `auto`, `native`, `off`.

- `auto`: Try optimal protocol, fallback to external tools
- `native`: Use only built-in decoders (jpeg, png, tiff, webp)
- `off`: Disable image rendering

```sh
fetch --image native example.com/image.png
fetch --image off example.com/image.jpg
```

### Pager Control

**Flag**: `--no-pager`

Disable piping output to a pager like `less`.

```sh
fetch --no-pager example.com
```

## Verbosity Options

### Verbose Output

**Flag**: `-v, --verbose`

Increase verbosity of output to stderr. Can be used multiple times:

- `-v`: Show response headers
- `-vv`: Show request and response headers
- `-vvv`: Show DNS and TLS details

```sh
fetch -v example.com
fetch -vv example.com
fetch -vvv example.com
```

### Silent Mode

**Flag**: `-s, --silent`

Suppress verbose output. Only warnings and errors are written to stderr.

```sh
fetch -s example.com
```

### Ignore HTTP Status

**Flag**: `--ignore-status`

Don't determine exit code from HTTP status. Always exit with code 0 instead of using 4xx/5xx status codes.

```sh
fetch --ignore-status example.com
```

## Configuration Options

### Config File

**Flag**: `-c, --config PATH`

Specify a custom configuration file path.

```sh
fetch --config ~/.config/fetch/custom.conf example.com
```

## Utility Options

### Help

**Flag**: `-h, --help`

Print help information.

```sh
fetch --help
```

### Version Information

**Flag**: `-V, --version`

Print version information.

```sh
fetch --version
```

### Build Information

**Flag**: `--buildinfo`

Print detailed build information including version, commit, and build date.

```sh
fetch --buildinfo
```

### Update

**Flag**: `--update`

Update the fetch binary in place.

```sh
fetch --update
```

### Auto-Update

**Flag**: `--auto-update (ENABLED|INTERVAL)`

Enable or configure auto-updates. This is a hidden flag not shown in help output.

```sh
fetch --auto-update true
fetch --auto-update 24h
```

### Shell Completion

**Flag**: `--complete SHELL`

Output shell completion scripts. Supported shells: `fish`, `zsh`.

```sh
fetch --complete zsh > ~/.zshrc.d/fetch-completion.zsh
fetch --complete fish > ~/.config/fish/completions/fetch.fish
```

### Dry Run

**Flag**: `--dry-run`

Print request information without actually sending the request.

```sh
fetch --dry-run -m POST -j '{"test": true}' example.com
```

## Value Formats

### File References

Many options support file references with the `@` prefix:

- `@filename` - Read content from file
- `@-` - Read content from stdin
- `@~/path` - Home directory expansion supported

### Environment Variables

The following environment variables are recognized:

- `AWS_ACCESS_KEY_ID` - For AWS Signature V4 authentication
- `AWS_SECRET_ACCESS_KEY` - For AWS Signature V4 authentication
- `VISUAL` or `EDITOR` - For editor integration
- `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` - For proxy configuration

### Special Characters

When using special characters in values, proper shell escaping may be required:

```sh
# Escape quotes in JSON
fetch -j '{"message": "Hello \"World\""}' example.com

# Use single quotes to avoid shell interpretation
fetch -H 'Authorization: Bearer token-with-$pecial-chars' example.com
```

## Advanced Usage

### Combining Options

Options can be combined for complex requests:

```sh
fetch \
  --method POST \
  --header "Content-Type: application/json" \
  --header "Authorization: Bearer token" \
  --json '{"user": "john", "action": "login"}' \
  --query "version=2" \
  --timeout 30 \
  --verbose \
  example.com/api/auth
```

### Using with Pipes

```sh
# Send stdin as request body
echo '{"hello": "world"}' | fetch -j @- -m POST example.com

# Save response to file and view
fetch example.com/large-response.json | jq . > formatted.json

# Chain requests
fetch example.com/auth | jq -r '.token' | fetch --bearer @- example.com/protected
```

### Configuration Precedence

Options are applied in the following order (highest to lowest precedence):

1. Command line flags
2. Domain-specific configuration
3. Global configuration
4. Default values

This allows for flexible configuration where you can set defaults globally and override them per-domain or per-command.
