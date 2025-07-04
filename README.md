# fetch

`fetch` is a modern, high-level HTTP(S) client for the command line.

![Example of fetch with an image and JSON responses](./assets/example.jpg)

### Features include:

- **Response formatting**: automatically formats and colors output for supported types (json, xml, etc.)
- **Image rendering**: render images directly in your terminal
- **Compression**: automatic gzip response body decompression
- **Authentication**: support for Basic Auth, Bearer Token, and AWS Signature V4
- **Form body**: send multipart or urlencoded form bodies
- **Editor integration**: use an editor to modify the request body
- **Configuration**: global and per-host configuration
- _and more!_

---

## Installation

You can install `fetch` using an installation script, by compiling from source,
or from pre-built binaries.

### Installation Script

For macOS or Linux, download and run the [install.sh](./install.sh) script:

```sh
curl -fsSL https://raw.githubusercontent.com/ryanfowler/fetch/main/install.sh | bash
```

### Building from Source

Ensure you have Go installed, then run:

```sh
go install github.com/ryanfowler/fetch@latest
```

### Pre-built Binaries

Visit the [GitHub releases page](https://github.com/ryanfowler/fetch/releases)
to download the binary for your operating system.

### Updating

Once installed, you can update the fetch binary in-place by running:

```sh
fetch --update
```

Or you can let the application auto-update by including the following setting in
your [configuration file](#Configuration):

```ini
auto-update = true
```

---

## Usage

To make a GET request to a URL and print the status code to stderr and the response body to stdout:

```sh
fetch example.com
```
<pre><code><span style='opacity:0.67'>HTTP/1.1</span> <span style='color:green'><b>200</b></span> <span style='color:green'>OK</span>

{
  &quot;<span style='color:blue'><b>name</b></span>&quot;: &quot;<span style='color:green'>example</span>&quot;,
  &quot;<span style='color:blue'><b>value</b></span>&quot;: 42
}
</code></pre>

### Authentication Options

**AWS Signature V4**: `--aws-sigv4 REGION/SERVICE`

Sign the request using [AWS Signature V4](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html).  
Requires: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables to be set.

```sh
fetch --aws-sigv4 us-east-1/s3 example.com
```

**Basic Authentication**: `--basic USER:PASS`

Enable HTTP Basic Authentication.

```sh
fetch --basic username:password example.com
```

**Bearer Token**: `--bearer TOKEN`

Enable HTTP Bearer Token Authentication.

```sh
fetch --bearer mysecrettoken example.com
```

### Request Body Options

Body options generally take values in the format: `[@]VALUE`

- a value without a prefix of `@` is sent directly.
- a value prefixed with `@` sends a file at the given path.
- a value of `@-` sends the data read from stdin.

**Raw Request Body**: `-d, --data [@]VALUE`

Send a raw request body data.

```sh
fetch -d 'Hello, world!' -m PUT example.com
```

**JSON Request Body**: `-j, --json [@]VALUE`

Sends a JSON request body.

```sh
fetch -j '{"hello":"world"}' -m PUT example.com
```

**XML Request Body**: `-x, --xml [@]XML`

Sends an XML request body.

```sh
fetch -x `<Tag>value</Tag>` -m PUT example.com
```

**URL-Encoded Form Body**: `-f, --form KEY=VALUE`

Send a URL-encoded form body.

```sh
fetch -f hello=world -m PUT example.com
```

**Multipart Form Body**: `-F, --multipart KEY=[@]VALUE`

Send a multipart form body.

```sh
fetch -F hello=world -F data=@/path/to/file.txt -m PUT example.com
```

**Editor Integration**: `-e, --edit`

Edit the request body with an editor before sending. An editor is chosen using
the `VISUAL` or `EDITOR` environment variables, falling back to a group of
well-known editors.

```sh
fetch --edit -m PUT example.com
```

### Output Options

**Output To File**: `-o, --output PATH`

Write the response body to the specified file.
If a file with the same path already exists, it will be truncated.
If the file does not already exist, it will be created.

```sh
fetch -o /path/to/file.txt example.com/file.txt
```

**Colored Output**: `--color OPTION`

Set whether output should be colored or not.
By default, `fetch` automatically determines if color should be used.  
Must be one of: `auto`, `off`, or `on`.

```sh
fetch --color off example.com
```

**Formatted Output**: `--format OPTION`

Set whether output should be formatted or not.
By default, `fetch` automatically determines if output should be formatted.  
Must be one of: `auto`, `off`, or `on`.

```sh
fetch --format off example.com
```

**Image Rendering**: `--image OPTION`

Set how images should be rendered to the terminal.
By default, `fetch` automatically attempts to decode the image and render it with the optimal image protocol.
Setting the value to `native` disables the fallback to search the local machine for a tool that can decode the image.
`fetch` natively supports the jpeg, png, tiff, and webp formats.
Must be one of: `auto`, `native`, or `off`.

```sh
fetch --image native example.com
```

**Verbosity**: `-v, --verbose`

Increase verbosity of the output to stderr; use multiple times for extra verbosity.

One `-v` outputs response headers. Two `-v`s outputs request headers as well. Three `-v`s prints DNS and TLS details as they occur.

```sh
fetch -vv example.com
```

**Silent**: `-s, --silent`

Supress verbose output; takes precedence over the verbose flag.
Only warnings and errors will be written to stderr.

```sh
fetch -s example.com
```

**Disable Pager Usage**: `--no-pager`

Disable piping output to a pager.

```sh
fetch --no-pager example.com
```

### General Request Options

**Method**: `-m, -X, --method METHOD`

Specify the HTTP method to use.

```sh
fetch -m POST example.com
```

**Headers**: `-H, --header NAME:VALUE`

Set custom headers on the request.

```sh
fetch -H x-custom-header:value example.com
```

**Query Parameters**: `-q, --query KEY=VALUE`

Append query parameters to the URL.

```sh
fetch -q hello=world example.com
```

**Range Requests**: `-r, --range RANGE`

Set the [Range](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range) request header.
Can be specified multiple times for multiple ranges.

```sh
fetch -r 0-1023 example.com
```

**Maximum Allowed Redirects**: `--redirects NUM`

Set the maximum allowed automatic redirects. Use `0` to disable redirects.

```sh
fetch --redirects=0 example.com
```

**Timeout**: `--timeout SECONDS`

Set a timeout for the entire request in seconds.

```sh
fetch --timeout 2.5 example.com
```

**Custom DNS Server**: `--dns-server IP[:PORT]|URL`

Use a custom DNS server, either the IP (and optional port) of a UDP server, or the HTTPS URL of a DNS-over-HTTPS server.

```sh
fetch --dns-server https://1.1.1.1/dns-query example.com
```

**Proxy**: `--proxy PROXY`

Route the request through the specified proxy.

```sh
fetch --proxy http://localhost:8000 example.com
```

**Unix Socket**: `--unix PATH`

Make the request over a Unix domain socket. Only available on Unix-like systems.

```sh
fetch --unix /var/run/service.sock http://unix/
```

**Insecure TLS**: `--insecure`

Allow for invalid TLS certificates from the server.

```sh
fetch --insecure example.com
```

**Disable Automatic Decompression**: `--no-encode`

Disable automatically requesting and decompressing gzip response bodies.

```sh
fetch --no-encode example.com
```

---

## Configuration

`fetch` can be configured using a file with an ini-like format. It searches for
a config file in the following order:

- the file location specified with the `-c` or  `--config` flag
- on Windows at `%AppData%\fetch\config`
- on Unix-like systems at `$XDG_CONFIG_HOME/fetch/config` or `$HOME/.config/fetch/config`

Settings can be applied globally, or to specific hosts. The order of precedence
for options are:

- CLI flags
- domain-specific configuration
- global configuration


An example of the configuration options are:

```ini
# Global settings

# Enable or disable auto-update or set the minimum interval to check for updates.
# The value can either be a boolean, or a specific interval (e.g. '4h').
# By default, auto-updating is disabled.
auto-update = true

# Enable or disable colored output. Value must be one of "auto", "off", or "on".
# By default, color is set to "auto".
color = off

# Use a custom DNS server. Value must be either an IP (with an optional port),
# or an HTTPS url to use DNS-over-HTTPS.
dns-server = 1.1.1.1:53

# Enable or disable formatted output. Value must be one of "auto", "off", or "on".
# By default, format is set to "auto".
format = on

# Set a header on the HTTP request. Must be in the format "name: value".
header = x-custom-header: value
header = x-another-header: another_value

# Specify the highest allowed HTTP version for the request. Must be one of "1" or "2".
# By default, HTTP is set to 2.
http = 1

# Don't determine exit code from the HTTP status (will always exit with 0).
# By default, 4xx or 5xx statuses result in non-zero exit codes.
ignore-status = true

# Enable or disable image rendering. Value must be one of "auto", "native", or "off".
# By default, image is set to "auto".
image = native

# Accept invalid TLS certificates (DANGER).
insecure = true

# Enable or disable automatically compressing response body.
# By default, compression via gzip is enabled.
no-encode = true

# Enable or disable piping the response body through a pager like "less".
# By default, a pager will be used if available on your system.
no-pager = true

# Specify a proxy url to use for the request.
proxy = http://localhost:8000

# Append query parameters to the HTTP request. Must be in the format "key=value".
query = key=value
query = num=42

# Specify the allowed number of automatic redirects.
redirects = 0

# Disable printing informational data to stderr.
silent = true

# Specify a timeout for the HTTP request. Must be an interval string.
timeout = 30s

# Specify the minimum allowed TLS version to use. Must be in the range "1.0" - "1.3".
tls = 1.3

# Specify the verbosity level. Must be 0 or greater.
# 0 = normal
# 1 = verbose
# 2 = extra verbose
# 3 = debug
verbosity = 2

# Domain-specific settings that take precedence over global options.
[example.com]
header = x-my-header: my_value
timeout = 10s
```

---

## License

`fetch` is released under the [MIT License](LICENSE).

