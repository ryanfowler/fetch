# fetch

`fetch` is a modern command-line HTTP(S) client.
It supports a wide variety of HTTP features — from basic GET requests to options such as custom headers,
authentication (including AWS signature V4), multipart or urlencoded forms, and automatic response body decompression.
It also features built‑in request formatting, syntax highlighting, progress indicators, and even in-terminal image rendering.

---

## Installation

You can install `fetch` from the pre-built binaries or compile it from source.

### Using Pre-built Binaries

Visit the [GitHub releases page](https://github.com/ryanfowler/fetch/releases)
to download the binary for your operating system.

### Building from Source

Make sure you have Go installed, then run:

```bash
go install -trimpath -ldflags="-s -w" github.com/ryanfowler/fetch/cmd/fetch@latest
```

### Updating

Once installed, you can update the fetch binary in-place by running:

```bash
fetch --update
```

---

## Basic Usage

To make a GET request to a URL and print the response body to stdout:

```bash
fetch https://api.example.com/data
```

By default, `fetch` uses the GET method. To use a different HTTP method (e.g. POST), use the `--method` (or `-m`) option:

```bash
fetch -m POST https://api.example.com/submit
```

---

## Custom Headers and Query Parameters

### Custom Headers

Use the `--header` (or `-H`) flag to append custom headers. For example:

```bash
fetch -H "Accept: application/json" -H "X-Custom-Header: hello" https://api.example.com/data
```

### Query Parameters

Append query parameters using the `--query` (or `-q`) flag:

```bash
fetch -q "key1=value1" -q "key2=value2" https://api.example.com/search
```

These parameters will be URL‑encoded and appended to the request URL.

---

## Sending Request Bodies

### Raw Data and Files

Use the `--data` (or `-d`) flag to send a raw request body. To send data directly:

```bash
fetch -m POST --json -d '{"name": "Alice", "age": 30}' https://api.example.com/users
```

The `--json` flag sets the request's `Content-Type` header to `application/json`.

If you want to load the request body from a file, prefix the file path with an `@`:

```bash
fetch -m POST -d @payload.json https://api.example.com/users
```

### Form and Multipart Data

For URL‑encoded form submissions, use the `--form` (or `-f`) option. This option accepts key=value pairs:

```bash
fetch -m POST -f "username=alice" -f "password=secret" https://api.example.com/login
```

For multipart form submissions, use the `--multipart` (or `-F`) option:

```bash
fetch -m POST -F "file=@/path/to/image.png" https://api.example.com/upload
```

### Using an Editor

If you want to interactively create or edit the request body before sending, use the `--edit` (or `-e`) option:

```bash
fetch --edit -m PUT https://api.example.com/update
```

Your preferred editor (from the `VISUAL` or `EDITOR` environment variables) will be opened so you can enter the body content.

---

## Authentication

### Basic Authentication

Use the `--basic` option followed by `USER:PASS`:

```bash
fetch --basic "alice:secret" https://api.example.com/protected
```

### Bearer Authentication

Use the `--bearer` option followed by your token:

```bash
fetch --bearer "your_access_token" https://api.example.com/secure-data
```

### AWS Signature V4

For services that require AWS Signature Version 4 signing, use the `--aws-sigv4` option with the format `REGION/SERVICE`.
Ensure that the environment variables `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are set.

```bash
fetch --aws-sigv4 "us-east-1/s3" https://s3.amazonaws.com/your-bucket/your-object
```

---

## Other Options

### HTTP Versions

Force the use of a specific HTTP version with the `--http` flag. Supported values are `1` and `2`:

```bash
fetch --http 2 https://api.example.com/data
```

### Proxy Support

To route your request through a proxy server, use the `--proxy` option:

```bash
fetch --proxy http://proxy.example.com:8080 https://api.example.com/data
```

### Dry-Run Mode

Want to see what the request will look like without actually sending it? Use `--dry-run` to print the full request details:

```bash
fetch --dry-run https://api.example.com/data
```

### Verbosity Levels

Control the amount of information printed to stderr with the `-v` or `--verbose` flag.
One `-v` will print the response headers, two `-vv` will also print the request headers.

```bash
fetch -v https://api.example.com/data
fetch -vv https://api.example.com/data
```

Alternatively, use the `--silent`(or `-s`) flag to suppress any output to stderr:

```bash
fetch -s https://api.example.com/data
```

---

## Output and Display

### Saving to a File

To write the response body to a file instead of stdout, use the `--output` (or `-o`) option:

```bash
fetch -o response.json https://api.example.com/data
```

### Pager and In-Terminal Rendering

If stdout is a TTY, `fetch` automatically uses a pager (like `less`) for long text responses unless you disable it with the `--no-pager` flag.

### Image Rendering

If the response is an image (e.g. JPEG, PNG, TIFF, WebP), `fetch` can render it directly in the terminal using one of several protocols.
Depending on your terminal emulator (e.g. iTerm2, Kitty, Ghostty, or others), the image will be rendered inline or using block graphics.

---

## Examples

### 1. Simple GET Request

```bash
fetch https://api.github.com/repos/ryanfowler/fetch
```

### 2. POST JSON Data with Bearer Token

```bash
fetch -m POST --json -d '{"title": "New Issue", "body": "Issue description"}' \
  --bearer "your_token_here" \
  https://api.github.com/repos/ryanfowler/fetch/issues
```

### 3. Send a Form Submission

```bash
fetch -m POST -f "username=alice" -f "password=secret" https://example.com/login
```

### 4. Upload a File via Multipart Form

```bash
fetch -m POST -F "file=@/path/to/upload.png" https://example.com/upload
```

### 5. AWS S3 Request with Signature V4

Ensure your AWS credentials are set:

```bash
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
fetch --aws-sigv4 "us-west-2/s3" https://s3.amazonaws.com/your-bucket/your-object
```

### 6. Editing the Request Body with an Editor

```bash
fetch --edit -m PUT https://api.example.com/update
```

An editor window will open so you can write or modify the request body before it is sent.

### 7. Verbose Dry-Run

See the full details of the request without actually sending it:

```bash
fetch --dry-run -vv https://api.example.com/data
```

---

## License

`fetch` is released under the [MIT License](LICENSE).

