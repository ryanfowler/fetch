# Output Formatting

`fetch` automatically formats and syntax-highlights response bodies based on content type.

## Format Control

### `--format OPTION`

Control response body formatting:

| Value  | Description                                |
| ------ | ------------------------------------------ |
| `auto` | Format when stdout is a terminal (default) |
| `on`   | Always format output                       |
| `off`  | Never format output                        |

```sh
fetch --format off example.com/api    # Raw output
fetch --format on example.com/api     # Force formatting
```

### `--color OPTION`

Control syntax highlighting:

| Value  | Description                               |
| ------ | ----------------------------------------- |
| `auto` | Color when stdout is a terminal (default) |
| `on`   | Always use colors                         |
| `off`  | Never use colors                          |

```sh
fetch --color off example.com/api     # No colors
fetch --color on example.com/api | less -R  # Colors piped to less
```

## Supported Content Types

### JSON

**Content-Types**: `application/json`, `*/*+json`, `*/*-json`

Features:

- Pretty-printing with proper indentation
- Syntax highlighting for keys, strings, numbers, booleans, null

```sh
fetch example.com/api/users
```

Output:

```json
{
  "id": 1,
  "name": "John Doe",
  "email": "john@example.com",
  "active": true
}
```

### XML

**Content-Types**: `application/xml`, `text/xml`, `*/*+xml`

Features:

- Proper indentation
- Color-coded elements, attributes, and content

```sh
fetch example.com/api/data.xml
```

Output:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<users>
  <user id="1">
    <name>John Doe</name>
    <email>john@example.com</email>
  </user>
</users>
```

### YAML

**Content-Types**: `application/yaml`, `application/x-yaml`, `text/yaml`, `text/x-yaml`, `*/*+yaml`

Features:

- Syntax highlighting for keys, string values, comments, anchors/aliases, tags, and document markers
- Original formatting preserved exactly

```sh
fetch example.com/config.yaml
```

Output:

```yaml
server:
  host: localhost
  port: 8080
  features:
    - auth
    - logging
```

### HTML

**Content-Type**: `text/html`

Features:

- Proper indentation of nested elements
- Syntax highlighting
- Embedded CSS handling

```sh
fetch example.com
```

### CSS

**Content-Type**: `text/css`

Features:

- Selector highlighting
- Property and value coloring
- Proper indentation

```sh
fetch example.com/styles.css
```

### Markdown

**Content-Types**: `text/markdown`, `text/x-markdown`

Features:

- Syntax highlighting for headings, bold, italic, code spans, links, images
- Fenced code block delegation to JSON, YAML, XML, HTML, CSS formatters
- Blockquote and list marker highlighting

```sh
fetch example.com/README.md
```

### CSV

**Content-Types**: `text/csv`, `application/csv`

Features:

- Column alignment for readability
- Vertical "record view" for wide data that doesn't fit terminal width

```sh
fetch example.com/data.csv
```

Standard output (fits terminal):

```
name        email               age
John Doe    john@example.com    30
Jane Smith  jane@example.com    25
```

Vertical mode (wide data):

```
--- Record 1 ---
name:  John Doe
email: john@example.com
age:   30

--- Record 2 ---
name:  Jane Smith
email: jane@example.com
age:   25
```

### MessagePack

**Content-Types**: `application/msgpack`, `application/x-msgpack`, `application/vnd.msgpack`

Features:

- Automatic conversion to JSON format
- Same formatting as JSON responses

```sh
fetch example.com/api/data.msgpack
```

### Protocol Buffers

**Content-Types**: `application/protobuf`, `application/x-protobuf`, `application/x-google-protobuf`, `application/vnd.google.protobuf`, `*/*+proto`

Features:

- Wire format parsing (without schema)
- Field number display
- With gRPC schema: field names and proper types

Without schema (generic parsing):

```
1: "John Doe"
2: 30
3: "john@example.com"
```

With schema (via `--proto-file` or `--proto-desc`):

```json
{
  "name": "John Doe",
  "age": 30,
  "email": "john@example.com"
}
```

See [gRPC documentation](grpc.md) for schema-aware formatting.

### Server-Sent Events (SSE)

**Content-Type**: `text/event-stream`

Features:

- Streaming output as events arrive
- SSE-shaped `event:` and `data:` output
- JSON `data:` payloads are formatted and syntax-highlighted
- Request timeouts still apply to long-running event streams

```sh
fetch example.com/events
```

Output:

```
event: message
data: { "text": "Hello!", "user": "john" }

event: message
data: { "text": "Hi there!", "user": "jane" }
```

When color is enabled, `event` and `data` labels are highlighted, and JSON values
inside `data:` use the same syntax highlighting as JSON responses. In automatic
compression mode, compressed SSE responses are retried without `Accept-Encoding`
so proxies and servers are less likely to buffer events before delivery.

### NDJSON / JSON Lines

**Content-Types**: `application/x-ndjson`, `application/ndjson`, `application/x-jsonl`, `application/jsonl`, `application/x-jsonlines`

Features:

- Streaming output line by line
- Each line formatted as JSON

```sh
fetch example.com/stream.ndjson
```

Output:

```json
{"id": 1, "event": "start"}
{"id": 2, "event": "data", "value": 42}
{"id": 3, "event": "end"}
```

### Images

**Content-Type**: `image/*`

Images are rendered directly in the terminal. See [Image Rendering](image-rendering.md) for details.

## Output to File

### `-o, --output PATH`

Write response body to a file:

```sh
fetch -o response.json example.com/api/data
```

Formatting is disabled when writing to a file, but compression decoding is still
enabled by default. If the response uses `Content-Encoding` for a `.gz`, `.br`,
or `.zst` asset, use `--compress off` for byte-for-byte downloads.

### `-o -` (Stdout)

Force output to stdout, bypassing binary detection:

```sh
fetch -o - example.com/file.bin > output.bin
```

### `-O, --remote-name`

Save to current directory using filename from URL:

```sh
fetch -O example.com/files/document.pdf
# Creates ./document.pdf
```

### `-J, --remote-header-name`

Use filename from `Content-Disposition` header. If no usable header filename is
available, fetch warns and falls back to the URL filename:

```sh
fetch -O -J example.com/download
# Uses server-provided filename
```

### `--clobber`

Overwrite existing files:

```sh
fetch -o output.json --clobber example.com/data
```

## Pager

By default, when stdout is a terminal, `fetch` pipes response body output through a pager for easier navigation. Image responses bypass the pager so native terminal image protocols are interpreted by the terminal.

### Pager Mode

Use `--pager auto` to page terminal stdout, `--pager on` to force the pager, or `--pager off` to disable it.

```sh
fetch --pager off example.com/large-response
```

### Pager Environment

When paging is enabled, fetch uses `$PAGER` if it is set. Set `NO_PAGER` to disable the default `auto` pager. If `$PAGER` is unset, fetch falls back to `less -FIRX`. When `$LESS` is set, fetch runs `less` without adding its default flags so your `LESS` options apply.

The fallback `less -FIRX` flags are:

- `-F` - Quit if output fits on screen
- `-I` - Case-insensitive search
- `-R` - Handle ANSI colors
- `-X` - Don't clear screen on exit

## Binary Detection

When stdout is a terminal, `fetch` checks if the response appears to be binary data. If so, it displays a warning instead of corrupting your terminal:

```
warning: the response body appears to be binary (content type: application/octet-stream)
```

To force output:

```sh
fetch -o file.dat example.com/binary.dat
fetch -o - example.com/binary.dat > file.dat
fetch --image off example.com/image.png
```

## Configuration

Set defaults in your [configuration file](configuration.md):

```ini
# Always format output
format = on

# Disable colors
color = off

# Disable pager
pager = off
```

## Examples

### Pipe to jq

```sh
fetch --format off example.com/api | jq '.users[0]'
```

### Save Pretty JSON

```sh
fetch --format on example.com/api | tee response.json
```

### Force Colors in Pipe

```sh
fetch --format on --color on example.com/api | less -R
```

### Byte-for-Byte Download

```sh
fetch --compress off -o archive.tar.gz example.com/archive.tar.gz
```

## See Also

- [CLI Reference](cli-reference.md) - All formatting options
- [Image Rendering](image-rendering.md) - Terminal image display
- [Configuration](configuration.md) - Default settings
