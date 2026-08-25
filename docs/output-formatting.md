# Output Formatting

`fetch` automatically formats and syntax-highlights response bodies based on
content type. Raw output and streaming formats avoid whole-body buffering; all
bounded transformations use the caps in [Limits and safety](limits.md).

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

Buffered formatters limit generated output to 1 MiB and reject excessive
nesting. When formatting exceeds a limit, fetch returns the original response
body instead of retaining partial formatted output. Use raw output for larger
or highly nested responses.

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

## Article extraction

Use `--article` to extract the readable part of an HTML or XHTML response as
Markdown. The output starts with YAML frontmatter. Markdown responses pass
through with only a `url` frontmatter field. Article extraction uses the final
URL after redirects to resolve links.

Article mode decodes the response before extraction and accepts at most 16 MiB
of decoded content. It does not run JavaScript, so content rendered only by
client-side scripts is not available. Output files and pipes receive raw,
uncolored Markdown. On a terminal, embedded article images are fetched and
rendered unless `--image off` is set. `--format`, `--color`, and `--pager` affect
presentation only.

```sh
fetch --article https://example.com/story
fetch --article --output story.md https://example.com/story
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
- Blockquote and list marker highlighting; TTY blockquotes use a muted rule
  and muted text
- Bold blue table headers with dimmed table borders and separators
- TTY prose wraps to the detected terminal width, capped at 100 columns by
  default, using display-cell widths;
  wide tables use a vertical record layout
- On TTYs, links and image alt text are rendered as clickable OSC 8 terminal
  hyperlinks; non-terminal output does not contain OSC 8 hyperlink escapes

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
- Event type and data parsing
- JSON in `data:` fields is formatted when each event is complete
- LF, CRLF, and CR line endings are supported
- Individual events are limited to 16 MiB

In automatic compression mode, a compressed `text/event-stream` response to a
GET or HEAD request is drained up to a small bounded prefix and retried once
without `Accept-Encoding`. Unsafe methods keep the original response and show a
warning instead of replaying the request.

```sh
fetch example.com/events
```

Output:

```
event: message
data: {"user": "john", "text": "Hello!"}

event: message
data: {"user": "jane", "text": "Hi there!"}
```

### NDJSON / JSON Lines

**Content-Types**: `application/x-ndjson`, `application/ndjson`, `application/x-jsonl`, `application/jsonl`, `application/x-jsonlines`

Features:

- Streaming output line by line
- Each line formatted as JSON
- LF and CRLF line endings are supported
- Individual records are limited to 16 MiB

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

Formatting is disabled when writing to a file.

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

Use filename from `Content-Disposition` header:

```sh
fetch -O -J example.com/download
# Uses server-provided filename
```

The extended `filename*` parameter is preferred. Server-provided names are
restricted to one safe filename component. Path separators, control characters,
Windows device names, and alternate-data-stream syntax are removed or rejected.
Malformed or missing header names fall back to the URL filename with a warning.
Downloads use an exclusive temporary file and an atomic commit. Existing
symlink destinations are rejected, including with `--clobber`.

### `--clobber`

Overwrite existing files:

```sh
fetch -o output.json --clobber example.com/data
```

## Pager

Use `--pager auto|on|off` to control paging. In `auto` mode, formatted text
is paged only when stdout is a terminal. `on` forces a pager for text output,
and `off` disables it. Images bypass the pager. `--no-pager` remains a
compatibility alias for `--pager off`.

```sh
fetch --pager off example.com/large-response
fetch --pager on --format on example.com/large-response
```

In automatic mode, `NO_PAGER` disables paging. If `PAGER` is set, fetch parses
its executable and arguments without a shell. Shell operators are not
interpreted. Invalid pager quoting is an error. If `PAGER` is unset, fetch uses
`less -FIRX`; when `LESS` is set, fetch invokes `less` without adding default
flags.

Raw output (`--format off` or `--output -`) and image bytes bypass the pager.
A pager that exits early is treated as a clean output termination. Startup or
other nonzero pager failures are reported.

## Binary Detection

When stdout is a terminal, `fetch` checks if the response appears to be binary data. If so, it displays a warning instead of corrupting your terminal:

```
warning: the response body appears to be binary (content type: application/octet-stream)
```

To force output:

```sh
fetch -o - example.com/binary.dat > file.dat
```

## Configuration

Set defaults in your [configuration file](configuration.md):

```ini
# Always format output
format = on

# Disable colors
color = off

# Disable pager
no-pager = true
```

## Examples

### Pipe to jq

```sh
fetch --format off example.com/api | jq '.users[0]'
```

### Save Pretty JSON

```sh
fetch --format on --pager off example.com/api | tee response.json
```

### Force Colors in Pipe

```sh
fetch --format on --color on --pager off example.com/api | less -R
```

### Raw Binary Download

```sh
fetch -o archive.zip example.com/download.zip
```

## See Also

- [CLI Reference](cli-reference.md) - All formatting options
- [Image Rendering](image-rendering.md) - Terminal image display
- [Configuration](configuration.md) - Default settings
- [Article extraction](article.md) - Readable Markdown output
- [HAR recording](har.md) - Sidecar capture
- [Limits and safety](limits.md) - Shared resource caps
