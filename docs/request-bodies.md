# Request Bodies

`fetch` provides multiple options for sending request bodies with different content types.

## Overview

Payload source options are **mutually exclusive** - you can only use one per request:

| Option            | Content-Type                        | Use Case               |
| ----------------- | ----------------------------------- | ---------------------- |
| `-d, --data`      | Auto-detected                       | Raw data, binary files |
| `-j, --json`      | `application/json`                  | JSON APIs              |
| `-x, --xml`       | `application/xml`                   | XML/SOAP APIs          |
| `-f, --form`      | `application/x-www-form-urlencoded` | Simple forms           |
| `-F, --multipart` | `multipart/form-data`               | File uploads           |

When no method is specified, these options default the method to `POST`.
`--edit` also defaults to `POST` when composing a body. Use `-m`/`--method` to
send a body with another method, such as `PUT`.

## Raw Data

The `-d` or `--data` flag sends raw request body data. Content-Type is auto-detected when reading from files.

### Inline Data

```sh
fetch -d 'Hello, world!' -m PUT example.com/resource
```

### From File

```sh
fetch -d @data.txt -m PUT example.com/resource
fetch -d @payload.bin example.com/upload
```

### From Stdin

```sh
echo 'Request body' | fetch -d @- -m PUT example.com/resource
cat data.json | fetch -d @- example.com/api
```

### Content-Type Detection

When using `@filename`, the Content-Type is detected from the file extension.
Multipart file parts use the same policy. Some examples are:

| Extension        | Content-Type               |
| ---------------- | -------------------------- |
| `.json`          | `application/json`         |
| `.xml`           | `application/xml`          |
| `.html`, `.htm`  | `text/html`                |
| `.txt`, `.text`  | `text/plain`               |
| `.csv`           | `text/csv`                 |
| `.md`            | `text/markdown`            |
| `.ndjson`        | `application/x-ndjson`     |
| `.msgpack`       | `application/msgpack`      |
| `.pb`            | `application/protobuf`     |
| Image extensions | matching `image/*` type    |
| Unknown          | `application/octet-stream` |

Override with a header:

```sh
fetch -d @data.bin -H "Content-Type: application/custom" example.com
```

## JSON Bodies

The `-j` or `--json` flag sends JSON data and sets `Content-Type: application/json`.

### Inline JSON

```sh
fetch -j '{"name": "test", "value": 42}' example.com/api
```

### From File

```sh
fetch -j @payload.json example.com/api
```

### From Stdin

```sh
echo '{"key": "value"}' | fetch -j @- example.com/api

# Build JSON dynamically
jq -n '{name: "test", time: now}' | fetch -j @- example.com/api
```

### Nested JSON

```sh
fetch -j '{
  "user": {
    "name": "John",
    "email": "john@example.com"
  },
  "settings": {
    "theme": "dark",
    "notifications": true
  }
}' example.com/api/users
```

## XML Bodies

The `-x` or `--xml` flag sends XML data and sets `Content-Type: application/xml`.

### Inline XML

```sh
fetch -x '<user><name>John</name></user>' example.com/api
```

### From File

```sh
fetch -x @request.xml example.com/soap/endpoint
```

### SOAP Example

```sh
fetch -x '<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <GetUser>
      <UserId>123</UserId>
    </GetUser>
  </soap:Body>
</soap:Envelope>' example.com/soap
```

## URL-Encoded Forms

The `-f` or `--form` flag sends URL-encoded form data. Use multiple times for multiple fields.

### Basic Form

```sh
fetch -f username=john -f password=secret example.com/login
```

### With Special Characters

Values are automatically URL-encoded:

```sh
fetch -f "message=Hello World!" -f "email=user@example.com" example.com/contact
```

### Generated Content-Type

```
Content-Type: application/x-www-form-urlencoded
```

Request body:

```
username=john&password=secret
```

## Multipart Forms

The `-F` or `--multipart` flag sends multipart form data, typically used for file uploads.

### Text Fields

```sh
fetch -F name=John -F email=john@example.com example.com/users
```

### File Uploads

Use `@` prefix to upload files:

```sh
fetch -F file=@document.pdf example.com/upload
fetch -F avatar=@photo.jpg -F name=John example.com/profile
```

When uploading a file by path, only the file's base name is sent in the multipart `filename` parameter.

### Multiple Files

```sh
fetch -F "files=@doc1.pdf" -F "files=@doc2.pdf" example.com/upload
```

### Mixed Content

```sh
fetch \
  -F "title=My Document" \
  -F "description=A sample upload" \
  -F "file=@document.pdf" \
  -F "thumbnail=@preview.png" \
  example.com/documents
```

### Home Directory Expansion

The `~` is expanded to your home directory:

```sh
fetch -F config=@~/config.json example.com/settings
```

## Editor Integration

The `-e` or `--edit` flag opens an editor to compose or modify the request body before sending.
When the request has a recognized Content-Type, the temporary edit file uses the matching extension from the shared MIME policy.

### Basic Usage

```sh
fetch --edit example.com/resource
```

### With Initial Content

Combine with other body options to edit before sending:

```sh
fetch -j '{"name": "template"}' --edit example.com/api
```

### Editor Selection

The editor is selected in this order:

1. `VISUAL` environment variable
2. `EDITOR` environment variable
3. Well-known editors (`vim`, `nano`, etc.)

```sh
EDITOR=code fetch --edit example.com/api
```

## File Reference Syntax

Body options that accept `[@]VALUE` support these formats:

| Format      | Description              |
| ----------- | ------------------------ |
| `value`     | Use the literal value    |
| `@filename` | Read content from file   |
| `@-`        | Read content from stdin  |
| `@~/path`   | Read from home directory |

### Examples

```sh
# Literal value
fetch -j '{"inline": true}' example.com

# From file
fetch -j @data.json example.com

# From stdin
cat data.json | fetch -j @- example.com

# Home directory
fetch -d @~/Documents/data.txt -m PUT example.com
```

## Method Inference

When a request body flag is provided without `--method`, `fetch` uses `POST`.
An explicit method always wins, so use `-m PUT`, `-m PATCH`, or even `-m GET`
when a body must be sent with a different method.

```sh
# Inferred POST
fetch -j '{"data": true}' example.com

# Explicit override
fetch -m PUT -j '{"data": true}' example.com
```

## Large Files

For large file uploads, consider:

1. **Streaming**: `fetch` streams file content rather than loading it all into memory
2. **Timeout**: Set appropriate timeouts with `--timeout`
3. **Progress**: Use `-v` to see request/response headers

```sh
fetch -F "large=@bigfile.zip" --timeout 300 -v example.com/upload
```

## Examples

### REST API Create

```sh
fetch -j '{
  "title": "New Post",
  "content": "Hello, World!",
  "published": true
}' example.com/api/posts
```

### Form Login

```sh
fetch -f username=admin -f password=secret example.com/login
```

### File Upload with Metadata

```sh
fetch \
  -F "file=@report.pdf" \
  -F "title=Monthly Report" \
  -F "tags=finance,monthly" \
  example.com/documents
```

### GraphQL Query

```sh
fetch -j '{
  "query": "{ user(id: 1) { name email } }"
}' example.com/graphql
```

### Webhook Payload

```sh
fetch -j @webhook-payload.json \
  -H "X-Webhook-Secret: $WEBHOOK_SECRET" \
  example.com/webhooks/receive
```

## See Also

- [CLI Reference](cli-reference.md) - All request body options
- [gRPC](grpc.md) - Sending Protocol Buffer messages
- [Output Formatting](output-formatting.md) - Response formatting
