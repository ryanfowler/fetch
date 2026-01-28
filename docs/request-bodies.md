# Request Bodies

`fetch` provides multiple options for sending request bodies with different content types.

## Overview

Request body options are **mutually exclusive** - you can only use one per request:

| Option            | Content-Type                        | Use Case               |
| ----------------- | ----------------------------------- | ---------------------- |
| `-d, --data`      | Auto-detected                       | Raw data, binary files |
| `-j, --json`      | `application/json`                  | JSON APIs              |
| `-x, --xml`       | `application/xml`                   | XML/SOAP APIs          |
| `-f, --form`      | `application/x-www-form-urlencoded` | Simple forms           |
| `-F, --multipart` | `multipart/form-data`               | File uploads           |

## Raw Data

The `-d` or `--data` flag sends raw request body data. Content-Type is auto-detected when reading from files.

### Inline Data

```sh
fetch -d 'Hello, world!' -m PUT example.com/resource
```

### From File

```sh
fetch -d @data.txt -m PUT example.com/resource
fetch -d @payload.bin -m POST example.com/upload
```

### From Stdin

```sh
echo 'Request body' | fetch -d @- -m PUT example.com/resource
cat data.json | fetch -d @- -m POST example.com/api
```

### Content-Type Detection

When using `@filename`, the Content-Type is detected from the file extension.
Some examples are:

| Extension | Content-Type               |
| --------- | -------------------------- |
| `.json`   | `application/json`         |
| `.xml`    | `application/xml`          |
| `.html`   | `text/html`                |
| `.txt`    | `text/plain`               |
| `.csv`    | `text/csv`                 |
| Unknown   | `application/octet-stream` |

Override with a header:

```sh
fetch -d @data.bin -H "Content-Type: application/custom" -m POST example.com
```

## JSON Bodies

The `-j` or `--json` flag sends JSON data and sets `Content-Type: application/json`.

### Inline JSON

```sh
fetch -j '{"name": "test", "value": 42}' -m POST example.com/api
```

### From File

```sh
fetch -j @payload.json -m POST example.com/api
```

### From Stdin

```sh
echo '{"key": "value"}' | fetch -j @- -m POST example.com/api

# Build JSON dynamically
jq -n '{name: "test", time: now}' | fetch -j @- -m POST example.com/api
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
}' -m POST example.com/api/users
```

## XML Bodies

The `-x` or `--xml` flag sends XML data and sets `Content-Type: application/xml`.

### Inline XML

```sh
fetch -x '<user><name>John</name></user>' -m POST example.com/api
```

### From File

```sh
fetch -x @request.xml -m POST example.com/soap/endpoint
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
</soap:Envelope>' -m POST example.com/soap
```

## URL-Encoded Forms

The `-f` or `--form` flag sends URL-encoded form data. Use multiple times for multiple fields.

### Basic Form

```sh
fetch -f username=john -f password=secret -m POST example.com/login
```

### With Special Characters

Values are automatically URL-encoded:

```sh
fetch -f "message=Hello World!" -f "email=user@example.com" -m POST example.com/contact
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
fetch -F name=John -F email=john@example.com -m POST example.com/users
```

### File Uploads

Use `@` prefix to upload files:

```sh
fetch -F file=@document.pdf -m POST example.com/upload
fetch -F avatar=@photo.jpg -F name=John -m POST example.com/profile
```

### Multiple Files

```sh
fetch -F "files=@doc1.pdf" -F "files=@doc2.pdf" -m POST example.com/upload
```

### Mixed Content

```sh
fetch \
  -F "title=My Document" \
  -F "description=A sample upload" \
  -F "file=@document.pdf" \
  -F "thumbnail=@preview.png" \
  -m POST example.com/documents
```

### Home Directory Expansion

The `~` is expanded to your home directory:

```sh
fetch -F config=@~/config.json -m POST example.com/settings
```

## Editor Integration

The `-e` or `--edit` flag opens an editor to compose or modify the request body before sending.

### Basic Usage

```sh
fetch --edit -m PUT example.com/resource
```

### With Initial Content

Combine with other body options to edit before sending:

```sh
fetch -j '{"name": "template"}' --edit -m POST example.com/api
```

### Editor Selection

The editor is selected in this order:

1. `VISUAL` environment variable
2. `EDITOR` environment variable
3. Well-known editors (`vim`, `nano`, etc.)

```sh
EDITOR=code fetch --edit -m POST example.com/api
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
fetch -j '{"inline": true}' -m POST example.com

# From file
fetch -j @data.json -m POST example.com

# From stdin
cat data.json | fetch -j @- -m POST example.com

# Home directory
fetch -d @~/Documents/data.txt -m PUT example.com
```

## Method Inference

When a request body is provided without specifying a method, the default is still GET. Always specify the method explicitly for clarity:

```sh
# Explicit POST
fetch -j '{"data": true}' -m POST example.com

# Don't rely on implicit behavior
fetch -j '{"data": true}' example.com  # Still uses GET!
```

## Large Files

For large file uploads, consider:

1. **Streaming**: `fetch` streams file content rather than loading it all into memory
2. **Timeout**: Set appropriate timeouts with `--timeout`
3. **Progress**: Use `-v` to see request/response headers

```sh
fetch -F "large=@bigfile.zip" --timeout 300 -v -m POST example.com/upload
```

## Examples

### REST API Create

```sh
fetch -j '{
  "title": "New Post",
  "content": "Hello, World!",
  "published": true
}' -m POST example.com/api/posts
```

### Form Login

```sh
fetch -f username=admin -f password=secret -m POST example.com/login
```

### File Upload with Metadata

```sh
fetch \
  -F "file=@report.pdf" \
  -F "title=Monthly Report" \
  -F "tags=finance,monthly" \
  -m POST example.com/documents
```

### GraphQL Query

```sh
fetch -j '{
  "query": "{ user(id: 1) { name email } }"
}' -m POST example.com/graphql
```

### Webhook Payload

```sh
fetch -j @webhook-payload.json \
  -H "X-Webhook-Secret: $WEBHOOK_SECRET" \
  -m POST example.com/webhooks/receive
```

## See Also

- [CLI Reference](cli-reference.md) - All request body options
- [gRPC](grpc.md) - Sending Protocol Buffer messages
- [Output Formatting](output-formatting.md) - Response formatting
