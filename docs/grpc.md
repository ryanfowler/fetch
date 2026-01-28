# gRPC Support

`fetch` supports making gRPC calls with automatic protocol handling, JSON-to-protobuf conversion, and formatted responses.

## Overview

gRPC (gRPC Remote Procedure Calls) is a high-performance RPC framework that uses Protocol Buffers for serialization and HTTP/2 for transport.

## Basic gRPC Request

### `--grpc`

Enable gRPC mode. This flag:

- Forces HTTP/2 protocol
- Sets method to POST
- Adds gRPC headers (`Content-Type: application/grpc+proto`, `TE: trailers`)
- Applies gRPC message framing
- Handles gRPC response framing

```sh
fetch --grpc https://localhost:50051/package.Service/Method
```

### URL Format

The service and method are specified in the URL path:

```
https://host:port/package.ServiceName/MethodName
```

Example:

```sh
# Call Echo method on EchoService in the echo package
fetch --grpc https://localhost:50051/echo.EchoService/Echo
```

## Proto Schema Options

To enable JSON-to-protobuf conversion and rich response formatting, provide a proto schema.

### `--proto-file PATH`

Compile `.proto` files using `protoc` (must be installed). Supports multiple comma-separated paths.

```sh
fetch --grpc --proto-file service.proto \
  -j '{"message": "hello"}' \
  https://localhost:50051/echo.EchoService/Echo
```

Multiple files:

```sh
fetch --grpc --proto-file common.proto,service.proto \
  -j '{"request": "data"}' \
  https://localhost:50051/pkg.Service/Method
```

### `--proto-desc PATH`

Use a pre-compiled descriptor set file. Useful when:

- `protoc` isn't available at runtime
- You want faster startup (no compilation)
- Building CI/CD pipelines

Generate a descriptor set:

```sh
protoc --descriptor_set_out=service.pb --include_imports service.proto
```

Use the descriptor:

```sh
fetch --grpc --proto-desc service.pb \
  -j '{"message": "hello"}' \
  https://localhost:50051/echo.EchoService/Echo
```

### `--proto-import PATH`

Add import paths for proto compilation. Use with `--proto-file` when your protos have imports.

```sh
fetch --grpc \
  --proto-file service.proto \
  --proto-import ./proto \
  --proto-import /usr/local/include \
  -j '{"field": "value"}' \
  https://localhost:50051/pkg.Service/Method
```

## How It Works

### With Proto Schema

1. The service and method are extracted from the URL path
2. `fetch` looks up the method's input/output message types in the schema
3. JSON request bodies are converted to protobuf wire format
4. The request is framed with gRPC length-prefix
5. Response protobuf is formatted as JSON with field names from the schema

### Without Proto Schema

When no schema is provided:

- Request bodies must be raw protobuf (not JSON)
- Responses are formatted using generic protobuf parsing
- Field numbers are shown instead of names

## Request Bodies

### JSON to Protobuf

With a proto schema, send JSON that matches your message structure:

```sh
fetch --grpc --proto-file user.proto \
  -j '{
    "name": "John Doe",
    "age": 30,
    "email": "john@example.com"
  }' \
  https://localhost:50051/users.UserService/CreateUser
```

The JSON is automatically converted to protobuf wire format.

### Nested Messages

```sh
fetch --grpc --proto-file order.proto \
  -j '{
    "customer": {
      "id": 123,
      "name": "Jane"
    },
    "items": [
      {"product_id": 1, "quantity": 2},
      {"product_id": 5, "quantity": 1}
    ]
  }' \
  https://localhost:50051/orders.OrderService/CreateOrder
```

### Empty Requests

For methods that take empty messages:

```sh
fetch --grpc --proto-file service.proto \
  https://localhost:50051/health.HealthService/Check
```

Or with an empty JSON object:

```sh
fetch --grpc --proto-file service.proto \
  -j '{}' \
  https://localhost:50051/health.HealthService/Check
```

### File-based JSON

```sh
fetch --grpc --proto-file service.proto \
  -j @request.json \
  https://localhost:50051/pkg.Service/Method
```

## Response Formatting

### With Schema

Responses are formatted as JSON with field names:

```json
{
  "name": "John Doe",
  "age": 30,
  "email": "john@example.com",
  "created_at": {
    "seconds": 1704067200,
    "nanos": 0
  }
}
```

### Without Schema

Generic protobuf parsing shows field numbers:

```
1: "John Doe"
2: 30
3: "john@example.com"
4 {
  1: 1704067200
  2: 0
}
```

## TLS and Security

### Self-Signed Certificates

For development servers with self-signed certificates:

```sh
fetch --grpc --insecure \
  --proto-file service.proto \
  -j '{"request": "data"}' \
  https://localhost:50051/pkg.Service/Method
```

### Custom CA Certificate

```sh
fetch --grpc \
  --ca-cert ca.crt \
  --proto-file service.proto \
  -j '{"request": "data"}' \
  https://server.example.com:50051/pkg.Service/Method
```

### mTLS

```sh
fetch --grpc \
  --cert client.crt \
  --key client.key \
  --ca-cert ca.crt \
  --proto-file service.proto \
  -j '{"request": "data"}' \
  https://secure.example.com:50051/pkg.Service/Method
```

## Debugging

### Verbose Output

See request and response headers:

```sh
fetch --grpc --proto-file service.proto \
  -j '{"field": "value"}' \
  -vv \
  https://localhost:50051/pkg.Service/Method
```

### Dry Run

Inspect the request without sending:

```sh
fetch --grpc --proto-file service.proto \
  -j '{"field": "value"}' \
  --dry-run \
  https://localhost:50051/pkg.Service/Method
```

### Edit Before Sending

Modify the JSON request body in an editor:

```sh
fetch --grpc --proto-file service.proto \
  -j '{"template": "value"}' \
  --edit \
  https://localhost:50051/pkg.Service/Method
```

## Examples

### Health Check

```sh
fetch --grpc https://localhost:50051/grpc.health.v1.Health/Check
```

### Create Resource

```sh
fetch --grpc --proto-file api.proto \
  -j '{
    "resource": {
      "name": "my-resource",
      "type": "TYPE_A",
      "config": {"key": "value"}
    }
  }' \
  https://api.example.com/resources.ResourceService/Create
```

### List with Pagination

```sh
fetch --grpc --proto-file api.proto \
  -j '{"page_size": 10, "page_token": ""}' \
  https://api.example.com/users.UserService/ListUsers
```

### With Authentication

```sh
fetch --grpc --proto-file api.proto \
  -H "Authorization: Bearer $TOKEN" \
  -j '{"id": "123"}' \
  https://api.example.com/users.UserService/GetUser
```

## Troubleshooting

### "protoc not found"

Install Protocol Buffers compiler:

```sh
# macOS
brew install protobuf

# Ubuntu/Debian
apt install protobuf-compiler

# Or use --proto-desc with pre-compiled descriptors
```

### "method not found in schema"

- Verify the URL path matches `package.Service/Method` exactly
- Check that your proto file defines the service and method
- Ensure all required imports are included via `--proto-import`

### "failed to parse JSON"

- Verify JSON syntax is correct
- Check field names match proto definitions (use snake_case)
- Ensure types match (strings quoted, numbers not quoted)

### Connection Errors

- gRPC requires HTTP/2 - ensure server supports it
- Check port number (gRPC typically uses different ports than REST)
- For TLS issues, try `--insecure` for testing

### Response Parsing Errors

- If response is empty, check gRPC status in headers (`-vv`)
- Verify proto schema matches server's actual message format
- Try without schema to see raw wire format

## Limitations

- **Unary calls only**: Streaming RPCs are not supported
- **Single message**: Cannot send multiple messages in one request
- **gRPC-Web**: Standard gRPC protocol only, not gRPC-Web

## See Also

- [CLI Reference](cli-reference.md) - All gRPC options
- [Authentication](authentication.md) - mTLS setup
- [Troubleshooting](troubleshooting.md) - Common issues
