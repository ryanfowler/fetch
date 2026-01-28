# Troubleshooting

This guide helps diagnose and fix common issues with `fetch`.

## Exit Codes

`fetch` uses exit codes to indicate the result of a request:

| Exit Code | Meaning                            |
| --------- | ---------------------------------- |
| 0         | Success (HTTP 2xx-3xx)             |
| 4         | Client error (HTTP 4xx)            |
| 5         | Server error (HTTP 5xx)            |
| 6         | Other HTTP status or request error |

### Ignore HTTP Status

To always exit 0 regardless of HTTP status:

```sh
fetch --ignore-status example.com/not-found
echo $?  # Always 0 if request completed
```

## Debugging with Verbosity

### `-v` - Response Headers

```sh
fetch -v example.com
```

Shows:

- HTTP version and status
- Response headers

### `-vv` - Request and Response Headers

```sh
fetch -vv example.com
```

Shows:

- Request method and URL
- Request headers
- Response headers

### `-vvv` - Full Debug Output

```sh
fetch -vvv example.com
```

Shows:

- DNS resolution details
- TLS handshake information
- All headers

## Dry Run Mode

Preview the request without sending:

```sh
fetch --dry-run -m POST -j '{"test": true}' example.com
```

Shows:

- Complete request that would be sent
- Headers and body
- Useful for debugging authentication and body formatting

## Common Issues

### TLS Certificate Errors

**Symptom**: "certificate signed by unknown authority" or similar

**Causes**:

- Self-signed certificate
- Expired certificate
- Wrong hostname
- Missing intermediate certificates
- Corporate SSL inspection

**Solutions**:

1. **For development/testing only**:

   ```sh
   fetch --insecure https://self-signed.example.com
   ```

2. **Add custom CA certificate**:

   ```sh
   fetch --ca-cert /path/to/ca.crt https://internal.example.com
   ```

3. **Check certificate details**:

   ```sh
   fetch -vvv https://example.com 2>&1 | grep -i tls
   ```

4. **Verify certificate externally**:
   ```sh
   openssl s_client -connect example.com:443 -showcerts
   ```

### Connection Timeouts

**Symptom**: Request hangs or "context deadline exceeded"

**Causes**:

- Server unreachable
- Firewall blocking connection
- DNS resolution failure
- Slow server response

**Solutions**:

1. **Set explicit timeout**:

   ```sh
   fetch --timeout 10 example.com
   ```

2. **Test DNS resolution**:

   ```sh
   fetch --dns-server 8.8.8.8 -vvv example.com
   ```

3. **Test network connectivity**:
   ```sh
   ping example.com
   curl -v example.com
   ```

### Connection Refused

**Symptom**: "connection refused"

**Causes**:

- Server not running
- Wrong port
- Firewall blocking

**Solutions**:

1. **Verify the URL and port**
2. **Check if service is running**:
   ```sh
   nc -zv example.com 443
   ```

### DNS Resolution Failures

**Symptom**: "no such host" or DNS errors

**Solutions**:

1. **Try alternative DNS**:

   ```sh
   fetch --dns-server 8.8.8.8 example.com
   fetch --dns-server https://1.1.1.1/dns-query example.com
   ```

2. **Verify hostname**:
   ```sh
   nslookup example.com
   dig example.com
   ```

### Proxy Issues

**Symptom**: Connection errors when using proxy

**Solutions**:

1. **Verify proxy URL format**:

   ```sh
   fetch --proxy http://proxy:8080 example.com
   fetch --proxy socks5://proxy:1080 example.com
   ```

2. **Test without proxy**:

   ```sh
   unset HTTP_PROXY HTTPS_PROXY
   fetch example.com
   ```

3. **Check proxy authentication**:
   ```sh
   fetch --proxy http://user:pass@proxy:8080 example.com
   ```

### HTTP/2 Issues

**Symptom**: "http2: server sent GOAWAY" or protocol errors

**Solutions**:

1. **Force HTTP/1.1**:

   ```sh
   fetch --http 1 example.com
   ```

2. **Check server HTTP/2 support**:
   ```sh
   curl --http2 -v example.com 2>&1 | grep -i alpn
   ```

### gRPC Errors

**Symptom**: gRPC calls failing

**Common issues**:

1. **Method not found**:
   - Check URL path format: `/package.Service/Method`
   - Verify proto schema includes the method

2. **Proto compilation fails**:
   - Install `protoc`: `brew install protobuf`
   - Check import paths: `--proto-import`

3. **JSON conversion errors**:
   - Verify JSON field names match proto (use snake_case)
   - Check types: strings must be quoted

```sh
# Debug gRPC request
fetch --grpc --proto-file service.proto \
  -j '{"field": "value"}' \
  --dry-run \
  https://localhost:50051/pkg.Service/Method
```

### Image Rendering Not Working

**Symptom**: Images show as raw bytes or don't display

**Solutions**:

1. **Check terminal support**:
   - Use Kitty, iTerm2, WezTerm, or Ghostty for best results

2. **Force native decoding**:

   ```sh
   fetch --image native example.com/image.png
   ```

3. **Install image adapters**:

   ```sh
   brew install vips imagemagick ffmpeg
   ```

4. **Disable image rendering**:
   ```sh
   fetch --image off example.com/image.jpg
   ```

### Binary Data Warning

**Symptom**: "the response body appears to be binary"

**Solutions**:

1. **Save to file**:

   ```sh
   fetch -o output.bin example.com/file.bin
   ```

2. **Force output to stdout**:
   ```sh
   fetch -o - example.com/file.bin > output.bin
   ```

### Large Response Truncated

**Symptom**: Response appears cut off

**Info**: Formatting is limited to 16MB of data

**Solutions**:

1. **Save to file** (no size limit):

   ```sh
   fetch -o large-response.json example.com/large
   ```

2. **Disable formatting**:
   ```sh
   fetch --format off example.com/large
   ```

## Configuration Issues

### Config File Not Loading

1. **Check location**:
   - Windows: `%AppData%\fetch\config`
   - macOS/Linux: `~/.config/fetch/config`

2. **Specify explicitly**:

   ```sh
   fetch --config /path/to/config example.com
   ```

3. **Validate syntax**:
   - Check for error messages on stderr
   - Verify INI format

### Settings Not Applied

**Precedence** (highest to lowest):

1. Command-line flags
2. Host-specific config
3. Global config
4. Defaults

Use dry-run to verify:

```sh
fetch --dry-run example.com
```

## Getting More Help

### Version and Build Info

```sh
fetch --version
fetch --buildinfo
```

### Help Text

```sh
fetch --help
```

### Report Issues

If you encounter a bug:

1. Gather debug output:

   ```sh
   fetch -vvv example.com 2>&1
   ```

2. Note your environment:

   ```sh
   fetch --buildinfo
   uname -a
   ```

3. Report at: https://github.com/ryanfowler/fetch/issues

## See Also

- [CLI Reference](cli-reference.md) - All options and flags
- [Configuration](configuration.md) - Config file format
- [Advanced Features](advanced-features.md) - Network options
