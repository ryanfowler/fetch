# HAR recording

`--har PATH` writes one HTTP Archive (HAR) 1.2 sidecar while the normal
response continues through the usual output pipeline:

```sh
fetch --har request.har https://example.com
fetch --har request.har -o response.bin https://example.com/download
```

The file records the final effective exchange after redirects, retries, and
Digest authentication. Request and response headers retain duplicate values.
Timing fields that are not available are `-1`.

Request and response bodies are captured through a bounded streaming tee. Each
body is limited to 16 MiB. UTF-8 text is stored as `text`; binary data is stored
as base64 while within the limit. If a body is larger, the captured payload is
omitted entirely and the HAR contains:

```text
Body omitted by fetch because it exceeds the 16 MiB HAR capture limit
```

Unary gRPC calls are supported when a local schema or successful reflection
positively identifies the method as unary. Framed non-text bodies are base64
encoded and trailers and gRPC status remain in the exchange. Schema-less or
unresolved gRPC methods are rejected for HAR because their cardinality is not
known. WebSocket sessions, DNS/TLS inspection, gRPC list/describe, dry runs,
and unbounded gRPC streams do not support HAR recording.

## Safety and sensitivity

HAR files are intentionally faithful reproductions. They can contain
Authorization headers, cookies, session tokens, request bodies, and response
bodies. Store them with private permissions, review them before sharing, and do
not commit them to a repository.

The HAR destination cannot be `-` and cannot be the response output path. The
file is written to an exclusive temporary file and committed atomically. Use
`--clobber` to replace an existing regular file. Symlink destinations are
rejected.
