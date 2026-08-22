# Limits and safety invariants

These limits are part of the Go implementation. They apply even when a server
omits `Content-Length`.

| Area                                     | Limit or rule                             |
| ---------------------------------------- | ----------------------------------------- |
| Article decoded body                     | 16 MiB                                    |
| Readability DOM elements                 | 500,000                                   |
| HAR request body                         | 16 MiB                                    |
| HAR response body                        | 16 MiB                                    |
| WebSocket message                        | 16 MiB                                    |
| WebSocket piped text line                | 16 MiB                                    |
| WebSocket interactive entry              | 16 MiB                                    |
| Streaming SSE/NDJSON record              | 16 MiB                                    |
| Composite curl/protocol materialization  | 16 MiB                                    |
| gRPC encoded and decompressed message    | 64 MiB                                    |
| gRPC reflection                          | 128 messages and 64 MiB total             |
| MessagePack/schema-less protobuf nesting | 128 levels                                |
| Complete formatted response              | 1 MiB                                     |
| Schema-less protobuf fields              | 1,000,000                                 |
| Clipboard capture                        | 1 MiB                                     |
| DoH wire response                        | 65,535 bytes                              |
| DoH JSON/error response                  | 1 MiB bounded body                        |
| Default DoH transaction timeout          | 5 seconds when no narrower budget applies |
| Release metadata                         | 1 MiB                                     |
| Update checksum sidecar                  | 1 KiB                                     |
| Update archive                           | 128 MiB                                   |
| Update unpacked data                     | 512 MiB                                   |
| Update archive entries                   | 128                                       |
| Dry-run body preview                     | 1,024 bytes                               |
| Effective `Retry-After`                  | 30 seconds; clamped values warn           |
| Update redirects                         | 10                                        |

Ordinary downloads, uploads, SSE, NDJSON, gRPC streams, and raw output stream
instead of buffering a complete body. A bounded transformation reports an
error when it crosses its limit. Request, connect, DNS, TLS, retry, redirect,
body-read, and subprocess work uses the applicable wall-clock budget. A zero
request or connect timeout means unlimited for that budget.

Output files, HAR files, sessions, HTTP/3 cache files, skill installations, and
updater staging use exclusive temporary state and atomic commits. Symlink
redirects are rejected. Terminal diagnostics escape untrusted control bytes;
Authorization, proxy authorization, cookies, session tokens, and AWS session
tokens are redacted. HAR artifacts are the exception because they are intended
to reproduce the exchange and can contain sensitive data.

Image rendering also rejects decoded dimensions above 8192 by 8192. External
image adapters and pagers run without a shell, with bounded output and a
process deadline. See [output formatting](output-formatting.md), [HAR](har.md),
[updates](updates.md), and [Agent Skill](agent-skill.md) for feature details.
