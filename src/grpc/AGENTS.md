# gRPC development notes

Applies to `src/grpc/` and its submodules. Protobuf conversion and schema work must also follow `../proto/AGENTS.md`.

- Reuse the standard gRPC framing, header, status, and compression helpers.
- Reflection and descriptor reads must be bounded by decoded bytes and message count.
- Client and bidirectional streaming input must convert incremental JSON directly to framed protobuf; do not materialize the complete input.
- Enforce `framing::MAX_MESSAGE_SIZE` on incremental and buffered paths.
- Preserve complete-frame streaming and trailers for formatted `application/grpc+proto` responses.
- Keep plaintext loopback h2c support restricted to the gRPC path.
