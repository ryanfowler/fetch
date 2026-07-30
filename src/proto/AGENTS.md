# Protobuf development notes

Applies to `src/proto/` and its submodules. Transport-level gRPC work must also follow `../grpc/AGENTS.md`.

- Reuse shared descriptor discovery, schema, conversion, and JSON-stream parsing helpers.
- Reflection and descriptor processing must remain bounded by decoded bytes and message count.
- Streaming JSON conversion must process values incrementally rather than materializing all input.
- Enforce gRPC framing message-size limits before allocating or encoding a frame.
- Preserve local-schema and reflection behavior across unary, client-streaming, and bidirectional paths.
