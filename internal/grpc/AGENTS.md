# gRPC maintainer guidance

Keep framing incremental and enforce the 64 MiB message and reflection
aggregate limits before allocation. Reflection v1alpha fallback is allowed only
for a v1 UNIMPLEMENTED response. Reuse the ordinary TLS, proxy, DNS,
authentication, session, and timeout paths. Preserve final trailer status and
terminal-safe grpc-message output. Unary HAR is bounded; unbounded streaming
HAR is rejected. Add malformed-frame and cancellation tests with protocol
changes.
