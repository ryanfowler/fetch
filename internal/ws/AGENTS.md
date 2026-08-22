# WebSocket maintainer guidance

WebSocket mode uses the shared proxy, resolver, TLS, ECH, session, and timeout
policy. Keep text, binary, stdin, queue, and interactive paths byte-bounded at
16 MiB. Preserve backpressure and finish normal close handshakes after local
EOF. Never write untrusted binary or close text raw to a terminal. Unsupported
normal-response options must be rejected before connecting. Add cancellation
and leak tests for lifecycle changes.
