# Integration test development notes

Applies to `tests/` and `tests/support/`.

- Integration tests execute the compiled `fetch` binary. Put reusable servers and fixtures in the appropriate `tests/support/` module.
- Bind TCP and UDP test servers to `127.0.0.1:0`; do not reserve fixed ports.
- Use `mpsc` request notifications and `recv_timeout` rather than polling server state.
- `run_fetch` isolates the HTTP/3 cache by default; preserve that isolation in new helpers.
- CI runs integration tests with two test threads. If a socket test fails transiently with connection refusal or reset, diagnose with `-- --test-threads=1` before weakening assertions.
- Keep waits bounded and diagnostics useful. Do not add arbitrary sleeps when an event or channel can signal readiness.
