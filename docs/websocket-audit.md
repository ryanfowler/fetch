# Historical WebSocket implementation audit

> **Status:** Historical pre-fix audit. The findings below describe the
> implementation before the WebSocket hardening work and are retained as design
> context. They are not a current issue list, and their source line references
> may no longer match the code. Regression coverage now tracks the resolved
> behavior.

At the time of this audit, the existing WebSocket unit and integration tests
passed, but the implementation had several correctness, security, and
resource-management issues.

## 1. Remote terminal escape injection — High severity

**Locations:**

- `src/websocket/mod.rs:757-767`
- `src/websocket/mod.rs:775-786`
- `src/core.rs:172-218`

Incoming text messages are written directly to a terminal when formatting is disabled or JSON parsing fails. A malicious server can send ANSI/OSC escape sequences to change terminal titles, manipulate clipboard contents, overwrite terminal output, or trigger terminal-emulator vulnerabilities.

Binary output has the same problem. `bytes_appear_printable()` explicitly treats `ESC` as safe, so binary data containing terminal escape sequences may be emitted directly to the terminal. It also fails to count trailing incomplete UTF-8 sequences as unsafe.

### Recommended fix

- Sanitize unformatted text with `interactive::sanitize_message_text()` when stdout is a terminal.
- Never write binary WebSocket frames directly to a terminal; display a binary indicator instead.
- If printable binary output is retained, use a stricter predicate that rejects all terminal control sequences, especially `ESC`.
- Fix `bytes_appear_printable()` to count incomplete trailing UTF-8 as unsafe.
- Add tests for text and binary payloads containing ANSI, OSC, BEL, carriage return, and incomplete UTF-8 sequences.

## 2. Interactive history has an unbounded byte footprint — High severity

**Locations:**

- `src/websocket/interactive.rs:115-134`
- `src/websocket/interactive.rs:495-496`
- `src/websocket/interactive.rs:641-645`

Interactive history is capped at 10,000 messages, but not by bytes. Each message may be up to 16 MiB, so the theoretical retained history is roughly 160 GiB. A server can exhaust client memory by sending many maximum-sized messages.

History replay also clones entries with `to_vec()`, which can temporarily increase memory usage further.

### Recommended fix

- Use a byte-bounded `VecDeque` history.
- Track total retained bytes and evict oldest entries until under a fixed budget.
- Represent a single message larger than the history budget with a truncated or placeholder entry.
- Avoid cloning replay slices; iterate by reference.
- Cache sanitized/formatted output rather than retaining and reformatting full payloads repeatedly.

## 3. `--ws-message-mode` is ignored in interactive mode — High severity

**Locations:**

- `src/websocket/mod.rs:117-123`
- `src/websocket/interactive.rs:649-757`

Interactive mode does not receive the selected message mode and always sends text using `String::from_utf8_lossy()`.

Consequences:

- `--ws-message-mode binary` still sends interactive input as text.
- `--ws-message-mode binary` sends the initial message as text.
- Invalid UTF-8 in an initial binary payload is silently replaced with U+FFFD.
- `--ws-message-mode text` does not reject invalid initial data as noninteractive mode does.

### Recommended fix

Pass `WebSocketMessageMode` into `run_terminal()` and use the shared `outgoing_message()` helper for both the initial message and interactive input. This preserves invalid bytes in auto/binary modes and provides consistent behavior across modes.

## 4. Empty initial messages are inconsistently handled — Medium severity

**Location:**

- `src/websocket/interactive.rs:675`

Interactive mode filters out empty initial messages, while noninteractive mode sends them. Therefore `fetch ws://example.test -d ""` behaves differently depending on the selected mode.

### Recommended fix

Send the message whenever `initial_message` is `Some`, including zero-length messages. Only `None` should mean that no initial message was supplied.

## 5. Close frames are not flushed and close status is discarded — High severity

**Locations:**

- `src/websocket/mod.rs:747`
- `src/websocket/mod.rs:134-146`
- `src/websocket/interactive.rs:699-725`

When a peer sends a close frame, the code immediately returns. Tungstenite queues the close response internally, but it must be flushed with `flush()` or `Sink::close()`. Dropping the split stream can terminate the TCP connection without completing the WebSocket close handshake.

The close code and reason are also ignored. Server closures such as 1008 Policy Violation or 1011 Internal Error still result in exit code 0.

Interactive Ctrl-D and stdin EOF also return without sending a close frame.

### Recommended fix

- Return a structured read outcome containing the received close frame.
- Flush the queued close response before dropping the connection.
- Send a close frame on interactive stdin EOF.
- Expose the close code and reason.
- Treat abnormal close codes as failures while treating 1000/1001 as normal.
- Sanitize close reasons before printing them because they are server-controlled.

Add tests verifying that the client sends a close response and returns a failure for abnormal close codes.

## 6. Interactive input is unbounded and inefficient — High severity

**Locations:**

- `src/websocket/interactive.rs:288-375`
- `src/websocket/interactive.rs:549-582`

The interactive editor has no maximum input size. `LineEditor::insert()` and `Vec::insert()` are O(n), and the input line is redrawn after every character. Large pasted input can therefore cause quadratic CPU behavior and excessive memory use.

### Recommended fix

- Enforce the same 16 MiB maximum as other outgoing messages.
- Use a gap buffer or another efficient editable buffer.
- Batch redraws for large pasted input.
- Reject oversized input with a clear status message.

## 7. Noninteractive stdin buffering is bounded by messages, not bytes — Medium severity

**Locations:**

- `src/websocket/mod.rs:41`
- `src/websocket/mod.rs:371-374`

The channel capacity is 16 messages, but each text message can be 16 MiB. A slow server can therefore cause approximately 256 MiB of queued input, in addition to the current message and tungstenite buffers.

### Recommended fix

Use a byte-budgeted queue, or reduce the queue to one message and apply backpressure before reading additional large lines. Also configure a finite `max_write_buffer_size` in `WebSocketConfig`.

## 8. Environment and system proxies are bypassed — Medium severity

**Locations:**

- `src/websocket/mod.rs:229`
- `src/http/client.rs:994-1030`

WebSocket dialing only uses `cli.proxy.as_deref()`. HTTP requests use environment and system proxy configuration when `--proxy` is absent, including `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`.

HTTP and WebSocket requests therefore behave differently. In a corporate environment, WebSocket traffic may bypass the configured proxy or fail unexpectedly.

### Recommended fix

Centralize proxy selection and reuse it for WebSockets. Honor:

- Explicit `--proxy`
- `HTTP_PROXY`/`HTTPS_PROXY`
- `ALL_PROXY`
- `NO_PROXY`
- System proxy configuration, if supported

Map `ws://` to HTTP proxy selection and `wss://` to HTTPS proxy selection.

## 9. Several CLI options are silently ignored — Medium severity

**Locations:**

- `src/flag_registry.rs`
- `src/app.rs:741-800`

The WebSocket validator rejects only some unsupported options. These options currently have no effect:

- `--unix`
- `--redirects`
- `--range`
- `--compress`
- `--no-encode`
- `--image`
- `--ignore-status`
- `--proto-desc`
- `--proto-file`
- `--proto-import`

`--compress` is particularly misleading: HTTP content encoding and WebSocket per-message compression are different mechanisms, and no WebSocket compression extension is negotiated or decoded.

### Recommended fix

Either implement each feature or reject it explicitly with a WebSocket-specific diagnostic. At minimum, add these flags to the WebSocket conflict registry. `--pager` should either produce the same warning style as `--timing` or be explicitly documented as ignored.

## 10. `-d @-` is read before the WebSocket connection is established — Medium severity

**Locations:**

- `src/websocket/mod.rs:85`
- `src/websocket/mod.rs:315`
- `src/websocket/mod.rs:96-109`

Initial message materialization happens before dialing. Consequently, `fetch ws://example.test -d @-` waits for all stdin input before performing the handshake. This prevents interactive server-driven workflows and contradicts the documented behavior that the client connects before reading piped input.

The read also occurs outside the request timeout budget.

### Recommended fix

Keep the body descriptor until after the handshake. Establish the WebSocket first, then materialize `@-` and send the initial message. Use `spawn_blocking` for blocking stdin/file reads.

## 11. `--ws-interactive on` can silently fall back to noninteractive mode — Medium severity

**Locations:**

- `src/websocket/mod.rs:117-123`
- `src/websocket/interactive.rs:1440-1441`

`--ws-interactive on` verifies that stdio are terminals, but `execute()` only enters interactive mode if terminal-size detection succeeds and the terminal has at least five rows. Otherwise it silently falls through to noninteractive mode.

This contradicts the meaning of `on` and the documented “require the prompt” behavior.

### Recommended fix

For explicit `on`, return an error when terminal-size detection fails or the terminal is too small. Only `auto` should fall back.

## 12. Interactive JSON formatting parses every message twice — Low/Medium severity

**Location:**

- `src/websocket/interactive.rs:457-470`

The code first parses JSON only to check whether parsing succeeds, then parses it again in `format_json_line_to()`.

### Recommended fix

Call `format_json_line_to()` once and use its success/failure result. Cache the formatted/sanitized representation in message history to avoid reformatting on resize and replay.

## 13. Interactive stdin errors are silently treated as clean EOF — Low/Medium severity

**Location:**

- `src/websocket/interactive.rs:757-773`

`spawn_stdin_reader()` discards all stdin read errors. The receiving loop then interprets channel closure as normal stdin completion and exits successfully.

### Recommended fix

Send `Result<Vec<u8>, io::Error>` through the channel, distinguish EOF from read failure, report the error, and perform a graceful close.

## 14. Interactive terminal width calculations are incomplete — Low severity

**Locations:**

- `src/websocket/interactive.rs:549-582`
- `src/websocket/interactive.rs:1028-1056`

The custom width logic does not correctly handle combining characters, variation selectors, newer emoji, grapheme clusters, or zero-width characters. This can cause cursor and wrapping misalignment.

### Recommended fix

Use a Unicode width/grapheme library such as `unicode-width`, and consider grapheme-aware editing for cursor movement and deletion.

## 15. Verbose and dry-run output exposes credentials — Security hardening

**Locations:**

- `src/websocket/mod.rs:535-558`
- `src/websocket/mod.rs:615-714`

`-v`, `-vv`, and `--dry-run` print all handshake headers, including `Authorization`, `Cookie`, `Set-Cookie`, AWS signing headers, and session tokens. This is risky in CI logs and shared terminals.

### Recommended fix

Redact sensitive headers by default, with an explicit opt-in flag for displaying them. At minimum redact `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, and AWS security-token headers.

## Validation performed

The following commands were run successfully:

```bash
cargo test --locked --all-features --lib --bins websocket:: -- --nocapture
cargo test --locked --all-features --test websocket -- --test-threads=2
```
