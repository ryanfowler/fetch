# ECH (Encrypted Client Hello) Support — Scoping Document

## What is ECH?

Encrypted Client Hello (ECH) is a TLS 1.3 extension that encrypts the ClientHello
message—including the SNI (Server Name Indication)—so passive network observers
cannot see which server the client is connecting to. It is the successor to the
earlier ESNI (Encrypted SNI) proposal and is defined in the IETF TLS working
group draft `draft-ietf-tls-esni` (which has been stable and deployed
in-production by Cloudflare, among others, for several years).

ECH works in two layers:

1. **Discovery**: The server's ECH public configuration is distributed through
   DNS HTTPS/SVCB records via the `ech` SvcParamKey (value 5). The client
   fetches this before connecting.

2. **Handshake**: The client encrypts the real ClientHello (with the target SNI)
   inside an outer ClientHello addressed to a "cover" or "public name." The
   server that holds the corresponding private key decrypts the inner
   ClientHello; servers that don't have the key fall back to the outer
   ClientHello (which typically has a generic SNI like `cloudflare-ech.com`).

## Good news: rustls already has full ECH support

rustls 0.23.41 (the version fetch currently uses) includes complete client-side
ECH support:

- **`rustls::client::EchMode`** — Enum controlling ECH behavior:
  - `EchMode::Enable(EchConfig)` — Real ECH with a server's config
  - `EchMode::Grease(EchGreaseConfig)` — Anti-ossification GREASE ECH

- **`rustls::client::EchConfig::new(ech_config_list, hpke_suites)`** — Constructs
  an `EchConfig` from raw ECH config bytes (base64-decoded from the DNS `ech`
  SvcParam) and a list of supported HPKE suites.

- **`ConfigBuilder::with_ech(mode)`** — Wires ECH into the `ClientConfig`
  builder and implicitly selects TLS 1.3 only.

- **`ClientConnection::ech_status()`** — Returns `EchStatus`:
  `NotOffered | Grease | Offered | Accepted | Rejected`.

- **HPKE suites** — The aws-lc-rs crypto provider ships 12 HPKE suites covering
  P-256, P-384, P-521, and X25519 with AES-128/256-GCM and ChaCha20Poly1305
  (available via `ALL_SUPPORTED_SUITES`).

- **`EchConfigListBytes`** type alias for the raw bytes from DNS.

- **`EncryptedClientHelloError`** error type.

This means **no new TLS library dependency is needed**. ECH works
transparently through the existing rustls stack, including for QUIC/H3
(though see Open Question #6 below).

## Value for fetch

- **Privacy**: Users querying sensitive APIs or endpoints benefit from SNI
  encryption.

- **Parity**: curl added ECH support in 8.9.0 (July 2024). As a curl-inspired
  tool with `--from-curl`, fetch should track this capability.

- **Modern TLS posture**: ECH is the natural complement to encrypted DNS
  (DoH/DoT/DoQ), which fetch already supports.

## Integration Points

### 1. DNS SVCB/HTTPS Record Parsing (`src/dns/svcb.rs`)

The SVCB/HTTPS record parser handles keys 0–4, 6, and 7. Key 5 (ECH) is currently
unhandled and silently skipped. Changes needed:

- Add `KEY_ECH: u16 = 5` constant.
- Add `ech: Option<Vec<u8>>` field to `SvcbRecord`. Store the raw bytes—this is
  an `ECHConfigList` per the spec, exactly what `EchConfig::new()` expects.
- Add `KEY_ECH` to `SUPPORTED_MANDATORY_KEYS`.
- Parse `ech` in `record_from_params` (store raw bytes).
- Add `ECH=<base64>` formatting in `format_svc_param` for `--inspect-dns`.

**Files**: `src/dns/svcb.rs`

### 2. DNS Inspection Output (`src/dns/inspect/rdata.rs`)

No changes needed—`format_rdata` calls into `svcb::format_rdata` which picks
up the new key automatically.

**Files**: No changes needed.

### 3. CLI Flags & Config (`src/cli.rs`, `src/config/mod.rs`)

New user-facing options:

| Flag | Config key | Values | Default | Description |
|---|---|---|---|---|
| `--ech` | `ech` | `auto`, `on`, `off` | `auto` | Enable/disable ECH |
| `--ech-config` | `ech-config` | `@file` or base64 | — | Explicit ECH config (bypasses DNS) |
| `--ech-grease` | `ech-grease` | boolean | `false` | Send GREASE ECH when no real config is available |
| `--ech-hard-fail` | `ech-hard-fail` | boolean | `false` | Fail if ECH is not accepted by the server |

- **`auto`**: Use ECH if the server advertises it in HTTPS/SVCB DNS records.
  Warn in verbose mode when using plain UDP/system DNS. Gracefully fall back
  to non-ECH if no config is found.
- **`on`**: Require ECH; error if no ECH config is available.
- **`off`**: Never use ECH (default without `--ech`).

- **`--ech-config`**: Accepts a base64-encoded `ECHConfigList` or `@file` path
  to a file containing one. When set, DNS-based ECH discovery is skipped.

- **`--ech-grease`**: When no real ECH config is available, send a GREASE ECH
  extension (using a random key). Prevents ossification without real
  encryption. Implicitly true in `auto` mode when no config is found, or can
  be explicitly requested.

- **`--ech-hard-fail`**: When set, the connection fails if the server rejects
  or ignores the ECH offer (i.e., `ech_status()` is not `Accepted`).
  Without this flag, a rejected ECH offer falls through to the outer
  ClientHello and succeeds.

**Files**: `src/cli.rs`, `src/config/mod.rs`

### 4. TLS Client Configuration (`src/tls/mod.rs`)

Extend `rustls_platform_client_config_with_options` (or add a sibling function)
to accept optional ECH parameters:

```rust
pub fn rustls_platform_client_config_with_options(
    ca_cert_paths: &[String],
    cert_path: Option<&str>,
    key_path: Option<&str>,
    insecure: bool,
    min_tls: Option<(&str, &str)>,
    max_tls: Option<&str>,
    ech_mode: Option<rustls::client::EchMode>,  // NEW
) -> Result<rustls::ClientConfig, FetchError>
```

When `ech_mode` is `Some`, call `builder.with_ech(ech_mode)` which implicitly
restricts protocol versions to TLS 1.3. The existing TLS version bounds
(`--min-tls`/`--max-tls`) must be validated against this: if ECH is active and
min/max allow TLS 1.2, we should warn (or error) that ECH requires TLS 1.3.

**Files**: `src/tls/mod.rs`

### 5. HTTP Transport Client (`src/http/transport/client.rs`)

`ClientConfig` needs new fields:

```rust
pub(super) ech_mode: Option<rustls::client::EchMode>,
pub(super) ech_hard_fail: bool,
```

The `ClientBuilder` needs corresponding setters that the `configure_tls`
function in `src/http/client.rs` can call.

The ECH mode must be plumbed through to the TLS config. In the
`tls_stream_for_config` path, when `EchMode::Enable` is configured,
the resulting `rustls::ClientConfig` already handles everything—no
additional changes needed for the handshake itself.

For the H3 path (`connect_http3_client_with_addrs`), the rustls `ClientConfig`
(with ECH) is converted to a `QuicClientConfig` via `QuicClientConfig::try_from`.
The ECH extension should work through the QUIC layer since it's a TLS-layer
feature, though see Open Question #6.

**Files**: `src/http/transport/client.rs`, `src/http/transport/mod.rs`,
`src/http/transport/h3.rs` (verification only)

### 6. HTTP Client Builder (`src/http/client.rs`)

In `build_client_for_url`:

1. If ECH mode is `auto` or `on`, query HTTPS/SVCB DNS records for the `ech`
   key. This can piggyback on the existing SVCB record fetch already done for
   auto-H3 discovery in `resolve_dns_for_client`. If auto-H3 isn't enabled but
   ECH is, a separate SVCB query is needed (or the auto-H3 query should
   always be done when ECH is active).

2. Build `EchConfig` from the DNS result: base64-decode the `ech` bytes →
   `EchConfigListBytes`, then `EchConfig::new(ech_config_list, hpke_suites)`.
   The HPKE suites come from `rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES`.

3. If an explicit `--ech-config` is supplied, use that instead.

4. If ECH mode is `on` and no config is available, error.

5. If `--ech-grease` is set and no real config is available, construct an
   `EchGreaseConfig` and use `EchMode::Grease(...)`.

6. Warn in verbose mode when ECH is used with plaintext DNS.

**Files**: `src/http/client.rs`

### 7. TLS Inspection (`src/tls/inspect.rs`)

`--inspect-tls` should report ECH status. The `ClientConnection::ech_status()`
method provides this. Required display information:

- ECH mode (enabled / grease / not offered)
- Cover/outer SNI (the `public_name` from the ECH config)
- Whether ECH was accepted or rejected by the server
- Inner SNI (the actual target hostname, when ECH succeeded)

**Files**: `src/tls/inspect.rs`, `src/tls/inspect/render.rs`

### 8. Verbose Output (`-vvv` and `--timing`)

In verbose mode, report:
- ECH config source (DNS / explicit `--ech-config` / GREASE)
- If from DNS: the resolver used and query duration
- Whether ECH was accepted or rejected
- The cover/outer SNI

**Files**: `src/http/response/metadata.rs` (connection metadata output)

### 9. WebSocket (`src/websocket/`)

The WebSocket handshake builds its own TLS config. This path needs to carry
the ECH mode through similarly to the HTTP path. Since `wss://` connections
already use `rustls_platform_client_config_with_options`, adding the `ech_mode`
parameter there should be sufficient.

**Files**: `src/websocket/` (connection setup)

### 10. `--from-curl` (`src/cli/from_curl.rs`)

curl's ECH flags:
- `--ech <config>` — maps to `--ech on` + `--ech-config <config>` or
  `--ech auto` when `<config>` is `auto`
- `--ech-hard-fail` — maps directly

Unsupported curl ECH variants (e.g., `--ech false` or GREASE-specific flags)
should produce clear diagnostics.

**Files**: `src/cli/from_curl.rs`

## Dependency Impact

**No new dependencies needed.** rustls 0.23.41 already includes ECH support
through the `aws-lc-rs` crypto provider that fetch already uses.

The `hpke` types used by `EchConfig::new()` are part of rustls' public API:
- `rustls::client::EchConfig`
- `rustls::client::EchMode`
- `rustls::client::EchGreaseConfig`
- `rustls::client::EchStatus`
- `rustls::crypto::hpke::Hpke`
- `rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES`
- `pki_types::EchConfigListBytes` (re-exported as `rustls::pki_types::EchConfigListBytes`)

## Build Impact

**None.** ECH is already compiled into rustls. No new features need to be
enabled—the HPKE implementation ships by default with `aws-lc-rs`.

## Implementation Plan

### Phase 1: DNS Discovery & CLI Plumbing (estimated: 1–3 days)

- [ ] Add `KEY_ECH = 5` and `ech: Option<Vec<u8>>` to `SvcbRecord`
- [ ] Parse `ech` SvcParam in `record_from_params`
- [ ] Add `KEY_ECH` to `SUPPORTED_MANDATORY_KEYS`
- [ ] Format `ech` in `format_svc_param` (as `ECH=<base64>`)
- [ ] Add `--ech`, `--ech-config`, `--ech-grease`, `--ech-hard-fail` CLI flags
- [ ] Add `ech`, `ech-config`, `ech-grease`, `ech-hard-fail` config options
- [ ] Add `--ech` to `--from-curl` translation
- [ ] `--inspect-dns` includes ECH config in HTTPS/SVCB output
- [ ] Unit tests for SVCB parsing and CLI/config validation

### Phase 2: ECH-enabled Connections (estimated: 3–5 days)

- [ ] Extend `configure_tls` / `rustls_platform_client_config_with_options` to
      accept an `Option<EchMode>` parameter
- [ ] Build `EchConfig` from DNS SVCB `ech` bytes in `build_client_for_url`
- [ ] Wire `EchMode` through `ClientConfig` and `ClientBuilder`
- [ ] Handle `--ech on` (error on no config), `auto` (graceful fallback),
      `off`, and `--ech-grease`
- [ ] ECH + auto-H3: share the SVCB DNS query between both features
- [ ] Warn in verbose mode when ECH is used with plaintext/system DNS
- [ ] `--ech-hard-fail`: check `ech_status()` after handshake and error on
      non-`Accepted`
- [ ] Wire ECH through WebSocket TLS setup
- [ ] `--inspect-tls` shows ECH status
- [ ] Integration tests against known ECH-enabled endpoints (e.g., Cloudflare)

### Phase 3: Polish & Docs (estimated: 1–2 days)

- [ ] Verbose output (`-vvv`) reports ECH status and SNI details
- [ ] `--timing` waterfall includes ECH-relevant phases
- [ ] New doc page `docs/ech.md`
- [ ] Update `docs/cli-reference.md`, `docs/configuration.md`

## Testing Strategy

### Unit tests

- SVCB/HTTPS record parsing with `ech` key (valid, malformed, empty, multiple
  configs in list)
- ECH config selection from `EchConfigListBytes`
- `--ech` mode validation (valid/invalid values)
- `--ech-config` base64 decoding and `@file` support
- `--ech-hard-fail` with `EchStatus::Rejected` → error
- TLS version validation: ECH + `--min-tls 1.2` → warning

### Integration tests

- **Positive**: `--ech on` against a known ECH-enabled server (Cloudflare) verifies
  `ech_status() == Accepted`
- **Fallback**: `--ech auto` against a non-ECH server → non-ECH connection succeeds
- **Hard-fail**: `--ech on --ech-hard-fail` against a non-ECH server → error
- **Explicit config**: `--ech-config <base64>` with a pre-obtained ECH config
- **GREASE**: `--ech-grease` against a non-ECH server → connection succeeds
  with GREASE extension sent
- **DNS inspection**: `--inspect-dns` shows `ECH=<base64>` for servers
  advertising it
- **TLS inspection**: `--inspect-tls` shows ECH status (accepted/rejected)
- **Auto-H3 interaction**: ECH + HTTP/3 (both use SVCB records)
- **Proxy**: ECH through an HTTP CONNECT proxy (proxy sees outer SNI only)
- **WebSocket**: `wss://` with ECH
- **curl compat**: `--from-curl 'curl --ech hard ...'` works correctly

## Risks & Open Questions

### Risks

1. **ECH + TLS 1.2**: rustls' `with_ech()` implicitly selects TLS 1.3 only.
   If the user has `--min-tls 1.2` and `--ech on`, we must either:
   (a) error out (clean but strict), or
   (b) warn and force TLS 1.3 (pragmatic).
   Recommend (a) — error with a clear message.

2. **DNS confidentiality**: ECH is most effective when the DNS query for the
   ECH config is encrypted. If `--dns-server` is not configured (or is plain
   UDP), the SVCB query leaks the hostname. We should emit a warning in
   verbose mode. Optionally, in `auto` mode, we could use a well-known DoH
   resolver just for the SVCB query.

3. **ECH key rotation**: Server ECH keys rotate. The TTL on HTTPS/SVCB records
   governs validity. We should respect SVCB TTLs and re-fetch when they
   expire.

4. **Cover name leakage**: The outer ClientHello SNI is the `public_name` from
   the ECH config (e.g., `cloudflare-ech.com`). This is visible to network
   observers. This is inherent to ECH and not something fetch can change.

5. **`EchConfig` is per-server**: The `ClientConfig` produced by
   `with_ech()` is specific to one ECH config. fetch currently builds one
   `ClientConfig` per request, so this is fine. But the auto-H3 pool shares
   H3 connections by origin—if ECH is active, the pool key should include
   ECH status to avoid mixing ECH and non-ECH connections to the same origin.

### Open Questions

1. **What HPKE suites should we pass to `EchConfig::new()`?** The full
   `ALL_SUPPORTED_SUITES` list covers everything. This gives the best chance
   of finding a compatible config.

2. **Should `--ech auto` be the default?** curl defaults to off. Given that
   ECH requires an extra DNS query (SVCB) which adds latency, and not all
   servers advertise ECH, defaulting to `auto` might add latency for no
   benefit in many cases. Recommend defaulting to `auto` but ensuring the
   SVCB query doesn't delay the main connection (fire-and-forget parallel
   lookup, same pattern as auto-H3).

3. **Should `--ech auto` work with the system resolver?** Yes. Even if DNS
   isn't encrypted, ECH still encrypts the SNI on the wire. The DNS query
   leaks the hostname, but that's a separate (pre-existing) concern. Warn
   in verbose mode.

4. **Should `--ech-config` accept a file path (`@file`) in addition to
   inline base64?** Yes, for consistency with `--data`, `--json`, etc.

5. **Interaction with `--insecure`**: ECH should work with `--insecure`.
   Certificate verification bypass applies to the inner connection.

6. **ECH + QUIC/H3**: rustls `ClientConfig` with ECH is converted to
   `QuicClientConfig` via `QuicClientConfig::try_from`. This should work
   because ECH is a TLS-layer extension, but it needs verification.
   quinn 0.11.x uses rustls for TLS, so the ECH extension should be
   included in the QUIC handshake.

7. **How to fetch SVCB records when auto-H3 is disabled but ECH is on?**
   Currently SVCB queries only happen for auto-H3 discovery. We need to
   either:
   (a) Always query SVCB when ECH mode is `auto`/`on`, or
   (b) Reuse the auto-H3 SVCB query results for ECH when both are active.
   Option (b) is cleaner—fetch SVCB records once and extract both ALPN and
   ECH data.

## Summary

rustls 0.23.41 already includes full client-side ECH support. The integration
work for fetch is primarily:

1. **Parse ECH from DNS SVCB records** (the `ech` SvcParamKey 5 is currently
   skipped) — `src/dns/svcb.rs`
2. **Plumb CLI flags and config** — `src/cli.rs`, `src/config/mod.rs`
3. **Build `EchConfig` from DNS and wire it into the rustls `ClientConfig`**
   — `src/tls/mod.rs`, `src/http/client.rs`
4. **Surface ECH status in inspection and verbose output**
   — `src/tls/inspect.rs`, verbose output paths
5. **Handle edge cases**: TLS version conflicts, encrypted DNS warnings,
   hard-fail mode, GREASE, WebSocket, `--from-curl`

No new dependencies are required. Estimated total effort: **1–2 weeks** for a
complete, tested implementation.
