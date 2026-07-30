# DNS development notes

Applies to `src/dns/` and its submodules.

- Custom DNS is scoped to each request URL and redirect target.
- Resolve A and AAAA concurrently. Allow progress when either family succeeds while preserving successful records, resolver diagnostic order, IPv6 scope IDs, and Happy Eyeballs staggering.
- UDP queries advertise EDNS(0), randomize IDs, and fall back to TCP on truncation using the remaining timeout budget.
- DoH uses RFC 8484 POST first and its existing JSON fallback. Share the `DohClient` across concurrent address-family lookups and keep response bodies bounded.
- TLS/QUIC resolver hostnames use system DNS for bootstrap and retain SNI and certificate verification.
- ECH discovery can be required even when a remote-resolving proxy bypasses A/AAAA lookup; do not couple those decisions.
- DNS inspection must report partial fallback failures as failures rather than silently presenting incomplete success.
- Reuse `custom.rs`, `wire.rs`, and `doh.rs`; keep inspection orchestration and rendering under `inspect.rs` and its helpers.
