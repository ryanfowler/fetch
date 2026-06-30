# Encrypted Client Hello (ECH)

fetch supports Encrypted Client Hello (ECH), a TLS 1.3 extension that encrypts
the ClientHello message—including the SNI (Server Name Indication)—so passive
network observers cannot see which server the client is connecting to.

## Quick Start

```bash
# Auto mode: use ECH if the server advertises it
fetch --ech auto https://example.com

# Require ECH (fail if unavailable)
fetch --ech on https://cloudflare.com

# Disable ECH
fetch --ech off https://example.com
```

## Modes

- **`auto`** — Use ECH if the server advertises it in DNS. Falls back to
  GREASE ECH when no real config is found. If the server rejects the offer,
  the connection proceeds (outer ClientHello fallback). This is the
  recommended mode for general use.

- **`on`** — Require ECH. Errors if the server does not advertise ECH in DNS,
  and fails if the server rejects the offer.

- **`off`** — Never use ECH (the default).

  ECH defaults to `off` rather than `auto` because `auto` requires an extra
  DNS SVCB query on every HTTPS request, which adds latency with no benefit
  when the server doesn't support ECH. Use `--ech auto` or set `ech = auto`
  in your config to enable opportunistic ECH.

## GREASE ECH

In `auto` mode, when no real ECH config is found, fetch sends a randomized
GREASE ECH extension to prevent protocol ossification. This happens
automatically and requires no extra flags.

## How It Works

1. **Discovery**: fetch queries the server's HTTPS/SVCB DNS record for the
   `ech` SvcParam (key 5). This record contains the server's public ECH
   configuration.

2. **Handshake**: fetch encrypts the real ClientHello (with the target SNI)
   inside an outer ClientHello addressed to a "cover" or "public name". The
   server that holds the corresponding private key decrypts the inner
   ClientHello.

3. **DNS privacy**: ECH is most effective when paired with encrypted DNS
   (`--dns-server` with DoH, DoT, or DoQ). Without encrypted DNS, the
   SVCB query for the ECH config leaks the hostname. fetch emits a warning
   in verbose mode when ECH is used with plaintext DNS.

## Configuration

ECH mode can be set in `~/.config/fetch/config`:

```ini
ech = auto
```

Or per-host:

```ini
[example.com]
ech = on
```

## TLS Version Requirements

ECH requires TLS 1.3. If ECH is active and `--min-tls` or `--max-tls`
would allow TLS 1.2, fetch reports an error. Remove the version constraints
or raise them to 1.3 when using ECH.

## Inspection

- **`--inspect-dns`** shows the ECH configuration when a server advertises
  it in HTTPS/SVCB records (displayed as `ECH=<base64>`).

- **`--inspect-tls`** reports whether ECH was accepted or rejected by the
  server, along with the outer/cover SNI.

## curl Compatibility

curl's `--ech` flag maps to fetch:

| curl | fetch |
|------|-------|
| `--ech hard` | `--ech on` |
| `--ech true` | `--ech on` |
| `--ech auto` | `--ech auto` |
| `--ech false` | `--ech off` |

The `--from-curl` flag translates curl's ECH flags automatically.
