# Security Policy

## Supported Versions

Security fixes are provided in new releases of `fetch` for the latest released
version. Older releases are not supported for security fixes; users should
upgrade to the latest release to receive security updates.

## Reporting a Vulnerability

Please do not report suspected vulnerabilities in public issues, discussions, or
pull requests.

Use GitHub private vulnerability reporting when available:

https://github.com/ryanfowler/fetch/security/advisories/new

If private vulnerability reporting is unavailable, open a public issue that asks
for a secure contact path, but do not include exploit details, credentials,
tokens, private keys, request bodies, session files, or sensitive endpoint URLs.

Useful reports include:

- Affected `fetch` version or commit.
- Operating system and terminal environment, when relevant.
- The smallest command or configuration needed to reproduce the issue.
- Expected behavior and observed behavior.
- Whether the issue requires local access, a malicious server, a malicious
  proxy, a crafted response body, a crafted archive, or user-supplied files.
- Any known impact, such as credential disclosure, certificate validation
  bypass, command execution, file overwrite, denial of service, or update
  integrity failure.

You can expect an initial acknowledgement after the report is seen, followed by
follow-up questions or a fix plan when the issue is confirmed. Please allow time
for validation and patch preparation before public disclosure.

## Scope

Security-sensitive areas include:

- HTTP, HTTP/2, HTTP/3, WebSocket, and gRPC request handling.
- TLS verification, certificate display, mTLS, proxy tunnels, and DNS overrides.
- Authentication helpers for Basic, Bearer, Digest, AWS SigV4, cookies, and
  named sessions.
- Response formatting and terminal rendering for untrusted server data.
- File upload, output-file, clipboard, pager, editor, and shell completion
  paths.
- Install and self-update archive download, checksum validation, extraction, and
  replacement logic.

Reports about dependency vulnerabilities are welcome when they include an
exploit path or explain how `fetch` is affected by the vulnerable code.

## Disclosure and Fixes

When a vulnerability is confirmed, the preferred process is:

1. Validate the issue and assess severity.
2. Prepare and test a fix privately when practical.
3. Release a patched version.
4. Publish an advisory or public issue with appropriate credit, unless the
   reporter requests otherwise.

Please coordinate disclosure before publishing proof-of-concept code or detailed
exploit notes.

## Security Best Practices for Users

- Keep `fetch` updated.
- Avoid placing long-lived secrets directly in shell history.
- Treat output from untrusted servers as untrusted, even when formatted for
  readability.
- Review `--insecure`, custom CA, proxy, DNS, pager, editor, clipboard, and
  output-file usage in sensitive environments.
- Prefer HTTPS release artifacts and verify installation/update integrity.
