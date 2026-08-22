# Go migration parity harness

This branch resumes the Go implementation from the pinned migration baseline
and uses the Rust implementation as a behavioral oracle.

| Revision | Role |
| --- | --- |
| `22ad319f4541ad8d4d198613d32417aa4a491a3c` | Go migration baseline |
| `ea39416950cc89496b891fcc8bc75b0b68f0d0fe` | Rust parity target |

The baseline is intentionally independent of the Rust source tree. Normal Go
builds and tests do not build, download, or require Rust.

## Running differential fixtures

Build the Rust target separately, then provide its executable to the opt-in
integration test:

```sh
FETCH_PARITY_RUST_BINARY=/path/to/rust/fetch \
  go test ./integration -run '^TestDifferentialParity$' -v
```

The Go candidate is built automatically in a temporary directory. To test a
specific candidate binary, set `FETCH_PARITY_GO_BINARY` as well:

```sh
FETCH_PARITY_GO_BINARY=/path/to/go/fetch \
FETCH_PARITY_RUST_BINARY=/path/to/rust/fetch \
  go test ./integration -run '^TestDifferentialParity$' -v
```

Each parity case invokes both binaries with the same arguments, stdin, and
environment snapshot against a deterministic local fixture server. Each
process receives a private working directory; the shared home/config/cache
namespace is reset between runs so state cannot leak from one implementation
to the other. The harness captures stdout, stderr, exit status, and explicitly
requested generated files. Fixture code may also compare selected
server-observed request properties such as method, URL, duplicate headers, and
body bytes.

By default, comparison normalizes only documented nondeterminism: timing
values, DNS transaction IDs, loopback ephemeral ports, private temporary
paths, build-version strings, dates, and HTTP header ordering. Header values
and duplicate header occurrences remain part of the comparison. A case may
opt into semantic comparison when byte-for-byte output is not appropriate;
exit status and captured files are still checked by the harness.

The one intentional migration difference is HTTP header wire order. Go's
standard HTTP stack emits deterministic header order rather than preserving
the Rust implementation's original order. Parity fixtures therefore compare
header names without order while retaining every duplicate value.

Fixtures are organized by subsystem in their own test files. New parity cases
should use local servers and explicit deadlines, and must not depend on public
network services or the developer's config, session, cache, or output files.

## Release gate

Run `scripts/qualify-release.sh` for the final formatting, module, analysis,
race, vulnerability, cross-build, and release smoke checks. A release
candidate must also run it with `--require-parity` and
`FETCH_PARITY_RUST_BINARY` set. See [release qualification](release-qualification.md)
for the complete procedure and the intentional Go header-order difference.
