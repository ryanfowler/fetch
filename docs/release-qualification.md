# Release qualification

The release gate is `scripts/qualify-release.sh`. Run it from a clean Go
checkout:

```sh
./scripts/qualify-release.sh
```

The gate runs formatting, documentation, module, static-analysis, test, race,
vulnerability, and supported-target cross-build checks. It also smoke-tests the
host binary with `--version` and `--buildinfo`.

`govulncheck` and `staticcheck` must be available in `PATH`. CI installs the
pinned Staticcheck `2026.2.1` and govulncheck `v1.7.0` tools before it runs the
gate. Run the gate from a clean checkout.

## Differential parity

The Rust implementation is an external behavioral oracle. It is not a build or
test dependency. To run the parity corpus, build the pinned Rust target
`ea39416950cc89496b891fcc8bc75b0b68f0d0fe` separately and set its executable:

```sh
FETCH_PARITY_RUST_BINARY=/path/to/rust/fetch \
FETCH_PARITY_RUST_REVISION=ea39416950cc89496b891fcc8bc75b0b68f0d0fe \
  ./scripts/qualify-release.sh --require-parity
```

The harness invokes both binaries against deterministic local fixtures and
compares exit status, output, files, request semantics, and duplicate header
values. It normalizes only documented nondeterminism. Go's deterministic
header serialization is the one intentional migration difference.

## Release artifacts

The release workflow builds statically linked Go binaries for Linux, macOS,
and Windows on amd64 and arm64. It checks archive contents, checksums, and the
native Linux artifact before upload. The qualification script also exercises
startup, help, a local JSON request, an 8 MiB streamed download, and a 4 MiB
upload under generous timeout budgets. The installer and updater tests use
isolated local fixtures and never replace the developer's executable.

Go is the maintained implementation. The Rust source is retained only as the
historical parity oracle for the migration.
