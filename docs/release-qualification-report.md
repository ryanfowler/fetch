# Release qualification report

This report records the final qualification run for the Go migration release
candidate. The Rust oracle was built separately from commit
`ea39416950cc89496b891fcc8bc75b0b68f0d0fe`.

## Results

- Documentation, formatting, module tidy, module verification, `go vet`, and
  Staticcheck passed.
- `go test -v -parallel 8 ./...` passed.
- `go test -race ./...` passed.
- `govulncheck ./...` reported no vulnerabilities in called code.
- All six `CGO_ENABLED=0` release targets built successfully:
  Linux, macOS, and Windows on amd64 and arm64.
- Host `--version` and `--buildinfo` smoke tests passed.
- Local performance qualification passed for startup, help, JSON output, an
  8 MiB streamed download, and a 4 MiB upload.
- The differential parity corpus passed for normal JSON output, duplicate
  response headers, request bodies with duplicate query values, and decoded
  output files.
- Installer, updater, archive-safety, skill, and malicious-input tests passed.

## Scope and limitations

The parity harness normalizes only documented nondeterminism. It preserves
header values and duplicate occurrences while ignoring header order. Go's
standard HTTP stack uses deterministic header serialization; this is the only
intentional migration difference.

The release workflow runs archive-content and checksum validation for every
platform artifact. It executes the extracted Linux amd64 artifact on the CI
host. Other target binaries are cross-built and archive-validated but are
smoke-tested on their native CI platforms when those runners are available.

The Rust executable is an external parity oracle. Normal Go builds do not need
Rust or Cargo. The dedicated parity CI job builds the pinned oracle only for
behavioral comparison.
