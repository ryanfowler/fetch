# Go migration note

`fetch` is implemented and released as a Go program. This tree does not need
Rust or Cargo to build, test, install, or update the client.

The migration compares the Go implementation from the pinned `golang` baseline
`22ad319f4541ad8d4d198613d32417aa4a491a3c` with the historical Rust behavior
oracle at `main` revision
`ea39416950cc89496b891fcc8bc75b0b68f0d0fe`. The Rust source is a reference for
behavior only. It is not a runtime or build dependency.

The one intentional migration difference is request-header wire order. Go's
`net/http` stack uses its normal deterministic header serialization and does not
preserve user-specified wire order. Header names and duplicate values remain
represented deterministically in CLI output. `--sort-headers` is retained as a
compatibility no-op.

Use Go 1.27.0 or a later compatible Go 1.27 patch release. Release and CI builds
use `CGO_ENABLED=0` for Linux, macOS, and Windows amd64/arm64 targets.

Maintainers should validate changes with:

```sh
gofmt -s -w .
go mod tidy
go mod verify
go vet ./...
go test -v -parallel 8 ./...
go test -race ./...
staticcheck ./...
```

Keep the option registry, embedded CLI reference, configuration guide,
completion scripts, Agent Skill, and this migration note synchronized when
public behavior changes.
