# fetch

`fetch` is a Go HTTP(S) client CLI. Use Go 1.27.0 or a later compatible
Go 1.27 patch release.

## Development commands

```sh
gofmt -s -w .
go test -v -parallel 8 ./...
go build .
go mod tidy && go mod verify
staticcheck ./...
```

CI also builds release targets with `CGO_ENABLED=0`.

## Repository notes

- `main.go` is the entry point.
- CLI options are defined in `internal/cli`; `docs/cli-reference.md` is
  embedded in the binary. Update the relevant documentation when public
  behavior changes.
- Read `integration/AGENTS.md` before changing integration tests.
