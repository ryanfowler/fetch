#!/usr/bin/env bash
# Run the release gate locally or in CI. The Rust oracle is intentionally
# external; set FETCH_PARITY_RUST_BINARY to include the differential corpus.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if [[ "${RELEASE_QUALIFICATION_ALLOW_DIRTY:-0}" != "1" ]]; then
  git diff --exit-code
  git diff --cached --exit-code
  if [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
    printf '%s\n' 'release qualification requires a clean checkout' >&2
    git ls-files --others --exclude-standard >&2
    exit 1
  fi
fi

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'release qualification requires %s in PATH\n' "$1" >&2
    exit 1
  }
}

require_command go
require_command git
require_command staticcheck
require_command govulncheck
require_command python3

if [[ "${1:-}" == "--require-parity" ]]; then
  require_parity=1
  shift
else
  require_parity=0
fi
if (($# != 0)); then
  printf 'usage: %s [--require-parity]\n' "$0" >&2
  exit 2
fi

printf '%s\n' '== format =='
if [[ -n "$(gofmt -s -l .)" ]]; then
  printf '%s\n' 'gofmt reported files that need formatting' >&2
  gofmt -s -l . >&2
  exit 1
fi

printf '%s\n' '== documentation =='
python3 scripts/check-docs.py

printf '%s\n' '== modules =='
go mod tidy
git diff --exit-code -- go.mod go.sum
go mod verify

printf '%s\n' '== analysis =='
# Staticcheck's aggregate package analyzer is parallel by default and can
# trigger an upstream IR analyzer race on Go 1.27. Analyze each package in a
# bounded order instead; this runs the same checks without hiding diagnostics.
while IFS= read -r package; do
  printf 'staticcheck %s\n' "$package"
  GOMAXPROCS=1 staticcheck "$package"
done < <(go list ./...)
go vet ./...

printf '%s\n' '== tests =='
go test -v -parallel 8 ./...
go test -race ./...
govulncheck ./...

printf '%s\n' '== cross-builds =='
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/fetch-release-build.XXXXXX")
cleanup() {
  rm -rf "$build_dir"
}
trap cleanup EXIT

while IFS=: read -r goos goarch suffix; do
  output="$build_dir/fetch-$goos-$goarch$suffix"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w -buildid=' -o "$output" .
  test -s "$output"
done <<'TARGETS'
linux:amd64:
linux:arm64:
darwin:amd64:
darwin:arm64:
windows:amd64:.exe
windows:arm64:.exe
TARGETS

printf '%s\n' '== host smoke =='
host_binary="$build_dir/fetch-host"
go build -trimpath -ldflags='-s -w -buildid=' -o "$host_binary" .
"$host_binary" --version >/dev/null
"$host_binary" --buildinfo >/dev/null
FETCH_QUALIFY_BINARY="$host_binary" scripts/qualify-performance.sh

rust_oracle_revision=ea39416950cc89496b891fcc8bc75b0b68f0d0fe
if ((require_parity)) && [[ "${FETCH_PARITY_RUST_REVISION:-}" != "$rust_oracle_revision" ]]; then
  printf 'FETCH_PARITY_RUST_REVISION must be %s when parity is required\n' "$rust_oracle_revision" >&2
  exit 1
fi
if [[ -n "${FETCH_PARITY_RUST_BINARY:-}" ]]; then
  if [[ ! -x "$FETCH_PARITY_RUST_BINARY" ]]; then
    printf 'FETCH_PARITY_RUST_BINARY is not an executable file: %s\n' "$FETCH_PARITY_RUST_BINARY" >&2
    exit 1
  fi
  printf '%s\n' '== differential parity =='
  FETCH_PARITY_GO_BINARY="$host_binary" \
    go test ./integration -run '^TestDifferentialParity$' -v
elif ((require_parity)); then
  printf '%s\n' 'FETCH_PARITY_RUST_BINARY is required by --require-parity' >&2
  exit 1
else
  printf '%s\n' '== differential parity (skipped: FETCH_PARITY_RUST_BINARY is unset) =='
fi

printf '%s\n' 'release qualification passed'
