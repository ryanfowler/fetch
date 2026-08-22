#!/bin/bash
set -euo pipefail

# Installation script for fetch.
# Usage: curl -fsSL https://raw.githubusercontent.com/ryanfowler/fetch/main/install.sh | bash

RESET=""
BOLD=""
DIM=""
RED=""
GREEN=""
YELLOW=""
if [ -t 2 ]; then
  RESET=$'\033[0m'
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  RED=$'\033[31m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
fi

info() {
  printf '%b\n' "${BOLD}${GREEN}info${RESET}: $*" >&2
}

warning() {
  printf '%b\n' "${BOLD}${YELLOW}warning${RESET}: $*" >&2
}

error() {
  printf '%b\n' "${BOLD}${RED}error${RESET}: $*" >&2
}

fail() {
  error "$*"
  exit 1
}

compile_msg() {
  printf '\nTry compiling from source by running: %b\n' "${DIM}go install github.com/ryanfowler/fetch@latest${RESET}" >&2
}

if ! command -v curl >/dev/null 2>&1; then
  error "curl is required but not installed"
  compile_msg
  exit 1
fi

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print tolower($1)}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print tolower($NF)}'
  else
    return 1
  fi
}

if ! sha256_file /dev/null >/dev/null 2>&1; then
  error "sha256sum, shasum -a 256, or openssl dgst -sha256 is required"
  compile_msg
  exit 1
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
  linux|darwin) ;;
  *)
    error "platform not supported by install script: $OS/$ARCH"
    compile_msg
    exit 1
    ;;
esac
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *)
    error "platform not supported by install script: $OS/$ARCH"
    compile_msg
    exit 1
    ;;
esac

PLATFORM="${OS}-${ARCH}"

# These overrides are intentionally explicit test hooks. Production downloads
# must use HTTPS. An HTTP endpoint is accepted only when the caller opts in and
# the endpoint is loopback, which lets integration tests use a local fake release
# service without weakening the normal installer.
API_URL=${FETCH_INSTALL_API_URL:-${FETCH_INSTALL_RELEASE_URL:-https://api.github.com/repos/ryanfowler/fetch/releases/latest}}
ALLOW_HTTP=${FETCH_INSTALL_ALLOW_HTTP:-0}

is_loopback_http_url() {
  local authority=${1#http://}
  authority=${authority%%/*}
  authority=${authority%%\?*}
  authority=${authority%%#*}
  case "$authority" in
    *'@'*) return 1 ;;
    localhost|localhost:*|127.0.0.1|127.0.0.1:*|\[::1\]|\[::1\]:*) return 0 ;;
    *) return 1 ;;
  esac
}

validate_url() {
  case "$1" in
    https://*) return 0 ;;
    http://*)
      if [ "$ALLOW_HTTP" != 1 ] || ! is_loopback_http_url "$1"; then
        fail "refusing non-HTTPS download URL: $1"
      fi
      ;;
    *) fail "release URL must use HTTPS: $1" ;;
  esac
}

validate_url "$API_URL"

CURL_ARGS=(--fail --silent --show-error --location)
if [ "$ALLOW_HTTP" = 1 ]; then
  # The test hook permits an HTTP initial URL, but redirects remain HTTPS-only.
  CURL_ARGS+=(--proto '=http,https' --proto-redir '=https')
else
  CURL_ARGS+=(--proto '=https' --proto-redir '=https')
fi

download_limited() {
  local url=$1
  local destination=$2
  local maximum=$3
  local label=$4
  local pipeline_status size

  # Use a bounded pipe rather than relying only on Content-Length or curl's
  # version-dependent --max-filesize behavior for chunked responses.
  set +e
  curl "${CURL_ARGS[@]}" "$url" | head -c "$((maximum + 1))" > "$destination"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  size=$(wc -c < "$destination")
  if [ "$size" -gt "$maximum" ]; then
    error "$label is larger than the permitted limit"
    return 1
  fi
  if [ "${pipeline_status[0]}" -ne 0 ]; then
    return 1
  fi
}

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fetch-install.XXXXXX")
STAGED_PATH=""
cleanup() {
  if [ -n "${STAGED_PATH:-}" ] && { [ -e "$STAGED_PATH" ] || [ -L "$STAGED_PATH" ]; }; then
    rm -f "$STAGED_PATH"
  fi
  if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

RELEASE_JSON="$TMP_DIR/release.json"
info "fetching latest release metadata"
if ! download_limited "$API_URL" "$RELEASE_JSON" 1048576 "release metadata"; then
  fail "unable to download latest release metadata"
fi

if command -v jq >/dev/null 2>&1; then
  VERSION=$(jq -er '.tag_name // empty' "$RELEASE_JSON") || fail "unable to determine the latest release tag"
else
  VERSION=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"\\]*\)".*/\1/p' "$RELEASE_JSON" | head -n 1)
  [ -n "$VERSION" ] || fail "unable to determine the latest release tag"
fi

# The tag is used only in an asset name. Reject path separators and control
# characters before it reaches any filesystem or archive operation.
case "$VERSION" in
  ""|*/*|*\\*|*[!A-Za-z0-9._+@-]*) fail "release tag contains unsupported characters" ;;
esac

ARCHIVE_NAME="fetch-${VERSION}-${OS}-${ARCH}.tar.gz"
CHECKSUM_NAME="${ARCHIVE_NAME}.sha256"

get_asset_urls() {
  local wanted=$1
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg name "$wanted" \
      '[.assets[]? | select(.name == $name) | .browser_download_url // empty] | .[]' \
      "$RELEASE_JSON"
    return
  fi

  # Parse one JSON object at a time. Matching the complete name field avoids
  # selecting the checksum URL when looking up the archive (the checksum name
  # contains the archive name as a prefix).
  awk -v wanted="$wanted" '
    BEGIN { RS="{" }
    {
      object=$0
      gsub(/[[:space:]]/, "", object)
      needle="\"name\":\"" wanted "\""
      if (index(object, needle) == 0) next
      marker="\"browser_download_url\":\""
      start=index(object, marker)
      if (start == 0) next
      value=substr(object, start + length(marker))
      sub(/".*/, "", value)
      gsub(/\\\//, "/", value)
      print value
    }
  ' "$RELEASE_JSON"
}

ARCHIVE_URLS="$TMP_DIR/archive.urls"
CHECKSUM_URLS="$TMP_DIR/checksum.urls"
get_asset_urls "$ARCHIVE_NAME" > "$ARCHIVE_URLS"
get_asset_urls "$CHECKSUM_NAME" > "$CHECKSUM_URLS"
[ "$(wc -l < "$ARCHIVE_URLS")" -eq 1 ] || fail "release has no unique ${ARCHIVE_NAME} asset"
[ "$(wc -l < "$CHECKSUM_URLS")" -eq 1 ] || fail "release has no unique ${CHECKSUM_NAME} checksum asset"
ARCHIVE_URL=$(sed -n '1p' "$ARCHIVE_URLS")
CHECKSUM_URL=$(sed -n '1p' "$CHECKSUM_URLS")
validate_url "$ARCHIVE_URL"
validate_url "$CHECKSUM_URL"

ARCHIVE_PATH="$TMP_DIR/$ARCHIVE_NAME"
CHECKSUM_PATH="$TMP_DIR/$CHECKSUM_NAME"
info "downloading ${VERSION} for ${PLATFORM}"
if ! download_limited "$ARCHIVE_URL" "$ARCHIVE_PATH" $((128 * 1024 * 1024)) "release archive"; then
  fail "unable to download release archive"
fi
if ! download_limited "$CHECKSUM_URL" "$CHECKSUM_PATH" 1024 "checksum sidecar"; then
  fail "unable to download checksum sidecar"
fi

EXPECTED_DIGEST=$(LC_ALL=C awk 'NF { print $1; exit }' "$CHECKSUM_PATH")
if [ "${#EXPECTED_DIGEST}" -ne 64 ] || ! printf '%s\n' "$EXPECTED_DIGEST" | LC_ALL=C grep -Eq '^[0-9A-Fa-f]{64}$'; then
  fail "checksum sidecar does not begin with exactly 64 hexadecimal characters"
fi
EXPECTED_DIGEST=$(printf '%s' "$EXPECTED_DIGEST" | tr 'A-F' 'a-f')
ACTUAL_DIGEST=$(sha256_file "$ARCHIVE_PATH") || fail "unable to calculate archive SHA-256"
if [ "$EXPECTED_DIGEST" != "$ACTUAL_DIGEST" ]; then
  fail "checksum verification failed (expected ${EXPECTED_DIGEST}, got ${ACTUAL_DIGEST})"
fi

# Bound decompression before asking tar to inspect untrusted entry metadata.
# This keeps a highly compressible archive from expanding without limit during
# listing, even on curl/tar versions that do not provide a streaming size cap.
MAX_TAR_STREAM_BYTES=$((512 * 1024 * 1024 + 128 * 1024))
UNCOMPRESSED_ARCHIVE="$TMP_DIR/archive.tar"
set +e
gzip -dc "$ARCHIVE_PATH" | head -c "$((MAX_TAR_STREAM_BYTES + 1))" > "$UNCOMPRESSED_ARCHIVE"
GZIP_PIPE_STATUS=("${PIPESTATUS[@]}")
set -e
UNCOMPRESSED_SIZE=$(wc -c < "$UNCOMPRESSED_ARCHIVE")
[ "$UNCOMPRESSED_SIZE" -le "$MAX_TAR_STREAM_BYTES" ] || fail "unpacked release archive is larger than 512 MiB"
[ "${GZIP_PIPE_STATUS[0]}" -eq 0 ] || fail "failed to decompress release archive"

# Validate the archive before writing any destination. The release format is
# deliberately narrow: one regular root-level fetch executable and nothing
# else. Extract its bytes to a private file instead of using broad tar extract.
ARCHIVE_LIST="$TMP_DIR/archive.list"
ARCHIVE_VERBOSE="$TMP_DIR/archive.verbose"
if ! tar -tf "$UNCOMPRESSED_ARCHIVE" > "$ARCHIVE_LIST"; then
  fail "failed to inspect release archive"
fi
ENTRY_NAME=""
ENTRY_COUNT=0
while IFS= read -r entry; do
  [ -n "$entry" ] || fail "release archive contains an empty entry name"
  ENTRY_COUNT=$((ENTRY_COUNT + 1))
  case "$entry" in
    fetch|./fetch)
      [ -z "$ENTRY_NAME" ] || fail "release archive contains duplicate fetch executables"
      ENTRY_NAME=$entry
      ;;
    *) fail "release archive contains unexpected entry: $entry" ;;
  esac
done < "$ARCHIVE_LIST"
[ "$ENTRY_COUNT" -eq 1 ] && [ -n "$ENTRY_NAME" ] || fail "release archive does not contain exactly one fetch executable"

if ! tar -tvf "$UNCOMPRESSED_ARCHIVE" > "$ARCHIVE_VERBOSE"; then
  fail "failed to validate release archive entries"
fi
while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  entry_type=${entry:0:1}
  [ "$entry_type" = "-" ] || fail "release archive contains a non-regular fetch entry"
done < "$ARCHIVE_VERBOSE"

CANDIDATE_PATH="$TMP_DIR/fetch"
set +e
tar -xOf "$UNCOMPRESSED_ARCHIVE" "$ENTRY_NAME" | head -c "$((512 * 1024 * 1024 + 1))" > "$CANDIDATE_PATH"
PIPELINE_STATUS=("${PIPESTATUS[@]}")
set -e
CANDIDATE_SIZE=$(wc -c < "$CANDIDATE_PATH")
[ "$CANDIDATE_SIZE" -le $((512 * 1024 * 1024)) ] || fail "extracted fetch is larger than 512 MiB"
[ "${PIPELINE_STATUS[0]}" -eq 0 ] || fail "failed to extract fetch executable"
[ -f "$CANDIDATE_PATH" ] && [ ! -L "$CANDIDATE_PATH" ] || fail "extracted fetch is not a regular file"
[ "$CANDIDATE_SIZE" -gt 0 ] || fail "release archive contains an empty fetch executable"

# Select the destination before staging. FETCH_INSTALL_DIR is useful for
# package managers and tests; the default never writes outside these two
# conventional locations.
if [ -n "${FETCH_INSTALL_DIR:-}" ]; then
  INSTALL_DIR=$FETCH_INSTALL_DIR
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  INSTALL_DIR=/usr/local/bin
elif [ -n "${HOME:-}" ]; then
  INSTALL_DIR="$HOME/.local/bin"
else
  fail "HOME is not set; set FETCH_INSTALL_DIR"
fi
if [ -e "$INSTALL_DIR" ] || [ -L "$INSTALL_DIR" ]; then
  [ -d "$INSTALL_DIR" ] && [ ! -L "$INSTALL_DIR" ] || fail "install directory is not a real directory: $INSTALL_DIR"
else
  mkdir -p "$INSTALL_DIR" || fail "unable to create install directory: $INSTALL_DIR"
fi
# Resolve relative custom directories so generated paths cannot be parsed as
# options by the filesystem utilities below.
INSTALL_DIR=$(cd "$INSTALL_DIR" && pwd -P)
TARGET="$INSTALL_DIR/fetch"
if [ -L "$TARGET" ]; then
  fail "refusing to replace symlink target: $TARGET"
fi
if [ -e "$TARGET" ] && { [ -d "$TARGET" ] || [ ! -f "$TARGET" ]; }; then
  fail "installation target is not a regular file: $TARGET"
fi

# mktemp creates the stage exclusively inside the destination directory. The
# final mv therefore remains one same-filesystem rename, not a copy followed by
# a non-atomic replacement.
STAGED_PATH=$(mktemp "$INSTALL_DIR/.fetch-install.XXXXXX")
if ! cp "$CANDIDATE_PATH" "$STAGED_PATH"; then
  fail "unable to stage fetch in $INSTALL_DIR"
fi
chmod 0755 "$STAGED_PATH"
[ -f "$STAGED_PATH" ] && [ ! -L "$STAGED_PATH" ] || fail "staged fetch is not a regular file"

# Validate the staged candidate before touching an existing installation. Close
# stdin and impose both a file-output limit and a wall-clock limit because the
# archive is not trusted merely because its digest matched the release sidecar.
VERSION_PATH="$TMP_DIR/version.txt"
validate_staged_version() {
  local pid deadline status
  # Bash's file-size limit is portable across the Bash versions shipped by
  # supported macOS releases. The candidate replaces this shell, so the PID we
  # retain is also the PID that can be terminated on timeout.
  ( ulimit -f 8; exec "$STAGED_PATH" --version </dev/null > "$VERSION_PATH" 2>/dev/null ) &
  pid=$!
  deadline=$((SECONDS + 10))
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 1
    fi
    sleep 1
  done
  set +e
  wait "$pid"
  status=$?
  set -e
  return "$status"
}
validate_staged_version || fail "staged fetch --version failed or timed out"
VERSION_OUTPUT=$(head -c 4096 "$VERSION_PATH")
VERSION_NAME=$(printf '%s' "$VERSION_OUTPUT" | awk 'NR == 1 { print $1; exit }')
[ "$VERSION_NAME" = fetch ] || fail "staged fetch --version reported an unexpected program identity"

# Check again immediately before the rename. rename/mv replaces the directory
# entry and never follows the final target, while this check gives a clear
# error for a symlink that appeared during installation.
if [ -L "$TARGET" ]; then
  fail "refusing to replace symlink target: $TARGET"
fi
if [ -e "$TARGET" ] && { [ -d "$TARGET" ] || [ ! -f "$TARGET" ]; }; then
  fail "installation target is not a regular file: $TARGET"
fi
if ! mv -f "$STAGED_PATH" "$TARGET"; then
  fail "atomic replacement failed for $TARGET"
fi
STAGED_PATH=""
info "fetch ${VERSION} successfully installed to ${DIM}${TARGET}${RESET}"

# Completion files contain only the fixed fetch command. Values from SHELL are
# used for selection and are never evaluated as shell code.
HOME_DIR=${HOME:-}
case "${SHELL:-}" in
  */bash)
    if [ -n "$HOME_DIR" ]; then
      # shellcheck disable=SC2016
      completion='eval "$(fetch --complete=bash)"'
      if ! grep -qF "$completion" "$HOME_DIR/.bashrc" 2>/dev/null; then
        printf '\n# fetch completions\n%s\n' "$completion" >> "$HOME_DIR/.bashrc"
        info "completions appended to ${DIM}${HOME_DIR}/.bashrc${RESET}"
      fi
    fi
    ;;
  */zsh)
    if [ -n "$HOME_DIR" ]; then
      # shellcheck disable=SC2016
      completion='eval "$(fetch --complete=zsh)"'
      if ! grep -qF "$completion" "$HOME_DIR/.zshrc" 2>/dev/null; then
        printf '\n# fetch completions\n%s\n' "$completion" >> "$HOME_DIR/.zshrc"
        info "completions appended to ${DIM}${HOME_DIR}/.zshrc${RESET}"
      fi
    fi
    ;;
  */fish)
    if [ -n "$HOME_DIR" ]; then
      mkdir -p "$HOME_DIR/.config/fish/completions"
      "$TARGET" --complete=fish > "$HOME_DIR/.config/fish/completions/fetch.fish"
      info "completions installed to ${DIM}${HOME_DIR}/.config/fish/completions/fetch.fish${RESET}"
    fi
    ;;
esac

if ! command -v fetch >/dev/null 2>&1; then
  warning "you may need to add ${DIM}${INSTALL_DIR}${RESET} to your PATH"
fi
