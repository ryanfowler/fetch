#!/bin/bash
set -e

# Installation script for fetch
# Usage: curl -fsSL https://raw.githubusercontent.com/ryanfowler/fetch/main/install.sh | bash
#        curl -fsSL https://raw.githubusercontent.com/ryanfowler/fetch/main/install.sh | bash -s -- --completions

RESET=""
BOLD=""
DIM=""
RED=""
GREEN=""
YELLOW=""

# Set escape sequences if stderr is a terminal.
if [ -t 2 ]; then
  RESET="\033[0m"
  BOLD="\033[1m"
  DIM="\033[2m"
  RED="\033[31m"
  GREEN="\033[32m"
  YELLOW="\033[33m"
fi

# Print info message.
info() {
  echo -e "${BOLD}${GREEN}info${RESET}: $1"
}

# Print warning message.
warning() {
  echo -e "${BOLD}${YELLOW}warning${RESET}: $1"
}

# Print error message.
error() {
  echo -e "${BOLD}${RED}error${RESET}: $1"
}

# Print compile from source message.
compile_msg() {
  echo -e "\nTry compiling from source by running: '${DIM}cargo install --git https://github.com/ryanfowler/fetch --locked${RESET}'"
}

usage() {
  cat <<'EOF'
Usage:
  curl -fsSL https://raw.githubusercontent.com/ryanfowler/fetch/main/install.sh | bash
  curl -fsSL https://raw.githubusercontent.com/ryanfowler/fetch/main/install.sh | bash -s -- --completions

Options:
  --completions       Install shell completions into the detected shell config.
  --no-completions    Do not modify shell completion files (default).
  -h, --help          Print this help.

Environment:
  FETCH_INSTALL_COMPLETIONS=1 is equivalent to --completions.
EOF
}

sha256_file() {
  if command -v sha256sum &> /dev/null; then
    sha256sum "$1" | awk '{ print tolower($1) }'
  elif command -v shasum &> /dev/null; then
    shasum -a 256 "$1" | awk '{ print tolower($1) }'
  elif command -v openssl &> /dev/null; then
    openssl dgst -sha256 "$1" | awk '{ print tolower($NF) }'
  else
    return 1
  fi
}

parse_sha256_checksum() {
  awk '
    { contents = contents $0 "\n" }
    END {
      sub(/^[[:space:]]+/, "", contents)
      print tolower(substr(contents, 1, 64))
    }
  ' "$1"
}

install_completions() {
  case "$SHELL" in
    */bash)
      # shellcheck disable=SC2016
      COMPLETION_CMD='eval "$(fetch --complete=bash)"'
      if ! grep -qF "$COMPLETION_CMD" "$HOME/.bashrc" 2>/dev/null; then
        printf '\n# fetch completions\n%s\n' "$COMPLETION_CMD" >> "$HOME/.bashrc"
        info "completions appended to '${DIM}${HOME}/.bashrc${RESET}'"
      fi
      ;;
    */fish)
      mkdir -p "$HOME/.config/fish/completions"
      "$INSTALL_DIR/fetch" --complete=fish > "$HOME/.config/fish/completions/fetch.fish"
      info "completions installed to '${DIM}${HOME}/.config/fish/completions/fetch.fish${RESET}'"
      ;;
    */zsh)
      # shellcheck disable=SC2016
      COMPLETION_CMD='eval "$(fetch --complete=zsh)"'
      if ! grep -qF "$COMPLETION_CMD" "$HOME/.zshrc" 2>/dev/null; then
        printf '\n# fetch completions\n%s\n' "$COMPLETION_CMD" >> "$HOME/.zshrc"
        info "completions appended to '${DIM}${HOME}/.zshrc${RESET}'"
      fi
      ;;
    *)
      warning "completions were not installed because SHELL is not bash, fish, or zsh"
      print_completion_commands
      ;;
  esac
}

print_completion_commands() {
  cat <<'EOF'

Shell completions were not installed automatically.
To enable completions, run the command for your shell:

  # Bash
  echo 'eval "$(fetch --complete bash)"' >> ~/.bashrc

  # Zsh
  echo 'eval "$(fetch --complete zsh)"' >> ~/.zshrc

  # Fish
  mkdir -p ~/.config/fish/completions
  fetch --complete fish > ~/.config/fish/completions/fetch.fish
EOF
}

INSTALL_COMPLETIONS="${FETCH_INSTALL_COMPLETIONS:-0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --completions)
      INSTALL_COMPLETIONS=1
      ;;
    --no-completions)
      INSTALL_COMPLETIONS=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      error "unknown install option: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

case "$INSTALL_COMPLETIONS" in
  1|true|TRUE|yes|YES|on|ON)
    INSTALL_COMPLETIONS=true
    ;;
  0|false|FALSE|no|NO|off|OFF|"")
    INSTALL_COMPLETIONS=false
    ;;
  *)
    error "FETCH_INSTALL_COMPLETIONS must be 1, 0, true, false, yes, no, on, or off"
    exit 1
    ;;
esac

# Determine OS and architecture.
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  darwin) OS="darwin" ;;
  linux) OS="linux" ;;
  *)
    error "platform not supported by install script: $OS/$ARCH"
    compile_msg
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    error "platform not supported by install script: $OS/$ARCH"
    compile_msg
    exit 1
    ;;
esac

PLATFORM="${OS}-${ARCH}"

# Fetch the latest release asset.
info "fetching latest release tag"

if ! command -v curl &> /dev/null; then
  error "curl is required but not installed"
  exit 1
fi

if ! command -v sha256sum &> /dev/null &&
   ! command -v shasum &> /dev/null &&
   ! command -v openssl &> /dev/null; then
  error "sha256sum, shasum, or openssl is required to verify the downloaded artifact"
  exit 1
fi

HAS_JQ=false
if command -v jq &> /dev/null; then
  HAS_JQ=true
fi

RELEASE_JSON=$(curl -fsSL https://api.github.com/repos/ryanfowler/fetch/releases/latest)

# Parse the version tag.
VERSION=""
if $HAS_JQ; then
  VERSION=$(echo "$RELEASE_JSON" | jq -r .tag_name)
else
  VERSION=$(echo "$RELEASE_JSON" | grep -o '"tag_name": *"[^"]*"' | sed 's/"tag_name": *"//;s/"//')
fi
if [ -z "$VERSION" ]; then
  error "unable to determine the latest version"
  exit 1
fi

# Parse the artifact and checksum urls.
ARTIFACT_NAME="fetch-${VERSION}-${PLATFORM}.tar.gz"
CHECKSUM_NAME="${ARTIFACT_NAME}.sha256"
DOWNLOAD_URL=""
CHECKSUM_URL=""
if $HAS_JQ; then
  DOWNLOAD_URL=$(echo "$RELEASE_JSON" | jq -r --arg name "$ARTIFACT_NAME" '.assets[] | select(.name == $name) | .browser_download_url')
  CHECKSUM_URL=$(echo "$RELEASE_JSON" | jq -r --arg name "$CHECKSUM_NAME" '.assets[] | select(.name == $name) | .browser_download_url')
else
  DOWNLOAD_URL="https://github.com/ryanfowler/fetch/releases/download/${VERSION}/${ARTIFACT_NAME}"
  CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
fi
if [ -z "$DOWNLOAD_URL" ]; then
  error "no release artifact found for ${OS}/${ARCH}"
  exit 1
fi
if [ -z "$CHECKSUM_URL" ]; then
  error "no checksum sidecar found for ${ARTIFACT_NAME}"
  exit 1
fi

# Create temporary directory.
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
BINARY_PATH="${TMP_DIR}/fetch"
ARCHIVE_PATH="${BINARY_PATH}.tar.gz"
CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"

# Download the artifact.
info "downloading latest version (${VERSION})"
if ! curl -fsSL "$DOWNLOAD_URL" -o "$ARCHIVE_PATH"; then
  error "unable to download artifact"
  exit 1
fi
if ! curl -fsSL "$CHECKSUM_URL" -o "$CHECKSUM_PATH"; then
  error "unable to download artifact checksum"
  exit 1
fi

CHECKSUM_BYTES=$(wc -c < "$CHECKSUM_PATH" | tr -d '[:space:]')
if [ "${CHECKSUM_BYTES:-0}" -gt 1024 ]; then
  error "artifact checksum sidecar is too large"
  exit 1
fi

EXPECTED_SHA=$(parse_sha256_checksum "$CHECKSUM_PATH")
if ! printf '%s' "$EXPECTED_SHA" | grep -Eq '^[0-9a-f]{64}$'; then
  error "artifact checksum sidecar does not start with a SHA-256 digest"
  exit 1
fi

if ! ACTUAL_SHA=$(sha256_file "$ARCHIVE_PATH"); then
  error "unable to calculate artifact checksum"
  exit 1
fi

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  error "artifact checksum mismatch for ${ARTIFACT_NAME}: expected ${EXPECTED_SHA}, got ${ACTUAL_SHA}"
  exit 1
fi
info "verified artifact checksum"

EXTRACTED="${TMP_DIR}/fetch.new"
if ! tar -xOf "$ARCHIVE_PATH" fetch > "$EXTRACTED" 2>/dev/null &&
   ! tar -xOf "$ARCHIVE_PATH" ./fetch > "$EXTRACTED" 2>/dev/null; then
  error "binary not found in archive"
  exit 1
fi

mv "$EXTRACTED" "$BINARY_PATH"
chmod 755 "$BINARY_PATH"

# Determine installation directory.
if [ -w "/usr/local/bin" ]; then
  # Can write to /usr/local/bin.
  INSTALL_DIR="/usr/local/bin"
else
  # Use home directory.
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

mv "$BINARY_PATH" "$INSTALL_DIR/fetch"
info "fetch successfully installed to '${DIM}${INSTALL_DIR}/fetch${RESET}'"

if [ "$INSTALL_COMPLETIONS" = true ]; then
  install_completions
else
  print_completion_commands
fi

# Clean up.
rm -rf "$TMP_DIR"

# Verify installation.
if ! command -v fetch &> /dev/null; then
  echo ""
  warning "you may need to add '${DIM}${INSTALL_DIR}${RESET}' to your PATH"
fi
