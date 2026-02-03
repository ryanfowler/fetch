#!/bin/bash
set -e

# Installation script for fetch
# Usage: curl -fsSL https://raw.githubusercontent.com/ryanfowler/fetch/main/install.sh | bash

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
    echo -e "\nTry compiling from source by running: '${DIM}go install github.com/ryanfowler/fetch@latest${RESET}'"
}

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

# Parse the artifact url.
DOWNLOAD_URL=""
if $HAS_JQ; then
  DOWNLOAD_URL=$(echo "$RELEASE_JSON" | jq -r ".assets[] | select(.name == \"fetch-${VERSION}-${PLATFORM}.tar.gz\") | .browser_download_url")
else
  DOWNLOAD_URL=$(echo "$RELEASE_JSON" | grep -o "\"browser_download_url\": *\"[^\"]*${PLATFORM}[^\"]*\"" | sed 's/"browser_download_url": *"//;s/"//')
fi
if [ -z "$DOWNLOAD_URL" ]; then
  error "no release artifact found for ${OS}/${ARCH}"
  exit 1
fi

# Create temporary directory.
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
BINARY_PATH="${TMP_DIR}/fetch"

# Download the artifact.
info "downloading latest version (${VERSION})"
if ! curl -fsSL "$DOWNLOAD_URL" -o "$BINARY_PATH.tar.gz"; then
  error "unable to download artifact"
  exit 1
fi

if ! tar -xzf "$BINARY_PATH.tar.gz" -C "$TMP_DIR"; then
  error "failed to extract archive"
  exit 1
fi

if [ ! -f "$BINARY_PATH" ]; then
  error "binary not found in archive"
  exit 1
fi

chmod +x "$BINARY_PATH"

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

# Optionally install completions.
case "$SHELL" in
  */bash)
    COMPLETION_CMD='eval "$(fetch --complete=bash)"'
    if ! grep -qF "$COMPLETION_CMD" "$HOME/.bashrc" 2>/dev/null; then
      printf "\n# fetch completions\n${COMPLETION_CMD}\n" >> "$HOME/.bashrc"
      info "completions appended to '${DIM}${HOME}/.bashrc${RESET}'"
    fi
    ;;
  */fish)
    mkdir -p "$HOME/.config/fish/completions"
    echo "fetch --complete=fish | source" > "$HOME/.config/fish/completions/fetch.fish"
    info "completions installed to '${DIM}${HOME}/.config/fish/completions/fetch.fish${RESET}'"
    ;;
  */zsh)
    COMPLETION_CMD='eval "$(fetch --complete=zsh)"'
    if ! grep -qF "$COMPLETION_CMD" "$HOME/.zshrc" 2>/dev/null; then
      printf "\n# fetch completions\n${COMPLETION_CMD}\n" >> "$HOME/.zshrc"
      info "completions appended to '${DIM}${HOME}/.zshrc${RESET}'"
    fi
    ;;
esac

# Clean up.
rm -rf "$TMP_DIR"

# Verify installation.
if ! command -v fetch &> /dev/null; then
  echo ""
  warning "you may need to add '${DIM}${INSTALL_DIR}${RESET}' to your PATH"
fi

