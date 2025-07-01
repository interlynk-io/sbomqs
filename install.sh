#!/bin/sh

set -e

REPO="interlynk-io/sbomqs"
VERSION="latest"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) echo "❌ Unsupported architecture: $ARCH" && exit 1 ;;
esac

# Resolve latest tag from GitHub API
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -s https://api.github.com/repos/$REPO/releases/latest | grep '"tag_name":' | cut -d'"' -f4)
fi

BINARY_NAME="sbomqs-${OS}-${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}"

echo "📦 Downloading $BINARY_NAME ($VERSION)..."

curl -sSL "$DOWNLOAD_URL" -o sbomqs
chmod +x sbomqs
sudo mv sbomqs /usr/local/bin/sbomqs

echo "✅ Installed sbomqs to /usr/local/bin"
sbomqs --version || echo "Run 'sbomqs' to get started."
