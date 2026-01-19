#!/bin/sh
# confcrypt installer
# Usage: curl -fsSL https://raw.githubusercontent.com/maurice2k/confcrypt/main/install.sh | sh

set -e

REPO="maurice2k/confcrypt"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="confcrypt"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    arm64|aarch64)
        ARCH="arm64"
        ;;
    *)
        echo "Error: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

case "$OS" in
    darwin)
        PLATFORM="darwin-${ARCH}"
        ;;
    linux)
        if [ "$ARCH" != "amd64" ]; then
            echo "Error: Linux builds are only available for amd64"
            exit 1
        fi
        PLATFORM="linux-amd64"
        ;;
    *)
        echo "Error: Unsupported OS: $OS"
        exit 1
        ;;
esac

# Get latest release tag
echo "Fetching latest release..."
LATEST_RELEASE=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_RELEASE" ]; then
    echo "Error: Could not determine latest release"
    exit 1
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_RELEASE}/confcrypt-${PLATFORM}"

echo "Installing confcrypt ${LATEST_RELEASE} for ${PLATFORM}..."

# Create temp file
TMP_FILE=$(mktemp)
trap "rm -f $TMP_FILE" EXIT

# Download binary
echo "Downloading from ${DOWNLOAD_URL}..."
if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP_FILE"; then
    echo "Error: Download failed"
    exit 1
fi

# Make executable
chmod +x "$TMP_FILE"

# Install (may need sudo)
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
fi

echo ""
echo "confcrypt ${LATEST_RELEASE} installed to ${INSTALL_DIR}/${BINARY_NAME}"
echo ""

# Check for FIDO2 dependency
if [ "$OS" = "darwin" ]; then
    if ! brew list libfido2 >/dev/null 2>&1; then
        echo "Note: For FIDO2 support, install libfido2:"
        echo "  brew install libfido2"
        echo ""
    fi
elif [ "$OS" = "linux" ]; then
    if ! ldconfig -p 2>/dev/null | grep -q libfido2 && ! dpkg -l libfido2-1 >/dev/null 2>&1; then
        echo "Note: For FIDO2 support, install libfido2:"
        echo "  apt install libfido2-1  # Debian/Ubuntu"
        echo "  dnf install libfido2    # Fedora"
        echo ""
    fi
fi

# Verify installation
if command -v confcrypt >/dev/null 2>&1; then
    echo "Verify: $(confcrypt --version)"
else
    echo "Note: ${INSTALL_DIR} may not be in your PATH"
fi
