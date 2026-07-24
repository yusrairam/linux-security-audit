#!/usr/bin/env bash
# Linux Security Audit Tool — quick installer
#
# Usage:
#   ./install.sh
#
# This installs the tool for the current user only (--user), so it
# does not need root/sudo, and adds the `security-audit` command to
# your PATH via pip's user script directory.

set -e

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required but not found. Install Python 3.8+ first." >&2
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(sys.version_info[:2] >= (3, 8))')
if [ "$PY_VERSION" != "True" ]; then
    echo "Error: Python 3.8 or higher is required." >&2
    exit 1
fi

echo "Installing Linux Security Audit Tool..."
python3 -m pip install --user --break-system-packages . 2>/dev/null \
    || python3 -m pip install --user .

USER_BASE=$(python3 -m site --user-base)
BIN_DIR="$USER_BASE/bin"

echo ""
echo "Installed successfully."

if command -v security-audit >/dev/null 2>&1; then
    echo "Run it with: security-audit"
else
    echo "Add this to your PATH to use the 'security-audit' command directly:"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    echo ""
    echo "Or run it right now with:"
    echo "  $BIN_DIR/security-audit"
fi

echo ""
echo "Examples:"
echo "  security-audit --format html -o report.html"
echo "  sudo security-audit               # for full coverage (root-only checks)"
