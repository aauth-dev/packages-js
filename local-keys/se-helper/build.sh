#!/bin/bash
# Build the Secure Enclave helper binary for macOS
# This is only needed on macOS — other platforms skip this step

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/../bin"
OUTPUT="$BIN_DIR/se-helper"

if [ "$(uname)" != "Darwin" ]; then
    echo "Skipping se-helper build (not macOS)"
    exit 0
fi

mkdir -p "$BIN_DIR"

echo "Compiling se-helper..."
swiftc -O -o "$OUTPUT" "$SCRIPT_DIR/main.swift"

echo "Codesigning se-helper..."
codesign --force --sign - "$OUTPUT"

echo "Built: $OUTPUT"
