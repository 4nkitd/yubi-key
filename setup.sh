#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! command -v go >/dev/null 2>&1; then
  echo "Error: Go is required to build yubiesp (install with: brew install go)" >&2
  exit 1
fi

echo "==> Building YubiESP CLI (with embedded ESP32 firmware & Chrome extension)..."
go build -o "$ROOT_DIR/yubiesp" .

"$ROOT_DIR/yubiesp" setup "$@"
rm -f "$ROOT_DIR/yubiesp"
