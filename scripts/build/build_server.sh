#!/usr/bin/env bash
# Build the Taburtuai C2 team server

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${ROOT}/bin/server"

echo "[*] Building taburtuaiC2 server..."

cd "${ROOT}"
go build \
  -ldflags="-s -w" \
  -o "${OUTPUT}" \
  ./cmd/server/

echo "[+] Server binary: ${OUTPUT}"
