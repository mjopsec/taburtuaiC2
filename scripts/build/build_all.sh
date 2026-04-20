#!/usr/bin/env bash
# Build all taburtuaiC2 components

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Building all components..."

bash "${SCRIPT_DIR}/build_server.sh"
bash "${SCRIPT_DIR}/build_agent.sh" "$@"

echo "[+] All builds complete."
