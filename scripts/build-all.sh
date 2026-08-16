#!/usr/bin/env bash
# Build the entire OxiBus workspace (release profile).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> oxibus workspace"
echo "    config: oxibus.toml"

cargo build --release --workspace

echo "==> artifacts"
ls -la target/release/oxibus-daemon target/release/oxibus-send \
  target/release/oxibus-monitor target/release/oxibus-launch \
  target/release/oxibus-uuidgen target/release/oxibus-cleanup-sockets \
  2>/dev/null || true

echo "Done."
