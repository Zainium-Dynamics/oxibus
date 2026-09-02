#!/usr/bin/env bash
# Build the entire OxiBus workspace (release profile).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> oxibus workspace"
echo "    config: oxibus.toml"

cargo build --release --workspace

echo "==> artifacts"
ls -la target/release/dbus-daemon target/release/dbus-send \
  target/release/dbus-monitor target/release/dbus-launch \
  target/release/dbus-uuidgen target/release/dbus-cleanup-sockets \
  target/release/libdbus_1.so \
  2>/dev/null || true

echo "Done."
