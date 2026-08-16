#!/usr/bin/env bash
# =============================================================================
# OxiBus installer (Zainium — no /usr)
# =============================================================================
# Same DESTROOT convention as elevate/scripts/install.sh and
# dbus/build-zainium-dbus.sh: DESTROOT *is* the syshub tree (the overlay's
# lower layer), so bin/lib land under it via the runtime prefix, and
# etc/var seed content lands at the same relative paths the live overlay
# mounts as real /etc, /var — never bake DESTROOT itself into a binary's
# compiled-in defaults (see oxibus.toml's prefix vs DESTROOT comment).
#
# Usage:
#   ./scripts/install.sh                          # DESTROOT=zairoot/overlayer/syshub
#   DESTROOT=/path/to/overlayer/syshub ./scripts/install.sh
#   ./scripts/install.sh --force-policy           # overwrite existing policy.d/00-default.toml
#   ./scripts/install.sh --force-config           # overwrite existing oxibus.toml
#   ./scripts/install.sh --skip-build             # use already-built target/release
#   ./scripts/install.sh --quantra                # also install the Quantra service file
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DESTROOT="${DESTROOT:-/run/media/alizain/ZAINIUM_DRIVE/zairoot/overlayer/syshub}"
FORCE_POLICY=0
FORCE_CONFIG=0
SKIP_BUILD=0
INSTALL_QUANTRA=0

for arg in "$@"; do
  case "$arg" in
    --force-policy) FORCE_POLICY=1 ;;
    --force-config) FORCE_CONFIG=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --quantra) INSTALL_QUANTRA=1 ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

BINDIR="${BINDIR:-${DESTROOT}/bin}"
ETCDIR="${ETCDIR:-${DESTROOT}/etc}"
STATEDIR="${STATEDIR:-${DESTROOT}/var/lib/oxibus}"
QUANTRA_SERVICES_DIR="${QUANTRA_SERVICES_DIR:-${DESTROOT}/engine/services}"

rel="${ROOT}/target/release"

log()  { printf '==> %s\n' "$*"; }
warn() { printf '!!  %s\n' "$*" >&2; }

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  log "building workspace (release)"
  ( cd "$ROOT" && cargo build --release --workspace )
fi

log "creating directories under DESTROOT='${DESTROOT}'"
install -d \
  "$BINDIR" \
  "$ETCDIR/oxibus/policy.d" \
  "$ETCDIR/oxibus/services" \
  "$DESTROOT/lib/oxibus/services" \
  "$STATEDIR"

log "installing binaries → $BINDIR"
for bin in oxibus-daemon oxibus-send oxibus-monitor oxibus-launch oxibus-uuidgen \
           oxibus-cleanup-sockets oxibus-run-session oxibus-update-activation-environment; do
  if [[ -f "$rel/$bin" ]]; then
    install -D -m 0755 "$rel/$bin" "$BINDIR/$bin"
  else
    warn "missing $rel/$bin (build failed or --skip-build without a prior build?)"
  fi
done

# oxibus-daemon-launch-helper is installed but deliberately left mode 0755
# owner-you here — it only becomes the privileged setuid-root helper once
# you run the chown/chmod block this script prints at the end. Never
# auto-applied: that's a root-owned, security-sensitive change this script
# should not silently perform.
if [[ -f "$rel/oxibus-daemon-launch-helper" ]]; then
  helper_dst="${DESTROOT}${LAUNCH_HELPER_PATH:-/libexec/oxibus-daemon-launch-helper}"
  install -D -m 0755 "$rel/oxibus-daemon-launch-helper" "$helper_dst"
else
  warn "missing $rel/oxibus-daemon-launch-helper"
fi

log "installing config → $ETCDIR/oxibus"
cfg_dst="$ETCDIR/oxibus/oxibus.toml"
if [[ -e "$cfg_dst" && "$FORCE_CONFIG" -eq 0 ]]; then
  warn "keeping existing $cfg_dst (use --force-config to replace)"
else
  install -D -m 0644 "$ROOT/oxibus.toml" "$cfg_dst"
fi

policy_dst="$ETCDIR/oxibus/policy.d/00-default.toml"
if [[ -e "$policy_dst" && "$FORCE_POLICY" -eq 0 ]]; then
  warn "keeping existing $policy_dst (use --force-policy to replace)"
else
  install -D -m 0644 "$ROOT/packaging/etc/oxibus/policy.d/00-default.toml" "$policy_dst"
fi

if [[ "$INSTALL_QUANTRA" -eq 1 ]]; then
  log "installing Quantra service → $QUANTRA_SERVICES_DIR/oxibus.toml"
  install -D -m 0644 "$ROOT/quantra/oxibus.toml" "$QUANTRA_SERVICES_DIR/oxibus.toml"
fi

log "done"
echo "  DESTROOT: ${DESTROOT}"
echo "  bins:     $BINDIR"
echo "  config:   $ETCDIR/oxibus/oxibus.toml"
echo "  policy:   $ETCDIR/oxibus/policy.d/"
echo "  services: $ETCDIR/oxibus/services/  (drop activation *.toml files here)"
if [[ "$INSTALL_QUANTRA" -eq 1 ]]; then
  echo "  quantra:  $QUANTRA_SERVICES_DIR/oxibus.toml"
else
  echo "  quantra:  not installed (pass --quantra to enable oxibus at boot)"
fi
echo ""
echo "REQUIRED — activate the setuid launch helper (root-owned dirs, not done above):"
echo "  sudo chown root:messagebus ${helper_dst:-${DESTROOT}/libexec/oxibus-daemon-launch-helper}"
echo "  sudo chmod 4750 ${helper_dst:-${DESTROOT}/libexec/oxibus-daemon-launch-helper}"
echo "  # Without this, system-bus activation of any service with a user= other"
echo "  # than messagebus fails closed (see oxibus-daemon-launch-helper's docs)."
echo ""
echo "Verify:"
echo "  ${BINDIR}/oxibus-daemon --session --print-address &"
echo "  ${BINDIR}/oxibus-send --session /org/freedesktop/DBus org.freedesktop.DBus.ListNames --print-reply"
