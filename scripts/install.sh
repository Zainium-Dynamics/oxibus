#!/usr/bin/env bash
# OxiBus installer script for Zainium OS environment.

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
      echo "Usage: $0 [--force-policy] [--force-config] [--skip-build] [--quantra]"
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
    warn "missing $rel/$bin"
  fi
done

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
echo "  services: $ETCDIR/oxibus/services/"
if [[ "$INSTALL_QUANTRA" -eq 1 ]]; then
  echo "  quantra:  $QUANTRA_SERVICES_DIR/oxibus.toml"
fi
echo ""
echo "Activate setuid launch helper:"
echo "  sudo chown root:messagebus ${helper_dst:-${DESTROOT}/libexec/oxibus-daemon-launch-helper}"
echo "  sudo chmod 4750 ${helper_dst:-${DESTROOT}/libexec/oxibus-daemon-launch-helper}"
