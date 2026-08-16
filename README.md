# OxiBus (Oxidized Bus)

A from-scratch Rust implementation of the D-Bus Specification for Zainium OS — a wire-protocol-compatible replacement for `dbus-daemon` + `libdbus`, config-driven twith no MAKEFILE is, built to the same `prefix` / `DESTROOT` convention as the rest of the native stack.

Every existing binary linked against `libdbus-1.so` or GDBus keeps working against `oxibus-daemon`, unmodified — this was verified live against the host's own unmodified `dbus-send` and `gdbus` (see [ARCHITECTURE.md](ARCHITECTURE.md#verified-interop)).

## Why

D-Bus itself (`dbus-1.16.2`, `~108k` lines of C across `dbus/` + `bus/`) is the interop layer nearly everything on the system depends on. OxiBus reimplements it natively in Rust rather than patching around the C build, using TOML configuration throughout instead of D-Bus's classic XML (`system.conf`, `.service` files) — but keeps everything XML never touches: the wire protocol, the socket paths, the SASL handshake, the driver interface. Old software doesn't need to know OxiBus exists.

## Layout

```
oxibus/
├── oxibus.toml                  # build-time config — the ONE file with paths/features
├── crates/
│   ├── oxibus-core/             # wire protocol: types, signatures, marshaling, messages
│   ├── oxibus-transport/        # AF_UNIX sockets, SO_PEERCRED, SCM_RIGHTS fd-passing
│   ├── oxibus-auth/             # SASL: EXTERNAL, ANONYMOUS, DBUS_COOKIE_SHA1
│   ├── oxibus-client/           # Connection / Proxy / ObjectServer (the new libdbus)
│   ├── oxibus-daemon/           # the bus itself + oxibus-daemon-launch-helper
│   ├── oxibus-config/           # shared oxibus.toml schema + loader
│   └── oxibus-tools/            # oxibus-send, -monitor, -launch, -uuidgen, ...
├── packaging/etc/oxibus/        # what ships to $DESTROOT/etc/oxibus
├── quantra/oxibus.toml          # Quantra service definition
└── scripts/{build-all,install}.sh
```

## Quick start

```bash
cargo build --release --workspace
./target/release/oxibus-daemon --session --print-address &
export DBUS_SESSION_BUS_ADDRESS=$(cat)   # or capture the printed address directly

./target/release/oxibus-send --session --print-reply \
  --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames

./target/release/oxibus-monitor --session
```

Real, unmodified `dbus-send`/`gdbus` work identically against the same address — no `OXIBUS_*` env vars required, they just read the standard `DBUS_SESSION_BUS_ADDRESS`.

## The tools

| Binary | Replaces | Notes |
|---|---|---|
| `oxibus-daemon` | `dbus-daemon` | `--system` \| `--session`, `--config PATH`, `--print-address` |
| `oxibus-daemon-launch-helper` | `dbus-daemon-launch-helper` | setuid-root; never invoked directly, see [ARCHITECTURE.md](ARCHITECTURE.md#the-setuid-launch-helper) |
| `oxibus-send` | `dbus-send` | supports `type:value` args including `array:type:v1,v2,...` |
| `oxibus-monitor` | `dbus-monitor` | uses `Monitoring.BecomeMonitor`, sees all traffic, not just signals |
| `oxibus-launch` | `dbus-launch` | starts (or reuses) a session bus, prints sh-syntax exports |
| `oxibus-run-session` | `dbus-run-session` | private session bus scoped to one command's lifetime |
| `oxibus-uuidgen` | `dbus-uuidgen` | `--ensure[=FILE]` / `--get[=FILE]` |
| `oxibus-cleanup-sockets` | `dbus-cleanup-sockets` | removes stale session socket files |
| `oxibus-update-activation-environment` | `dbus-update-activation-environment` | session bus only — see security note below |

## Configuration

Everything path-related lives in one file, `oxibus.toml`, in exactly the shape `elevate.toml` uses:

```toml
[paths]
prefix        = "/overlayer/syshub"   # baked-in runtime prefix (never a build-host path)
bindir        = "/bin"                # → joined with prefix
conf_dir      = "/etc/oxibus"         # absolute, NOT prefix-joined (etc/var/run live at the real OS root)
system_socket = "/run/oxibus/system_bus_socket"
```

No path is ever hardcoded outside this file's `default_*` functions (`crates/oxibus-config/src/lib.rs`), which only exist as the fallback when no `oxibus.toml` is found at all. See [ARCHITECTURE.md](ARCHITECTURE.md#configuration-philosophy) for why `bindir` and `conf_dir` resolve differently.

Security policy is `[[rule]]` tables under `/etc/oxibus/policy.d/*.toml` (last-match-wins, same evaluation model as classic D-Bus `<policy>` blocks — see [`packaging/etc/oxibus/policy.d/00-default.toml`](packaging/etc/oxibus/policy.d/00-default.toml)). Activation is one TOML file per service under `/etc/oxibus/services/`:

```toml
[service]
name = "org.freedesktop.Notifications"
exec = "/overlayer/syshub/bin/notification-daemon"
user = "notifications"   # required for system-bus activation — see launch helper docs
```

`org.freedesktop.*` names above (`org.freedesktop.DBus`, `org.freedesktop.Notifications`, etc.) are the D-Bus Specification's own bus/interface naming convention — OxiBus has to answer to them for wire compatibility with existing unmodified software, the same way it has to speak the same SASL handshake and message framing. That's a protocol requirement, not a dependency: OxiBus itself is a standalone Rust implementation built from the spec text, sharing no code with `freedesktop.org`'s `dbus`/`libdbus`.

## Building & installing

```bash
bash scripts/build-all.sh
bash scripts/install.sh --quantra          # installs binaries, config, policy, Quantra service
```

`install.sh` will print (but never run) the two `sudo` commands needed to arm the setuid launch helper — that step is deliberately not automated. See [ARCHITECTURE.md](ARCHITECTURE.md#the-setuid-launch-helper) for why it exists and what it does.

## Status

75 tests across 7 crates, all passing. See [ROADMAP.md](ROADMAP.md) for what's done and what's still open — Quantra integration and the setuid launch helper are both complete; the honest remaining gaps are documented there, not hidden.

## License

GPL-3.0-only, matching the rest of the Zainium native stack.
