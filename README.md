# OxiBus (Oxidized Bus)

A clean-room, musl-native D-Bus implementation in pure Rust for Zainium OS. It serves as a wire-protocol-compatible, drop-in replacement for `dbus-daemon`/`libdbus` and the standard `dbus-*` CLI tools — binaries are named and behave like the reference D-Bus so systemd units and desktop environments (e.g. COSMIC) pick it up without modification. It runs standalone just as well: systemd socket activation (`--address=systemd:`) and `sd_notify` readiness are supported, but neither is required.

## Quickstart

Build the workspace:
```bash
cargo build --release --workspace
```

Start the daemon in session mode:
```bash
./target/release/dbus-daemon --session --print-address
export DBUS_SESSION_BUS_ADDRESS="unix:path=/tmp/oxibus_session_socket,guid=4db4a87e35b7194f"
```

Send a message using `dbus-send`:
```bash
./target/release/dbus-send --session --print-reply \
    --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames
```

Monitor incoming traffic:
```bash
./target/release/dbus-monitor --session
```

## Binaries

| Binary | Purpose |
|---|---|
| `dbus-daemon` | The message bus itself (`--system`/`--session`). |
| `dbus-daemon-launch-helper` | Setuid-root helper that execs system-activated services as their configured user. |
| `dbus-send` | Send a method call or signal from the CLI. |
| `dbus-monitor` | Watch live bus traffic. |
| `dbus-launch` | Start a session bus and print/export its address (or run a command under it). |
| `dbus-run-session` | Run a command inside a private, throwaway session bus. |
| `dbus-uuidgen` | Generate/read the machine-id. |
| `dbus-cleanup-sockets` | Remove stale session-bus socket files. |
| `dbus-update-activation-environment` | Push environment variables into the bus for future activated services. |

Each accepts the reference tool's flags (see `--help`; a few niche ones like `dbus-monitor --pcap` are stubbed and error out rather than silently doing nothing). `dbus-daemon` additionally understands `--address=systemd:` (socket activation via `LISTEN_FDS`/`LISTEN_PID`) and sends `sd_notify` readiness, so a `Type=notify` systemd unit works unmodified.

## Architecture

OxiBus consists of modular crates:

- **`oxibus-core`**: D-Bus wire format marshaling, signatures, and types.
- **`oxibus-transport`**: `AF_UNIX` sockets, connection streaming, peer credentials (`SO_PEERCRED`), and file descriptor passing (`SCM_RIGHTS`).
- **`oxibus-auth`**: SASL authentication (`EXTERNAL`, `ANONYMOUS`, `DBUS_COOKIE_SHA1`).
- **`oxibus-client`**: Client API (connections, proxies, object servers).
- **`oxibus-daemon`**: Message router, name registry, security policies, and service activation.
- **`oxibus-config`**: Shared TOML configuration loader.
- **`oxibus-tools`**: D-Bus CLI utilities.

Policy and `.service`-file activation search both OxiBus's own config paths and the standard `dbus-1` locations (`/etc/dbus-1/system.d`, `/usr/share/dbus-1/services`, `/usr/share/dbus-1/system-services`, ...), so files installed by other packages for the reference daemon are picked up as-is.

## License

GPL-3.0-only
