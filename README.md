# OxiBus (Oxidized Bus)

A clean-room, musl-native, systemd-free D-Bus implementation in pure Rust for Zainium OS. It serves as a wire-protocol-compatible replacement for `dbus-daemon` and `libdbus`.

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

## Architecture

OxiBus consists of modular crates:

- **`oxibus-core`**: D-Bus wire format marshaling, signatures, and types.
- **`oxibus-transport`**: `AF_UNIX` sockets, connection streaming, peer credentials (`SO_PEERCRED`), and file descriptor passing (`SCM_RIGHTS`).
- **`oxibus-auth`**: SASL authentication (`EXTERNAL`, `ANONYMOUS`, `DBUS_COOKIE_SHA1`).
- **`oxibus-client`**: Client API (connections, proxies, object servers).
- **`oxibus-daemon`**: Message router, name registry, security policies, and service activation.
- **`oxibus-config`**: Shared TOML configuration loader.
- **`oxibus-tools`**: D-Bus CLI utilities.

## License

GPL-3.0-only
