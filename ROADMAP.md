# OxiBus Roadmap

## Feature Matrix

### Protocol & Transport
- [x] Wire protocol implementation (types, signatures, marshaling, framing)
- [x] `AF_UNIX` transport (path/abstract sockets, `SO_PEERCRED`, `SCM_RIGHTS` fd passing)
- [x] SASL authentication (`EXTERNAL`, `ANONYMOUS`, `DBUS_COOKIE_SHA1`)

### Daemon
- [x] Name registry (`RequestName`/`ReleaseName`, ownership queueing)
- [x] Standard driver interfaces (`org.freedesktop.DBus`, `Peer`, `Introspectable`, `Monitoring`)
- [x] Match rule engine
- [x] TOML and XML policy engines
- [x] On-demand service activation (`.service` files)
- [x] Limits enforcement (message size, connection caps, timeouts)
- [x] Privilege drop (`root` to `messagebus`)
- [x] Setuid activation helper

### Systemd Integration
- [x] `--address=systemd:` socket activation (`LISTEN_FDS`/`LISTEN_PID`, no libsystemd link)
- [x] `sd_notify` readiness (`READY=1`) for `Type=notify` units
- [x] `dbus-daemon` flag parity for the reference `dbus.service` invocation (`--nofork`, `--nopidfile`, `--syslog`/`--syslog-only`, `--systemd-activation`, `--print-pid`, `--introspect`, `--fork`)
- [ ] Starting systemd *units* by name via the systemd manager D-Bus API (bus-activatable `.service` files with `SystemdService=` still only get traditional activation)

### `libdbus-1.so.3` Compatibility
- [x] `oxibus-libdbus-compat`: C ABI shim producing `libdbus-1.so.3`, backed by `oxibus-client`
- [x] Connection lifecycle (`dbus_bus_get`, ref/unref, `dbus_bus_request_name`, `dbus_bus_add_match`)
- [x] Method calls and signals: build via `dbus_message_new_*` + the basic-type iterator API, `dbus_connection_send_with_reply_and_block`
- [x] `DBusError` (ABI-correct struct layout, `dbus_error_*`, `dbus_set_error_const`)
- [ ] Variadic `dbus_set_error`/`dbus_message_append_args`/`dbus_message_get_args` (stable Rust can't define C-variadic functions; needs proper version-script-based symbol export, not just a linked-in C shim)
- [ ] Non-blocking `dbus_connection_send` for method calls + `dbus_connection_pop_message`/filters (needs a pending-call registry)
- [ ] Container types (array/struct/dict/variant) in the iterator API

### Client & Tools
- [x] Client library (`Connection`, `Proxy`, `ObjectServer`)
- [x] `PropertiesChanged` signal helper (`Connection::properties_changed`)
- [x] `ObjectServer` auto-lists `list_properties()` in introspection XML
- [x] CLI binaries (`dbus-daemon`, `dbus-send`, `dbus-monitor`, `dbus-launch`, `dbus-uuidgen`, `dbus-cleanup-sockets`, `dbus-run-session`, `dbus-update-activation-environment`)
