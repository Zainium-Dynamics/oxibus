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

### Client & Tools
- [x] Client library (`Connection`, `Proxy`, `ObjectServer`)
- [x] CLI binaries (`oxibus-daemon`, `oxibus-send`, `oxibus-monitor`, `oxibus-launch`, `oxibus-uuidgen`, `oxibus-cleanup-sockets`, `oxibus-update-activation-environment`)
