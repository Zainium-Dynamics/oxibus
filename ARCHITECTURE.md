# OxiBus Architecture Specification

This document describes the design, architecture, and module breakdown of OxiBus.

## Design Goals

1. **Wire Specification Compliance**: Fully compliant with D-Bus Specification 0.41 over UNIX sockets.
2. **Config-Driven Paths**: All filesystem targets resolve via `oxibus.toml`.
3. **Least Privilege Boundaries**: Setuid elevation boundaries and message headers (`SENDER`) are verified in kernel-backed checks.
4. **TOML Configuration Standard**: System policy, service definitions, and daemon parameters use TOML.

## Crate Layering

```
oxibus-core   (pure protocol, types, marshaling)
    ↑
oxibus-transport   (AF_UNIX socket transport, credentials, fd passing)
    ↑
oxibus-auth   (SASL authentication state machines)
    ↑
oxibus-client   (Client connection, proxies, object server)
    ↑
oxibus-daemon   (Bus registry, message routing, policy enforcement)

oxibus-config   (Standalone configuration schema)
oxibus-tools    (CLI administration suite)
```

## Module Breakdown

### `oxibus-core`
- **`types.rs`**: Core D-Bus type definitions and self-describing value types (`Value`).
- **`signature.rs`**: Signature parser with depth and length validations.
- **`marshal.rs` / `unmarshal.rs`**: Wire marshaling and unmarshaling implementations.
- **`header.rs`**: Header layout and frame boundary parsing.
- **`message.rs`**: Message structure and serial generator.
- **`addr.rs`**: D-Bus address parser (`unix:path`, `unix:abstract`, `unix:tmpdir`).

### `oxibus-transport`
- Framed socket reading/writing via `UnixStream`.
- Peer credentials extraction via `SO_PEERCRED`.
- `SCM_RIGHTS` file descriptor passing.

### `oxibus-auth`
- SASL authentication handlers (`EXTERNAL`, `ANONYMOUS`, `DBUS_COOKIE_SHA1`).

### `oxibus-config`
- `GlobalConfig` and `PathsConfig` schema parsing for Zainium filesystem hierarchy (`/overlayer/syshub`).

### `oxibus-daemon`
- **`registry.rs`**: Connection and well-known name registry.
- **`dispatch.rs`**: Message routing, signal broadcast, and method call dispatch.
- **`driver.rs`**: Standard `org.freedesktop.DBus` service implementation.
- **`policy.rs`**: Security policy evaluation engine.
- **`activation.rs`**: Service activation manager.
- **`launch_helper.rs`**: Security boundary helper for setuid privilege execution.

### `oxibus-client`
- Client connection handle, async message reader, and `ObjectServer` interface.

## System Integration

- System daemon configuration provided via `quantra/oxibus.toml`.
- Setuid boundary managed by `oxibus-daemon-launch-helper`.
