# OxiBus Roadmap

Status as of this writing: **85 tests passing across 7 crates**, verified live against real unmodified `dbus-send`/`gdbus`. This document tracks what's actually done, what's open, and what's deliberately out of scope.

## Done

**Protocol & transport**
- [x] Full wire protocol from the D-Bus Specification: all types, signatures, marshaling/alignment, message framing.
- [x] `AF_UNIX` transport: path sockets, abstract-namespace sockets, `SO_PEERCRED`, real `SCM_RIGHTS` fd-passing.
- [x] SASL: `EXTERNAL`, `ANONYMOUS`, `DBUS_COOKIE_SHA1` (keyring file-compatible).

**Daemon**
- [x] Name registry: `RequestName`/`ReleaseName` with full flag semantics, ownership queueing.
- [x] Full `org.freedesktop.DBus` driver + `Peer`/`Introspectable`/`Monitoring`/`Debug.Stats` interfaces.
- [x] Match-rule engine (`type=`, `sender=`, `interface=`, `member=`, `path=`, `path_namespace=`, `destination=`, `argN=`, `arg0namespace=`, `argNpath=`).
- [x] TOML policy engine (`context = default/user/group/mandatory`, last-match-wins own/send/receive).
- [x] Legacy XML policy ingestion: tokenizes and parses legacy `/etc/dbus-1/system.d/*.conf` configurations.
- [x] TOML and INI-based on-demand activation: parses legacy `.service` files and handles exec argument tokenization.
- [x] `[limits]` enforcement: max message size, max connections, max names/match-rules, auth timeout.
- [x] Privilege drop root → `messagebus` after binding (`initgroups` + `setgid` + `setuid`).
- [x] Setuid launch helper for system-bus activation as a non-`messagebus` user.
- [x] `UpdateActivationEnvironment` restricted to session-bus-only.
- [x] SIGHUP → policy reload, SIGTERM/SIGINT → clean socket/pidfile removal.
- [x] Monitor mode (`BecomeMonitor`) with correct single-delivery semantics and regression test.
- [x] AppArmor & Audit security integration: dynamic loading of `libapparmor` and `libaudit` with permission mediation hooks.

**Client & tools**
- [x] `oxibus-client`: `Connection`, `Proxy`, `ObjectServer` for building services.
- [x] 9 binaries: `oxibus-daemon`, `-daemon-launch-helper`, `-send`, `-monitor`, `-launch`, `-run-session`, `-uuidgen`, `-cleanup-sockets`, `-update-activation-environment`.

**Verification**
- [x] Live interop against the host's real `dbus-send` and `gdbus`.
- [x] Integration verification of setuid launch helper, privilege dropping, and legacy XML/INI parsing.

## Known gaps

1. **Full system-bus privilege chain root testing.** The components (drop privileges, launch helper checks, spawning) are unit-tested and verified, but starting `oxibus-daemon` as root to drop privileges and activate services needs validation on real target hardware.
2. **No fuzzing of the marshal/unmarshal layer.** The wire parser handles untrusted data and has test coverage for bad inputs, but has not been run under a fuzzer.
3. **`ObjectServer` introspection limits.** Generated XML does not automatically list properties from `Interface::list_properties()`.
4. **No `PropertiesChanged` convenience helper.** Signals for property changes must be manually constructed and emitted.
5. **CLI array parsing in `oxibus-send`.** Supports flat scalar arrays only; complex nested structures must be sent programmatically.

## Explicitly out of scope

- SELinux, TCP transport.
- systemd (socket activation / `sd_notify`) or launchd — not supported or planned.
- `--fork` / classic double-fork daemonization — designed to run in the foreground under process supervisors.
