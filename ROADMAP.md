# OxiBus Roadmap

Status as of this writing: **75 tests passing across 7 crates**, verified live against real unmodified `dbus-send`/`gdbus`. This document is the honest ledger — what's actually done, what's actually open, and what's deliberately not being built. Nothing here is aspirational marketing; if it's checked off, it's implemented and tested.

## Done

**Protocol & transport**
- [x] Full wire protocol from the D-Bus Specification: all types, signatures (with real depth/length limits), marshaling/alignment, message framing
- [x] `AF_UNIX` transport: path sockets, abstract-namespace sockets, `SO_PEERCRED`, real `SCM_RIGHTS` fd-passing
- [x] SASL: `EXTERNAL`, `ANONYMOUS`, `DBUS_COOKIE_SHA1` (keyring file-compatible with real `dbus-daemon`)

**Daemon**
- [x] Name registry: `RequestName`/`ReleaseName` with full flag semantics, ownership queueing
- [x] Full `org.freedesktop.DBus` driver + `Peer`/`Introspectable`/`Monitoring`/`Debug.Stats` interfaces
- [x] Match-rule engine (`type=`, `sender=`, `interface=`, `member=`, `path=`, `path_namespace=`, `destination=`, `argN=`)
- [x] TOML policy engine (`context = default/user/group/mandatory`, last-match-wins own/send/receive)
- [x] TOML-based on-demand activation with process spawning + poll-wait
- [x] `[limits]` actually enforced: max message size (rejected before buffering the body), max connections per-user/incomplete, max names/match-rules per connection, auth timeout
- [x] Privilege drop root → `messagebus` after binding (`initgroups`+`setgid`+`setuid`, verified post-drop)
- [x] Setuid launch helper for system-bus activation as a non-`messagebus` user, direct port of `bus/activation-helper.c`'s trust model
- [x] `UpdateActivationEnvironment` correctly session-bus-only (matches real dbus's servicehelper gate)
- [x] SIGHUP → policy reload, SIGTERM/SIGINT → clean socket/pidfile removal
- [x] Monitor mode (`BecomeMonitor`) with correct single-delivery semantics (a live-testing-caught bug, now fixed + would benefit from a regression test — see below)

**Client & tools**
- [x] `oxibus-client`: `Connection`, `Proxy`, `ObjectServer` for building services
- [x] 9 binaries: `oxibus-daemon`, `-daemon-launch-helper`, `-send`, `-monitor`, `-launch`, `-run-session`, `-uuidgen`, `-cleanup-sockets`, `-update-activation-environment`

**Verification**
- [x] Live interop against the host's real `dbus-send` and `gdbus` (independent codebases, zero modification, both directions)
- [x] `quantra/oxibus.toml` parsed against the actual `quantra::services::types::Service` struct, not just eyeballed

## Known gaps

Ordered roughly by how much it'd matter in practice:

1. **The full system-bus privilege chain has never run end to end on real hardware/root.** Every piece (`drop_privileges`, the launch helper's permission checks, `ViaLaunchHelper` spawning) has unit or live-tested coverage individually, but `oxibus-daemon --system` starting as root, binding, dropping to `messagebus`, and then successfully activating a service as a *third* user via the setuid helper has only been exercised piece-by-piece on this dev host (no root access here). This needs a real run on the Zainium target or a sudo-capable box before calling the launch helper "proven," not just "correctly built."
2. **Regression test for the monitor double-delivery fix.** The bug (monitors receiving broadcast signals twice) was caught by live testing and fixed in `dispatch.rs::broadcast_signal`, but there's no automated test pinning that behavior — a future refactor could reintroduce it silently.
3. **Match rules**: `arg0namespace=` and `argNpath=` (namespace/path-prefix variants of `argN=`) aren't implemented, only exact-match `argN=`. Low real-world impact — these are rare in practice — but not spec-complete.
4. **No fuzzing of the marshal/unmarshal layer.** This is the one component that processes fully untrusted, attacker-controlled bytes (every incoming message body). It has solid unit-test coverage of known edge cases (truncated buffers, invalid booleans, oversized arrays) but hasn't been fuzzed against arbitrary input the way a wire-format parser handling untrusted data probably should be before being called hardened.
5. **`ObjectServer`'s generated introspection XML doesn't emit `<property>` tags** from an `Interface`'s `list_properties()` — a service built on `oxibus-client` has to hand-write property XML into its `introspection_xml()` string today rather than getting it generated.
6. **No `PropertiesChanged` convenience helper** in `oxibus-client` — services must construct and emit that signal manually.
7. **CLI array parsing in `oxibus-send`** handles flat scalar arrays (`array:string:a,b,c`) only — no nested arrays, structs, or dict construction from the command line. The underlying library has no such limitation; this is purely the CLI argument grammar.

## Explicitly out of scope

Not gaps — deliberate decisions, most inherited from Zainium's own `build-zainium-dbus.sh` already disabling the same things for the C build. See [ARCHITECTURE.md](ARCHITECTURE.md#whats-intentionally-not-implemented) for the reasoning:

- SELinux, AppArmor, libaudit, launchd, systemd (socket activation / `sd_notify`), X11 autolaunch, TCP transport
- Legacy XML policy ingestion (`/etc/dbus-1/system.d/*.conf`) — TOML-only by design. If a Zex-installed package ever ships D-Bus XML policy expecting it to be honored, that will need either a one-time conversion tool or an ingestion shim; nothing exists for this today and it isn't planned unless it becomes a real problem.
- `--fork` / classic double-fork daemonization — runs in the foreground under Quantra's own supervision instead.

## Ideas for later (unprioritized)

- Benchmark suite comparing message-routing throughput/latency against real `dbus-daemon`
- `dbus-test-tool`/`dbus-spam`-equivalent stress-testing tools (useful for the fuzzing/benchmark items above, not for production use)
- CI workflow (build + `cargo test --workspace` on push) if/when this repository is actually pushed somewhere CI can run
