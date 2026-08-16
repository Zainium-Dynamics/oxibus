# OxiBus Architecture

This document explains how OxiBus is put together and why, at the level of "what would a maintainer need to know before touching this." It assumes familiarity with the [D-Bus Specification](https://dbus.freedesktop.org/doc/dbus-specification.html); it does not re-explain the wire protocol, only how this implementation maps onto it.

## Design goals, in priority order

1. **Wire compatible, not API compatible.** Nothing that speaks real D-Bus over a Unix socket should be able to tell it's talking to OxiBus instead of `dbus-daemon`. Nothing about `libdbus`'s C API, GDBus's API, or sd-bus's API needs to be replicated — only the bytes on the wire.
2. **Config-driven paths, no hardcoding.** Every filesystem path traces back to `oxibus.toml`'s `[paths]` table, This is what lets the same source tree produce a binary whose compiled-in defaults are correct for `/overlayer/syshub` without ever encoding a build-host path into it.
3. **Least trust across privilege boundaries.** Anywhere OxiBus crosses from unprivileged to privileged (the setuid launch helper) or from "whatever a connected client claims" to "what the bus asserts as fact" (the `SENDER` header field), the boundary is enforced in code, not by convention.
4. **TOML instead of XML, everywhere that's actually a config format.** Policy, activation service files, and the daemon's own settings are TOML. The wire protocol itself, the SASL command grammar, and the object/interface/method model are unchanged — those aren't "config," they're the interop contract, and changing them would break the whole point.

## Crate layering

```
oxibus-core   (no I/O, no async — pure protocol logic)
    ↑
oxibus-transport   (AF_UNIX I/O, depends only on oxibus-core)
    ↑
oxibus-auth   (SASL state machines, depends on oxibus-transport for PeerCredentials)
    ↑
oxibus-client   (Connection/Proxy/ObjectServer — combines transport+auth+core)
    ↑
oxibus-daemon   (the bus — combines transport+auth+core, does NOT depend on oxibus-client)

oxibus-config   (standalone: TOML schema, no dependency on the protocol crates)
oxibus-tools    (depends on oxibus-client + oxibus-config, one bin per tool)
```

`oxibus-daemon` deliberately does not depend on `oxibus-client` — the bus talks the protocol directly over `oxibus-transport`/`oxibus-auth` rather than being "a client library user like everyone else." This mirrors real `dbus-daemon`, which doesn't link `libdbus`'s client-connection code either; the daemon's connection-handling has different invariants (it assigns unique names, it's the trust anchor for `SENDER`, it never calls `Hello` on itself) that don't fit the client abstraction.

## The protocol layer (`oxibus-core`)

Implemented directly from the Specification, not transliterated from libdbus's C:

- **`types.rs`** — `Type` (a parsed signature node) and `Value` (a self-describing concrete value; containers carry their element/field types, so a `Value` alone can always regenerate its own signature — needed for `VARIANT` marshaling, which requires that).
- **`signature.rs`** — recursive-descent parser enforcing the spec's actual limits: max array nesting 32, max struct nesting 32, max signature length 255 bytes.
- **`marshal.rs` / `unmarshal.rs`** — alignment-correct encode/decode for every type, both byte orders. Array marshaling writes a placeholder length, aligns to the element's natural alignment, encodes elements, then patches the length in place (the length is bytes of *element data*, excluding the alignment padding between the length field and the first element — a detail that's easy to get wrong and has a dedicated test).
- **`header.rs`** — the `yyyyuu` fixed prefix + `a(yv)` header fields array. `MessageHeader::peek_frame_len` returns the total frame length as soon as 16 bytes are buffered (the fixed prefix already contains `body_length`), which is what lets the transport layer reject an oversized claimed message *before* buffering the (attacker-controlled) body — see `limits.max_message_size` enforcement below.
- **`message.rs`** — `Message`, `MessageBuilder`, `SerialGenerator` (skips 0, which is reserved).
- **`addr.rs`** — D-Bus address strings (`unix:path=...`, `unix:abstract=...`, `unix:tmpdir=...`), including the spec's percent-escaping.

## Transport (`oxibus-transport`)

`Transport` wraps the socket as `Arc<UnixStream>` specifically so `Writer` (a cheap `Clone`) can be handed to a different task than the one driving reads, without splitting the fd or taking a lock per write — `tokio::net::UnixStream::ready()`/`try_io()` only need `&self`, which is exactly the property this relies on. This is what lets the daemon reply to an incoming method call from inside the same task that's reading the next message, and what lets a client's background reader task deliver replies while the foreground task is still awaiting a call.

`SO_PEERCRED` gives real (uid, gid, pid) with no explicit credential-passing dance required (unlike BSD's `SCM_CREDS`) — Linux attaches this to the socket itself once connected, which is why `oxibus-auth`'s `EXTERNAL` mechanism implementation is simpler than libdbus's (no `_dbus_read_credentials_socket` timing complexity to replicate).

Unix-fd passing (`SCM_RIGHTS`) is implemented with raw `sendmsg`/`recvmsg` via `try_io`, not through any higher-level tokio API (tokio doesn't have one for ancillary data). Fds ride with the *first* `sendmsg` of a message's bytes, matching the spec's requirement that all of a message's fds travel with it atomically.

## Authentication (`oxibus-auth`)

Three SASL mechanisms, matching `dbus/dbus-auth.c`'s state machine shape (`WaitingForAuth` → `WaitingForData` → `WaitingForBegin`), capped at 6 failures before disconnect (same as upstream):

- **EXTERNAL** — identity is the peer's uid as ASCII decimal, verified against `SO_PEERCRED`. No challenge/response needed since Linux gives us the credential directly.
- **ANONYMOUS** — grants a connection with no uid identity; only if `allow_anonymous = true`.
- **DBUS_COOKIE_SHA1** — full keyring implementation at `~/.dbus-keyrings/<context>`, **file-format compatible with real `dbus-daemon`'s keyring** (same directory, same `<id> <created> <hex-secret>` line format, same `flock`-based locking, same `NEW_KEY_TIMEOUT_SECONDS`/`EXPIRE_KEYS_TIMEOUT_SECONDS` constants). An OxiBus client and a real `dbus-daemon` sharing a `$HOME` can authenticate to each other over this mechanism without either side knowing the other exists.

## Configuration philosophy

`oxibus-config`'s `PathsConfig` has two different resolution rules depending on the field, and getting this backwards breaks the build in a way that's easy to not notice until you're staging a real install:

- `bindir`, `sbindir`, `libdir`, `share_dir` — **joined with `prefix`.** These are "distribution files," part of the read-mostly base layer that gets overlaid onto the live root.
- `conf_dir`, `state_dir`, `system_socket`, `runtime_dir` — **absolute, prefix-independent.** `/etc`, `/var`, `/run` are the *live, writable* paths on the booted system (often fresh tmpfs at `/run`), not something that lives permanently under `/overlayer/syshub`. A socket address compiled into a binary as `/overlayer/syshub/run/oxibus/...` would be wrong the moment the overlay's upper layers diverge from the lower one.

This exact split is what `build-zainium-dbus.sh` already encodes for the C build (`RUNTIME_PREFIX=/overlayer/syshub` vs. the separately-tracked `SYSTEM_SOCKET=/run/dbus/system_bus_socket`), and `oxibus.toml` was written to match it field-for-field rather than reinvent the convention.

`GlobalConfig::load_default()` checks `$OXIBUS_CONFIG`, then `/etc/oxibus/oxibus.toml`, then `/etc/oxibus.toml`, then a CWD-relative `oxibus.toml` (dev convenience). **The setuid launch helper does not use this loader** — see below for why.

## The daemon (`oxibus-daemon`)

### Registry (`registry.rs`)

Two independent maps behind `RwLock`: `connections` (unique name → `ConnectionEntry`) and `names` (well-known name → an ordered queue of `(unique_name, flags)`, index 0 = primary owner). `RequestName`/`ReleaseName` implement the exact `DBUS_NAME_FLAG_*`/`DBUS_REQUEST_NAME_REPLY_*` semantics from the spec, including queue-splicing on `REPLACE_EXISTING` (the displaced owner falls back into the queue unless it originally set `DO_NOT_QUEUE`). A connection's own unique name is never stored in `names` — it's implicitly "owned" by virtue of being a key in `connections`.

### Dispatch (`dispatch.rs`)

Every incoming message gets its `SENDER` field overwritten with the connection's real unique name before anything else happens — this is the one piece of data no client is ever trusted to self-report, matching the spec's explicit requirement that the bus enforce it. From there:

- **Signals** broadcast to every connection whose match rules match (`match_rules.rs` — full `type=`/`sender=`/`interface=`/`member=`/`path=`/`path_namespace=`/`destination=`/`argN=` support, with the spec's quoting rules for embedded `'`).
- **Method calls** addressed to `org.freedesktop.DBus` go to the driver; everything else resolves the destination's current owner, applies policy, and forwards. An unowned-but-activatable destination triggers on-demand activation with a poll-wait against `limits.activation_timeout_ms` before either delivering or replying `ServiceUnknown`.
- **Monitors** (`Monitoring.BecomeMonitor`) get a raw, unfiltered tap of every message via a separate code path (`deliver_to_monitors`) that fires before routing — deliberately *not* implemented as "give the monitor a catch-all match rule," because that double-delivers when combined with normal signal broadcast (this was a real bug caught during live testing, fixed by excluding `is_monitor` connections from the match-rule broadcast path).

### Driver (`driver.rs`) + side interfaces

`org.freedesktop.DBus`'s full method set (`Hello`, `RequestName`, `ReleaseName`, `ListNames`, `ListActivatableNames`, `NameHasOwner`, `GetNameOwner`, `ListQueuedOwners`, `StartServiceByName`, `AddMatch`, `RemoveMatch`, `GetConnectionUnixUser`, `GetConnectionUnixProcessID`, `GetConnectionCredentials`, `GetId`, `UpdateActivationEnvironment`), plus `org.freedesktop.DBus.Peer`, `.Introspectable`, `.Monitoring`, and `.Debug.Stats` handled as separate interfaces at the same bus object path (`dispatch.rs::handle_side_interface`) — matching the spec's actual interface boundaries rather than lumping everything into one dispatch table.

### Policy (`policy.rs`)

`[[rule]]` tables with `context = "default" | "user" | "group" | "mandatory"`, evaluated in that order (mandatory rules always apply last, so nothing below them can override), last-match-wins per operation (`own`/`send`/`receive`) — the same evaluation model as classic `<policy>` XML blocks, just TOML. An empty `policy.d/` means allow-everything (permissive dev/session default); a real system deployment ships `packaging/etc/oxibus/policy.d/00-default.toml` as a starting point.

### Activation (`activation.rs`)

One TOML file per service under `services_dir`/`vendor_services_dir`, loaded into a `name → ServiceDef` map at daemon startup. `SpawnStrategy` picks between:

- **`Direct`** (session bus): spawn the command in-process via `tokio::process::Command`, applying `UpdateActivationEnvironment`'s accumulated env (allowed here — no privilege boundary).
- **`ViaLaunchHelper`** (system bus): exec the setuid helper with *only* the bus name as an argument. See below.

### The setuid launch helper

This is the one place OxiBus crosses a real privilege boundary, and it's a direct, deliberate port of `bus/activation-helper.c` + `bus/activation-helper-bin.c` — not an approximation.

**The problem:** `oxibus-daemon` drops from root to `messagebus` right after binding its socket (`main.rs::drop_privileges`). A system service configured to run as some other user (say, a hardware daemon that needs `plugdev`) can't be spawned by a `messagebus`-uid process — there's no capability to hand over. Something has to bridge that gap, and whatever it is becomes the single most security-sensitive binary in the stack (real dbus's own `dbus-daemon-launch-helper` gets the same "this file is security sensitive" comment banner in its own source).

**The design principle:** the helper trusts *nothing* the calling `oxibus-daemon` process says, except the bus name — and even that's only used as a lookup key. Concretely:

1. It reads its config from exactly one hardcoded absolute path, `/etc/oxibus/oxibus.toml` — **not** `GlobalConfig::load_default()`, because that checks `$OXIBUS_CONFIG` and falls back to a CWD-relative file, either of which a compromised caller could steer. `TRUSTED_CONFIG_PATH` in `launch_helper.rs` is a `const`, not a parameter.
2. It clears its *entire* environment before doing anything else, then sets only `DBUS_STARTER_BUS_TYPE`/`OXIBUS_STARTER_BUS_TYPE=system`.
3. It verifies `getuid()` (the real uid, preserved across a setuid `execve`) equals the configured `bus.system.user`'s uid, and that `geteuid()` is actually 0. Both checks exist for different reasons: the first proves the genuine bus daemon invoked it (not some other local process that merely knows the path); the second proves the setuid bit is actually in effect (catches a botched install).
4. It re-reads the service file itself from the trusted service directories — never anything the daemon might have already parsed and handed over — and requires `user =` to be set (system activation with no configured user is a hard error, not "fall back to running as messagebus").
5. `initgroups` → `setgid` → `setuid` → `execve` directly, no shell. TOML's `exec`/`args` are already a real argv array, so there's no `_dbus_shell_parse_argv`-style word-splitting step to get wrong (a small but genuine simplification over the C original).

**A bug this caught in review:** Quantra's `Service` schema defaults `no_new_privileges` to `true`. `PR_SET_NO_NEW_PRIVS` is inherited by every descendant process and makes the kernel silently ignore setuid bits on `execve` — set on `oxibus-daemon`, it would have made the kernel ignore the helper's setuid bit entirely, so the helper would run at `messagebus` euid instead of root and *every* activation-as-a-different-user would fail (loudly, via the helper's own `euid != 0` check — fail-closed, not a security hole, but still broken). `quantra/oxibus.toml` explicitly sets `no_new_privileges = false` with a comment explaining why, matching why real `dbus.service` doesn't set `NoNewPrivileges=yes` either.

**Installation** (`scripts/install.sh`) copies the binary but deliberately does not `chown root:messagebus` / `chmod 4750` it — those are root-owned, security-sensitive changes the script prints as a ready-to-run `sudo` block rather than performing itself.

**`UpdateActivationEnvironment` is rejected outright on the system bus** (`ACCESS_DENIED`), matching `bus/driver.c`'s `bus_context_get_servicehelper() != NULL` check — once a servicehelper exists, letting any connected process inject environment variables that a setuid-launched service will inherit is a privilege escalation primitive, full stop.

## The client (`oxibus-client`)

`Connection` spawns one reader task that owns the mutable `Transport` (`read_message` needs `&mut self` for its internal buffer); a cloneable `Writer` is handed to that same task (for replying to incoming calls) and returned to the caller (for `call_method`/`emit_signal`). Pending method calls are tracked in a `HashMap<serial, oneshot::Sender<Message>>`; incoming signals fan out through a `broadcast` channel. A second `broadcast` channel (`subscribe_all_messages`) carries every message regardless of type, for monitor-mode tools — separate from the signal channel because ordinary clients should never see directed traffic that isn't theirs.

`ObjectServer` lets a connection also serve objects: `Interface` is a hand-written "manual `async_trait`" (methods return `Pin<Box<dyn Future<...>>>` explicitly) rather than pulling in the `async-trait` crate, since it needed to be `dyn`-compatible and native `async fn` in traits isn't yet without boxing.

## Verified interop

Live-tested against the **host machine's own, unmodified upstream D-Bus install** — not just OxiBus talking to itself:

```
$ dbus-send --session --print-reply --dest=org.freedesktop.DBus \
    /org/freedesktop/DBus org.freedesktop.DBus.ListNames
method return ...
   array [ string ":1.1" ]

$ gdbus introspect --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus
node /org/freedesktop/DBus { interface org.freedesktop.DBus { ... } }
```

Both `dbus-send` (linked against real `libdbus-1.so`) and `gdbus` (GLib's independent GDBus implementation) worked against `oxibus-daemon` with zero modification, in both directions (calls, introspection, and signal broadcast from `dbus-send` observed live by `oxibus-monitor`). This is the actual proof of the wire-compatibility goal — two codebases OxiBus has never seen, talking to it correctly on the first try.

`quantra/oxibus.toml` was similarly verified by parsing it against the *real* `quantra::services::types::Service` struct (copied verbatim from `zex-native/quantra-system`, including its `#[serde(deny_unknown_fields)]` guard) in a throwaway scratch crate — not just eyeballed against the field list.

## What's intentionally not implemented

SELinux, AppArmor, libaudit, launchd, systemd (socket activation, sd_notify), X11 autolaunch, TCP transport (unix: only — Zainium is a single-host bus, always was). None of these are "missing," they're out of scope by design.

💡 Note on Extensions: If you require SELinux, systemd support, or other transports for your own infrastructure, you are encouraged to fork the codebase and submit/maintain them as conditional Cargo features (--features selinux,systemd).
    
See [ROADMAP.md](ROADMAP.md) for gaps that *are* real and open.
