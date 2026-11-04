# A1 exit — rust-core: auto-lock wiring and syslog mirror (ADR-0010)

## Done
- `mooring-store`: `Store::app_setting` / `set_app_setting` for `app.*` keys in the `setting`
  table (`[a-z0-9_.]`, ≤ 64 bytes, values ≤ 16 KiB). Store bookkeeping keys are unreachable.
- `mooring-audit::syslog` (new, pure Rust):
  - RFC 5424 formatter: `<PRI>1 TS HOST mooring PROCID MSGID [mooring@0 seq="N" hash="H"] MSG`.
    PRI = facility·8 + severity (notice; warning for trust `changed`/`rejected` and
    `become_failed`). TS = UTC with µs. MSGID = event name. `hash` = SHA-256 of this entry's
    canonical line, i.e. the next entry's `prev`, so a collector can re-verify the chain.
    MSG = compact JSON of the entry passed through `redact()` (no BOM). Header fields are
    reduced to PRINTUSASCII; the message is capped at 8 KiB on a UTF-8 boundary.
  - Transports: UDP (RFC 5426), TCP and TLS with octet counting (RFC 6587 / 5425). TLS =
    rustls 0.23, ring provider (no aws-lc), roots from the OS store via `rustls-native-certs`
    (enterprise CAs installed in the OS store work). 5 s connect / write timeouts.
  - `SyslogMirror`: bounded queue (1024) + one sender thread; `send` never blocks. A full
    queue, connect failure (then 2 s backoff) or write failure increments `dropped`.
  - Wired into `AuditLog::record` after the local fsync (`AuditLog::set_mirror` / `mirror()`).
- Audit events, appended in a separate block: `vault_policy_changed`, `audit_syslog_changed`.
  Wire names follow the existing snake_case convention: ADR `vault.lock` = existing
  `vault_locked { reason }`, `vault.policy_changed` = `vault_policy_changed`,
  `audit.syslog_changed` = `audit_syslog_changed`.
- `src-tauri/src/autolock.rs`: one invoke-handler wrapper (`with_activity` in `lib.rs`)
  touches the clock before every command except the passive polls `app_info`,
  `vault_status`, `audit_verify`, `session_list`, `autolock_get`, `syslog_get` (the telemetry
  strip calls `audit_verify` every 60 s and would otherwise keep the vault open forever).
  5 s tokio tick; main-window `Focused(false)` → `window_hidden` (checked at once, off the
  event loop), `Focused(true)` → activity; suspend detection (below). Lock goes through
  `commands::vault::lock` (clipboard clear + audit `vault_locked { reason }`) and emits
  `vault:locked { reason }`. Signals that arrive while the vault is locked are discarded.
- Commands `autolock_get`, `autolock_set`, `syslog_get`, `syslog_set`, `syslog_test`,
  registered in a separate block at the end of `generate_handler!`; modules added at the end of
  `commands/mod.rs`.
- Dependencies (workspace `Cargo.toml`, one-line reasons inline): `rustls` 0.23 and
  `rustls-native-certs` 0.8 (mooring-audit), `rcgen` 0.14 (mooring-audit dev only),
  `sysinfo` added to mooring-app (already in the tree). `deny.toml` unchanged: all new crates
  are MIT / Apache-2.0 / ISC; `openssl-probe` (pulled by rustls-native-certs on Linux) is a
  pure-Rust path probe, not the banned `openssl` / `openssl-sys`. Cargo.lock changed — the
  orchestrator owns it; please re-lock on merge if needed.

## IPC (exact JSON)
```
autolock_get()                     -> {"idleMinutes":15,"onScreenLock":true,"onSleep":true,"onWindowHidden":true}
autolock_set({ policy: {"idleMinutes":5|null,"onScreenLock":bool,"onSleep":bool,"onWindowHidden":bool} })
                                   -> same shape (canonical)
   errors: input.invalid "invalid idleMinutes: must be 1..=1440 or null" · vault.locked
   unknown fields are rejected. autolock_get works while locked; autolock_set needs unlock.

syslog_get()                       -> null | {"host":"logs.example.test","port":6514,"transport":"tls",
                                       "facility":13,"enabled":true,"running":true,"dropped":0,"sent":42}
syslog_set({ host, port, transport: "udp"|"tcp"|"tls", facility, enabled })
                                   -> same shape as syslog_get (non-null)
   errors: input.invalid ("invalid host|port|facility|transport: ..."), syslog.failed, vault.locked
syslog_test()                      -> {"ok":true,"error":null} | {"ok":false,"error":"network error: ConnectionRefused"}
   errors: syslog.not_configured, vault.locked. Uses the stored config even when disabled;
   for UDP ok = the datagram left this host. May take up to ~10 s (DNS + 5 s timeouts).

event "vault:locked"               -> {"reason":"idle"|"screen_lock"|"sleep"|"window_hidden"}
   Emitted only by automatic locks; a user lock via vault_lock is signalled by its own result.
```
`dropped` / `sent` are the telemetry counters (`syslog_dropped` in ADR-0010); they reset when
the mirror is (re)started. The UI should poll `syslog_get` (passive, not activity).

## Per-OS coverage (Tauri 2.12, desktop)
| Trigger | macOS | Windows | Linux | How |
| --- | --- | --- | --- | --- |
| Idle | yes | yes | yes | 5 s tick, activity = any non-passive command |
| Window hidden / minimised / focus lost | yes | yes | yes (as reported by the WM / compositor; not verified on Wayland) | `WindowEvent::Focused(false)` on `main` |
| OS sleep | yes (detected on wake) | yes (detected on wake) | yes (detected on wake) | wall clock jumps > 30 s beyond `Instant`, or a tick arrives > 30 s late; reason `sleep`. Tauri has no desktop sleep `RunEvent` |
| Screen lock | indirect | indirect | indirect | no Tauri event; the lock screen takes focus → `window_hidden`, and idle runs on. `onScreenLock` currently has no own trigger |
| Idle across sleep | yes | yes | yes | suspended time is added to the idle clock (`Instant` stops in suspend on Linux/macOS) |

Lock-on-wake means the vault is locked when the machine resumes, before any user input
reaches the app (the first tick runs ≤ 5 s after resume; the UI receives `vault:locked`).

## Left open
- Native screen-lock / pre-sleep notifications (NSWorkspace `screensDidLock` /
  `willSleep`, `WTSRegisterSessionNotification` / `WM_POWERBROADCAST`, logind
  `PrepareForSleep` / `org.freedesktop.ScreenSaver`): need FFI/`unsafe` or zbus (only via
  keyring, with open advisories) — hook point is `AutoLock::signal`.
- Activity is IPC-only: reading terminal output without typing for the idle period locks the
  vault (sessions survive the lock, ADR-0006). A UI-side `activity` ping could be added.
- Detached windows (A2) are not considered for focus; only the `main` label is.
- No custom CA / client certificate setting for syslog TLS (`TlsRoots::Custom` exists
  internally); no queue-overflow persistence (the local log stays authoritative).
- UI: settings cards for auto-lock and syslog, `vault:locked` listener (ui-engineer).
- Shared `CARGO_TARGET_DIR` across worktrees: path crates get the same metadata hash in every
  worktree, so concurrent agents overwrite each other's `mooring-store` / `mooring-audit`
  artifacts and builds fail with "method not found" (or could pass stale). I had to `touch`
  sources before each build. Consider per-worktree target dirs for the final gate.

## Decision needed
1. **Blur grace.** ADR-0010 says `Focused(false)` → `window_hidden`; implemented literally
   (`BLUR_GRACE = 0`). With the default policy (`onWindowHidden: true`) every alt-tab, and the
   native file dialog from `tauri-plugin-dialog` (SFTP), locks the vault. Recommendation:
   `BLUR_GRACE = 60 s`, or default `onWindowHidden` to false — one-constant change in
   `src-tauri/src/autolock.rs`.
2. **SD-ID `mooring@0`.** RFC 5424 reserves enterprise number 0; strict collectors may reject
   it. Options: register an IANA PEN, or use `32473` (RFC 5612 documentation PEN). Kept as the
   ADR says.
3. **Syslog host in the audit log** — decided: included (inventory-class like a connection
   host; a redirected mirror must be visible in the chain).

## Test evidence
`CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/home/claude/nexus/target-shared`, cloud Linux:
- `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets -- -D warnings`
  clean.
- `cargo test --workspace`: 431 passed / 0 failed / 3 ignored (was 390 at round 3).
- New tests: store app settings 3; syslog formatter goldens + hostile inputs 6 (CR/LF/NUL/ESC,
  `]`/`"`/`\`, bidi, `password=` / `Bearer` redaction, 8 KiB cap on multi-byte text, facility
  clamp); loopback collectors 11 (UDP, TCP octet-counted order, TLS with an rcgen self-signed
  cert, untrusted cert refused, name mismatch refused, 2000 entries to a closed port: all
  counted dropped, writer never blocked, local chain intact; config validation table incl.
  URLs, ports, brackets, IDN, label/total length; wire shape, unknown fields);
  auto-lock wiring with a fake clock 13 (idle lock once + audit reason, activity defers,
  focus → `window_hidden`, focus as activity, policy off, signals discarded while locked,
  suspend via wall clock, late tick, suspended time counted as idle, NTP backwards jump,
  live policy change, no vault, passive command list, event payload); autolock commands 5;
  syslog commands 6 (parse table with hostile values, mirror + counters + disable, restart from
  the stored config before unlock, locked refusals, `syslog_test` ok/refused, unreachable
  collector never fails a user action).
