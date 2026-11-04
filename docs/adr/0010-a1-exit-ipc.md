# ADR-0010: A1 exit — forwarding, SFTP, auto-lock and syslog over IPC

Status: Accepted · 2026-11-04 (Phase A1 exit) · amended 2026-11-04 after security review 4

## Context
`mooring-proto-ssh` already implements port forwarding and SFTP (ADR-0007), the vault has a
pure auto-lock policy (ADR-0006) and the audit log is hash-chained (ADR-0002). None of them is
reachable from the UI yet. This ADR extends ADR-0008 with the commands that close A1 items 1, 3
and 5. Conventions (camelCase, `IpcError`, secrets inward only, base64 bytes) are unchanged.

## Decision

### Port forwarding (per SSH session)
```
forward_open({ sessionId, kind: "local"|"remote"|"dynamic", bind: {host, port}, target?: {host, port}, exposure: "loopback"|"external" })
    -> ForwardInfo { id, kind, bind, target|null, exposure, openedAt, connections }
forward_close({ sessionId, forwardId })        -> void
forward_list({ sessionId })                    -> ForwardInfo[]
```
`exposure` defaults to `loopback`; `external` requires a UI confirmation and is audited
(`session.forward.open { exposure }`). Limits are the crate's (64 forwards, 128 connections
each). Forwards die with the session.

### SFTP (per SSH session)
```
sftp_list({ sessionId, path })                 -> { entries: [{name, kind, size, mtime, mode}], truncated }
sftp_stat({ sessionId, path })                 -> Entry
sftp_mkdir / sftp_rename({ sessionId, from, to }) / sftp_remove({ sessionId, path })   -> void
sftp_pick_local({ sessionId, mode: "folder"|"file" }) -> { pickId, name } | null   # null = user cancelled
sftp_download({ sessionId, remote, pick, overwrite?: bool, onProgress: Channel<Progress> }) -> { transferId }
sftp_upload({ sessionId, pick, remoteDir, onProgress: Channel<Progress> })  -> { transferId }
sftp_transfers({ sessionId })                  -> Progress[]     # running transfers, for re-adoption after unlock
sftp_cancel({ sessionId, transferId })         -> void
```
**Local paths never cross the IPC boundary (review 4, B-4).** `sftp_pick_local` opens the native
dialog *from Rust* (`tauri-plugin-dialog` Rust API, `pick_folder` / `pick_file` with a
`oneshot`), stores the chosen `PathBuf` in `AppState` under a random 128-bit `pickId` and returns
only the display `name`. A pick is single-use, bound to its `sessionId`, expires after 10 min and
is cleared on lock; an unknown, reused or foreign pick → `input.invalid "pick"`. The WebView gets
no `dialog:*` or `fs:*` permission — the `main` capability stays `core:default`. The app-data-dir
refusal and `LocalPath` (ADR-0007) remain as defence in depth; `LocalPath` also refuses names
ending in `.` or space. A download refuses an existing target with `sftp.exists` unless
`overwrite` is true (L-15). Uploads write `<dir>/.<name>.mooring-part-<hex>` and rename on
success; cancel/failure removes the part file and leaves the original intact (L-16).
`Progress = { transferId, bytesDone, bytesTotal|null, state: "running"|"done"|"failed"|"cancelled", error|null }`.
Transfers stream (256 KiB blocks, ≤ 8 in flight) and audit `session.sftp.transfer`
(direction, bytes, outcome) without file contents.

### Auto-lock
```
autolock_get()                                  -> AutoLockPolicy { idleMinutes|null, onScreenLock, onSleep, onWindowHidden }
autolock_set(policy)                            -> AutoLockPolicy    # persisted in setting table; audited `vault.policy_changed`
```
Tauri wiring: every command except the passive pollers (`app_info`, `vault_status`,
`audit_verify`, `session_list`, `forward_list`, `sftp_transfers`, `autolock_get`, `syslog_get` —
the list is exported to the UI as `POLLED_COMMANDS` and tested on both sides, M-8) touches the
clock; a 5 s tick checks `should_lock`; window `Focused(false)` for **≥ 60 s** → `window_hidden`
(`BLUR_GRACE`, M-9; focus loss while a Mooring-owned native dialog is open is ignored);
`idleMinutes` is 1..=1440 or null; OS sleep is detected by a wall-clock jump / late tick (no
Tauri desktop event). Lock emits `vault.lock { reason }` and the UI event `vault:locked { reason }`.
On every lock, forwards with `exposure: external` are closed and audited (M-10, amends
ADR-0006: sessions and loopback forwards survive a lock). After unlock the UI re-adopts live
sessions via `session_list`, `forward_list` and `sftp_transfers`.

### Syslog mirror (item 5)
```
syslog_get()                                    -> SyslogConfig | null
syslog_set({ host, port, transport: "udp"|"tcp"|"tls", facility, enabled })  -> SyslogConfig
syslog_test()                                   -> { ok, error|null }
```
Every audit entry is also sent as RFC 5424 (`APP-NAME=mooring`, structured data
`[mooring@32473 seq="..." hash="..." trunc="1"? redacted="1"?]` — 32473 is the RFC 5612
documentation PEN until Mooring's own IANA PEN is assigned, N-12/N-13) when enabled. `facility` is
the RFC 5424 keyword on the wire (`"local4"`; numeric codes accepted on input). TLS uses rustls
(ring) with the system roots; send failures never block the local audit write and are counted
(`syslog_dropped` in telemetry). A redirect records `audit.syslog_changed` on the old mirror
first, then on the new one (L-17); startup from a stored config records `audit.syslog_started`
and an hourly `audit.heartbeat` lets collectors alert on silence (L-18). No new C dependency;
implementation in `mooring-audit::syslog` with a loopback test server.

### Capability change
None. The first draft granted `dialog:allow-open` / `dialog:allow-save` to the WebView; review 4
(B-4) rejected that because the chosen path then crossed the IPC boundary as a string. The
dialog is opened from Rust and the `main` capability stays `core:default`; a test asserts the
capability file contains no `dialog:` or `fs:` permission.

## Consequences
The UI gains a Forwards panel, an SFTP panel (two-pane browser with transfers), auto-lock
settings and a syslog settings card. Fuzz targets (`known_hosts`, `kubeconfig`,
`vault header`, `import_age`, `socks`) and a nightly job are QA's part of the same exit.
