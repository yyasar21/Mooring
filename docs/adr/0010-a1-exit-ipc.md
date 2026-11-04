# ADR-0010: A1 exit — forwarding, SFTP, auto-lock and syslog over IPC

Status: Accepted · 2026-11-04 (Phase A1 exit)

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
sftp_download({ sessionId, remote, localDir, onProgress: Channel<Progress> }) -> { transferId }
sftp_upload({ sessionId, localPath, remoteDir, onProgress: Channel<Progress> })  -> { transferId }
sftp_cancel({ sessionId, transferId })         -> void
```
`localDir` / `localPath` come from the OS file dialog (`tauri-plugin-dialog`, capability
`dialog:allow-open` and `dialog:allow-save` only — the UI never types a local path); the Rust
side confines them with `LocalPath` (ADR-0007). `Progress = { transferId, bytesDone, bytesTotal|null, state: "running"|"done"|"failed"|"cancelled", error|null }`.
Transfers stream (256 KiB blocks, ≤ 8 in flight) and audit `session.sftp.transfer`
(direction, bytes, outcome) without file contents.

### Auto-lock
```
autolock_get()                                  -> AutoLockPolicy { idleMinutes|null, onScreenLock, onSleep, onWindowHidden }
autolock_set(policy)                            -> AutoLockPolicy    # persisted in setting table; audited `vault.policy_changed`
```
Tauri wiring: every command touches the clock; a 5 s tick checks `should_lock`; window
`Focused(false)` → `window_hidden`; OS sleep/lock via `tauri::RunEvent` where exposed, else the
idle timer covers it (documented per OS in the handoff). Lock emits `vault.lock { reason }` and
the UI event `vault:locked { reason }`.

### Syslog mirror (item 5)
```
syslog_get()                                    -> SyslogConfig | null
syslog_set({ host, port, transport: "udp"|"tcp"|"tls", facility, enabled })  -> SyslogConfig
syslog_test()                                   -> { ok, error|null }
```
Every audit entry is also sent as RFC 5424 (`APP-NAME=mooring`, structured data
`[mooring@0 seq="..." hash="..."]`) when enabled; TLS uses rustls with the system roots; send
failures never block the local audit write and are counted (`syslog_dropped` in telemetry).
No new C dependency; implementation in `mooring-audit::syslog` with a loopback test server.

### Capability change
`dialog:allow-open`, `dialog:allow-save` are added to the `main` capability for the file
pickers; nothing else. Security review is required for this change (ADR-0003).

## Consequences
The UI gains a Forwards panel, an SFTP panel (two-pane browser with transfers), auto-lock
settings and a syslog settings card. Fuzz targets (`known_hosts`, `kubeconfig`,
`vault header`, `import_age`, `socks`) and a nightly job are QA's part of the same exit.
