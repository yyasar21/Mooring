# A1 exit — rust-core: forwarding + SFTP over IPC (ADR-0010)

Branch `worktree-agent-afcbb84a92bf8c28e`. Commits: `c6dedf7` audit events, `dd9d969` `SshControl`,
`6948d0b` forward commands, `e437661` SFTP commands, `3255fb7` dialog plugin + capability.

## Done

- **`mooring-proto-ssh`**: `SshControl` (from `SshSession::control()`), a cheap clone that reaches
  forwards and SFTP while the session task owns the `SshSession`. `SshSession` keeps delegating
  wrappers, so the crate API and tests are unchanged. `ForwardInfo` gains `bind_host`,
  `target_addr`, `opened_at`, `connections`; `ForwardId: FromStr` (`fwd-<n>`);
  `LocalPath::check_new_file` / `check_existing_file` (pre-flight; transfers re-check at use).
- **`mooring-audit`**: `forward_opened { connection, id, kind, bind, target, exposure }`,
  `forward_closed { connection, id, kind, bind, target }`,
  `sftp_transfer { connection, transfer, direction, bytes, outcome }` — appended at the end of
  `AuditEvent` in a separate block. Every open is audited (not only `external`). These are the
  snake_case log names for ADR-0010's `session.forward.open` / `session.sftp.transfer`.
- **Commands** (`src-tauri/src/commands/{forward,sftp,sftp_transfers}.rs`), registered in
  `lib.rs` and `commands/mod.rs` under a `// ADR-0010` comment, separate from other blocks.
- **Dialog**: `tauri-plugin-dialog` 2.8.4 (one `tauri` 2.12.5 in `Cargo.lock`), registered with
  `.plugin(tauri_plugin_dialog::init())`; `capabilities/main.json` gains exactly
  `dialog:allow-open`, `dialog:allow-save`. The UI side needs `@tauri-apps/plugin-dialog`.

## IPC (camelCase arguments, `IpcError { code, message }` on failure)

### Forwards
```jsonc
// invoke("forward_open", …)
{ "sessionId": "…", "kind": "local", "bind": { "host": "127.0.0.1", "port": 0 },
  "target": { "host": "db.example.test", "port": 5432 }, "exposure": "loopback" }
// → ForwardInfo
{ "id": "fwd-1", "kind": "local", "bind": { "host": "127.0.0.1", "port": 40123 },
  "target": { "host": "db.example.test", "port": 5432 }, "exposure": "loopback",
  "openedAt": "2026-11-04T10:00:00.123Z", "connections": 0 }

{ "sessionId": "…", "kind": "dynamic", "bind": { "host": "127.0.0.1", "port": 1080 } }
// → { "id": "fwd-2", "kind": "dynamic", …, "target": null, … }

{ "sessionId": "…", "kind": "remote", "bind": { "host": "localhost", "port": 8080 },
  "target": { "host": "127.0.0.1", "port": 3000 } }

// invoke("forward_close", { "sessionId": "…", "forwardId": "fwd-1" }) → null
// invoke("forward_list",  { "sessionId": "…" })                      → ForwardInfo[] (by id)
```
- `bind.port: 0` picks a free port (returned). `bind.host` for local/dynamic and `target.host` for
  remote must be an IP literal or `localhost`. `exposure` is optional (default `loopback`);
  a non-loopback bind needs `"external"`, which the UI must confirm first.
- `dynamic` must not have `target`; `local`/`remote` require it. `connections` is a live count.
- Errors: `input.invalid`, `session.not_found`, `session.not_connected`, `forward.limit` (64),
  `forward.bind` (port in use / server refused `tcpip-forward`), `forward.not_found`.

### SFTP
```jsonc
// invoke("sftp_list", { "sessionId": "…", "path": "/home/alice" })
{ "entries": [ { "name": "notes.txt", "kind": "file", "size": 5, "mtime": 1793000000, "mode": 420 },
               { "name": "src", "kind": "dir", "size": 4096, "mtime": 1793000000, "mode": 493 } ],
  "truncated": false }
// invoke("sftp_stat",   { "sessionId": "…", "path": "/home/alice/notes.txt" }) → Entry
// invoke("sftp_mkdir",  { "sessionId": "…", "path": "/home/alice/new" })       → null
// invoke("sftp_rename", { "sessionId": "…", "from": "/a", "to": "/b" })        → null
// invoke("sftp_remove", { "sessionId": "…", "path": "/b" })  → null (file, symlink or EMPTY dir)

// const ch = new Channel<Progress>(); ch.onmessage = …
// invoke("sftp_download", { "sessionId": "…", "remote": "/home/alice/notes.txt",
//                           "localDir": <dir from open({ directory: true })>, "onProgress": ch })
// invoke("sftp_upload",   { "sessionId": "…", "localPath": <file from open()>,
//                           "remoteDir": "/home/alice", "onProgress": ch })
{ "transferId": "6f1c…" }
// Progress events (0..n "running", then exactly one final event):
{ "transferId": "6f1c…", "bytesDone": 262144, "bytesTotal": 1048593, "state": "running", "error": null }
{ "transferId": "6f1c…", "bytesDone": 1048593, "bytesTotal": 1048593, "state": "done", "error": null }
{ "transferId": "6f1c…", "bytesDone": 0, "bytesTotal": null, "state": "failed", "error": "remote path not found" }
// invoke("sftp_cancel", { "sessionId": "…", "transferId": "6f1c…" }) → null; then a "cancelled" event
```
- `mode` is decimal on the wire (`420` = `0o644`); `size`/`mtime`/`mode` may be `null`.
- Download saves `localDir/<basename of remote>`, replacing an existing regular file; the file
  appears only when complete. Upload writes `remoteDir/<file name>` (create/truncate).
- Events can arrive before the `invoke` promise resolves: key them by `transferId`.
- `bytesTotal` for downloads is the server's size hint and may be `null`.
- Errors: `input.invalid` (path checks, confinement), `session.not_found`,
  `session.not_connected`, `sftp.not_found`, `sftp.denied`, `sftp.failed`, `transfer.limit` (8
  per session), `transfer.not_found`. Messages never contain local paths or server text.

## Left open

- A cancelled **upload** leaves a partial remote file and the remote handle open until the
  session ends (the transfer future is dropped mid-request). Downloads leave nothing behind.
- No recursive upload/download/remove (crate is single-file, `remove` refuses non-empty dirs).
- Forward/SFTP commands are not vault-gated (consistent with `session_send`: live sessions keep
  running after lock, ADR-0006). If the UI hides sessions while locked this is fine.
- `test_ssh_server.rs` includes `crates/mooring-proto-ssh/tests/common/sftp_server.rs` by
  `#[path]` (test-util/test only) to avoid a third copy; QA owns that file — keep it compatible
  or move it into a shared test-support crate.
- The minimal test server does not implement `tcpip-forward`; the remote-forward success path is
  covered by `crates/mooring-proto-ssh/tests/forward.rs`, the command test covers the refusal.

## Decision needed

1. **Security review — capability change** (ADR-0003): `dialog:allow-open` + `dialog:allow-save`
   on `main`, plus the new dependency `tauri-plugin-dialog` (transitive: `rfd`, `tauri-plugin`,
   `tauri-plugin-fs`; fs commands are not registered).
2. **Security review — trust in dialog paths**: Rust cannot prove `localDir`/`localPath` came
   from the dialog; a compromised WebView can name any absolute directory. Mitigations here:
   the app data dir is refused, the file is exactly one confined name (no `..`, symlink, ADS,
   device names). Stronger option: open the dialog from Rust inside `sftp_download`/`sftp_upload`
   (then the UI drops `localDir`/`localPath`); needs an ADR-0010 amendment.
3. Audit names: snake_case `forward_opened` / `sftp_transfer` (log convention) vs. the dotted
   ADR wording; `sftp_transfer` carries no remote path (ADR field list) — add it if forensics
   needs it.
4. Shared `CARGO_TARGET_DIR` across worktrees: path-dependency artifacts have the same names in
   every worktree, so a build in one worktree can make cargo reuse another worktree's rlib
   (seen here as phantom compile errors). `touch`ing the sources before each build avoided it;
   orchestrator should consider per-worktree target dirs or `--locked` serial builds.

## Test evidence

`CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/home/claude/nexus/target-shared`:
`cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets -- -D warnings`
clean (only the pre-existing `unknown lint: clippy::unused_async_trait_impl` toolchain warning);
`cargo test --workspace`: 28 test binaries, **404 passed, 0 failed** (3 ignored, pre-existing).
`mooring_app_lib` 72 (new: 5 forward, 3 sftp, 4 transfer, 1 sessions audit), `e2e_flow` 13,
`mooring_proto_ssh` 56 + integration (forward 10, sftp 8, …), `mooring_audit` 10 (new: wire names).
The cancel test (multi-thread runtime, holds the first block until cancelled) passed 6/6 reruns.
