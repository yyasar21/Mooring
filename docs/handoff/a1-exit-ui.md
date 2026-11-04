# A1 exit · ui-engineer · forwarding, SFTP, auto-lock, syslog (ADR-0010)

Branch `worktree-agent-af3f81762b77b9842`, on top of `ac27b8b` (ADR-0010). Built against the
ADR-0010 contract with `MockTransport`; nothing here talks to the Rust commands yet.

## Done

| Commit | What |
| --- | --- |
| `bd70014` | **feat(ui): typed IPC clients and mocks.** `ExitIpc` (types in `lib/ipc.types.exit.ts`) is part of `Ipc`. `TauriTransport` gains `forward_*`, `sftp_*` (a `Channel` per transfer, decoded by `lib/ipc.decode.exit.ts`), `autolock_*`, `syslog_*` and `onVaultLocked` (`listen("vault:locked")`). `MockTransport` now extends `MockExitBase` (`lib/ipc.mock.exit.ts`): forward registry with the crate limits, an in-memory SFTP tree per session (`lib/ipc.mock.fs.ts`, crate error behaviour), transfers that stream progress and can be cancelled or made to fail, auto-lock policy, syslog config and test, and `fireAutoLock(reason)`. Input rules live in `lib/validate.exit.ts`, shared by the forms and the mock. `lib/dialog.ts` wraps `@tauri-apps/plugin-dialog` `open` (the only way a local path enters the UI). |
| `97e3749` | **feat(ui): vault:locked.** `App` subscribes once; `useApp.lockedByBackend` wipes every store and the unlock screen names the reason (idle, screen lock, sleep, hidden window, unknown). A `user` reason shows nothing. |
| `144a5bc` | **feat(ui): forwards panel.** SSH tabs get a tool switcher (Terminal / Forwards / Files) above the terminal, which stays mounted underneath. The panel lists kind, bind, target, exposure and connections (polled every 5 s), opens local / remote / dynamic forwards from a validated form, closes them, and maps `IpcError` codes to English (`stores/errors.ts` `describeError`). External exposure always goes through a confirmation dialog that names the bind address. |
| `acbda3f` | **feat(ui): SFTP panel.** The local pane only shows metadata (folder and file name picked in the OS dialog, kept in memory, never typed). The remote pane is a keyboard-driven listbox (arrows, Home/End, Enter opens a folder or downloads a file, Backspace goes up, F2 renames, Delete removes) with breadcrumbs, Up, Refresh, New folder, Download, Rename and Delete. Delete is always confirmed and never recursive. The transfers drawer shows progress, Cancel, and the done, failed and cancelled states. `stores/transfers.ts` keeps file names only, cancels a transfer stopped before its id arrives, ignores progress that arrives after a terminal state, and is wiped on lock. |
| `d31a3e1` | **feat(ui): settings view.** A title-bar "Settings" view. **Auto-lock** card: idle minutes (1–1440, or off = `null` = never) and the screen-lock, sleep and hidden-window switches. It warns when nothing can ever lock the vault. **Syslog** card: host, port, UDP/TCP/TLS (the port follows the transport default), RFC 5424 facility, enabled, and "Send test entry" with its result. Plaintext transports are flagged. The audit viewer gets labels for the ADR-0010 events. |
| `7f2cbaa` | **fix(ui):** `Modal` renders through a portal, so a dialog opened inside a tool panel no longer ends up clipped under that panel's stacking context. SFTP rows get short accessible names. Crumb separator fix. |

Placeholders: the repo rule (CLAUDE.md) is `example.test` + RFC 5737, so fixtures use
`*.example.test`, `192.0.2.10`, `logs.example.test` and `down.invalid` (RFC 6761, the mock's "never answers" host).
Demo local picks outside Tauri are `/home/demo/...`. No private names.

## Left open
- **No screenshot of the unlock-with-reason screen**: the page cannot reach the mock to fire an
  auto-lock. `VaultLocked.test.tsx` covers the behaviour.
- **Connection counts are polled** (5 s, only while the Forwards panel is open). If Rust adds a
  `forward:changed` event, the hook can switch to it.
- **No overwrite prompt on download**: Rust's `LocalPath` and its persist policy decide what
  happens when the file already exists. The UI does not ask.
- **Single file only**: no multi-select and no drag-and-drop. A drop would hand the WebView a
  local path that did not come from the dialog, so drag-and-drop is left out on purpose.
- Main JS bundle is 412.6 kB (126.9 kB gzip), CSS 77 kB. The panels are not lazy-loaded yet.
- `@tauri-apps/plugin-dialog` ^2.8.4 was added to `apps/desktop/package.json` and
  `pnpm-lock.yaml` as the brief asked. Both files belong to the orchestrator, and the
  dependency needs security-reviewer approval. Justification: it is the JS side of
  `tauri-plugin-dialog`, which ADR-0010 requires for the file pickers. The Rust plugin and
  the capability are not part of this branch.

## Decision needed
1. **`dialog:allow-save` is unused.** The UI calls only `open` (folder for downloads, file for
   uploads), so the capability could be just `dialog:allow-open`.
2. **Syslog `facility` wire type.** The UI sends the RFC 5424 keyword (`"authpriv"`, `"local4"`, …).
   If Rust prefers the code (0–23), the change is one line in `SyslogCard` and the types.
3. **Remote-forward target.** The crate's `forward_remote` takes a `SocketAddr` target. The UI
   accepts a host name too, so Rust must resolve it or refuse it with `input.invalid`.
4. **Audit `syslog_set`.** The mock records `audit.syslog_changed`. Turning the mirror off is a
   way to hide tampering, so I recommend an audit entry for it.
5. **Idle bounds.** ADR-0010 sets none. The UI uses 1–1440 minutes, and Rust should use the same bounds.

## Contract assumptions the Rust side must satisfy
- **Command args** (camelCase): `forward_open({sessionId, kind, bind:{host,port}, target:{host,port}|null, exposure})`,
  `forward_close({sessionId, forwardId})`, `forward_list({sessionId})`, `sftp_list|sftp_stat|sftp_mkdir|sftp_remove({sessionId, path})`,
  `sftp_rename({sessionId, from, to})`, `sftp_download({sessionId, remote, localDir, onProgress})`,
  `sftp_upload({sessionId, localPath, remoteDir, onProgress})`, `sftp_cancel({sessionId, transferId})`,
  `autolock_get()`, **`autolock_set({ policy })`** (wrapped), `syslog_get()`,
  **`syslog_set({ host, port, transport, facility, enabled })`** (flat), `syslog_test()`.
- **Paths** are absolute POSIX strings. The UI joins `dir + "/" + name` and sends `/..`-free normalised paths.
- **ForwardInfo**: `{ id, kind, bind:{host, port /* resolved when 0 was asked */}, target|null, exposure, openedAt /* ISO 8601 */, connections }`.
  An `exposure` that is not `"loopback"` is displayed as external.
- **Entry**: `kind` lowercase `file|dir|symlink|other`, `size` bytes, `mtime` Unix seconds or null, `mode` (`& 0o7777`) or null.
- **Progress channel**: `{ transferId, bytesDone, bytesTotal|null, state, error|null }`, camelCase (snake_case is tolerated).
  Messages may arrive before the command returns. Exactly one terminal message (`done|failed|cancelled`) per transfer,
  with nothing after it. `sftp_cancel` causes a final `cancelled` message. **When a session ends, its running
  transfers must emit `failed`**, otherwise their rows stay "running". An unknown `state` is shown as failed.
- **`vault:locked` event**: payload `{ reason }` with `user|idle|screen_lock|sleep|window_hidden`, emitted after the
  lock took effect. The UI handles it whether or not `vault_lock("user")` also emits it.
- **AutoLockPolicy**: `{ idleMinutes: int|null, onScreenLock, onSleep, onWindowHidden }`. Out-of-range input is refused with `input.invalid`.
- **Syslog**: `syslog_get` returns `null` when never configured. `syslog_test` before any config throws
  `syslog.not_configured`. A delivery failure returns `{ ok:false, error }` and does not throw. For UDP, `ok` means "sent".
- **Error codes the UI maps** (others fall back to the scrubbed message): `vault.locked`, `session.not_found`,
  `session.failed` (not connected yet), `session.unsupported` (not SSH), `forward.limit`, `forward.bind_failed`,
  `forward.refused`, `forward.not_found`, `sftp.not_found`, `sftp.permission`, `sftp.exists`, `sftp.not_empty`,
  `sftp.not_a_directory`, `sftp.not_a_file`, `sftp.local_path`, `sftp.transfer_not_found`, `syslog.not_configured`.
  `input.invalid` messages are shown verbatim, so they must name the field and never contain a path or secret.
- **Validation mirrored in `lib/validate.exit.ts`**: host = DNS name or IP literal (no scheme, port or brackets);
  bind port 0–65535 (0 = any free), target and syslog port 1–65535; a non-loopback bind requires `exposure: "external"`;
  `dynamic` has `target: null`; names ≤ 255 bytes without `/` or NUL.

## Test evidence
- `pnpm lint && pnpm typecheck && pnpm test && pnpm build` green from the repo root.
- Vitest: **22 files, 165 tests** (baseline was 14 files, 109 tests: +8 files, +56 tests). New: `ipc.exit.test.ts` (decoders,
  validation, mock forwards, SFTP, transfers, auto-lock, syslog, vault:locked), `ipc.tauri.test.ts` (command names, arg
  shapes, Channel decoding, error mapping, event subscription against a mocked `invoke`/`listen`), `dialog.test.ts`
  (plugin mocked), `VaultLocked.test.tsx`, `forwards.test.tsx`, `sftp.test.tsx`, `transfers.test.ts`, `settings.test.tsx`.
- Screenshots: Playwright (`playwright-core` from `/opt/node-tools`, not added to the project) driving Chrome against
  `vite preview`, 1440×860, dark and light, in `docs/handoff/img/a1-exit-ui/`: `01-forwards`, `02-forward-expose-confirm`,
  `03-sftp` (done, cancelled, running download and running upload), `04-settings`.
