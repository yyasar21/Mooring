# A1 — ui-engineer handoff (item 4 + audit viewer from item 5)

Branch `worktree-agent-aece4a57698e71d8e`. Built against ADR-0008 with `MockTransport`; nothing
calls Rust except `apps/desktop/src/lib/ipc.ts` (`TauriTransport`). The visible product name is
**Mooring** (orchestrator decision); package scopes, crates and paths still say `nexus`.

## Done
- `src/lib/ipc.ts` + `ipc.types.ts`: one `Ipc` interface for every ADR-0008 command plus the A0
  vault/app commands and `windowDetach`. `TauriTransport` uses `invoke()` and one
  `@tauri-apps/api/core` `Channel` per session. Wire codec: `Bytes.data` / `Frame.rgba` base64 ⇄
  `Uint8Array`, `peer_identity` → `peerIdentity`, flattened audit entries → `{ event, details }`;
  unknown session event kinds become `closed`. `ipc` is picked once (`inTauri()` → Tauri, else
  mock); tests swap it with `setIpc()`.
- `src/lib/ipc.mock.ts` (+ `ipc.seed.ts`): in-memory tree with inheritance, cycle and root
  checks; 3 credentials (metadata only, secrets discarded); sessions echo input, raise a TOFU
  `Prompt` (id 1) on first open of each host, a secret keyboard-interactive prompt (id 2) for
  connections tagged `otp`, `exit` closes; `credentialCopyPassword` audits and returns
  `{ clearsInMs: 30000 }`; fuzzy `connection_search`; audit tail newest first with `before`.
- Stores (zustand): `tree`, `credentials`, `sessions` (tabs; terminal output kept out of React in a
  1 MiB capped per-tab buffer), `ui` (theme, pane widths, palette, dialogs, view), `app` (boot,
  unlock, lock — lock wipes every vault-derived store).
- Screens: three-pane shell with keyboard-resizable splitters; WAI-ARIA tree (roving tabindex,
  ↑↓ ← → Home End, Enter opens, mod+Enter opens a new tab, F2 inline rename, drag a row onto a
  folder to move it); tab strip (close, middle-click close, drag or Alt+Shift+←/→ to reorder,
  detach button + mod+Shift+D); state rail under each tab (taut = connected, drifting dashes =
  connecting, frayed = closed); xterm.js terminal (fit + WebGL, DOM renderer fallback, resize sent
  as `Resize`, lazy chunk); inline prompt modal answered via `SessionInput::Answer`; inspector
  with read-only credential reference (name/kind/username/inherited-from) and "Copy password" with
  a 30 s countdown chip driven by Rust's `clearsInMs` (UI never touches the clipboard); folder,
  connection, credential and credential-list dialogs (secret fields write-only, cleared before the
  request is awaited, empty on edit = keep stored secret); command palette on mod+K backed by
  `connection_search` plus app actions; audit log viewer (newest first, filter box, paging, verify
  badge). Dark default, light theme checked, focus rings everywhere, no `console.*`, no `any`.
- Shortcuts (`src/lib/shortcuts.ts`): inside a terminal on Linux/Windows plain Ctrl+K/W/I stay with
  the shell; the app answers to Ctrl+Shift+K/W/I there. Cmd on macOS always goes to the app.
- Tokens (`packages/ui/src/tokens.css`): warn/danger soft fills, tab-rail tokens, terminal surface
  tokens for both themes, density sizes. Primary buttons are neutral; the teal accent is used only
  for selection, focus and connected state.

### Ipc methods rust-core must implement (command name → TS method)
`app_info` appInfo · `vault_status` vaultStatus · `vault_create` vaultCreate · `vault_unlock`
vaultUnlock · `vault_lock` vaultLock · `vault_change_password` vaultChangePassword · `tree_list`
treeList · `folder_create` folderCreate · `folder_rename` folderRename · `folder_move` folderMove
· `folder_set_default_credential` folderSetDefaultCredential · `folder_delete` folderDelete ·
`connection_create` connectionCreate · `connection_update` connectionUpdate · `connection_move`
connectionMove · `connection_delete` connectionDelete · `connection_search` connectionSearch ·
`credential_list` credentialList · `credential_create` credentialCreate ·
`credential_update_meta` credentialUpdateMeta · `credential_replace_secret`
credentialReplaceSecret · `credential_delete` credentialDelete · `credential_copy_password`
credentialCopyPassword · `session_open` sessionOpen · `session_send` sessionSend ·
`session_close` sessionClose · `session_list` sessionList · `audit_tail` auditTail ·
`audit_verify` auditVerify · `window_detach` windowDetach (new, see below).

Wire assumptions rust-core must match:
- Command args are camelCase (Tauri default), e.g. `{ parentId, name }`, `{ connectionId, size,
  onEvent }`; return DTOs are camelCase as written in ADR-0008 (`#[serde(rename_all =
  "camelCase")]`).
- `SessionEvent` / `SessionInput` keep the `nexus_core` shapes (`kind`, snake_case fields such as
  `peer_identity`) with `Vec<u8>` serialised as **base64 strings** (`serde_with::base64` or
  equivalent), both directions.
- `SessionInput` needs a new variant `Answer { id: u32, text: String }` — it is in ADR-0008 but
  not yet in `crates/nexus-core/src/session.rs`.
- `audit_tail` returns entries flattened as `nexus_audit::AuditEntry` serialises today (`seq`,
  `at`, `prev`, `event`, event fields); the UI never shows `prev` and treats every other field
  as display text.

### `windowDetach` note for rust-core
`window_detach({ sessionId })` → `void` is **not in ADR-0008**. Intended behaviour: open a new
window (label `session-<id>`, same `main` capability, no remote content) that renders only that
session's tab, and re-route the session's event `Channel` to it; the calling window then drops the
tab (the UI does this on success). The mock records the id and does nothing. Needs an ADR-0008
amendment (architect) and a capability check (security) before rust-core implements it; until
then the Tauri call fails with `ipc.unknown`, the tab stays where it is and the tree shows the
error.

## Left open
- No graphical rendering for RDP/VNC (`frame` events are ignored; the tab shows a placeholder).
- `session_list` is typed but unused (no re-attach after a window reload yet).
- Change-password UI and auto-lock indicators not built (commands typed only).
- Tree is not virtualised; fine for hundreds of rows, revisit with `@tanstack/react-virtual` past
  ~2 000 nodes.
- `audit_tail` paging relies on `before` meaning "seq strictly less than".
- Accessibility review with the Design plugin not run in this environment.

## Decision needed
- Amend ADR-0008 for `window_detach` (shape above) and the `Answer` variant on `SessionInput`.
- Confirm base64 for `Vec<u8>` on both channel directions (ADR-0008 states it for events only).
- Whether the "Delete folder and contents" cascade needs a typed confirmation step.

## Test evidence
- `pnpm install && pnpm typecheck && pnpm lint && pnpm test && pnpm build` from the repo root:
  clean; vitest 8 files / 40 tests passed (ipc codec + mock, 4 stores, App boot → palette → tab →
  lock, tree keyboard nav + F2 rename, palette open-connection, inspector copy flow, TOFU +
  keyboard-interactive prompt answer with terminal echo, reject + reconnect, audit viewer render
  and filter, credential and connection dialogs, shortcut routing). Build: main chunk 300 kB,
  terminal chunk 444 kB, no warnings.
- Screenshots (Playwright driving the system Chrome; the bundled chromium download is blocked by
  the egress proxy, so `@playwright/test` was **not** added to the project):
  `docs/handoff/img/a1-ui/01-shell-dark.png`, `02-palette.png`, `03-tofu-prompt.png`,
  `04-terminal-and-otp.png`, `05-copy-countdown.png`, `06-audit.png`,
  `07-connection-dialog.png`, `08-shell-light.png`, `09-credential-dialog-light.png`.
- Dependencies added to `apps/desktop/package.json`:
  - `@xterm/xterm` ^6.0.0: terminal emulator for SSH tabs (A1 item 3/4).
  - `@xterm/addon-fit` ^0.11.0: sizes the terminal to its pane and drives `Resize`.
  - `@xterm/addon-webgl` ^0.19.0: GPU renderer; falls back to the built-in DOM renderer.
