# A1 · rust-core · Tauri IPC layer (ADR-0008)

Worktree `.claude/worktrees/agent-ab96f81eb189d8335`, on top of `85a9f05` (ADR-0008
amendments). Not merged. Linux, WebView toolchain installed: `mooring-app` was compiled,
linted and tested here.

## Done

| Commit | What |
| --- | --- |
| `91a06c9` | **build:** `base64 0.22` and `arboard 3.7` (default features off) added to root `[workspace.dependencies]`, each with a one-line justification. `mooring-app` gains `mooring-store`, `mooring-proto-ssh`, `uuid`, `time`, `sha2`, `base64`, `arboard`; dev: `tempfile`, `russh`. |
| `41a1ddc` | **AppState / errors / vault.** `AppState { vault, store: Mutex<StoreSlot>, audit: Arc<Mutex<AuditLog>>, sessions, settings }`. Store at `$APP_DATA/mooring.db`, root folder "All connections" created on first start. `with_ready()` requires an unlocked vault and binds `Store::set_vault_id` on first use after unlock, never earlier (A1-QA-2). A bind failure at unlock (`store.vault_mismatch`) locks the vault again. **L2:** the header write copies the old header to `vault.header.json.bak`, writes a temp file (mode 0600), runs `sync_all`, renames, then fsyncs the directory. The `.bak` is deleted after the next successful unlock or password change. `IpcError` mapping lives in `error.rs`. `vault_change_password`: KDF is calibrated → `Vault::change_password` → durable persist. If the write fails, the persisted header is restored (locked). On error from a locked vault, the vault stays locked. Audits `password_changed`. |
| `7db6d6f` | **Tree:** all 11 ADR-0008 tree commands, camelCase DTOs, `effectiveCredentialId`. Moving or deleting the root returns `tree.root` (the store reports moving the root as a cycle, so the command checks for the root first). |
| `5e929f8` | **Credentials:** list/create/update_meta/replace_secret/delete return metadata only. Secrets are capped at 64 KiB and must be non-empty. `credential_copy_password` works only for `password` credentials. It writes through `arboard` and excludes the value from clipboard history (Linux/macOS/Windows; also from Windows cloud clipboard). It audits `credential_used{purpose:"copy"}` and returns `{ clearsInMs: 30000 }`. The clear task holds only a SHA-256 digest and clears only if the clipboard still has the same value. A single `arboard::Clipboard` is kept for the process lifetime, because on X11/Wayland the owner must stay alive. Tests use `MemoryClipboard`, so no display is needed. |
| `c1a1dcf` | **Sessions:** `session_open` resolves the connection and its effective credential, then opens the secret (vault must be unlocked). Password → `ConnectSecret::Password`; ssh_key → `PrivateKey` plus the optional `secret2` passphrase; certificate → `session.failed`. It builds `ConnectParams` and calls `SshSession::connect` with `$APP_DATA/known_hosts` (agent on in production). Non-SSH protocols return `session.failed` "`<proto>` sessions are not available in this version". There is one Tokio task per session, kept in `HashMap<String, SessionHandle>`. Each task takes commands (`Input`/`Close` with reply channels) and calls `next_event`, then sends `WireEvent` (base64 `data`/`rgba`, snake_case, `kind` tag) to `Channel<WireEvent>`. After every event it drains `take_audit_events` into `trust_decision {host:"h:port", fingerprint, decision: accepted|rejected|changed}`. Auth success and failure go to tracing only (there is no audit variant for them). Audits: `credential_used{connect}` (before connecting), `session_opened` (on `Connected`, with peer identity), `session_closed` (when the task ends, with the reason). `session_send` decodes base64 (64 KiB cap) and wraps `Answer.text` as `SecretString` at deserialisation (4 KiB cap; hand-written redacted `Debug`; `deny_unknown_fields`). `session_close` / `session_list` (`connecting|connected|closed`). Max 64 sessions. `window_detach` → `ipc.unknown` (A2). |
| `59e42cf` | **Audit + wiring:** `audit_tail` (newest first, `seq < before`, limit clamped to 1..=500, streaming window so memory stays bounded) and `audit_verify` (`{ ok, entries, brokenAt }`); both require unlock, because entries reveal inventory. `lib.rs` registers all 30 commands under the names the UI calls and runs `AppState::shutdown()` (abort sessions, `Store::close()`) on `RunEvent::Exit` (review condition 1). A unix test for `create_private_dir` (M2 follow-up). |

Layout: `src-tauri/src/{lib,state,error,dto,clipboard,sessions,test_ssh_server}.rs`,
`commands/{mod,vault,tree,credentials,sessions,sessions_tests,audit}.rs`. Every file is under 450
lines. Logic is in plain functions taking `&AppState`; `#[tauri::command]` wrappers are thin
and named exactly as the UI invokes them.

### Error codes produced
ADR-0008 list (`vault.locked`, `vault.unlock`, `vault.weak_password`, `tree.root`,
`tree.cycle`, `tree.not_found`, `input.invalid`, `credential.not_found`, `session.not_found`,
`session.failed`, `store.io`, `ipc.unknown`) plus these existing or extra codes the UI shows as generic
errors: `vault.missing`, `vault.exists`, `vault.password_too_long`, `vault.tampered`,
`vault.format`, `vault.kdf`, `store.vault_mismatch`, `tree.invalid`, `clipboard.unavailable`,
`audit.io`, `state.io`, `state.poisoned`.

## Left open
- **Connection `updatedAt`** equals `createdAt`: `mooring_core::Connection` has no
  `updated_at`, and the store does not return its column. A small store/core change.
- **Folder `sort`** is the folder's position in the store's `ORDER BY sort, name` order.
  No IPC sets it yet.
- **Auto-lock** (`src-tauri/src/autolock.rs`, ADR-0006) is not wired: no idle timer and no
  OS signals. `vault_lock` takes the `reason` from the UI.
- **Keyring commands** are still unwired (M1). `vault_change_password` has no keyring item
  to delete. When keyring is wired, add `store.delete(vault_id)` + `vault.keyring_disabled`
  audit after the persist (ruling c).
- **Audit event names** are the existing `mooring_audit::AuditEvent` snake_case variants
  (`credential_used`, `session_opened`, `session_closed`, `trust_decision`, `vault_*`,
  `password_changed`). The dotted names in the brief (`session.open`,
  `trust.host_key.added`, ...) would need new `AuditEvent` variants. See Decision 2.
- **Session handshake timeout:** none on the Tauri side. A stuck handshake stays
  `connecting` until the user closes the tab (proto-ssh handoff, same note).
- The test SSH server is a trimmed copy of `crates/mooring-proto-ssh/tests/common` in
  `src-tauri/src/test_ssh_server.rs` (cfg(test)). The original lives in QA-owned
  `crates/*/tests/**` and cannot be imported from another crate.
- The clipboard on a real display was **not** exercised (CI has none). A manual check on
  each OS is owed: copy → paste works, value gone after 30 s, absent from history managers.
- Not run: cargo-deny, cargo-audit, gitleaks (not installed). A `cargo deny` run should
  confirm arboard's transitive tree (x11rb, wl-clipboard-rs off, objc2 on macOS,
  windows-sys on Windows) passes the license and ban lists.

## Decision needed
1. **Dependency approval (security-reviewer):** `arboard 3.7` (1Password, MIT/Apache-2.0,
   no unsafe in our code, `default-features = false`, text only) and `base64 0.22` (already
   transitive). Both are recorded in the root `Cargo.toml` with a justification.
2. **Audit vocabulary:** keep the current `AuditEvent` variants, or have rust-core add
   `TrustHostKeyAdded/Mismatch`, `CredentialCopied` and `SessionOpen/Close` with dotted
   names to match ADR-0007's `trust.host_key.*`. The UI's audit viewer shows whatever `event`
   contains, so either works.
3. **Unlock gating for the tree:** every tree, credential, session and audit command
   requires an unlocked vault (matches the UI mock and the "lock wipes vault-derived
   stores" behaviour). Confirm this is intended for the read-only `tree_list`.
4. **SSH agent in production** is on (`allow_agent = true`, ADR-0007 default). It is used
   when no credential resolves or the key fails.

## Capability / config changes the orchestrator must make
**None.** Every command is an app command covered by `core:default` (custom commands
need no permission entry in Tauri 2 unless an allow-list is introduced). The clipboard goes
through Rust (`arboard`), not `tauri-plugin-clipboard-manager`, so there is no plugin and no
capability. `tauri.conf.json` is unchanged. On Linux, packagers should note that `arboard`
talks to X11 directly (via `x11rb`, no C library). Wayland-native clipboard
(`wayland-data-control`) is off, so on pure Wayland it goes through XWayland.

## Test evidence
```
cargo fmt --all                                              clean
cargo clippy --workspace --all-targets -- -D warnings        clean
cargo test --workspace                                       all green
  mooring-app (lib)            41 passed
    error 4 · dto 3 · state 4 · clipboard 1 · sessions 2 · lib 1 (data dir 0700)
    vault 7   lifecycle+audit, oversized password, reload locked, change password
              (persist, .bak dropped, old pw refused, reload), locked stays locked,
              foreign store → store.vault_mismatch + re-locked, no bind before unlock
    tree 4    locked refusal, folder round trip + root/cycle/not_found, 11 validation
              rejections + unknown credential, connection round trip + inheritance +
              search + move + delete
    credentials 5  metadata-only round trip (no secret in JSON), validation, copy sets +
              clears + audits (no secret in log), newer clipboard value kept,
              non-password/locked refused
    sessions 8  in-process russh: TOFU (wrong id refused) → connected → echo → resize →
              close → registry empty + audit {credential_used, trust_decision accepted,
              session_opened, session_closed}, no password in audit, known_hosts hashed;
              known host + remote exit cleanup; host-key mismatch hard stop + audited
              "changed"; rdp gate / bad id / bad size / missing / locked; refused TCP;
              input caps + window_detach; WireInput parsing + redacted Debug
    audit 2   paging newest-first with before, verify detects tampering, locked refusal
  mooring-audit 7 · mooring-core 10 · mooring-proto-ssh 24+9+8+5 (1 ignored lab)
  mooring-store 18+7+7+6+4+8+6 · mooring-vault 52 (2 ignored) +3+7+2+3
mooring-app tests run 3× in a row: green, ~3.5 s each.
```
