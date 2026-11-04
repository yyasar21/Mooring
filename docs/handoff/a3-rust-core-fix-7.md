# A3 — rust-core fix 7: security review 6 findings

Branch: worktree `agent-a73455010f2519f67`, started from `a3` @ `7b02715`. Not merged. No
manifest or lockfile changed. One commit per finding (M-16 and N-45 share one: the wording
lives in the same constant). Goldens re-blessed once: `ipc-codes.json` gains `confirm.busy`
and `confirm.cooldown`; the manifest and passive lists are unchanged.

## Done (per id: fixed, with file:line)

- **M-16** (`05248c8`) — fixed.
  - Cancel first, Return refuses: `src-tauri/src/commands/vsphere_confirm.rs:80-95`
    (`CANCEL`, `buttons` = `OkCancelCustom("Cancel", ok)`, `confirmed` maps **by label only**:
    `Custom(s) if s == ok && s != "Cancel"`; `Ok`/`Yes`/`No`/`Cancel` never confirm) and
    `src-tauri/src/commands/sync_gate.rs:69-83` (`YesNoCancelCustom("Cancel", ONCE, PIN)`,
    `trust_answer` by label only, the positional `Res::Yes/No` arms are gone); the fork
    confirmation uses the same `confirmed`. `tauri-plugin-dialog` 2.x maps every OS result
    to `Custom(<label>)` for custom buttons (Linux mapped manually in `desktop.rs:227-251`),
    so the label mapping is portable.
  - Single flight + cool-down: new `src-tauri/src/confirm_gate.rs` (`ConfirmGate` in
    `AppState::confirm`, also on `VsCtx`): `acquire` (`:101`) refuses `confirm.busy` while a
    dialog is open and `confirm.cooldown` for 10 s after a cancelled **destructive** dialog of
    the same `kind:target` (`COOLDOWN`); both audited `confirm_refused { kind, target, reason }`
    (new `AuditEvent::ConfirmRefused`, `crates/mooring-audit/src/event.rs`). Decision:
    **own codes** (`confirm.busy`, `confirm.cooldown`), not `vsphere.busy`/`sync.in_progress`,
    because the gate spans vSphere and sync and the UI should say "a dialog is open" rather than
    "a sync is running". Cool-down key is per target, not per action: a cancelled "Power off"
    also blocks "Reset" of the same VM for 10 s (the stricter reading of the review).
  - Scopes: `vsphere_vm.rs:178` (`vsphere_power`, destructive = off/reset),
    `vsphere_vm.rs:243` (`vmrc`, not destructive), `vsphere_login.rs:157` (`vsphere_trust`,
    destructive), `sync_gate.rs:184` (`sync_trust`, destructive), `sync.rs:306` (`sync_fork`,
    destructive). `Prompt::ask` (`vsphere_confirm.rs:122`) and `sync_gate::confirm`/`ask_trust`
    now take the gate and return `IpcResult<bool>`. `Prompt::new(&confirm)` and the command
    function signatures used by `tests/e2e_flow` are unchanged.
  - Tests: `confirm_gate::tests` (single flight, per-target cool-down with a simulated clock,
    expiry, dropped slot counts as cancelled, audit rows), `vsphere_confirm::tests`
    (button order of both dialogs, label-only mapping for every positional result, a parked
    dialog makes a second `ask` fail `confirm.busy` without a dialog, cool-down after cancel),
    `vsphere_sync_tests::power_needs_opt_in_and_the_native_dialog` (cancel → `stop` and
    `reset` on the same VM refused `confirm.cooldown`, two `confirm_refused` rows, another VM
    free), `sync_tests` (rejected trust prompt and cancelled fork resolution cool down).
    `ConfirmGate::clear_cooldowns` (test-util) lets reject-then-accept tests continue.
  - **QA owed:** per-OS manual check that Return/Escape refuse on all five dialogs.
- **N-45** (`05248c8`) — fixed: `sync_gate.rs:69` `ONCE = "Trust once (this sync only)"`;
  pinned by `vsphere_confirm::tests::cancel_is_the_first_button_everywhere`.
- **L-33** (`5f2c161`) — fixed: `src-tauri/src/oidc_window.rs:39` `storage()` =
  `web::ephemeral_storage(state, "oidc-<sourceId>", os)` (own `WebView2` profile
  `<cache>/web-ephemeral/oidc-<sourceId>` on Windows, `incognito` elsewhere);
  `TauriOidcWindows::open` applies it (`:379` `initialization_script_for_all_frames`, the
  `data_directory` when the plan has one) and removes the profile on `Destroyed` (`:399`);
  the start sweep (`web::sweep::ephemeral_profiles`) removes a leftover because the `oidc-`
  name is never an open web window's UUID. `Storage::ephemeral_dir()` added
  (`web/mod.rs`). Test: `web::tests::oidc_window_storage_is_an_own_profile_on_windows`.
- **L-34** (`7d23af9`) — fixed. `crates/mooring-secrets/src/cache.rs`: lock epoch
  (`epoch()` `:175`), `drain_for_lock()` (`:306`, bumps the epoch and empties the cache
  synchronously, returns `Drained` whose `retire()` revokes ours), `put(.., epoch)` (`:215`)
  refuses a token whose login started in an older epoch and hands it back as `Rejected`
  (revoked by the engine). `engine.rs:125` captures the epoch before the login, `remember`
  (`:143`) revokes and fails `locked` on rejection; `OidcFlow.epoch` is set in `begin_oidc`
  and checked in `complete_oidc` (`:333`) before the code is exchanged.
  `src-tauri/src/secrets_runtime.rs:237` `on_lock` drains synchronously and spawns only the
  revokes. `oidc_window::begin` re-checks the epoch after `begin_oidc` (`:199`, no window)
  and after `open` (`:228`, closes it, `failed: locked`). Tests:
  `mooring-secrets::tests::a_lock_during_a_login_refuses_and_revokes_the_token` (provider
  stands in for the lock: cache empty, `revoke-self` sent, next login works, stale OIDC flow
  never exchanges) and
  `secrets_runtime::tests::a_lock_during_a_login_or_an_oidc_begin_leaves_nothing_behind`
  (mock Vault with a 400 ms `response_delay`, real `vault::lock` mid-flight: `locked` result,
  cache empty, token revoked; lock during `begin` → `vault.locked`, no window opened).
- **L-37** (`caf07b9`) — fixed: `src-tauri/src/commands/sync_join.rs:45-130` (`JOIN_TMP`,
  `HeaderWriter` trait with `FsHeaderWriter`, `discard_staged`, `recover_staged_header`);
  `join_with` stages the header (0600, fsync) **before** the apply (`:238`), discards it on
  an apply failure (`:258`, the store is bound back by `JoinLocal::apply`), renames it right
  after a successful apply (`:267`); a failed rename keeps the staged file and the process
  continues with the joined vault in memory; `AppState::new` (`state.rs:236`) completes the
  rename at the next start when the store is bound to the staged header's vault, else
  removes the leftover. Test: `sync_tests::vault_join_header_write_failures_never_strand_the_device`
  (injected `FailingWriter`: stage failure → bootstrap intact, unlocks, retry joins; commit
  failure → joined vault live, restart installs the staged header and unlocks; a stale staged
  header is removed).
- **N-39** (`09a222f`) — fixed: `src-tauri/src/commands/vsphere_console.rs:58` `post_open`
  (= `hide_if_locked` + log) called after `build()` + `register` and after `reopen` + `show`.
  Test: `vsphere_sync::tests::client_window_post_open_hides_when_locked`.
- **N-40** (`6c21ae6`) — fixed: `src-tauri/src/kube_sessions.rs:138` (`set_client` tests
  `ended` under the client mutex), `:216` (`teardown` sets `ended` and takes the client under
  the same mutex). Test: `kube::tests::a_client_set_after_the_teardown_is_dropped`.
- **N-41** (`1fc3b62`) — fixed: `crates/mooring-secrets/src/client.rs:192-195`
  (`token_from_body` refuses `root` in `identity_policies` too; `AuthBlock.identity_policies`
  added in `wire.rs`). Vector: `client::tests::login_responses_with_root_anywhere_are_refused`.
- **N-42** (`ae8a1e4`) — fixed: `src-tauri/src/commands/secret_sources.rs:177`
  (`changed_event`: only the fields set / changed, `ca_pem` fingerprints via
  `conn_options::ca_fingerprints` when `caPem` is among them, `warning` for `caPem`,
  `allowHttp` or an **added** `allowedOrigins` entry, `:231`). `AuditEvent::SecretSourceChanged`
  gains `ca_pem` (omitted when empty). Test: `secret_sources::tests::token_source_crud_and_test_never_return_the_token`.
- **N-43** (`9d34479`) — fixed: new `src-tauri/src/web/refusals.rs` (`RefusalBudget`:
  `AUDITED` = 16, `OIDC_FLOOD` = 64). Web windows: `web::refusal_audited` (`web/mod.rs:213`)
  from `Ctx::blocked`, `WebEntry.refusals`, one `web_navigation_blocked_suppressed { count }`
  row in `closed_entry` (`commands/web.rs:82`). OIDC windows: `Session.refusals`,
  `Session::end`/`fail` (`oidc_window.rs:78-95`) write `secret_refused_suppressed { count }`
  once when the window closes; at 64 refusals the window is closed (`:301-306`,
  `failed: navigation_flood`, audited). Tests: `web::refusals::tests`,
  `web::tests::refused_navigations_are_capped_per_window_and_summarised_on_close`,
  `secrets_runtime::tests::an_oidc_navigation_flood_closes_the_window_after_sixteen_audited_refusals`.
- **N-44** (`67fa9c6`) — fixed: `crates/mooring-sync/src/backend/s3.rs:30` `SIGN_TTL` = 60 s;
  `signed_path!` (`:144`) returns `Zeroizing<String>` (signature + STS token). The session
  token and secret were already `SecretString` on our side and `Zeroizing` inside rusty-s3's
  `Credentials`; the signer's transient `Url` is the remaining unzeroized copy (R-EXT-STR).
  Tests: `s3::tests::presigned_paths_expire_after_a_minute`; the loopback mock
  (`tests/s3_mock.rs`) now refuses any presign with `X-Amz-Expires > 60`, so every S3 test
  proves the TTL end to end.
- **N-46** (`17ccdec`) — fixed: `src-tauri/src/golden.rs:127`
  `cargo_lock_pins_the_reviewed_webview_crates` reads the workspace `Cargo.lock` and fails
  unless `wry == 0.57.1` and `tauri-runtime-wry == 2.12.3` (comment points at review 6 / L-32).
- **L-35** (`5e3172c`) — fixed (task scope): new `src-tauri/src/commands/sync_trust.rs:37`
  `conflicts()` (for every connection `host:port` of a protocol with a trust file, more than
  one distinct fingerprint → `TrustConflict`), `KnownCerts::distinct_pins`
  (`mooring-core/src/known_certs/mod.rs:271`), run after every `AppLocal::apply`
  (`sync_local.rs:60`, `:109`) and audited `trust_conflict { file, host }` (new
  `AuditEvent::TrustConflict`, names only). Not auto-resolved. SSH `known_hosts` exempt.
  Test: `sync_tests::conflicting_pins_after_a_sync_are_audited_not_resolved` (two devices pin
  different fingerprints for `rdp.example.test:3389`; both lines kept; one row per device
  after its merge/pull; the row carries no fingerprint or hashed line).
- **L-36** — nothing to do (accepted risk R-VMRC-ARGV; the VMRC option help text is UI-owned).

## Left open
- M-16 per-OS manual Return/Escape check (QA).
- L-35: the review's `sync_status.conflicts` surfacing and a `sync_trust_conflict` name were
  not done; the task asked for the audit row `trust_conflict { file, host }` only. If the UI
  should list conflicts, the `sync_status` DTO needs a field (orchestrator / ui-engineer).
- `JoinLocal` (vault_join) does not run the L-35 check: a join applies into an empty store,
  so the first sync after it covers the same files.
- N-43 web windows: the UI event `WebEvent::Blocked` is also suppressed beyond 16 per window
  (same budget as the audit), so a flooding page cannot flood the main window's channel either.

## Decision needed
- M-16 cool-down granularity (per target vs per target+action) — implemented per target; say
  if the review prefers per action.

## Test evidence
```
Linux x86_64, 2026-11-05, worktree agent-a73455010f2519f67 @ 5e3172c
cargo fmt --all -- --check                                                  ok
cargo clippy -p mooring-app -p mooring-secrets -p mooring-sync -p mooring-core -p mooring-audit --all-targets -- -D warnings   ok
cargo check --workspace --all-targets                                       ok
cargo test -p mooring-app -p mooring-secrets -p mooring-sync -p mooring-core -p mooring-audit
  mooring-app lib 267 passed (1 ignored) · e2e_flow 19 passed · mooring-audit 34 ·
  mooring-core 152 + 14 + 8 · mooring-secrets 31 + 4 + 6 · mooring-sync 33 + 4 + 7 + 5
MOORING_BLESS=1 cargo test -p mooring-app golden   ipc-codes.json: + confirm.busy, confirm.cooldown
```
New tests: 19 (confirm_gate 3, vsphere_confirm 3, vsphere/sync cool-down updates 3,
oidc storage 1, L-34 2, L-37 1, N-39 1, N-40 1, N-41 1, N-42 extended 1, N-43 3, N-44 1,
N-46 1, L-35 1, audit wire names 3).
