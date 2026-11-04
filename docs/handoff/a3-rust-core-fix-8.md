# A3 — rust-core fix 8: security re-review 6b

Branch: worktree `agent-a5feb2e2e431f1cd9`, started from `a3` @ `a17bb6d`. Not merged. No
manifest or lockfile changed. One commit per finding (plus one clippy and one file-size
commit). Goldens re-blessed once: `ipc-codes.json` gains `http.trust_conflict`; the manifest
and passive lists are unchanged.

## Done (per id: fixed, with file:line)

- **B-6** (`4e99197`) — fixed, **option 2** (no new dependency).
  - Every confirmation is `YesNoCancelCustom("Cancel", <ok>, "Not now")`
    (`src-tauri/src/commands/vsphere_confirm.rs:80-95` `CANCEL`, `NOT_NOW`, `refuses`,
    `buttons`): the first slot (OS default, Return) and the plugin's cancel slot (Escape,
    close box, Alt+F4, Cmd+W: rfd's positional `Cancel`, rewritten by
    `tauri-plugin-dialog` 2.8.4 `desktop.rs:228-253` into the cancel-slot label on every
    desktop OS) both carry a refusing label; only the middle button confirms. `confirmed`
    maps by label and refuses both refusing labels (`:97`); `slots()` (`:103`) is the pure
    invariant check. The two refusing labels differ in text ("Cancel" / "Not now") so no
    label names two buttons. `sync_gate::DialogPrompter::confirm` (fork) uses the same
    `buttons`.
  - **Sync trust prompt split in two** (`src-tauri/src/commands/sync_gate.rs:66-115`,
    `:130-150`): dialog 1 "Untrusted sync storage certificate" = Cancel / *Trust once (this
    sync only)* / Not now (`trust_buttons`, `trust_once`); dialog 2 "Remember sync storage
    certificate?" opens **only** after a click on "Trust once" = Cancel / *Trust and remember*
    / Not now (`remember_buttons`, `remember_answer`): "Not now" (Escape / close) = trust once,
    "Trust and remember" = pin, **"Cancel" (Return) = refuse everything** (the task did not say
    what Return on dialog 2 does; refusing is the fail-closed reading — say if it should be
    trust-once instead). The `SyncPrompter` trait is unchanged (one `reply(TrustAnswer)`).
  - Tests (`vsphere_confirm::tests`): `the_first_and_the_cancel_slot_refuse_in_every_dialog`
    (the catalogue of all six builders: power, VMRC, vSphere trust, sync trust 1 + 2, fork;
    first and cancel slot refuse, differ, the ok label does not refuse);
    `the_plugin_remap_of_escape_and_return_refuses` (the plugin's table replayed through
    `plugin_remap` for `Cancel` / `Yes` / `No` → `confirmed`, `trust_once`,
    `remember_answer`); `results_are_mapped_by_label_never_by_position` extended;
    `the_doubles_take_os_results_through_the_plugin_remap`: **`FixedConfirm::with_result(r)`**
    and **`ScriptedPrompter::with_results(r1, r2)`** feed positional OS results through
    `plugin_remap` + the label mapping (Escape on dialog 1 → no dialog 2 → `Reject`; click once
    then Escape → `Once`; click once then Return → `Reject`). `FixedConfirm::new(bool)` and
    `ScriptedPrompter::new(..)` are unchanged, so no other test moved.
  - QA (`docs/qa/native-dialogs.md`): "Close box / Alt+F4 / Cmd+W refuses" column, row 4
    split into 4a / 4b with the dialog-2 semantics, power row lists all five actions.
    **Owed per OS:** Return, Escape, close box refuse and a click confirms on all dialogs.
  - **Upstream report text** (tauri-apps/plugins-workspace, *not filed*):
    > `tauri-plugin-dialog` `desktop.rs` `show_message_dialog` remaps rfd's positional
    > `MessageDialogResult::Cancel` into `Custom(<cancel-slot label>)` for `OkCancelCustom`
    > and `YesNoCancelCustom`, with no `cfg`, although the comment says "on Linux". rfd
    > returns that positional `Cancel` not only for a click on the cancel button but for a
    > dismissed dialog: GTK `GTK_RESPONSE_DELETE_EVENT` (Escape, close box; async path
    > `backend/gtk3/message_dialog.rs`), Windows TaskDialog `IDCANCEL` under
    > `TDF_ALLOW_DIALOG_CANCELLATION` (Escape, Alt+F4, close box), macOS any modal end that
    > is not a button. A caller that puts a confirming label in the cancel slot therefore gets
    > a confirmation for Escape / the close box. Suggest: keep rfd's `Cancel` as `Cancel`
    > (do not remap by position), or document that the cancel slot must hold the refusing
    > label on every OS.
- **M-16 cool-down** (`674f1f3`) — fixed: `src-tauri/src/commands/vsphere_vm.rs:180`
  `destructive: a != PowerAction::On` (guest shutdown / reboot cool down too;
  `is_destructive` keeps the data-loss wording). Test:
  `vsphere_sync_tests::power_needs_opt_in_and_the_native_dialog` (cancelled `start` → no
  cool-down, the `shutdown` dialog opens; cancelled `shutdown` → `reboot` refused
  `confirm.cooldown`).
- **L-34** (`9288532`) — fixed. (a) `src-tauri/src/commands/vault.rs:148-152`
  `state.secrets.on_lock()` runs **after** `lock_with_reason` and the guard drop; (b)
  `src-tauri/src/secrets_runtime.rs:239-241` drains before `fail_all`; (c)
  `crates/mooring-secrets/src/engine.rs:293` reads the epoch at entry of `begin_oidc`. Test
  (a): `secrets_runtime::tests::a_login_that_starts_after_the_lock_epoch_finds_the_key_gone`
  holds the vault mutex while `vault::lock` runs on another thread: with the fixed order the
  epoch cannot move before the wipe (the lock waits for the mutex), so a login started after
  the bump fails `locked` and nothing is cached; with the old order the epoch moved under the
  key and the token was cached after the lock (verified: the test fails on `a17bb6d`'s
  `vault.rs`).
- **L-35** (`ceee760`) — fixed, **fail closed**.
  - `crates/mooring-core/src/known_certs/mod.rs:258-273` `check` returns new
    `CertTrust::Conflict` when `distinct_pins(host, port) > 1`, whatever is presented (a
    duplicated line of one pin is not a conflict); `decide` maps it to new
    `CertVerdict::Conflict`. `crates/mooring-proto-ssh/src/known_hosts.rs:205-224`
    `conflicting_key_types` (non-revoked keys grouped by algorithm; several key *types* per
    host stay normal) and `check` → new `TrustDecision::Conflict { key_types }`.
  - Consumers: `mooring-http` `TrustVerdict::Conflict` → `HttpError::TrustConflict` =
    **`http.trust_conflict`** (`error.rs`, `connect.rs:177`, `client.rs`); RDP
    (`proto-rdp/src/connect.rs:197`, `:287`), VNC (`proto-vnc/src/tls.rs`, `connect.rs:275`,
    `error.rs` `VncError::TrustConflict`), SSH (`proto-ssh/src/handler.rs:82-94`) and kube
    (`proto-kube/src/error.rs`, `exec.rs`) close with new **`CloseCode::TrustConflict`**
    (`trust_conflict`, not retryable). Mapped in `secrets/error.rs` (→ `Trust`),
    `vsphere_login.rs:197`, `kube_wire.rs:141`, `graphical_task.rs:131`, `sync.rs`
    (`SYNC_CODES` + a static message). Nothing is prompted or resolved: the user removes the
    host's pins in the known-certificates manager (`known_certs_remove` removes every pin of
    the host:port, so the next connect is a fresh TOFU prompt, never a silent trust).
  - **`sync_status.conflicts` DTO addition** (`src-tauri/src/commands/sync_trust.rs:41-77`
    `StatusConflict`, `#[serde(untagged)]`): the merge conflicts of the last run (unchanged
    shape) followed by the standing trust conflicts as
    `{ "kind": "trust", "id": "<file>", "name": "<host:port>" }` (`id` = `known_rdp_certs`,
    `known_vnc_certs`, `known_sync_certs`, `known_hosts`, …), computed live in `sync_status`
    (`sync.rs:143-148`) over the user's connections, SSH included, and cleared the moment the
    pins are removed. The audit row `trust_conflict { file, host }` after every apply stays.
  - Tests: `known_certs::tests::conflicting_pins_fail_closed_until_removed`,
    `decision_table_has_four_rows` (+ conflict), `session_tests` (wire name, not retryable);
    `known_hosts_tests::conflicting_keys_of_one_type_fail_closed` (dup / two types / revoked /
    two ed25519); `mooring-http tests/trust.rs::conflicting_pins_fail_closed_until_one_is_removed`
    (two pins → `http.trust_conflict` even with `trusted_once`, no request → remove → pin →
    connects); `proto-ssh tests/trust.rs::conflicting_host_keys_fail_closed_until_one_is_removed`
    (two ed25519 keys, one the server's → `trust_conflict`, no fingerprint in the reason →
    keep one → connects); `sync_tests_6b::conflicting_pins_after_a_sync_are_audited_listed_and_fail_closed`
    (two devices → both lines kept, audited, listed in the DTO with the exact JSON, `check` =
    `Conflict` for every presented pin, known_hosts per key type listed, `known_certs::remove`
    clears it); `sync_tests_6b::a_conflicting_sync_endpoint_pin_refuses_the_run_until_removed`
    (stray pin on the S3 host → `http.trust_conflict`, never prompted, `last_error` carries the
    code → remove → asked again and pinned).
- **L-37** (`e54fe7e`) — fixed: `src-tauri/src/commands/sync_join.rs:112-143`
  `recover_staged_header` (a) keeps the staged file and returns the staged vault when the
  rename fails (it is the only copy; the device binds to the vault its store belongs to), (b)
  installs only while the current header's vault id differs from the staged one; otherwise
  removes the stale staged copy. `state.rs:316-322` `save_header_bytes` removes a staged
  header of the vault it just wrote (`staged_vault_id`). Test:
  `sync_tests_6b::a_staged_header_is_neither_lost_nor_installed_over_a_newer_one` (a: header
  path blocked by a directory → staged kept, staged vault returned; b: commit failure →
  `vault_change_password` → staged gone → restart → old password refused, new one unlocks;
  a stale copy planted later is removed, not installed).
- **N-43** (`a7e2c4b`) — fixed: `oidc_window.rs:311-317` refusals outside `Pending` go
  through `s.refusals.refused()`; `web/mod.rs:215` `unwrap_or(false)`. Tests:
  `an_oidc_navigation_flood_closes_the_window_after_sixteen_audited_refusals` (+20 refusals
  after the flood: still 16 rows, one summary); `refused_navigations_are_capped_per_window_and_summarised_on_close`
  (no entry → not audited; closed entry → not audited).
- **N-47** (`545f229`) — fixed: `src-tauri/src/confirm_gate.rs:26-29`, `:49-80`
  (`AUDITED` = 16, `AUDIT_WINDOW` = 1 h of process uptime; the first 16 refusals of a window
  get a row each, the rest are counted; one `confirm_refused_suppressed { count }` (new
  `AuditEvent::ConfirmRefusedSuppressed`, `mooring-audit/src/event.rs`) is written when the
  next window's first refusal arrives). The last window's count is not written at exit.
  Tests: `confirm_gate::tests::refusal_rows_are_bounded_per_hour_of_uptime`,
  `chain_tests::confirm_refused_has_a_stable_wire_name` (+ suppressed).
- **N-48** (`5dc2367`) — fixed: `src-tauri/src/commands/web.rs:241` the reopen path calls
  `post_open` (= `hide_if_locked`, `:278`), the build path the same. Test:
  `web::tests::web_open_post_check_hides_when_locked`.
- **N-49** (`8f22b02`) — fixed: `src-tauri/src/golden.rs:119-124` pins
  `tauri-plugin-dialog == 2.8.4` and `rfd == 0.17.2` (comment points at 6b B-6).
- **L-38 nit** (`c884b06`) — fixed: `web_open` left `NOT_GATED`; pinned in
  `tests/e2e_flow/support.rs:163` through `web::plan(st, conn, StorageOs::current(), None)`
  (`vault.locked` after the lock).

## Left open
- B-6 per-OS manual run of `docs/qa/native-dialogs.md` (QA): Return / Escape / close box /
  Alt+F4 / Cmd+W refuse, click confirms, on all dialogs incl. 4a and 4b.
- Upstream report for the plugin remap: text above, not filed (owner decides).
- L-35: the sync endpoint itself is not a connection row, so a conflict on
  `known_sync_certs` is not listed in `sync_status.conflicts`; it surfaces as
  `sync_status.lastError.code == "http.trust_conflict"` (tested). SSH known_hosts conflicts
  are listed but the UI has no known-hosts manager (the close reason says "remove the extra
  known_hosts entries").
- N-47: the suppressed count of the last hour is lost at process exit (no exit hook on the
  gate).

## Decision needed
- B-6 dialog 2: "Cancel" (Return) refuses everything (implemented). If the owner prefers
  Return = trust once (the review's original option-2 sketch had trust-once in both refusing
  slots), change `remember_answer` only.

## UI DTO changes (ui-engineer)
- `sync_status.conflicts` is now heterogeneous: existing merge entries
  `{ kind: "folder"|"connection"|"credential", id, name, resolution }` plus trust entries
  `{ kind: "trust", id: "<trust file>", name: "<host:port>" }` (no `resolution`). A banner
  should say "conflicting certificate pins for <name>; remove them under Settings → Known
  certificates (<id>)" and link to the known-certificates manager.
- New IPC error code `http.trust_conflict` (static message, no host or fingerprint) from
  sync, vSphere, kube and secret-source commands.
- New `CloseCode` `"trust_conflict"` on `session_closed` (SSH / RDP / VNC / kube), not
  retryable; same UI treatment as `trust_mismatch` with a "remove the pins" hint.
- Native dialogs: every confirmation has three buttons ("Cancel" / confirm / "Not now");
  the sync trust prompt is two dialogs. `KnownCertsCard` copy still says "Trust and remember",
  which is now the second dialog's button.

## Test evidence
```
Linux x86_64, 2026-11-05, worktree agent-a5feb2e2e431f1cd9 @ 8e54b12
cargo fmt --all -- --check                                                   ok
cargo clippy -p mooring-app -p mooring-secrets -p mooring-sync -p mooring-core -p mooring-http
  -p mooring-proto-ssh -p mooring-proto-rdp -p mooring-proto-vnc -p mooring-proto-kube
  -p mooring-audit -p mooring-vsphere --all-targets -- -D warnings             ok
cargo check --workspace --all-targets                                        ok
cargo test (same crates incl. --test e2e_flow)
  mooring-app lib 274 passed (1 ignored) · e2e_flow 21 · mooring-audit 34 · mooring-core 153+14+8
  mooring-http 10+5+11+1+8+4 · mooring-proto-kube 32+8+6 · mooring-proto-rdp 62+6+7
  mooring-proto-ssh 63+9+8+10+3+9+9+6 · mooring-proto-vnc 74+7 · mooring-secrets 31+4+6
  mooring-sync 33+4+7+5 · mooring-vsphere 25+5+7
MOORING_BLESS=1 cargo test -p mooring-app golden   ipc-codes.json: + http.trust_conflict
```
New / extended tests: 20 (B-6 4, M-16 1, L-34 1, L-35 8, L-37 1, N-43 2, N-47 2, N-48 1).
