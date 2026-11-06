# A4 — rust-core F2: security review 7 fix round

Branch: worktree `agent-a6961f3993944a7ca`, from `a4` @ `96ab1e1` (F1 merged). Fourteen
commits, one per finding plus two `chore` (clippy / goldens, `state.rs` line budget). Not
merged. No new dependency, no lockfile change (`cargo metadata --locked` clean).
`src-tauri/tauri.conf.json` touched for L-39 only (`requireSignedVersion: true`). QA-owned
files touched where a finding changed pinned behaviour: `src-tauri/tests/e2e_flow/a4_update.rs`
(N-51 timings, N-55 `cask_present`), `a4_ldap.rs` (L-43 dialog counts 1 → 2).

## Done (per id: fixed at)

| ID | Status | Where |
| --- | --- | --- |
| L-39 | fixed | `src-tauri/tauri.conf.json` (`plugins.updater.requireSignedVersion: true`); `updater/source.rs:150-161` (`check_inner` rebuilds the update with `Updater::restore_update`, which forces `require_signed_version` on whatever the config says), `:178` (`MissingSignedVersion` → `update.signature`); `commands/update.rs:83` (`UpdateSettings.last_verified`), `:152-181` (`check_floor`, `raise_floor`), `:220` / `:267` (check and install refuse `offered < lastVerified` with `update.downgrade`, audited `update.refused`), `:295` (the floor is raised from `before_install`, i.e. after the package verified, before anything is written; monotonic) |
| L-40 | fixed (manifest cap post-parse, see Left open) | new `updater/download.rs`: `RELEASE_DOWNLOAD_PREFIX`, `check_download_url` (`https://github.com/yyasar21/Mooring/releases/download/v<offered>/<asset>`, asset `[A-Za-z0-9._-]+`, nothing else → `update.manifest`), `manifest_within_cap` (64 KiB), `capped` (256 MiB declared or counted per chunk; the plugin's download future is dropped at the first await after the cap is crossed, which closes the connection; one 10 min deadline for the whole transfer; both `update.network`); `updater/source.rs:199-226` (URL check before the download, `update.timeout = DOWNLOAD_DEADLINE`, then `Update::install(bytes)` on the verified bytes). `download::tests::configured_endpoint_shares_the_release_tree` pins the endpoint and the config flag |
| L-41 | fixed | `commands/import.rs:84-105` (`importKeyFiles` honoured only for `{ known: "openssh" }`; a picked file ignores it and the plan carries `key_files_only_for_known_location` / `source_ref: importKeyFiles`); `crates/mooring-import/src/plan.rs` (`WarningCode::KeyFilesOnlyForKnownLocation`) |
| L-43 | fixed | `crates/mooring-import/src/ldap/client.rs` (`handshake` split out of `connect`; new `probe_tls`: TCP + TLS handshake + close, no LDAP frame); `commands/ldap_import.rs:89-125` (`ConfirmedBinds`, in `AppState::ldap_binds`, cleared in `vault::lock`), `:255-279` (`confirm_bind`: Gate kind `ldap_bind`, target `host:port`, destructive; title "Mooring · Directory sign-in", ok label "Sign in to <host:port>", text names the credential's display name and the host only), `:281-297` (`settle_trust`: probe → TOFU prompt → probe again), `:299-316` (`with_trust`: trust → confirm → op). Both `ldap_import_test` and `ldap_import_preview` are gated. Declined → `ldap.bind_declined` + `confirm_refused { kind: ldap_bind, target, reason: declined }` (and the Gate's cool-down); no prompt object → `ldap.confirm_required` |
| N-51 | fixed | `updater/mod.rs:140-152` (`begin_install` refuses `< MIN_CHECK_GAP` after the previous install attempt with `update.rate_limited`, before any network; input / matrix / session refusals happen earlier and do not start the gap; not audited, like the check gap) |
| N-52 | fixed | new `src-tauri/src/audit_budget.rs` (`AuditBudget`, `NET_AUDITED = 32`, `WINDOW = 1 h`); `commands/net.rs:64-80` (`NetRuntime::audit` / `audit_at`; every `net_*` row goes through it); `crates/mooring-audit/src/event/a4.rs` (new `NetSuppressed { count }` → `net_suppressed`) |
| N-53 | fixed | `src-tauri/src/import_plans.rs` (`with(now, …)` sweeps expired plans on every access — `insert`, `take`, `len`, `clear`; `sweep(now)`; `install(app)` starts a `SWEEP_TICK` = 60 s task, wired in `lib.rs` setup after `autolock::install`) |
| N-54 | fixed | `commands/ldap_import.rs:172-179` (`bind_credential`: empty stored password → `ldap.bind` before any network; non-UTF-8 stays `credential.secret_missing`). Note: the store already refuses to seal an empty secret on every write path (`validate_secret`), so this is the last line, tested on its own |
| N-55 | fixed | `updater/install_mode.rs:107-132` (`CASKROOMS` = `/opt/homebrew/Caskroom/`, `/usr/local/Caskroom/`; `under_roots`, `cask_present_in`), `InstallFacts.cask_present` (probe: `Caskroom/mooring` exists under either root), `decide`: `MacApp` with `cask_present` **or** a canonical path under a Caskroom → `manualReason: homebrew`. `/usr/local/Homebrew/` is no longer a prefix (it never holds a cask) |
| N-56 | fixed | `updater/notes.rs:13-35` (`is_dropped` now covers U+00AD, U+061C, U+180B–180F, U+200B–200F, U+202A–202E, U+2060–2064, U+2066–206F, U+FE00–FE0F, U+FEFF, U+FFF9–FFFB, U+E0000–E007F, U+E0100–E01EF plus C0/C1; U+2028 / U+2029 map to `\n` and then collapse like blank lines) |
| N-60 | fixed | `commands/mod.rs:72-84` (`off_thread`: `spawn_blocking` + join-error mapping; `credentials::offload` uses it); `commands/import.rs:390-412` (`import_preview` / `import_apply` are `async` and run read + parse + duplicate scan / the apply transaction on the blocking pool via the `AppHandle`) |
| N-50 (6c) | fixed | `crates/mooring-secrets/src/error.rs:138-146` (`SecretsError::prompt_decision()` answers the decision only for `TrustVerdict::Prompt`; `trust_decision()` stays for audit rows). When `secret_source_trust` lands it must use `prompt_decision()` |

## UI contract changes (ui-engineer)

- New IPC codes: `update.downgrade` ("older than a release this install already verified";
  from `update_check` and `update_install`, audited `update.refused`), `ldap.bind_declined`
  (the user cancelled the sign-in dialog), `ldap.confirm_required` (no prompter; never from
  the real commands, which always carry one). `ipc-codes.json` re-blessed.
- `update_settings_get` / `update_settings_set` result: new field `lastVerified: string | null`
  (RFC: the semver string of the highest verified package). Always present.
- Import plan warnings: new `code: "key_files_only_for_known_location"` with
  `sourceRef: "importKeyFiles"` (`apps/desktop/src/lib/ipc.types.import.ts` union and
  `importText.ts` need the entry). The wizard should show the key-file toggle only on the
  known-location tile (review 7 L-41 UI note).
- A second native dialog in the LDAP flow: after the certificate dialog (first contact) and
  before the bind, "Mooring · Directory sign-in" — Cancel / "Sign in to <host:port>" / Not
  now — once per (credential, host:port) per unlocked session; `ldap_import_test` and
  `ldap_import_preview` both raise it. `confirm.busy` / `confirm.cooldown` apply as elsewhere.
  `docs/qa/native-dialogs.md` should gain the row (qa).
- New audit rows: `net_suppressed { count }`, `confirm_refused { kind: "ldap_bind", reason:
  "declined" }`.

## Left open / decision needed

- **L-40 manifest cap is post-parse, not in flight.** The plugin fetches `latest.json` with its
  own reqwest client (`res.json()`, no cap); `reqwest` is not a direct dependency of
  `mooring-app` and `mooring-http` would drop the plugin's `system-proxy` support (corporate
  proxies) and needs a `CertProtocol` of its own. The client therefore bounds the manifest by
  the 30 s request deadline in flight and refuses a parsed body over 64 KiB. Options: (a) add
  `reqwest` as a direct dependency (orchestrator + security review) and fetch the manifest
  with `Content-Length` / running-count caps, then `restore_update(raw_json)`; (b) accept the
  residual under R-UPD (a hostile manifest costs at most 30 s × link speed of memory, behind
  the GitHub release location). Recommend (a) for 0.1.1.
- L-40 download cap granularity: the abort happens at the first await after the chunk that
  crossed the cap, so the buffer can exceed 256 MiB by one chunk (reqwest chunks are ≤ 16 KiB
  on HTTP/1.1 bodies). A declared `Content-Length` over the cap aborts at the first chunk.
- L-43 ordering is trust → confirm → bind: the handshake-only probe means a CA-valid attacker
  host still sees a TLS handshake (and the client IP) before the dialog. The password never
  leaves without the confirmation. Confirming before any network would change every Q1
  refusal test (the first dialog would be the sign-in, not the certificate); flagged here for
  the reviewer, easy to flip if wanted.
- The sign-in confirmation is remembered in memory until lock, not in the store (the review's
  option "remember the pair in the store (audited)" was not taken: the owner brief said
  "remember confirmed pairs in memory until lock").
- `ldap_import_test` refusals are still not `import_refused` (F1, Q1 agreed).

## Test evidence (Linux x86_64, rustc 1.97.0, 2026-11-06)

```
cargo fmt --all -- --check                                                       clean
cargo clippy -p mooring-app -p mooring-import -p mooring-secrets -p mooring-audit --all-targets -- -D warnings
                                                                                 clean (pre-existing unknown_lints note only)
cargo test -p mooring-app --lib --features test-util                            349 passed, 1 ignored (pre-existing)  (was 331)
cargo test -p mooring-app --test e2e_flow                                       39 passed
cargo test -p mooring-import (+ --features directory)                           66 + 2 + 9 passed
cargo test -p mooring-net                                                       44 + 4 + 8 + 5 passed
cargo test -p mooring-secrets                                                   32 + 4 + 6 passed
cargo test -p mooring-audit                                                     36 passed
MOORING_BLESS=1 cargo test -p mooring-app golden                                ipc-codes.json re-blessed (+3 codes); manifest / passive unchanged
cargo metadata --locked                                                         ok
```

New tests: `updater::notes::tests::strips_invisible_format_characters_and_tag_block`,
`updater::tests::homebrew_cask_is_detected_by_caskroom_presence_and_resolved_path`,
`import_plans::tests::expired_plans_are_swept_on_every_access`,
`ldap_import::tests::empty_bind_password_is_refused_before_any_network`,
`mooring_secrets::error::tests::only_the_prompt_verdict_offers_a_dialog`,
`audit_budget::tests::first_n_get_rows_then_one_summary_per_window`,
`net::tests::net_audit_rows_are_bounded_per_hour_of_uptime`,
`import::tests::picked_ssh_config_ignores_the_key_file_opt_in_with_a_warning`,
`import::tests::preview_and_apply_run_off_the_ipc_thread`,
`update_tests::install_is_rate_limited_between_attempts`,
`update_tests::verified_floor_refuses_a_later_downgrade_offer`,
`ldap_import::tests::first_bind_of_a_pair_asks_and_a_refusal_never_binds`,
`ldap_import::tests::confirmed_pair_is_remembered_until_lock_and_scoped_to_credential_and_host`,
`mooring_import::ldap::mock_tests::probe_tls_settles_trust_without_an_ldap_frame`,
`updater::download::tests::*` (URL table, manifest cap, capped reader ×3, config pins).
