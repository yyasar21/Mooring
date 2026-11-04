# A3 — qa-engineer (Q3: L-38 gate matrix, E2E for vSphere / secrets / sync, M-16 QA part)

Scope: security review 6 (`docs/security/a3-review-6.md`) rows L-38 and the QA part of M-16;
the U2/U3 handoff "Left open: no E2E" items. Worktree branch
`worktree-agent-abcac690978da962d` from `a3` @ `7b02715`. Not merged. No product code touched
(`src-tauri/src/**`, `crates/**`, `apps/desktop/src/**` untouched; rust-core edits them in
parallel for fix round 7).

## PASS / FAIL per item

### 1. L-38 — locked-vault matrix against `ipc-manifest.json` — PASS

`src-tauri/tests/e2e_flow/support.rs`, new `src-tauri/tests/e2e_flow/gate_matrix.rs`, wired in
`e2e_flow.rs` (step 7 of the main flow) and `e2e_flow/kube.rs`.

- **Indirectly gated commands added** (`vault.locked`): `kube_open` (`connect_plan::kube` →
  `state.ready()`), `kube_contexts` (`with_ready`), `vsphere_console` — called through its gate
  `vsphere_vm::vm_target(&VsCtx::of(state), id)` because the Tauri wrapper needs an `AppHandle`.
- **Session-bound kube commands** (`support::kube_session_bound_codes`): `kube_access`,
  `kube_namespaces`, `kube_pods`, `kube_pod`, `kube_exec_open`, `kube_logs_open`, `kube_logs_close`
  (seven: the review's six plus `kube_logs_close`, which is bound the same way). The kube flow
  (`kube_cluster_exec_forward_lock_unlock`) now calls each with the **ended cluster's id after the
  lock** and expects `session.not_found`; the main flow calls them with a never-issued id.
- **More direct rows pinned while at it**: `connection_options_get/set`, `known_certs_list/remove`,
  `syslog_get`, `syslog_test`, `session_screenshot`, `session_set_view_only` (L-26 order: vault
  before session lookup), `window_detach` (`plan_detach`), `web_clear_data` (`check_clear`).
- **Golden check** `gate_matrix::matrix_covers_manifest(gated, session_bound)`: reads
  `src-tauri/ipc-manifest.json` (the checked-in golden of `guard::COMMANDS`), and fails unless
  every command is in exactly one of: the `vault_gated_codes` rows, the session-bound kube rows,
  or `NOT_GATED` — a `&[(&str, &str)]` with a one-line reason per command (`app_info`,
  `vault_*` lifecycle, `session_list`, the ADR-0006 session-bound SSH/SFTP/forward commands,
  `web_*` window-bound / `AppHandle`-only wrappers, `autolock_set` / `syslog_set` / `sftp_pick_local`
  (gated, pinned by unit tests, need fixtures the flow does not carry), `secret_source_revoke`,
  `secret_source_oidc_status`). A listed name that is not in the manifest, a duplicate, or an
  empty reason fails too. The hard-coded `assert_eq!(locked.len(), 44)` is gone: the count comes
  from the manifest, so rust-core's round-7 additions fail the test loudly instead of silently
  passing.
- Negative check done by hand: removing `app_info` from `NOT_GATED` →
  `commands in ipc-manifest.json that are neither in the locked-vault matrix nor in NOT_GATED
  (add a row or an allow-list reason, review 6 L-38): ["app_info"]`.
- Numbers at this HEAD: manifest 103 = 57 `vault.locked` rows + 7 session-bound kube rows +
  39 `NOT_GATED` rows.

Command: `cargo test -p mooring-app --test e2e_flow` → **21 passed, 0 failed** (Linux, 18 s; the two
new tests are `gate_matrix::locked_matrix_covers_the_manifest`,
`gate_matrix::not_gated_list_names_only_manifest_commands`). `cargo fmt --check` clean,
`cargo clippy -p mooring-app --test e2e_flow -- -D warnings` clean.

### 2. E2E (Playwright + `node:test`, mock transport) — PASS, 11 new flows

`apps/desktop/e2e/vsphere.e2e.mjs` (4) and `apps/desktop/e2e/secrets-sync.e2e.mjs` (7), both in
`make e2e` and `.github/workflows/e2e.yml` (steps "vSphere flows", "Secret source and vault sync
flows"). Accessible-name selectors only; the Rust-native dialogs and the external systems are the
mock's knobs set through the `window.__mooringE2E.transport` probe (`vsphereDown`, `vsphereHidden`,
`confirmPower`, `oidcOutcome`, `confirmResolve`, `remoteEdits`, `simulateAlarm`,
`simulateTrustPrompt`); every flow ends with the page-error check and, where it matters, a
"no secret in the DOM / audit" assertion.

| Flow | Covers |
| --- | --- |
| import wizard | vCenter down → alert + Next disabled → Test again → signed-in status; parent folder defaults to the vCenter's folder; Start import → report `5 added …`; Show the folder selects the synced root; `vsphere_sync_started/finished` audited; no UI session |
| synced tree | `SyncBadge` on root (name) and child (glyph only), `aria-readonly`, `draggable=false`; F2 → read-only reason, toolbar New connection disabled; hide `vm-build-vm` → Refresh now → `1 missing`, row `data-sync="missing"`, the VM panel explains it and has no Power |
| VM power | Power disabled with the opt-in title, VMRC disabled, guest identity; opt-in through the vCenter's **Edit connection** dialog (switches); menu items with reasons / destructive flags; Power off → `requested` status with **no UI confirm**; `confirmPower=false` → "Cancelled in the dialog"; Escape returns focus; audit `stop:requested, stop:done, start:cancelled`; no `vmrc://` anywhere |
| consoles | Open in vSphere Client → `web-c-vc` label + `vsphere_console` audit; VMRC off until opt-in, then "Ticket handed…", no ticket in the audit; Enter on the row = third console row, still no session |
| secret sources: token | Credentials → New API token credential → Settings → Add source… (validation alert, Token method, credential select) → Test → "Signed in with Token: token TTL 1 h, not renewable, 2 policies." → Forget; `secret_login { method: token }` audited; token value never in the DOM or audit |
| secret sources: OIDC | create OIDC source (role required, redirect URI shown) → Sign in… → "Sign-in window open." → the 1 s `oidc_status` poll → "Signed in with OIDC …"; `oidcOutcome=closed` → the closed-window explanation |
| secret sources: delete | Delete ops vault → in-use warning → Confirm → `source.in_use` friendly alert, row stays; delete `db via vault` in Credentials → Confirm delete → "Deleted ops vault." / "No secret sources" |
| external_ref | edit `db via vault` (source, reference, version 7, field map `password → pass`) → Save → Test reference → "1 required name is missing and 1 extra key would be refused", present/missing/extra **names**; `hunter2` never in the DOM; `secret_resolved` audited |
| vault sync | Off + vault id → Set up… (endpoint/bucket/region/key/30 min) → Idle + storage line → Sync now "Pushed generation 1." → back to the workspace → `fork` → global banner (no Resolve on it) → Open Vault sync settings → card alarm, banner gone, heading focused, Sync now disabled → `confirmResolve=false` "You cancelled…" → keep remote → "Resolved, keeping the remote copy." → `remoteEdits` → "Merged … 1 conflict" + Merge conflicts list "both copies kept" → Disable, keep bucket → Off; `sync.fork_detected`, `sync.disabled` audited; no key material in the audit |
| global banner (U4) | manual schedule → trust-prompt error banner with the hint, `data-kind="error"` → Open settings → Sync now clears it → `rollback` → Dismiss → lock + unlock brings it back (per unlocked session) |
| first-run join | Join a synced vault instead → validation (vault id invalid, nothing created) → wrong vault id → "bucket does not hold a vault…", bootstrap kept, key input disabled, mock vault `unlocked` → right id → shell; one `vault_created`, `sync.joined`; secret not in DOM/audit; Vault sync card Idle, `dev-0002` |

Commands (Linux, headless Chromium 1243 from `PLAYWRIGHT_BROWSERS_PATH`):
- `make e2e` → flows 5/5, kube 6/6, vSphere 4/4, secrets-sync 7/7 = **22/22** (≈ 2 min).
- `pnpm exec tsc -p e2e/tsconfig.json` clean (boot module unchanged).
- `pnpm test` in `apps/desktop` → **58 files, 432 passed, 0 skipped** (unchanged by this task;
  the one skip of U3 is gone at this HEAD). `pnpm lint` clean.

### 3. M-16 QA part — manual checklist written, nothing automated (by design)

`docs/qa/native-dialogs.md`: one table row per native dialog (power action, VMRC, vSphere TOFU,
sync storage trust, fork/rollback resolution) × Return refuses / Escape refuses / click confirms,
plus the focus-steal-while-typing, single-flight (`confirm.busy`), cooldown (`confirm.cooldown`)
and audit checks. **It must run per OS on the real WebViews** (macOS WKWebView, Windows WebView2,
Linux WebKitGTK): `rfd` sets no default button and each OS chooses its own, and `FixedConfirm`
cannot see that. The macOS run is the first one owed; results go to
`docs/handoff/a3-qa-native-dialogs-<os>.md`. Until the three runs are green, M-16 stays an
A3-tag condition (review 6 §Conditions 1).

## Left open
- The E2E suites drive the **mock** transport: the vSphere TOFU prompt, the S3 trust prompt and
  the OIDC window interception on real WebViews are per-OS manual items (review 6 §Conditions 3
  and `docs/qa/native-dialogs.md`), not Playwright.
- `NOT_GATED` lists `web_open` / `web_focus` / `web_print` as "gated in the Tauri wrapper, needs an
  `AppHandle`": they are pinned by `web_tests.rs`, not by the flow. If rust-core ever exposes
  their gate as a plain function, move them into the matrix.
- rust-core round 7 may add commands or codes: the matrix test will name the missing command;
  the fix is one row (gated) or one reasoned line (`NOT_GATED`).

## Decision needed
- orchestrator: who runs the macOS native-dialog checklist and when (needs a signed dev build on
  a Mac with the mock vCenter / S3 from `mooring-testsrv`).

## Test evidence
```
Linux x86_64, 2026-11-04, worktree-agent-abcac690978da962d @ (see git log)
cargo test -p mooring-app --test e2e_flow           21 passed; 0 failed (18.4 s)
cargo fmt --all -- --check                           clean
cargo clippy -p mooring-app --test e2e_flow -D warnings   clean
make e2e                                             22/22 (flows 5, kube 6, vsphere 4, secrets-sync 7)
pnpm test (apps/desktop)                             58 files, 432 passed
pnpm lint (apps/desktop)                             clean
pnpm exec tsc -p e2e/tsconfig.json                   clean
```
