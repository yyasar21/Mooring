# A3 — orchestrator handoff

## Done
- ADR-0014 (Kubernetes sessions), 0015 (vSphere), 0016 (external secrets), 0017 (vault sync +
  sign-in) accepted with owner decisions; ADR-0014 amended (`kube.refused`); LDAPS importer and
  FIDO2 moved to A4 / post-A4; network tools moved to A4.
- Waves: K1 kubeconfig/resolve → K2 options → K3 kube client (ReadOnlyGuard) → K4 sessions,
  exec, logs, forwards ∥ V1 vSphere REST + inventory diff → V2 sync, scheduler, power, consoles ∥
  E1 Vault client + TokenCache → E2 secret sources, OIDC window, connect-time resolve ∥ S1 MSY1 +
  rusty-s3 → S2 sync commands, runner, trust gate, join ∥ Q1 kube/vCenter/Vault/S3 mock servers
  ∥ U1 typed IPC + cluster browser → U2 vSphere wizard/badges/power/consoles ∥ U3 secret
  sources, external_ref, vault sync, join → integration (S2/V2/E2; three merge bugs fixed with
  tests) → F1 (codes golden, 44 gated commands, kube body deadline) ∥ U4 (sync banner, N-33/34/36,
  lazy mock chunk) ∥ Q2 (37 fuzz targets, hostile suites, `assert_no_violations`, kube E2E) →
  review 6 → fix round 7 ∥ Q3 (gate matrix vs manifest, 11 E2E flows) → re-review 6b (BLOCKER
  B-6) → fix round 8 ∥ U5 → re-review 6c.
- Review-5 leftovers closed on the way: L-29, L-30, N-30..N-38 (rust-core), N-33/N-34/N-36 (UI).
- Security review 6: APPROVE WITH NITS (M-16, L-33..L-38, N-39..N-46). Re-review 6b found
  **B-6**: `tauri-plugin-dialog` 2.8.4 rewrites rfd's cancel result (Escape / close box) into
  the label in its cancel slot, so the M-16 fix made Escape *confirm* on Windows and Linux.
  Fix round 8: every native confirmation is `Cancel / <action> / Not now` (first and cancel
  slots refuse, label-only mapping, the plugin's remap replayed in a test); the sync trust
  prompt is two dialogs. Re-review 6c: **APPROVE WITH NITS** (N-50 forward-looking).
- Owner decisions taken during A3: `kube.refused`; VM cap 5 000; VMRC ticket host = connected
  host or a DNS SAN of the accepted certificate; `vault_join` takes `vaultId` + password;
  synced vSphere subtrees are device-local; secret sources are not synced; `confirm.busy` /
  `confirm.cooldown` (10 s, per target); trust conflicts **fail closed** (`http.trust_conflict`,
  `trust_conflict` close code) until one pin is removed; Return on the "remember" dialog refuses.
- main hotfixes while A3 ran (clippy 1.99 `as_chunks` / `is_ok_and`, macOS RDP test pump,
  Windows reconnect flake, colour-free CI annotations, vitest step annotations): main CI green
  at 5e90f60 on all three OSes; merged into a3.

## Left open
- **Per-OS manual run** of `docs/qa/native-dialogs.md` (Return, Escape, close box, Alt+F4 /
  Cmd+W refuse; middle button confirms) on macOS, Windows, Linux — the A3 tag condition.
- Carried: L-28 remainder + one green nightly fuzz run; L-31 (page-raised native UI while
  hidden) per OS; ADR-0013 E2E plan per OS; ADR-0016 §4 OIDC interception check per OS;
  Windows L-29 E2E; L-36 VMRC help text; M-14 upstream IronRDP issue; upstream report of the
  `tauri-plugin-dialog` cancel-slot remap (N-49 pins both crates meanwhile).
- `secret_source_trust` (E2 / F1 proposal: needs a `trust` field on `SourceTestDto`), SSH
  `known_hosts` manager in the UI (SSH trust conflicts are listed but not removable in the UI),
  `known_sync_certs` conflicts only surface as `lastError`, `s3_error_xml` fuzz target gated
  (the product parses no S3 XML), vCenter instance UUID for the Client deep link, kube cluster
  `onEvent`, `kube_info` after unlock.
- QA: E2E for the trust-conflict flow (`setMock` takes `remoteTrust`).

## Decision needed
- None blocking. Whether to file the plugin remap upstream now (owner).

## Test evidence
- Final gate on a3 (cloud Linux): see `docs/handoff/index.md` row and the CI run of the merge
  commit on main; locally `cargo fmt`, `cargo clippy --workspace --all-targets -D warnings`,
  `cargo test --workspace`, `cargo deny check`, `--locked` metadata (root + fuzz), vitest,
  `pnpm build`, `make e2e` (flows 5, kube 6, vSphere 4, secrets-sync 7), `invoke()` only in
  `lib/ipc.ts`.
