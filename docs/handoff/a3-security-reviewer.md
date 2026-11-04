# A3 — security-reviewer: review 6 (Kubernetes, vSphere, external secrets, vault sync)

Worktree from `a3` @ `49d7b98`. Docs only: `docs/security/a3-review-6.md`,
`docs/security/threat-model.md`, `SECURITY.md`, this note.

## Done
- Review 6 of `1b79c1b..49d7b98` (ADR-0014..0017, all A3 handoffs, review-5 closures).
  **Verdict `APPROVE WITH NITS`.** No blocker; **1 Medium (M-16)**, **6 Low (L-33..L-38)**,
  **8 Nits (N-39..N-46)**.
- Review-5 closures confirmed with file:line: L-29 (code), L-30, N-28 (c), N-30..N-38 fixed;
  L-32 partly (tauri pinned, wry not → N-46); L-31 and the L-28 remainder still open.
- Dependency rulings for every package new in `Cargo.lock` (kube 5 / k8s-openapi 0.29,
  tokio-tungstenite 0.30, rusty-s3 0.11, hkdf, httpdate dev-only approved; the kube `config`
  tree — serde-saphyr, encoding_rs/simdutf8, jsonpath-rust/pest/stacker/psm — accepted as
  compiled-not-executed, R-KUBE-CFG).
- Threat model: A3 assets, attacker T7 (sync storage operator), "Trust boundaries added in A3",
  risks R-KUBE-EXEC, R-KUBE-CFG, R-VMRC-ARGV, R-SYNC-OP, R-EXT-STR, A3 open items.
- SECURITY.md: scope extended to the four API clients and sync; a user-facing A3 section.

## Left open
- Per-OS checks I cannot run here: OIDC redirect interception on WebView2/WKWebView/WebKitGTK
  (ADR-0016 §4), L-31, the Windows L-29 E2E, and the M-16 Return/Escape check on the five
  native dialogs.
- `secret_source_trust` (F1 left open) is not built; when it lands, its DTO field and command
  need a review.

## Decision needed
- **rust-core:** M-16 (button order by label, one dialog at a time, cool-down after a
  cancelled destructive action); L-33, L-34, L-35, L-37; N-39..N-45.
- **qa-engineer:** L-38 (locked-vault matrix + "every command is gated or listed" golden);
  the L-28 remainder and a green nightly run.
- **orchestrator:** N-46 (lockfile test for `wry` / `tauri-runtime-wry`); file the kube-rs
  upstream ask (make `config` optional under `client`).
- **architect:** confirm R-VMRC-ARGV and R-SYNC-OP as accepted; add the VMRC argv note to the
  option help (L-36).
- **owner (U4 decision 2):** the sync banner may show `lastError.message` verbatim — approved,
  every `SyncError` message is static text.

## Test evidence
- `cargo deny check`: advisories, bans, licenses, sources ok.
- `cargo audit --no-fetch` against cargo-deny's advisory DB (2026-11-03): only RUSTSEC-2023-0071
  (R-RSA, ignored in `deny.toml`) plus pre-A3 unmaintained/unsound warnings.
- `cargo tree -i` for each new package (see the review's dependency table).
- Not run: builds, tests, geiger, gitleaks, semgrep, pnpm audit, cargo-fuzz (orchestrator gate
  runs builds and tests concurrently; no compile was done in this worktree).

---

# Re-review 6b (fix round 7 + Q3) — 2026-11-05, `a3` @ `7527a7d`

Docs only: the "Re-review 6b" section of `docs/security/a3-review-6.md`,
`docs/security/threat-model.md` (native-confirmation boundary, A3 open items), this note.

## Done
- Closure of every review-6 row with file:line. **Verdict `BLOCKER` for the A3 tag.**
- **M-16 is reopened as B-6.** `tauri-plugin-dialog` 2.8.4 (`src/desktop.rs:226-253`) remaps
  rfd's positional `Cancel` to `Custom(<cancel-slot label>)` on every desktop OS. Escape, Alt+F4
  and the close box all give that `Cancel` (GTK DELETE_EVENT, Windows IDCANCEL). Since the
  confirming label now sits in the cancel slot, they **confirm** power actions, VMRC, vSphere
  trust and fork resolution, and answer "Trust and remember" on the sync trust dialog.
- Fixed: L-33, L-38 (every `NOT_GATED` reason checked), N-39..N-42, N-44, N-45, N-46. M-16's
  single flight, cool-down, Cancel-first order, label mapping and the two new codes are all
  correct.
- Partial: the guest shutdown/reboot cool-down, L-34 (a), L-35 (a)(b), L-37 (a)(b),
  N-43 (a)(b).
- New: N-47 (`confirm_refused` audit flood), N-48 (`web_open` reopen path has no lock
  post-check), N-49 (pin `tauri-plugin-dialog` 2.8.4 and `rfd` 0.17.2 in the lockfile golden).
- Approved: `rfd =0.17.2` as a direct dependency of `mooring-app` if rust-core takes B-6
  option 1. It is already in the tree, so no new crate.

## Left open
- Per-OS checks I cannot run: the native-dialog checklist (after B-6), OIDC interception
  (ADR-0016 §4), L-31, the Windows L-29 E2E.

## Decision needed
- **rust-core:**
  - B-6 (option 1: map rfd's result ourselves; option 2: three slots with a refusing label
    last, and a two-step sync trust dialog);
  - guest-power cool-down (`destructive: a != On`);
  - L-34 (a): move `secrets.on_lock()` after `lock_with_reason`;
  - L-37 (a)(b);
  - L-35 (a)(b): together with ui-engineer for `sync_status.conflicts`, or fail closed instead;
  - N-43 (a)(b), N-47, N-48.
- **qa-engineer:** add "close box / Alt+F4 / Cmd+W refuses" to `docs/qa/native-dialogs.md`; run
  it per OS after B-6.
- **orchestrator:**
  - `rfd` direct dependency (if option 1);
  - N-49;
  - file the upstream tauri-apps/plugins-workspace issue for the unconditional remap.
- **owner:** L-35. Is surfacing conflicts in `sync_status` and the UI enough, or should a
  conflicting host fail closed until one pin is removed? The reviewer prefers fail closed.

## Test evidence
- Registry sources read: `tauri-plugin-dialog` 2.8.4 (`desktop.rs`, `Cargo.toml`), `rfd` 0.17.2
  (`gtk3`, `win_cid`, `macos` message dialogs).
- Greps: dialog builders (two, covering all five dialogs), no timeout around an ask, the
  `NOT_GATED` reasons against the command sources.
- Not run: builds, tests, the per-OS checklist, cargo-fuzz.
