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
