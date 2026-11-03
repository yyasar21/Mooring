# A1 · security-reviewer · items 1–2 (vault lifecycle, nexus-store)

Range reviewed: `240f611..6a0acd0` (crates, src-tauri, Cargo.toml, Cargo.lock).
Full review: [docs/security/a1-review.md](../security/a1-review.md).

## Done
- Reviewed ADR-0006 (calibration, auto-lock, header v2, keyring wrap, age export/import,
  vectors) and ADR-0005 (`nexus-store`) against the security-reviewer checklist.
- **Verdict: `BLOCKER`.** There are two blockers, both latent: no IPC command reaches them
  yet. The merged code can stay on `main`. The keyring, export and import commands must not
  be wired until both are fixed.
  - **B1** `crates/nexus-vault/src/keyring.rs:104-116, 142-153`: a failed `store.put` or
    `store.delete` returns early, so the vault stays **unlocked** (and a v1 header stays
    upgraded in memory). Fix: snapshot `(state, header)` first, then restore on every exit
    path. Add tests that start from a locked vault.
  - **B2** `crates/nexus-vault/src/kdf.rs:49-56`: `validate` has a floor but no ceiling, so a
    hostile header or import (`m_kib = u32::MAX`, …) aborts or OOMs the process. Fix: add
    `KdfParams::CEILING` (4 GiB / t 16 / p 16) in `validate`, plus a host-RAM check in
    `derive_kek`, and tests for both.
- Ruled on the four open decisions:
  - (a) keyring without a biometric ACL: **HOLD** the OS commands per platform; the
    vault-side wrap is approved.
  - (b) v1→v2 upgrade on password unlock: **approved**.
  - (c) `change_password` drops the wrap: **approved**, no auto-re-wrap. The Tauri command
    deletes the item after persisting.
  - (d) import scrypt cap 2^20: **approved**, and the export is pinned to 2^18.
- Non-blocking findings: M1 (Windows `ENTERPRISE` persistence / v1 API), M2 (data dir and DB
  modes), L1–L5, N1–N4. Each has a file:line and an exact fix in the review.
- Threat model updated to v1:
  - status column for A1;
  - new assets (header, WrapKey, export file);
  - new risks R-T2-KR (per-platform table), R-CAL (calibration and hostile cost) and R-INV
    (plaintext inventory, accepted with conditions);
  - open items.
- Dependencies `age` 0.12.1, `keyring` 4.2.0, `sysinfo` 0.40.1 and `rusqlite` 0.41.1
  (bundled SQLite 3.54.1): license, maintenance and unsafe footprint checked. They are
  conditionally approved, pending cargo-deny and cargo-audit in CI.

## Left open
- cargo-deny, cargo-audit, cargo-geiger, gitleaks and semgrep are **not installed** here, so
  none of them ran. CI `make check` must be green before the A1 exit.
- `nexus-app` was not compiled (no WebView toolchain). `keyring_store.rs` and `commands.rs`
  were reviewed by reading only.
- Real `cargo-fuzz` targets for `import_age` and `Header::from_bytes` are still owed (owner:
  qa-engineer / rust-core). The proptest stand-in is not a substitute at phase exit.
- `.gitleaks.toml` allow-list for `crates/nexus-vault/tests/vectors/` (owner: orchestrator).
- Re-review needed once B1/B2 are fixed, and again when the keyring, export, import and
  auto-lock Tauri commands and capabilities land.

## Decision needed
1. **Orchestrator / architect:** amend ADR-0006:
   - "upgraded on next successful password unlock" (ruling b);
   - the KDF ceiling (B2);
   - the export scrypt work factor pinned at log N = 18 (ruling d);
   - macOS ACL: `BiometryCurrentSet` (custom security-framework call) or `UserPresence`
     (`apple-native-keyring-store` `protected` + `access-policy`)?
2. **Orchestrator:** keyring unlock on Linux (Secret Service, no ACL). Ship it as an explicit
   opt-in with a warning (my recommendation), or not at all in A1?
3. **Orchestrator / release-engineer:** the macOS data-protection keychain needs a signed app
   with a `keychain-access-groups` entitlement. Schedule this with the A4 signing work, or
   earlier if macOS keyring unlock is an A1 deliverable.
4. **rust-core:** replace `keyring` (v1 API) with `keyring-core` + explicit per-platform
   stores (M1). This is a dependency change, so it needs my approval: pre-approved if it only
   swaps to crates already in the lockfile.

## Test evidence
Run in worktree `agent-a52de94842dc0dfbf` on 2026-11-03 (Linux):
```
cargo test -p nexus-vault -p nexus-store
  nexus-store  unit 16, credentials 7, crud 7, migrations 4, search 4   all passed
  nexus-vault  unit 40 (2 ignored), proptest 2, vectors 3                all passed
cargo clippy -p nexus-vault -p nexus-store --all-targets -- -D warnings  clean
cargo fmt --check                                                         clean
cargo tree -i {age,keyring,sysinfo,rusqlite} --workspace
  age, sysinfo -> nexus-vault; keyring -> nexus-app only; rusqlite -> nexus-store only
Lockfile: 463 -> 606 packages; no git sources; no openssl/native-tls
```
B1 and B2 were reproduced with a throwaway crate in the scratchpad (outside the repo) that
depends on `crates/nexus-vault` at HEAD:
```
hostile kdf params accepted by from_bytes: true
enable(locked, failing store)  -> Err(Keyring("denied")), state after = Unlocked
enable(locked, ok store)       -> state after = Locked
disable(locked, failing store) -> Err(Keyring("denied")), state after = Unlocked
```
