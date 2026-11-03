# A1 · security-reviewer · items 1–2 (vault lifecycle, mooring-store)

Full review and re-review: [docs/security/a1-review.md](../security/a1-review.md).

## Current verdict: `APPROVE WITH NITS` (re-review of `b256dcd..1e76c3a`, 2026-11-03)

The A1 items 1–2 code on `main` is approved. The first review's `BLOCKER` is lifted.

## Done

### Re-review (fix round)
- Checked every finding against the code and its test:
  - B1, B2, L1, L3, L4, L5, M2, N1, N2, N4 and A1-QA-2 are fixed and tested.
  - The shared `mooring-core` validators are approved: hosts now refuse control characters.
  - The dev-only `opt-level = 3` for scrypt is approved.
- **N3 is deferred.** It goes in the `vault_export` PR. `subtle` is pre-approved as a direct
  dependency for it.
- **L4 ruling: keep as-is.** That means `contentless_delete = 1`, `optimize` and
  `wal_checkpoint(TRUNCATE)` on close/drop, and the full rebuild on open.
  - I verified with SQLite 3.53.1 that `secure-delete` is a no-op under `contentless_delete`.
  - `optimize` removes the residue, and so does the open-time rebuild after a crash.
  - Dropping `contentless_delete` would move deletes to the error-prone `'delete'` command:
    old values have to match exactly, otherwise the index is silently corrupted.
  - Running `optimize` on every delete is O(index) per edit.
  - The residue is inventory metadata, which is already accepted as plaintext at rest (R-INV).
  - Conditions: call `Store::close()` from `RunEvent::Exit` when the store is wired, and add a
    one-line residue bound to ADR-0005 and R-INV.
- Two new nits:
  - **N5** `vault.rs:155-156`: the KDF RAM refusal is reported as `Unlock` ("wrong password").
    Pass `KdfParams` through instead.
  - **N6** `mooring-store/src/lib.rs:83-85`: `close()` checkpoints twice, because `Drop` runs it
    again.
- Threat model updated: status rows for B1/B2/L3/L4/L5/M2, R-CAL, R-INV conditions and the open
  items.

### First review (range `240f611..6a0acd0`)
- **Verdict:** BLOCKER, for B1 and B2.
- **Rulings:**
  - (a) Keyring commands: HOLD per platform.
  - (b) v1→v2 upgrade on password unlock: approved.
  - (c) Password change drops the keyring wrap: approved, no auto-re-wrap.
  - (d) Import cap 2^20, export pinned at 2^18.
- **Non-blocking findings:** M1, M2, L1–L5, N1–N4.
- **Dependencies:** `age`, `keyring`, `sysinfo` and `rusqlite` are conditionally approved,
  pending cargo-deny and cargo-audit.

## Left open
- **Wiring gates:**
  - Export and import commands may be wired, with N3 in the same PR.
  - Keyring commands stay on **HOLD** until M1 and R-T2-KR are done (biometric ACL, Windows
    `Local`/Hello, Linux opt-in).
- **L2** (durable header write: `sync_all` + `.bak`) is still open in `src-tauri/src/state.rs:58-65`.
  Required before A1 exit, and before any further header-rewriting command.
- `cargo-fuzz` targets for `Header::from_bytes` and `import_age`: owed for A1 exit (owners:
  qa-engineer / rust-core).
- The tools cargo-deny, cargo-audit, gitleaks and semgrep are not installed here. `mooring-app`
  has not been compiled (no WebView toolchain), so `make check` has to pass in CI on all three
  OSes.
- `.gitleaks.toml` allow-list for `crates/mooring-vault/tests/vectors/` (orchestrator).
- Re-review needed when the keyring, export, import and auto-lock Tauri commands and
  capabilities land.

## Decision needed
1. **Architect:** add the L4 residue bound to ADR-0005 and the threat model ("deleted inventory
   may persist in FTS segments until close or next open"). The ADR-0006 amendments from the
   first review are in `f93a86b`.
2. **Orchestrator:** schedule N5 and N6 (small, rust-core) and L2 (rust-core, src-tauri) before
   the A1 exit.
3. Still open from the first review:
   - macOS ACL choice, `BiometryCurrentSet` or `UserPresence` (architect).
   - Linux keyring opt-in (orchestrator).
   - macOS signing entitlement timing (release-engineer).
   - The M1 crate swap (rust-core; pre-approved if it uses only crates already in the lockfile).

## Test evidence
Re-review run in worktree `agent-a4fd903c4e7869598`, HEAD `1e76c3a`, Linux, 2026-11-03:
```
cargo test -p mooring-vault -p mooring-store                                         exit 0
  mooring-store  lib 18 · credentials 7 · crud 7 · migrations 6 · search 4 · tree_edges 8
               vault_store_integration 6 (0 ignored)
  mooring-vault  lib 52 (2 intentional ignores) · autolock_table 3 · calibration_props 7
               proptest_round_trip 2 · vectors 3
cargo clippy -p mooring-vault -p mooring-store -p mooring-core --all-targets -- -D warnings   clean
cargo fmt --all -- --check                                                               clean
FTS5 secure-delete experiment, run in the scratchpad (outside the repo):
  contentless_delete=1: token kept after delete, gone after optimize
  'delete' command:     token gone right after the delete
  crash path:           'delete-all' + rebuild on open removes the token from the file
```
