# A1 — orchestrator handoff (items 1–2)

## Done
- ADR-0005 (SQLite store) and ADR-0006 (vault lifecycle) accepted; ADR-0006 amended after the
  security review (v1→v2 upgrade on password unlock, keyring commands held, KDF ceiling, scrypt
  pin).
- Item 1 — vault: Argon2id calibration with RAM bound and ceiling, pure auto-lock policy/clock,
  header v2 (`vault_id`, `keyring_wrap`), vault-side keyring wrap with state-restoring error
  paths, `age` export/import (export log N = 18, import cap 2^20), committed test vectors verified
  with the `age` CLI, hostile-input property tests.
- Item 2 — `mooring-store`: schema v1 + v2 (FTS secure-delete), migrations, sealed credential
  columns bound to row + column, inheritance resolution, FTS5 search with query sanitising,
  0600 db file, WAL checkpoint on close; validators now shared from `mooring-core`.
- Gates (cloud Linux): fmt, clippy `-D warnings`, 138 tests passed / 0 failed / 2 intentionally
  ignored; pnpm lint/typecheck/test green; `.gitleaks.toml` allow-lists the vector dir; new
  `test-vectors` workflow; `ci.yml` YAML fixed (the concurrency block made the whole workflow
  invalid in A0).
- Security: initial BLOCKER (B1 keyring error path, B2 KDF ceiling) fixed in the fix round;
  re-review recorded in `docs/security/a1-review.md`; threat model v1.

## Left open
- `mooring-app` (src-tauri) has not been compiled since A0: no WebView toolchain in the cloud
  workspace. First `cargo build -p mooring-app` on the Mac may surface API mismatches in
  `commands.rs`, `state.rs`, `lib.rs`, `keyring_store.rs`.
- Not wired yet: `src-tauri/src/autolock.rs` (5 s tick + OS signals), keyring/export IPC
  commands (held by security until biometric ACL exists), `vault_create` still uses
  `KdfParams::DEFAULT` instead of calibrating.
- Security L2 (fsync + `.bak` on header write), M1 (Windows keyring persistence), N3, fuzz
  targets for `Header::from_bytes` / `import_age` (needs nightly + cargo-fuzz).
- A1 items 3–6 (SSH session, UI, audit viewer, E2E) not started.

## Decision needed
- GitHub repository (CI assumes Actions; `repository` in Cargo.toml points at
  `yunusyasar/mooring-remote`).
- Keyring unlock on Linux: off by default with explicit opt-in warning (reviewer's ruling) — confirm.

## Test evidence
- `cargo fmt --all -- --check && cargo clippy --workspace --exclude mooring-app --all-targets -- -D warnings && cargo test --workspace --exclude mooring-app` → 138 passed, 0 failed, 2 ignored (45 s).
- `pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm test` → clean, 2 UI tests.
- `make test-vectors` → header + 6 sealed vectors verified with the `age` CLI; tamper rejected.
- To run on the Mac: `cargo build -p mooring-app`, keyring round trip, Apple Silicon calibration
  (`cargo test -p mooring-vault --release --lib -- --ignored calibrate_real_host_smoke`),
  `brew install age gitleaks && make test-vectors && gitleaks detect --no-banner --redact`.
