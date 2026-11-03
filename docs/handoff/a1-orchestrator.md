# A1 — orchestrator handoff

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

## Round 2 (same day)
- Product renamed Nexus Remote → Mooring (`refactor!`), MIT LICENSE, repo `yyasar21/Mooring`.
- ADR-0007 (SSH trust/algorithms) and ADR-0008 (A1 IPC contract) accepted and amended after
  reviews (`Exposure`, `Prompt.purpose`, base64 both ways, `window_detach` → A2).
- Item 3: SSH core (TOFU/known_hosts, 4 auth methods, PTY shell, keepalive) and part b (local /
  remote / dynamic SOCKS5 forwarding, SFTP with confined local paths) — in-process russh test
  server, 71 crate tests.
- Tauri layer: all 30 ADR-0008 commands, store bound to the vault id after unlock, header write
  with fsync + `.bak`, clipboard copy via `arboard` with 30 s clear (also on lock/shutdown),
  navigation guard, `test-util` feature; the app compiles and tests on Linux (WebView toolchain
  installed in the cloud workspace).
- Item 4: UI v1 (ADR-0008, mock transport) then v2 bridge-console redesign (cyan = live /
  selection / focus, magenta = danger; Chakra Petch; CSS motion; 46 vitest tests).
- `age` pinned to `str4d/rage@b5b68c4` (ml-kem 0.3) with the owner's approval (R-AGE-PIN);
  RUSTSEC-2023-0071 accepted (R-RSA).
- QA pass 2: e2e IPC flow (vault → tree → credential → SSH → lock), ~3 000 hostile inputs;
  security review 2: APPROVE WITH NITS; fix round 2 closed QA-4, M-1..M-4, L-1, L-2, L-5..L-7, N-3.
- Gate (cloud Linux): 290 Rust tests / 0 failed / 3 intentionally ignored, clippy + fmt clean,
  46 UI tests, build clean, vectors verified with the `age` CLI.

## Left open
- `make dev` on macOS/Windows: manual checks owed — clipboard clear + history exclusion, OSC 8
  link guard, real ssh-agent, lab SSH (`MOORING_LAB_HOST`), keyring round trip.
- Not wired yet: `src-tauri/src/autolock.rs` (5 s tick + OS signals), keyring/export IPC
  commands (held by security until biometric ACL exists), `vault_create` still uses
  `KdfParams::DEFAULT` instead of calibrating.
- Security L2 (fsync + `.bak` on header write), M1 (Windows keyring persistence), N3, fuzz
  targets for `Header::from_bytes` / `import_age` (needs nightly + cargo-fuzz).
- A1 exit still owes: auto-lock wiring (idle/OS signals), keyring commands (HOLD until
  biometric ACL), forwarding + SFTP IPC and UI, syslog mirror (item 5), cargo-fuzz targets and
  nightly job, Playwright/tauri-driver E2E, 3-OS CI run after push, review-2 lows L-3/L-4/N-*.

## Decision needed
- GitHub repository (CI assumes Actions; `repository` in Cargo.toml points at
  a placeholder repository; now `yyasar21/Mooring`).
- Keyring unlock on Linux: off by default with explicit opt-in warning (reviewer's ruling) — confirm.

## Test evidence
- `cargo fmt --all -- --check && cargo clippy --workspace --exclude mooring-app --all-targets -- -D warnings && cargo test --workspace --exclude mooring-app` → 138 passed, 0 failed, 2 ignored (45 s).
- `pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm test` → clean, 2 UI tests.
- `make test-vectors` → header + 6 sealed vectors verified with the `age` CLI; tamper rejected.
- To run on the Mac: `cargo build -p mooring-app`, keyring round trip, Apple Silicon calibration
  (`cargo test -p mooring-vault --release --lib -- --ignored calibrate_real_host_smoke`),
  `brew install age gitleaks && make test-vectors && gitleaks detect --no-banner --redact`.
