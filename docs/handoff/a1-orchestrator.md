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

## Round 3 (same day)
- ADR-0009 typed credential model (15 kinds, protocol matrix, roles, overrides, TOTP) — core,
  store migration 0003/0004 with reseal on unlock, SSH connect secrets + `become`, Tauri
  commands, schema-driven UI (109 vitest tests).
- Public launch prep: private-infrastructure scrub (tree clean; history needs a squash — see
  public-scrub.md), README/guides/community files, release pipeline (macOS dmg/pkg + Homebrew
  tap, Windows exe/msi, Linux deb/rpm/AppImage, cosign keyless SHA256SUMS, SBOM, provenance),
  icons regenerated from `packaging/icon.svg`.
- Security review 3: BLOCKER B-3 (private key could land in plaintext `cert_pem`) + M-5..M-7
  fixed in fix round 3; actions pinned by SHA; release workflow split by privilege.
- Gate (cloud Linux): 390 Rust tests / 0 failed / 3 ignored; clippy + fmt clean; 109 UI tests;
  build clean; vectors verified; `verify-release.test.sh` 10/10.

## Round 4 — A1 exit (2026-11-04)
- ADR-0010 (forwarding, SFTP, auto-lock, syslog over IPC) accepted, amended after review 4.
- rust-core: `forward_open/close/list`, `sftp_*` incl. `sftp_pick_local` (dialog opened from
  Rust, single-use `pickId`; capability stays `core:default`), `sftp_transfers`, auto-lock
  wiring (activity hook with passive list `ipc-passive.json`, 5 s tick, 60 s blur grace, sleep
  by clock jump), external forwards closed on lock, RFC 5424 mirror (udp/tcp/tls, rustls+ring,
  `mooring@32473`, heartbeat, redirect audited on both collectors), QA-F2 kubeconfig fix.
- ui: Forwards panel, SFTP two-pane browser + transfers drawer, auto-lock and syslog settings,
  lock-survival re-adoption, ESLint no-alert, contract tests against `ipc-codes.json` /
  `ipc-passive.json`.
- qa: `fuzz/` workspace (known_hosts, kubeconfig with security oracle, vault header, import_age,
  socks5), stable corpus replay in `cargo test`, `fuzz-nightly.yml`, Playwright E2E (5 flows,
  `e2e.yml`, `make e2e`).
- Security review 4: BLOCKER B-4 (local path from WebView) + M-8..M-11, L-15..L-18, N-10..N-16 →
  all fixed in fix round 4; re-review APPROVE WITH NITS.
- Gate (cloud Linux): 485 Rust tests / 0 failed / 3 ignored, clippy + fmt clean; 185 vitest;
  E2E 5/5; build clean.

## Left open
- `make dev` on macOS/Windows: manual checks owed — clipboard clear + history exclusion, OSC 8
  link guard, real ssh-agent, lab SSH (`MOORING_LAB_HOST`), keyring round trip.
- Not wired yet: `src-tauri/src/autolock.rs` (5 s tick + OS signals), keyring/export IPC
  commands (held by security until biometric ACL exists), `vault_create` still uses
  `KdfParams::DEFAULT` instead of calibrating.
- Security L2 (fsync + `.bak` on header write), M1 (Windows keyring persistence), N3, fuzz
  targets for `Header::from_bytes` / `import_age` (needs nightly + cargo-fuzz).
- A1 exit still owes: keyring commands (HOLD until biometric ACL), 3-OS CI run after push,
  review-2 lows L-3/L-4/N-*, review-4 M-12 (non-ASCII kubeconfig keys — gate for any Kubernetes
  consumer), L-19 (upload part-file mode), N-17..N-22; IANA PEN request for the syslog SD-ID;
  owed fuzz targets (fingerprint::*, otp::decode_seed, parse_account, export_json).

## Before going public
- Publish from a single squashed commit into a fresh repository (security ruling G-1); never make
  the current private history public.
- GitHub settings per `docs/github-setup.md`; secrets per `docs/release.md`; create the
  `homebrew-mooring` tap repo; enable private vulnerability reporting.
- First CI run on 3 OSes; `cargo deny`, `cargo audit`, gitleaks, actionlint must pass in
  `security.yml` (not runnable in the cloud workspace); pin the semgrep container by digest.
- Kubeconfig fuzz target before any Kubernetes consumer; updater plugin needs its own review.

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
