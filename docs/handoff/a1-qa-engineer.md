# A1 · qa-engineer · items 1–2 (vault lifecycle, nexus-store)

Branch `worktree-agent-adbc6562436f4dbea`, on top of `6a0acd0` (main). Not merged.
Scope: A1 items 1 and 2 only. Items 3–6 (SSH, UI, audit viewer, E2E) are not started and
were not tested. Linux host (2 cores), cargo 1.97.0, age v1.1.1, no WebView toolchain,
no nightly / cargo-fuzz, no gitleaks binary.

## Done

| File | What |
| --- | --- |
| `crates/nexus-store/tests/vault_store_integration.rs` | Cross-crate: create vault (TEST) → in-memory store → folders / connections / password + SSH-key credentials → `effective_credential` (inherited + override) → lock → every secret open/replace fails `Vault(Locked)` while metadata + resolution still work → wrong password stays locked → unlock → opens. Header v2 written to disk → reload → `set_vault_id(header.vault_id)` idempotent → different vault gets `VaultIdMismatch` and `Tampered` on open. Password change keeps store secrets readable and `vault_id`. Keyring unlock opens store secrets; password change drops the wrap. Export of raw store columns → `age` → import → fields open under the imported header. One `#[ignore]` bug test (A1-QA-2). |
| `crates/nexus-store/tests/tree_edges.rs` | Inheritance after moving a folder and after moving a connection; shared default credential deleted → every reference `NULL`, falls back to root; folder cascade keeps credentials; 65-level deep chain (root fallback, nearest wins, sibling branch does not leak, mid-chain delete cascades); FTS survives `VACUUM` + reopen; diacritic/case folding (`Çankaya` ↔ `cankaya`); file reopen keeps data + schema version. |
| `crates/nexus-vault/tests/autolock_table.rs` | Two multi-step scenario tables (touch / signal / reset / set_policy / expect; 12 cases) plus a proptest against a reference idle model (256 cases). |
| `crates/nexus-vault/tests/calibration_props.rs` | Proptests on `calibrate_with` with a mock timer: always ≥ floor and valid, `t = 3`, `p = clamp(lanes,1,4)`, ≤ caller cap and ≤ ¼ RAM, only listed candidates (or the cap when none fit); monotonic in target, in RAM and in cap; verification guards non-linear hosts. Failing derivation (`Duration::MAX`) picks 64 MiB without overflow. Header below floor refused at parse. One `#[ignore]` bug test (A1-QA-1). |
| `tests/vectors/verify_age_export.py` | Uses the reference `age` CLI (through the existing `age_decrypt.py` pty wrapper) to decrypt `export.age`, then checks `header == header.json`, the set of sealed fields equals `sealed.json` exactly (no missing, no extra, no duplicates), and that a one-character-tampered copy is rejected. |
| `.github/workflows/test-vectors.yml` | Standalone workflow (push/PR on `crates/nexus-vault/**`, `tests/vectors/**`, itself; manual dispatch). `apt-get install age jq` on ubuntu-24.04, runs the verifier, and the README's `jq` header diff. `contents: read` only. |
| `.gitleaks.toml` | `useDefault = true` (no rule disabled) + a path allowlist for `^crates/nexus-vault/tests/vectors/` only, with the reason. |
| `Makefile` | `make test-vectors` target. |

`ci.yml` is untouched, as asked.

## Exit criteria (A1, items 1–2 plus the ADR-0005/0006 test plans)

| # | Criterion | Result | Evidence |
| --- | --- | --- | --- |
| 1a | Vault create / unlock / lock / change password | PASS | `vault::tests::*`, `vault_store_integration::{full_lifecycle…, password_change…}` |
| 1b | Auto-lock policy + clock (idle, screen lock, sleep, window hidden) | PASS (pure part) | `autolock::tests::*`, `autolock_table` (3 tests). The Tauri tick/OS-signal wiring (`src-tauri/src/autolock.rs`) does not exist yet: **NOT TESTABLE** |
| 1c | Keyring wrap opt-in (round trip with in-memory mock) | PASS (mock) | `keyring::tests::*`, `vault_store_integration::keyring_unlock_opens_store_secrets`. Real OS keyring: Mac/Windows only, see below |
| 1d | `export --age` / import round trip | PASS (library) | `export::tests::*`, `vault_store_integration::export_import…`. No CLI/command wiring yet |
| 1e | Vectors under `tests/vectors`, verifiable with the `age` CLI | PASS | `tests/vectors.rs` (3), `python3 tests/vectors/verify_age_export.py` → `OK: header + 6 sealed vectors verified with the age CLI; tamper rejected`; jq diff empty |
| 1f | Calibration ≈ 500 ms, params stored in header; monotonic + floor + RAM cap | PASS (mock) | `kdf::tests::*`, `calibration_props` (6). Real-host smoke `calibrate_real_host_smoke` is `#[ignore]`; not wired into `vault_create` yet (rust-core handoff) |
| 1g | Header v1 → v2 upgrade | PASS | `vault::tests::v1_header_unlocks_and_upgrades_to_v2`, `format::tests::*` |
| 1h | Hostile header cannot cause OOM (ADR-0006 security consequences) | **FAIL** | A1-QA-1 below |
| 2a | Folders, connections, tags, credentials (password, SSH key + passphrase, certificate) | PASS | `crud.rs`, `credentials.rs`, `tree_edges.rs` |
| 2b | Inheritance down the tree, per-connection override | PASS | `credentials::inheritance_resolution`, `tree_edges` (moves, deep chain, shared delete) |
| 2c | Full-text search | PASS | `search.rs`, `tree_edges::{search_survives_vacuum_and_reopen, search_folds_diacritics_and_case}` |
| 2d | SQLite bundled, sealed columns bound to row + column | PASS | `credentials::sealed_value_cannot_be_moved_between_rows_or_columns` |
| 2e | Migrations (empty, v1 reopen, downgrade refused) | PASS | `migrations.rs`, `tree_edges::data_survives_file_reopen`. v1 → v2 not testable until a v2 script exists |
| 2f | FK cascade on folder delete | PASS | `crud::deleting_a_folder_cascades…`, `tree_edges::folder_delete_cascade_keeps_credentials` |
| 2g | Proptest seal/open through the store | PASS | `credentials::seal_open_through_store_round_trips` |
| 2h | Store bound to vault via `vault_id` | PASS with bug | `vault_store_integration::header_v2_round_trip…`; A1-QA-2 below |
| 3 | SSH session | NOT STARTED | — |
| 4 | UI | NOT STARTED | — |
| 5 | Audit log viewer, syslog mirror | NOT STARTED | — |
| 6 | Tests: proptest vault round trip + tamper | PASS | `proptest_round_trip.rs` |
| 6 | cargo-fuzz targets (vault header, SSH packets), 1 h nightly | NOT STARTED | No nightly/cargo-fuzz here; proptest stand-in `export::tests::arbitrary_input_never_panics` only |
| 6 | Vitest for stores, Playwright E2E | NOT STARTED | Only `App.test.tsx` (2 tests) exists |
| X | All green on 3 OSes | **FAIL / UNKNOWN** | Linux pure gate green. `ci.yml` does not parse (A1-QA-3), so no CI run on any OS. macOS/Windows never run |
| X | `docs/security/a1-review.md` sign-off, threat model, handoff notes | NOT STARTED (security) / PASS (handoffs) | — |

## Bugs found

- **A1-QA-1 (security, nexus-vault)** — `KdfParams::validate` has a floor but no ceiling. A
  tampered `vault.header.json`, or a header inside an imported export, with `m_kib =
  u32::MAX` (4 TiB), huge `t` or `p` parses fine, and the next `unlock` runs Argon2 with it
  before the AEAD can reject the header: OOM / CPU DoS. ADR-0006 claims "a hostile header
  cannot cause OOM", which only holds for calibration. Test:
  `crates/nexus-vault/tests/calibration_props.rs::header_with_absurd_kdf_cost_is_refused_at_parse`
  (`#[ignore]`, fails when run with `--ignored`: `KdfParams { m_kib: 4294967295, t: 1, p: 1 } was accepted`).
  Fix: refuse in `validate()` above a ceiling (suggest m ≤ 4 GiB or ¼ RAM, t ≤ 64, p ≤ 16), and remove the `#[ignore]`.
- **A1-QA-2 (nexus-store)** — `Store::set_vault_id` accepts the nil UUID. A v1 header
  reports nil until its first password unlock assigns a random id. If the app binds before
  that, the store is pinned to nil and every later bind fails `VaultIdMismatch`, so the user is locked out of the store. Test:
  `crates/nexus-store/tests/vault_store_integration.rs::nil_vault_id_is_refused` (`#[ignore]`, fails with `--ignored`).
  Fix: reject `Uuid::nil()` as `Invalid`; the app should bind only after unlock.
- **A1-QA-3 (CI, orchestrator-owned `ci.yml`)** — line 6
  `concurrency: { group: ci-${{ github.ref }}, cancel-in-progress: true }` is not valid YAML
  (`{` inside a flow mapping; PyYAML: "expected ',' or '}', but got '{'"). GitHub refuses the
  whole workflow, so the 3-OS `check` matrix never runs. Fix: block style or quote the value
  (`group: "ci-${{ github.ref }}"`). `release.yml` and `security.yml` parse; their `${{ }}` inside
  `{ }` is quoted. I did not edit `ci.yml` (outside my brief).

## Left open

- `.gitleaks.toml` is **not validated with gitleaks**: the binary is not installed and I
  could not download it here. Checked: valid TOML; v8 schema (`[extend] useDefault`,
  `[allowlist] paths`). Run `gitleaks detect --no-banner --redact` (or `make audit`) once,
  on a machine that has it. With gitleaks ≥ 8.25 the `[allowlist]` table still works but is
  deprecated in favour of `[[allowlists]]`. Update it there if the scan warns.
- The `test-vectors` workflow has not been run on GitHub. Locally its two steps were run
  as-is and passed. Ubuntu 24.04 ships `age` 1.1.1 in `universe`.
- No fuzz targets, no Vitest store tests and no E2E. Those are owed in items 3–6.

## Must run on the Mac (and Windows where noted)

1. `make app-check` (`cargo clippy --workspace --all-targets -D warnings` + `cargo test --workspace`)
   and `cargo build -p nexus-app`. nexus-app has never compiled since A1-1 (`keyring_store.rs`, `commands.rs`). Windows as well.
2. Real keyring: an enable → reload → `unlock_with_keyring` → disable round trip through
   `OsWrapKeyStore` against the macOS Keychain (and Windows Credential Manager). Check that the
   item is deleted on disable. The biometric ACL is not implemented (rust-core Decision 2), so expect no Touch ID prompt yet.
3. Calibration on Apple Silicon:
   `cargo test -p nexus-vault --release --lib -- --ignored calibrate_real_host_smoke --nocapture`.
   Record the chosen `m_kib` and the time of one unlock with those params. Target ≈ 500 ms. Here
   (2 cores, 8 GiB) it took 0.48 s.
4. `make test-vectors` (needs `brew install age`). The pty wrapper is POSIX-only, so on Windows use WSL or skip.
5. `gitleaks detect --no-banner --redact` with the new `.gitleaks.toml`.

## Decision needed

- Orchestrator: fix `ci.yml` (A1-QA-3) before any 3-OS claim. It is a one-line change.
- rust-core + security-reviewer: KDF ceiling values for A1-QA-1.
- Should `test-vectors.yml` also run on macOS (brew `age`) for cross-OS vector parity? It is Linux only now.

## Test evidence (2026-11-03, worktree, after my changes)

```
cargo fmt --all -- --check                                              → clean
cargo clippy --workspace --exclude nexus-app --all-targets -- -D warnings → Finished, 0 warnings
cargo test --workspace --exclude nexus-app
  nexus-audit 7 · nexus-core 6 · proto-* 0
  nexus-store  lib 16 · credentials 7 · crud 7 · migrations 4 · search 4
               tree_edges 8 (new) · vault_store_integration 5 + 1 ignored (new)
  nexus-vault  lib 40 + 2 ignored · autolock_table 3 (new) · calibration_props 6 + 1 ignored (new)
               proptest_round_trip 2 · vectors 3
  → 118 passed, 0 failed, 4 ignored (2 pre-existing on purpose, 2 = bugs A1-QA-1/2)
cargo test -p nexus-vault --test calibration_props -- --ignored        → FAILED (A1-QA-1, expected)
cargo test -p nexus-store --test vault_store_integration -- --ignored  → FAILED (A1-QA-2, expected)
pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm test → ok; vitest 1 file, 2 tests
make test-vectors → OK: header + 6 sealed vectors verified with the age CLI; tamper rejected
YAML parse of .github/workflows/*.yml → release, security, test-vectors OK; ci.yml ERROR (A1-QA-3)
```

Baseline before my changes: the same gate was green (96 Rust tests + 2 ignored, 2 Vitest).
