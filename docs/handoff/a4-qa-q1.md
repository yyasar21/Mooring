# A4 — QA Q1 (ADR-0018 / 0019 / 0020 test plans, review 5 L-28 remainder)

Date: 2026-11-06 · Worktree `agent-a28d537a8aeb29d17` (branch `worktree-agent-a28d537a8aeb29d17`)
from `a4` @ `c3f1940`. Four commits, tests and QA-owned files only; no `crates/*/src`, no
`src-tauri/src`, no `apps/desktop/src`. U4 (LDAPS wizard form) runs concurrently: no LDAPS-form
E2E yet (TODO row in `apps/desktop/e2e/a4.e2e.mjs`).

## Result per item

| # | Item | Result | Command |
| --- | --- | --- | --- |
| 1a | 9 `import_*` + `ldap_filter_escape` + `ldap_ber_response` + 3 `net_*` targets build on stable, have seeds, `regressions/<t>/`, replay tests, nightly rows, doc rows | **PASS** (after the fix in 1c) | `cd fuzz && cargo check --bins --offline` → 54 bins, 0 warnings |
| 1b | L-28 remainder: `cut_text`, `framebuffer_ops` added; `rdp_reactivation` not added (no pure entry point, see Decision 2) | **PASS** (2 of 3) | `cargo test -p mooring-proto-vnc -p mooring-core --test fuzz_corpus` |
| 1c | Fuzz workspace: `cargo check --bins` **failed before Q1** — `fuzz/Cargo.toml` never mirrored the root `[patch.crates-io] age` (its header comment claimed it), so the lock held `age 0.12.1` from crates.io with `ml-kem 0.2.1`, which no longer compiles next to russh's `ml-kem 0.3` / `kem 0.3`. Patch added, lock re-resolved offline (+6 git/registry packages, −stale duplicates). | **FIXED** | `cd fuzz && cargo metadata --offline` |
| 1d | `docs/qa/fuzzing.md`: L-28 table, N1's table had split the A3 paragraph (moved), stable replay command lists `mooring-net` / `mooring-import`, stale "Still Q1" line replaced | **PASS** | — |
| 2a | Importer hostile fixtures, parser level (`crates/mooring-import/tests/hostile.rs`, 9 tests) | **PASS** | `cargo test -p mooring-import --test hostile` |
| 2b | Importer hostile fixtures, app level with audit assertions (`src-tauri/tests/e2e_flow/a4_import.rs`, 4 + 1 ignored) | **PASS**, 1 product gap (Decision 1) | `cargo test -p mooring-app --test e2e_flow a4_import` |
| 2c | LDAPS mock hostile knobs through `ldap_import_preview` / `_test` + `assert_no_violations` + TOFU trust / once / refuse (`a4_ldap.rs`, 5) | **PASS** | `cargo test -p mooring-app --test e2e_flow a4_ldap` |
| 2d | Network shims through `net_*`: flood → cap, two hanging → `net.busy`, missing → `net.tool_missing` + `net_tools`, wg hidden, rate limit, kube / vSphere refused, shell-shaped hosts (`a4_net.rs`, 4) | **PASS** | `cargo test -p mooring-app --test e2e_flow a4_net` |
| 2e | Updater Rust-side matrix over a scripted `UpdateSource` (`a4_update.rs`, 4): manual-mode offer never reaches the source, rate limit vs background, background downloads nothing, tampered manifest / signature refused + audited without `update.install`, single flight, unconfigured | **PASS**; plugin leg = manual step below | `cargo test -p mooring-app --test e2e_flow a4_update` |
| 3 | Playwright + `node:test` flows (`apps/desktop/e2e/a4.e2e.mjs`, 10): import wizard ×3 (opt-in, duplicates, mRemoteNG banner, refused file), onboarding ×2, Updates ×2 (+ title-bar badge), Network ×2, About ×1; in `make e2e` and `e2e.yml` | **PASS** | `make e2e` (5 files, 32 flows) |
| 4 | Gate matrix: `update_*`, `import_*`, `ldap_import_*`, `net_*` all rows of `vault_gated_codes`; `import_formats` in `NOT_GATED` ("static catalogue, no store, no I/O"); `net_tools` is a gated row (N1 chose gated; fine, the card is only rendered unlocked) | **PASS** | `cargo test -p mooring-app --test e2e_flow locked_matrix_covers_the_manifest` |
| 5 | fmt / clippy on touched crates, `pnpm test`, `make e2e` | **PASS** | see Test evidence |

## Decision needed

1. **Product gap (low): an undetected import file is not audited.** `import_preview` with a
   pick that `detect` does not recognise answers `import.format` but writes no
   `import_refused { code }` row (`commands/import.rs::preview` returns before the audit
   branch); every parser refusal is audited. ADR-0019 §5 says refusals are audited.
   `#[ignore]`d test `a4_import::undetected_format_is_audited_as_a_refusal` pins the
   expected behaviour — rust-core: audit that branch, un-ignore.
2. **`rdp_reactivation` fuzz target (L-28) needs an entry point from rust-core.** The
   Deactivation-Reactivation Sequence lives in `active::reactivate` (private, async over the
   framed socket) and the `ConnectionActivationFactory` comes out of the first handshake. A
   pure `mooring_proto_rdp::fuzz::reactivation(data)` (`ConnectionActivationSequence::new
   (config, io, user)` + `Sequence::step` per `[len, bytes]` frame → `check_desktop` /
   `ActiveStage::reactivate`) is ~40 lines in rust-core's `fuzz.rs`; the target, seeds and
   replay then follow the pattern (QA). Documented in `docs/qa/fuzzing.md`.
3. **Updater plugin leg is manual per OS** (ADR-0018 test plan "loopback `latest.json` +
   ephemeral key"). `PluginSource` cannot be driven in a test: the plugin's `Update` type is
   private, its reqwest client is `https_only`, and `configure_client` is the only hook (no
   way to trust a loopback certificate without weakening the product policy). Manual step
   for the Mac-side gate (owner + QA), once per OS, with the `v0.1.0-rc.2` draft:
   `scripts/release/updater-manifest.sh` output edited to (a) a wrong signature, (b) a
   version lower than the running one, (c) a bogus platform key, served from a local HTTPS
   endpoint whose certificate is in the OS trust store; expected `update.signature`,
   "up to date", `update.manifest`; then the real draft → in-app install on AppImage /
   user-writable `.app` / NSIS per-user, manual reason on deb / rpm / MSI / Homebrew.
   `verify-release.sh` step 5 already checks `latest.json` against the assets and
   `SHA256SUMS`.
4. Observations, no change asked: (a) `mooring-core::validate_host` accepts `\\unc\share`
   (no whitespace / control), so a PuTTY session with a UNC host imports as a connection
   while `mooring-net::Target::parse` refuses the same string — consistent with a typed host,
   worth a line in the import docs; (b) `ldap_import_test` refusals are audited as
   `cert_decision` only, not `import_refused` (it is not an import), and a run that dies on
   a hostile frame after a successful bind writes the refusal but no `ldap_bind` row;
   (c) `confirm.cooldown` (M-16) applies to the LDAPS TOFU dialog: a second prompt for the
   same host within 10 s of a refusal is refused without asking — expected, pinned.

## Left open

- LDAPS wizard E2E (after U4): tile → form → Test → preview → apply with the mock's knobs.
- `net_*` wall-clock deadline (30 s ping / 60 s traceroute) through the commands is not run
  in CI (too slow); `crates/mooring-net/tests/shim_runner.rs` pins it on `run_tool` with a
  500 ms deadline. Real-tool corpora from the three OSes (N1 left open) still to record.
- `ldap.timeout` through the command (30 s) is covered at the crate level only
  (`mock_tests::hostile_responses_never_panic_or_hang`, `slow_bind_hits_the_deadline`).
- First green nightly fuzz run: `fuzz-nightly.yml` has never run on a nightly toolchain
  (unchanged since A2); the stable `cargo check --bins` now passes, which it did not.
- The e2e `.mjs` files are outside `eslint src` (pre-existing); `tsc -p e2e/tsconfig.json`
  covers `boot.ts` only.

## Test evidence (Linux x86_64, rustc 1.97.0, node 22, 2026-11-06)

```
cargo fmt --all -- --check                                              clean (root + fuzz)
cargo clippy -p mooring-app -p mooring-import -p mooring-core -p mooring-proto-vnc --all-targets -- -D warnings
                                                                        clean (pre-existing unknown_lints note only)
cd fuzz && cargo check --bins --offline                                 54 bins, Finished (was: ml-kem 0.2.1 build failure)
cargo test -p mooring-import -p mooring-core -p mooring-proto-vnc -p mooring-net
                                                                        399 passed, 0 failed (import hostile 9; core fuzz_corpus 17 incl.
                                                                        framebuffer_ops ×3; vnc fuzz_corpus 10 incl. cut_text ×3)
cargo test -p mooring-app --test e2e_flow                               38 passed, 1 ignored (was 21; +17: a4_import 4, a4_ldap 5,
                                                                        a4_net 4, a4_update 4), gate matrix green
pnpm test                                                               69 files, 521 passed
make e2e (MOORING_E2E_BROWSER=/usr/bin/google-chrome)                   flows 5 + kube 6 + vsphere 4 + secrets-sync 7 + a4 10 = 32 passed
```

Commits: `7bc4c4d` test(fuzz) · `2bda142` test(import) · `f26a6b5` test(app) · `03444b1`
test(e2e) · this note. `target/` and `fuzz/target/` removed before the report.
