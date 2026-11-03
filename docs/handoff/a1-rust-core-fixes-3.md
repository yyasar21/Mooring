# A1 rust-core: fixes for security review 3

Agent: rust-core · 2026-11-03 · Worktree `agent-a1a23e4855725d52c`, branch
`worktree-agent-a1a23e4855725d52c`, base `b1aab78` (merge of A1 security review 3). Not merged.

Input: [a1-review-3.md](../security/a1-review-3.md). The orchestrator granted an exception for
`apps/desktop/src/lib/credentials.ts` and its tests, the credential form components that handle
paste, `.github/workflows/*.yml`, `scripts/release/verify-release.sh` and `.gitleaks.toml`.

## Done: finding → commit

| Finding | Commit | Change | Test (fails before, passes after) |
| --- | --- | --- | --- |
| **B-3** | `e17b8c6` | `fingerprint::x509_pem` refuses any PEM block that is not `CERTIFICATE` ("cert_pem may contain certificates only; put the private key in key_pem"). `normalise` (input **and** every stored read) requires `x509_pem` to succeed, except for the exact literal `X509_MIGRATION_PLACEHOLDER` = `(sealed until the next unlock)`. `legacy::move_certificate` calls `x509_pem(text)` and maps failure to `StoreError::Corrupt { what: "legacy certificate" }` before it writes anything. The reseal transaction rolls back, and the legacy `secret` stays sealed. UI: `detectKind` returns `parts`. A cert+key bundle is split: the `CERTIFICATE` blocks go to `cert_pem` and the `*PRIVATE KEY` blocks go to `key_pem`, in either order. A key that is pasted anywhere in the form outside a `data-secret` input is routed to the secret input or refused. It never reaches a plain field. | core `x509_refuses_any_non_certificate_block` (key before or after the cert, PUBLIC KEY block, placeholder; the error does not echo the key), `x509_cert_pem_refuses_a_bundled_private_key` (input and `from_stored`; the placeholder still reads). Store `kind_flipped_to_x509_never_moves_a_private_key_into_fields`: a migrated `ssh_key` row is flipped to `x509`, then `reseal_legacy` gives `store.corrupt`, the flag stays set, `fields_json` has no `PRIVATE KEY` and the legacy row is still there. Vitest `splits a certificate + private key bundle` (3 orders) and `splits a pasted certificate + key bundle: key into the secret input, never a plain field` (picker paste and a direct paste into the Certificate field). |
| **N-6** | `cdb7d7d` | `CredentialsView` drops `draft.seed.paste` once the editor has mounted and consumed it, and keeps only `{kind, n, name}`. The TOTP seed input was already uncontrolled (`SecretField`), so a regression test now pins that. | `drops the pasted blob from the view's React state once the editor has it (N-6)`: walks the React fiber hooks of the view (fails before). `keeps the OTP seed out of React state` (passes before and after: the input was already uncontrolled). |
| **M-5** | `6e57425` | Any mapping key `<<` anywhere is refused ("kubeconfig may not use YAML merge keys"). Forbidden user and cluster keys are compared with `eq_ignore_ascii_case` and searched in every mapping under each `users[]` / `clusters[]` entry, not only the direct keys of `user`. Anchors, aliases, tags, depth 32, 100k nodes and 1 MiB were already enforced (`rejects_yaml_tricks`). | `rejects_merge_keys_and_case_variants`: `<<: {exec: …}`, a harmless `<<`, `Exec`, `AUTH-PROVIDER`, `TokenFile`, a nested `exec`, a key beside `user`, a top-level merge, `Certificate-Authority`. No value is echoed. |
| **L-10** | `423f250` | Duplicate keys are found with a `HashSet` per mapping, and one mapping may hold at most 4 096 entries ("too many keys in one mapping"). `credential_create`, `credential_update_fields` and `credential_replace_secrets` are now `async`, and they call `offload(handle, bytes, f)`. At 64 KiB or more, `f` runs in `tokio::task::spawn_blocking`. `IpcError` passes through unchanged, and a panic becomes `{code: "internal", message: "internal error"}`. | `wide_mappings_are_capped_and_checked_in_n_log_n`: a ~1 MiB flat mapping took 166 s in a debug build before the fix. After it, the file is rejected in 0.04 s (release) and under 2 s (debug); 4 096 entries still parse and a late duplicate is still found. `large_inputs_run_off_the_calling_thread_and_keep_ipc_errors`, `a_large_kubeconfig_is_created_through_the_offload_path`. |
| **M-6** | `322e40f` | `sudo -p '[mooring]%% become password: '`, matched as `[mooring]% become password:`, which never appears in the echo. For every method, matching starts after the first `\n` (the end of the echo). After the password is sent, the next 4 KiB are watched for `Sorry, try again`, `incorrect password`, `Authentication failure`, `not in the sudoers` or the prompt again. On a match, the watcher sends `\x03` once, emits the `Bytes` notice `[mooring] become failed; the session continues as the login user`, pushes `TrustEvent::BecomeFailed`, and never resends. The Tauri layer records `AuditEvent::BecomeFailed { connection }` (`become_failed`). User input ends the failure watch. | Unit tests: `echo_split_at_every_offset_never_triggers` (current and old prompt forms, every byte cut), `failure_interrupts_once_and_never_resends` (five failure texts, split across reads), `success_and_user_input_end_the_watch_quietly`, `printed_prompt_never_appears_in_the_typed_command`. In-process server (now emulates the tty echo, the `%%` expansion and a wrong password): `become_failure_interrupts_once_notifies_and_keeps_the_login_user` sees exactly one password, one `^C` with nothing after it, the notice, and `BecomeFailed`, and the session still accepts input. `become_types_sudo_and_answers_the_prompt_once` failed on the old code against the echoing server. Tauri: `become_failure_is_audited_with_the_connection`. |
| **L-12** | `00329fd` | `verify-release.sh` (already `set -euo pipefail`) now exits 1 on: any file not covered by `SHA256SUMS` (`--allow-unlisted` downgrades this to a warning), an empty `SHA256SUMS`, any artifact without valid provenance, or an unknown option. It warns when `gh attestation` is missing. | New `scripts/release/verify-release.test.sh` with stub `gh` and `cosign`, 10 cases. 3 failed before (unlisted, `--allow-unlisted`, missing provenance); all 10 pass after. |
| **N-9** | `953120d` | The `private-ipv4-outside-tests` rule no longer exempts test paths. Only lockfiles are path-exempt, and only `10.0.0.1` is allow-listed by value. `known_hosts_tests.rs` now uses `192.0.2.10`. A new rule `private-cgnat-or-ula-address` covers `100.64.0.0/10` and `fd00::/8`; the range names themselves are allow-listed. | gitleaks was **not run** (see Left open). A Python check parses the TOML, classifies samples (RFC 1918, RFC 5737, `172.32`, CGNAT bounds, ULA, `2001:db8`) and scans the tracked tree: 0 hits. |
| **M-7** | `9f3f5ec` | `release.yml` is split by privilege. **build** has `contents: read`: tauri-action runs without `releaseId` or a token, and the bundles plus the `.pkg` go to `upload-artifact`. **sbom** (new) has `contents: read` and no id-token; it runs `cargo-cyclonedx =0.5.9 --locked` and syft with `syft-version: v1.55.0`. **publish** (new) has `contents: write` and no checkout; it uploads the artifacts to the draft. **finalize** has `contents`/`id-token`/`attestations: write`, no checkout and no `cargo install`. It uses only `cosign-installer` (with `cosign-release: v3.1.4`), `download-artifact` and `attest-build-provenance`. It hashes the **workflow artifacts**, not the draft, signs, attests and uploads, then fails if the draft holds any file that `SHA256SUMS` does not cover. | A structural check (Python + `yaml.safe_load`) asserts the job permissions and that the id-token job uses only the allowed actions and installs nothing. It also asserts that build and sbom never touch the release and that every `cargo install` is `=x.y.z --locked`. Passes. |
| **L-13** | `fbe12b1` | `cargo install artifact-signing-cli --version =0.12.0 --locked`, with a RISK comment: community crate, runs with `AZURE_CLIENT_SECRET`, bump only with review, replacement candidates. | The workflow check covers the exact pin. |
| **L-14** | `1ec4c1e` | `ci.yml`, `security.yml` and `test-vectors.yml`: every `uses:` is a commit SHA with a tag comment, resolved with `git ls-remote` on 2026-11-03 (annotated tags peeled). Checkout, setup-node, pnpm and rust-toolchain match `release.yml`; also rust-cache v2.9.3, cargo-deny-action v2.1.1, audit-check v2.0.0, gitleaks-action v2.3.9 and codeql upload-sarif v4.39.2. `rust-toolchain` now passes `toolchain: stable`. pnpm v6 reads its version from `packageManager`. | Workflow check: every `uses:` in all 5 workflows is a 40-hex SHA with a comment. |

The commits follow Conventional Commits, are in English, have no `Co-Authored-By`, and end with
the `Claude-Session` trailer.

## Left open

- **semgrep container digest (L-14).** `semgrep/semgrep` is still a floating tag, marked with a
  TODO in `security.yml`. This session's egress proxy refused Docker Hub.
- **gitleaks and actionlint were not run.** I downloaded both pinned releases and their checksums
  matched, but the permission system blocked running downloaded binaries, so I deleted them. The
  new gitleaks rules were checked only with Python `re`, which is close to RE2 for these patterns
  (no look-around). `security.yml` runs the real gitleaks on the PR. actionlint should be run
  once (`make check` or CI) before merge.
- **`latest.json` (M-7).** tauri-action no longer touches the release, so it does not produce
  `latest.json` or upload updater signatures. The updater artifacts (`*.app.tar.gz`, `*.sig`)
  still ship when the key is set. Review 3 recorded `latest.json` as unused, and enabling the
  updater needs its own review. `docs/release.md` (release-engineer) still mentions it; that
  section needs an edit.
- **macOS updater archive names (M-7).** The collect step renames `X.app.tar.gz[.sig]` to
  `X_<arch>.app.tar.gz[.sig]` to avoid collisions across the three macOS jobs, which is what
  tauri-action did before. This has not been exercised on a real runner. The first tag build
  should confirm the asset list.
- **Fuzz targets.** The fuzz gate carried forward from review 3 is unchanged: `kubeconfig_parse`
  still needs a cargo-fuzz target whose seed corpus includes the M-5 cases (`<<`, `Exec`).
- **Not in this task:** N-5, N-7 and N-8. L-11 was already wired in `vault::unlock`. With B-3,
  its kind-flip case now fails closed at unlock: the warning is logged and unlock still succeeds.

## Decision needed

- **M-6 notice text.** The failure notice is injected into the terminal stream as `Bytes`, which
  is what the task asked for. A dedicated `SessionEvent::Notice` would let the UI style it, but
  it means an ADR-0004 event change. Keep `Bytes`, or add the variant?
- **B-3 UI policy.** A private key pasted into any non-secret field of the credential form is
  now always intercepted. If that field's kind has no secret key input, the key is refused with a
  message. Confirm this is wanted for every kind, not only x509.

## Out-of-scope edits (for the orchestrator)

- `apps/desktop/src/components/credentials/CredentialEditor.tsx` and `CredentialsView.tsx`
  (B-3, N-6), plus `credentials.test.tsx`: these are the paste-handling components under the
  exception.
- `crates/mooring-audit` gains `AuditEvent::BecomeFailed` (a new wire name, `become_failed`).
- `src-tauri/tests/e2e_flow/credential_kinds.rs` (QA-owned): one expected string changed to the
  new sudo `-p` argument.
- No new dependency. `Cargo.toml`, `package.json` and the lockfiles are untouched.

## Test evidence

```
CARGO_INCREMENTAL=0 cargo fmt --all -- --check                               ok
CARGO_INCREMENTAL=0 cargo clippy --workspace --all-targets -- -D warnings     ok (0 warnings)
CARGO_INCREMENTAL=0 cargo test --workspace                                    390 passed, 0 failed, 3 ignored (36 binaries)
cargo test --release -p mooring-core wide_mappings                            ok, 0.04 s (L-10)
pnpm typecheck && pnpm lint && pnpm test && pnpm build                        ok; vitest 14 files, 109 tests
bash scripts/release/verify-release.test.sh                                   10 passed, 0 failed
python3 yaml.safe_load + structural check of .github/workflows/*.yml          5/5 parse; all uses: SHA-pinned; release privilege rules hold
python3 check of .gitleaks.toml                                               parses; regex samples ok; tree hits: 0
fails before → passes after: B-3 (store kind-flip, UI bundle), N-6 (fiber state), M-5,
  L-10 (166 s → 0.04 s), M-6 (2 integration tests vs old pump), L-12 (3 of 10 cases)
not run: gitleaks, actionlint (binaries blocked), cargo-deny, cargo-audit, semgrep
```
