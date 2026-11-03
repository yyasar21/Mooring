# A1 security review 3 — typed credentials (ADR-0009), release pipeline, public scrub

Reviewer: security-reviewer · 2026-11-03 · Range `git diff effedb4..e7a9154 -- crates src-tauri
apps packages Cargo.toml deny.toml .github packaging scripts SECURITY.md .gitleaks.toml`
(plus `Cargo.lock`), 154 files.

Inputs:
- [ADR-0009](../adr/0009-credential-model.md).
- Handoffs `a1-rust-core-credentials.md`, `a1-ui-engineer-credentials.md`, `public-scrub.md`,
  `public-release.md` and `public-docs.md`.
- Reviews [a1-review.md](a1-review.md) and [a1-review-2.md](a1-review-2.md), and the
  [threat model](threat-model.md).

Evidence gathered here (Linux, `CARGO_INCREMENTAL=0`):
- `cargo test -p mooring-core -p mooring-store`: all green (core 64, store 18 + 11 + 7 + 5 + 6 +
  4 + 8 + 6). `mooring-proto-ssh` `become_` unit tests: 3 green.
- A scratch harness (outside the repo) called `kubeconfig::parse` and `CredentialFields::from_input`
  with hostile inputs. Results are quoted per finding.
- **Not run:** `cargo deny` and `cargo audit` (neither installed here, no advisory DB);
  `gitleaks` (not installed; the new regex was checked with Python); `actionlint` and the
  workflows themselves. The pinned action SHAs could **not** be re-resolved: this session has
  no GitHub API access. The release handoff says they were resolved with `git ls-remote` on
  2026-11-03.

## Verdict: `BLOCKER`

One blocker, **B-3**: a private key can be stored in **plaintext** and sent to the WebView
through the X.509 certificate field. A same-user database writer (T2) can also use the pending
legacy reseal to make Mooring decrypt a vault secret into that field. The fix is small and local
(below). Everything else is `APPROVE WITH NITS` with conditions.

What holds:
- **AAD binding.** Each secret is sealed with credential id ‖ 0x1F ‖ name. Row and name swaps
  give `Tampered` (`tests/credentials.rs:157-169`). Legacy names (`secret`, `secret2`) are
  disjoint from the new ones.
- **Secret names are a closed set per kind.** An unknown name gives `store.corrupt` on read and
  is refused on write.
- **`fields_json` is re-validated on every read** with `deny_unknown_fields` (16 structs), and
  derived values cannot be set over IPC.
- **The matrix is enforced in Rust**, not only in the UI:
  - `ensure_role_credentials` runs on connection create/update;
  - `set_connection_role_credential` checks the link;
  - `resolve_credential` re-checks, inherited credentials included;
  - `check_override_fit` checks the overrides.
  The `credential_kinds()` snapshot test pins the UI table to the Rust table.
- **The TOTP code never crosses IPC.** `credential_copy_otp` returns
  `{clearsInMs, validForMs}` only. The seed and the code are `Zeroizing`.
- **Clipboard.** Every copyable secret goes through the same `arboard` path, which asks for
  history and cloud exclusion and clears on timer, lock and exit.
- **Redaction.** `credential_answer` is redacted in `Debug` and `Serialize`. `ConnectSecret`
  and `Become` have hand-written redacting `Debug`.
- **UI secret handling.** Secret inputs are uncontrolled. No `console.*` call exists outside
  tests.
- **Migration 0003** follows the SQLite 12-step rebuild. Foreign keys are off only around the
  transaction, and `foreign_key_check` must be empty before `COMMIT`.

## Findings

Numbering continues from reviews 1 and 2.

| ID | Sev | Where | Finding | Exact fix |
| --- | --- | --- | --- | --- |
| **B-3** | **Blocker** | `crates/mooring-core/src/credential/validate.rs:91-97` (X509 normalise), `crates/mooring-store/src/legacy.rs:187-200` (`move_certificate`), `crates/mooring-core/src/credential/fingerprint.rs:99-115`, `apps/desktop/src/lib/credentials.ts:104-115` (`detectKind`) | **(a)** `x509.cert_pem` is a *plaintext* field. It only has to be multiline text that contains *one* certificate block; any other PEM block is kept. Harness result: a cert + `PRIVATE KEY` bundle is accepted, and `to_json()` contains the key. Combined `cert+key` PEM files are common, and the UI paste detector routes such a bundle (certificate first) into `cert_pem`. The key then sits in `mooring.db` in clear and goes to the WebView on every `credential_list`. That breaks the first non-negotiable rule. **(b)** Confused deputy before the reseal. A T2 that edits the DB can flip a migrated `ssh_key` row to `kind='x509'`. On the next unlock, `reseal_legacy` opens legacy `secret` (the private key) under its valid AAD, treats it as the certificate (`Target::CertPem`) and writes it into plaintext `fields_json`. `move_certificate` accepts it, because `fingerprint::x509_pem(..).ok()` tolerates failure and the field check is only "multiline text". | 1. In `validate.rs` X509 arm, after `multiline(..)`, require that every `-----BEGIN ` in `cert_pem` is exactly `-----BEGIN CERTIFICATE-----`. Then require `fingerprint::x509_pem(&f.cert_pem)` to succeed, except for the literal migration placeholder. Error text: `"cert_pem may contain certificates only; put the private key in key_pem"`. 2. In `legacy.rs::move_certificate`, use `fingerprint::x509_pem(text)?`, not `.ok()`, plus the same every-block-is-CERTIFICATE rule. On failure return `StoreError::Corrupt { what: "legacy certificate" }` **before** writing anything, so the legacy row stays sealed. 3. In `credentials.ts::detectKind`, when a paste holds both a certificate and a private-key block, split it: certificate blocks go to `cert_pem`, the key block goes to the `key_pem` secret input. Never put a key into a non-secret field. 4. Tests: `from_input(X509, cert+key bundle)` is refused, and the error does not echo the key. A migrated `ssh_key` row whose kind is flipped to `x509` makes `reseal_legacy` fail with `store.corrupt` and leaves `fields_json` without `PRIVATE KEY`. A UI paste of a bundle fills `key_pem` and leaves no key text in the non-secret value. |
| **M-5** | Medium (latent: gate before any Kubernetes session or kubeconfig export) | `crates/mooring-core/src/credential/kubeconfig.rs:28-30`, `:120`, `:153-170` | The forbidden-key check is an exact, case-sensitive match on the direct keys of `users[].user`. Harness results: `<<: {exec: {command: /bin/sh}}` (YAML merge key, inline mapping, no anchor) is **accepted**, and so is `Exec:`. Go YAML (go-yaml v2 behind `sigs.k8s.io/yaml`) applies `<<` merges. Older or lenient decoders also match JSON field names case-insensitively. A kubeconfig that Mooring calls "self-contained" could therefore run `exec` once it is handed to kubectl or client-go. | Reject any mapping key `<<` anywhere in the tree (`"kubeconfig may not use YAML merge keys"`). Compare forbidden keys with `eq_ignore_ascii_case`. Apply the user-key list to every mapping under `users[]`, not just the `user` body. Tests for `<<`, `Exec`, `AUTH-PROVIDER` and a merge under `users[0].user`. |
| **M-6** | Medium | `crates/mooring-proto-ssh/src/become_.rs:44-48`, `:93-102`; `crates/mooring-proto-ssh/src/channel.rs:94-125` | The `sudo` prompt string is part of the typed command (`sudo -p '[mooring] become password: ' …`). The watcher inspects **all** output from the moment the command is sent, including the tty/readline **echo of that command**. If the echo reaches us split right after `password:` (readline redraws, long lines, pty read boundaries), the watcher fires early. The password is then written while the tty still has echo on: with a canonical-mode shell such as `dash` it is echoed in clear into the terminal stream, which means the WebView and the scrollback. Separately, a failed escalation (wrong password, not in sudoers) goes undetected (see the ruling below). | Make the printed prompt differ from the echoed text: use `sudo -p '[mooring]%% become password: '`. sudo prints `%%` as `%`, so match `[mooring]% become password:`, which never appears in the echo. For all methods, start matching only after the first `\n` in the output (the end of the echo). After sending, keep the watcher for another 4 KiB in "failure" mode: if the prompt reappears or the output matches `Sorry, try again`, `incorrect password` or `Authentication failure`, write `\x03`, emit `SessionEvent::Notice("become failed")` and audit `become_failed {connection}`. Never resend. Tests: echo split at every byte offset never triggers; prompt reappearance sends `^C` once and no second password. |
| **M-7** | Medium (gate: before the first signed public release) | `.github/workflows/release.yml:93-96`, `:283-288`, `:301-327` | **Release job isolation.** (1) The `build` jobs hold `contents: write` while they run third-party code: `pnpm install`, npm and cargo build scripts, `tauri-action`, and `cargo install artifact-signing-cli`. A poisoned dependency (T6) can therefore replace or add assets in the draft release, including other platforms' assets. (2) `finalize` checksums *whatever is in the draft* and signs it. (3) `finalize` holds `id-token: write` while it runs `cargo install cargo-cyclonedx` and `anchore/sbom-action` (which downloads syft at run time). Either could mint an OIDC token and cosign-sign an arbitrary `SHA256SUMS` under the genuine `release.yml` identity, which `verify-release.sh` and the Homebrew job trust. | Split by privilege. (a) `build`: `contents: read` only. Upload bundles with `actions/upload-artifact` (SHA-pinned) and set tauri-action without `releaseId`, or keep `releaseId` only in a separate `publish-assets` job. (b) New `sbom` job, `contents: read`, no `id-token`: runs cyclonedx and syft and uploads the SBOMs as an artifact. (c) `finalize`, the only job with `contents: write` + `id-token: write` + `attestations: write`: runs **no** `cargo install` and no third-party action except cosign-installer and attest-build-provenance. It downloads the workflow artifacts (not the draft), writes `SHA256SUMS`, signs, attests and uploads. Pin syft with `syft-version:`. |
| **L-10** | Low | `crates/mooring-core/src/credential/kubeconfig.rs:125`; `src-tauri/src/commands/credentials.rs:204-235` (sync commands) | Duplicate-key detection scans the whole map for each key, which is quadratic. Harness: one flat mapping with 30 000 keys (349 KB) takes 2.0 s; 60 000 keys (709 KB) take **10.3 s**; near the 1 MiB cap it takes more. The `credential_*` commands are synchronous `#[tauri::command]`s. Tauri runs those on the main thread, and they also hold the store mutex. A hostile kubeconfig (T4: a file the user pastes) freezes the app. | Use a `HashSet<&str>` per mapping for duplicates, and cap entries per mapping at 4 096 (`"kubeconfig has too many keys in one mapping"`). Make `credential_create`, `credential_update_fields` and `credential_replace_secrets` `async` and run the store call inside `tauri::async_runtime::spawn_blocking`, as L-3 did for the KDF. Test: a 1 MiB single-mapping file is rejected or parsed in < 200 ms in release mode. |
| **L-11** | Low (must land before the first public release) | `src-tauri/src/commands/vault.rs:95-101` | `reseal_legacy` is not called. Migrated rows keep their legacy names and the x509 placeholder `cert_pem` until it runs. Nothing is exposed, but the alias table becomes permanent and B-3(b) stays reachable. | Ruling: call it from `vault::unlock` right after the successful `with_ready` bind: `if let Err(e) = state.with_ready(\|v, s\| Ok(s.reseal_legacy(v)?)) { tracing::warn!(code = %IpcError::from(e).code, "legacy reseal deferred"); }`. Non-fatal: unlock still succeeds. Test: a v2 DB is unlocked once, then `reseal_pending()` is false, and the B-3 kind-flip test fails closed. |
| **L-12** | Low | `scripts/release/verify-release.sh:52-72` | A failed provenance check (`gh attestation verify`) and files not covered by `SHA256SUMS` only produce warnings; the script still says "verified" and exits 0. | `exit 1` when `failed > 0` (if `gh attestation` is available) and when `UNLISTED` is non-empty. Add `--allow-unlisted` for manual use. |
| **L-13** | Low (condition before setting the Azure secrets) | `.github/workflows/release.yml:201-203`, `:227` | `artifact-signing-cli` 0.12.0 is a community crate (`levminer/trusted-signing-cli`, first published 2026-05, about 10k downloads). It runs with `AZURE_CLIENT_SECRET` in its environment and signs the Windows binaries. It is pinned by version and the crates.io checksum, but it has no security review. | Prefer Microsoft's `Azure/trusted-signing-action` (SHA-pinned) or the `sign` .NET tool from the .NET Foundation. If the crate stays, record it in the threat model as a reviewed signing dependency and bump it only with review. |
| **L-14** | Low (qa-engineer / orchestrator scope) | `.github/workflows/security.yml:13-45`, `.github/workflows/ci.yml:19-25`, `.github/workflows/test-vectors.yml:22` | Those workflows still use tag pins (`@v4`, `@v2`, `@stable`) and an unpinned `semgrep/semgrep` container. The release workflows are SHA-pinned; these are not. | Pin to the SHAs already used in `release.yml`. Pin `cargo-deny-action`, `audit-check`, `gitleaks-action` and `upload-sarif` by SHA, and the container by digest. Dependabot (`github-actions`) keeps them current. |
| **N-5** | Nit | `crates/mooring-store/migrations/0003_typed_credentials.sql:35`, `src-tauri/src/commands/connect_plan.rs:58-60` | A migrated row with no username logs in as the literal `(unset)`. That is harmless, but it sends a bogus user name to the server. | Ruling below: keep the placeholder; `session_open` refuses it with `credential.secret_missing`-style text "Set a username for this credential". |
| **N-6** | Nit | `apps/desktop/src/components/credentials/CredentialsView.tsx:23`, `:38` | The pasted blob (for example a private key) stays in `draft.seed` React state for the editor's lifetime. The editor's own ref is cleared once it is consumed. Covered by R-IPC-BUF, but it contradicts "never enters React state". | After the editor mounts, call `setDraft(d => d && { kind: d.kind, n: d.n })`: keep the key, drop the seed. |
| **N-7** | Nit | `crates/mooring-core/src/credential/validate.rs:137-144` | `external_ref.reference` is plaintext. Users may paste a full secret URL with an embedded token (`?token=`, `hvs.`, `0.` Bitwarden access tokens). | Refuse references that contain `token=`, `secret=`, `hvs.` or a 40+ character base64/hex run, with "store only the reference, not a credential". |
| **N-8** | Nit | `.github/workflows/release-homebrew.yml:89` | The tap token is embedded in the clone URL and persisted in `tap/.git/config` for the rest of the job. | `git -c http.extraHeader="Authorization: basic $(printf 'x-access-token:%s' "$TAP_TOKEN" \| base64 -w0)" clone …`, or `gh repo clone` with `GH_TOKEN`. |
| **N-9** | Nit | `.gitleaks.toml:29-37` | The `private-ipv4-outside-tests` rule exempts every test path, yet the scrub rule says tests use RFC 5737 too. The regex is RE2-safe and correct (checked: matches 10/8, 172.16/12, 192.168/16; not 172.32.x or 192.0.2.x). It also matches inside longer dotted strings (`v1.10.0.0.1`), which is acceptable. | Drop the test-path exemptions and allow-list only the generic `10.0.0.1` with a `regexes` entry. Consider a second generic rule for CGNAT `100.64.0.0/10` and IPv6 ULA `fd[0-9a-f]{2}:`. |

### Carried forward (still open, unchanged by this range)
- From review 2: L-1..L-9 and N-1..N-4 as scheduled; the M-2/M-3 wiring gates; the keyring HOLD
  (R-T2-KR). M-1 and M-4 are now fixed in the tree: the pending digest is cleared on lock and
  exit, and the xterm `linkHandler` is inert.
- **Fuzz targets (CLAUDE.md rule) are still missing** for every new parser: `kubeconfig::parse`,
  `fingerprint::{ssh_public_key, ssh_certificate, ssh_private_key, x509_pem}`,
  `otp::decode_seed` and `parse_account`. Proptests stand in. Hard gate: no Kubernetes session
  and no `~/.kube/config` import before `kubeconfig_parse` has a cargo-fuzz target with a seed
  corpus that includes the M-5 cases.

## Rulings on open decisions

### `a1-rust-core-credentials.md`
1. **Placeholders** `(unset)` and `(sealed until the next unlock)`: **keep** them, because making
   `username` optional would weaken validation for every new row. Add N-5. The x509 placeholder
   disappears with the reseal (L-11) and must be exempt only as that exact literal under B-3.
2. **Reseal call site**: **call it from `vault_unlock`** (L-11), non-fatal, before the first
   public release. It must also run before any future `vault_export`, so that exports never
   carry legacy names.
3. **`credential_answer`** in ADR-0007 and **`connection_set_role_credential`**: both are
   approved from the security side. The answer is size-capped and its password redacted, and
   the role command validates the matrix. Keep both.
4. **New dependencies**: approved with conditions (see Dependencies).
5. **`become` failure undetected**: **Medium, merged into M-6.** The UI shows the remote
   output, so the user can see "Sorry, try again". But a user who trusts the "Become (sudo)" row
   may run commands believing they are root, and the second sudo prompt (labelled `[mooring]`)
   invites them to type the password into a stream that we no longer watch.
6. **Kubeconfig `username`/`password` users** (deviation 8): accept for now (no file or exec
   risk). They are sealed with the whole file. Revisit with the Kubernetes session ADR.

### `a1-ui-engineer-credentials.md`
- The client-side checks are mirrored in Rust: kind caps, `deny_unknown_fields`, the matrix,
  overrides, required secrets and kubeconfig rejection. The UI is advisory; Rust is
  authoritative. Copy the TS `parse_account` vectors into `account.rs` tests (UI handoff, left
  open).

### `public-release.md`
- **cosign keyless instead of minisign: approved.** No long-lived key, the identity is bound to
  `release.yml` in this repo, and every signature is logged in Rekor. Update
  `.claude/agents/release-engineer.md`, A4.md and `SECURITY.md` (done here).
- **tauri-action v1.0.0: no objection**, provided the SHA is the v1.0.0 tag commit (not
  re-verified here, see above).
- **Updater**: `latest.json` is produced but unused. Adding `tauri-plugin-updater` is a
  capability and trust-root change. It needs its own security review: pinned pubkey, an
  `https` endpoint on the GitHub release only, and no downgrade.
- **Entitlements**: the empty dict plus hardened runtime is approved (least privilege).
  Enabling `keychain-access-groups` belongs to the R-T2-KR macOS work and needs review then.

### `public-docs.md`
- `SECURITY.md` is **amended** by security-reviewer (see `SECURITY.md` in this commit). The
  docs agent's structure is kept, but two claims were wrong: "Linux minisign" signing, and
  "releases are signed" stated as unconditional.

## Checklist results

### 1. ADR-0009 implementation
- **Kinds and caps** follow ADR §5. They are enforced in `mooring-core` before SQL and before
  sealing; IPC also caps first (1 MiB per secret, 8 secrets, 128 KiB `fields`). VNC passwords
  over 8 bytes are rejected, not truncated. Single-line text refuses control, bidi and
  invisible characters, and PEM/YAML allow only `\n\r\t`. Validation errors name the field and
  never the value (tests assert no echo).
- **Secret naming and AAD**: correct; see Verdict. `open_secret` refuses a name that is not in
  the kind's schema before touching SQL.
- **Migration 0003** has these properties:
  - The directive is read from the first line only, and the pragma is set outside the
    transaction (inside one it would be a no-op).
  - `pragma_foreign_key_check` is evaluated inside the transaction, so a violation rolls back.
  - Foreign keys are restored even on error. One nit: a failing restore would mask the
    original error.
  - `ALTER TABLE … RENAME` with modern SQLite leaves the `folder`/`connection` FK text pointing
    at `credential`, which is the new table. Test `migration_v2` proves the links survive.
- **TOTP**:
  - Seed: ≤ 128 text bytes, ≥ 10 decoded bytes. Parameters are limited to digits 6|8, period
    30|60 and sha1/256/512 (`deny_unknown_fields`).
  - RFC 4226/6238 vectors pass. The code and the seed are `Zeroizing`; the code goes to the
    clipboard only.
  - Constant-time compare is not needed: we generate codes and never verify them.
- **Kubeconfig parser**: see M-5 and L-10. Otherwise sound:
  - Rejected: anchors, aliases, tags, duplicate keys, more than one document, depth > 32,
    > 100k nodes and > 1 MiB.
  - The scanner's own flow-level counter adds a second recursion bound: 200 000 nested `[`
    are rejected in 1.6 ms.
  - Alias and billion-laughs bombs cannot expand, because aliases are refused at the event
    level.
- **PEM and OpenSSH**: inputs are capped before parsing. Encrypted private keys are inspected
  without running the bcrypt KDF. FIDO `sk-*` keys are refused up front. The X.509 fingerprint
  hashes the DER of the first block; see B-3 for what else the field may hold.
- **`become`**: the target user is shell-safe (`[A-Za-z0-9._-]`, no leading `-`, ≤ 64) and
  checked before connecting. The password is sent once, only on a detected prompt, and only
  within 4 KiB. See M-6.
- **Clipboard**:
  - `copyable` is set on login passwords, passphrase, become, token, client_secret and the VNC
    password. It is *not* set on `private_key`, `key_pem`, `kubeconfig_yaml`, `otp_seed` or
    `refresh_token`.
  - The OTP clear time is never later than the code's validity.
  - One pending digest: a later copy replaces it, and the older timer leaves a changed
    clipboard alone.
- **Overrides**: trimmed, capped (256/253) and free of forbidden characters. They are checked
  against the effective kind on write, and `normalise` runs again after `apply_overrides`, so
  an override cannot create an invalid account.
- **UI**: invokes only in `ipc.ts`; no `innerHTML`; secret inputs are uncontrolled with
  `autocomplete=new-password` and are wiped on submit. The connect-time prompt's password is
  read from a ref and cleared. Paste detection never logs. The `localStorage` use is the theme
  only.

### 2. `fields_json` plaintext (R-INV extension)
Readable by T1/T2 and served to the WebView: usernames, NetBIOS domains, UPNs, vSphere
accounts, OAuth `client_id`/`token_url`/`scope`, the API header name/scheme, the become method
and user, kubeconfig context names, SSH public keys and **OpenSSH certificates** (principals,
key id, CA), **X.509 certificates** (subject, SANs, often internal host names), fingerprints
(they link keys across hosts), `external_ref` references (vault paths and item names), OTP
parameters and `secretNames` (which accounts have 2FA or a passphrase). Accepted as an
extension of R-INV per ADR-0009, with B-3 making sure no key material can land there. The threat
model is updated.

### 3. Dependencies
`cargo-deny` and `cargo-audit` are **not installed** here and were not run. They must pass in
`security.yml` before merge.

| Crate | License | `unsafe` in crate src | Notes | Ruling |
| --- | --- | --- | --- | --- |
| `saphyr-parser` 0.3.3 (**new**) | MIT OR Apache-2.0 | 0 | saphyr-rs org, yaml-rust2 lineage; scanner has its own recursion limit | **Approve**; fuzz target required (gate above) |
| `arraydeque` 0.5.1 (**new**, via saphyr) | MIT/Apache-2.0 | 72 | Fixed-capacity ring buffer for scanner lookahead; low release cadence | **Accept** as R-YAML-DEQ; the fuzz target runs under ASan; replace if saphyr drops it |
| `ssh-key` =0.7.0-rc.11 | Apache-2.0 OR MIT | 0 | RustCrypto pre-release, same exact pin as russh | Approve; follow russh's pin |
| `pem-rfc7468` 1.0.0 | Apache-2.0 OR MIT | 1 | RustCrypto, already in tree via `der` | Approve |
| `data-encoding` 2.11.1 | MIT | 6 | Widely used, already in tree via russh | Approve |
| `hmac` 0.13 / `sha1` 0.11 | MIT OR Apache-2.0 | 0 / 7 | RustCrypto; HMAC-SHA1 is the RFC 6238 default (no collision exposure) | Approve |
| `sha2-next` = `sha2` 0.11.1 | MIT OR Apache-2.0 | 39 (SIMD backends) | Rename to sit beside workspace `sha2` 0.10; both versions were already in the lock | Approve; **removal condition**: drop the alias when the workspace moves to `sha2` 0.11 |

`Cargo.lock` diff: only `saphyr-parser` and `arraydeque` are new packages. `digest` 0.10/0.11
and `sha2` 0.10/0.11 were already duplicated (`multiple-versions = "warn"`). All licenses are
in the `deny.toml` allow-list.

### 4. Release pipeline
- **Pinning**: every `uses:` in `release*.yml` is a 40-hex SHA with the tag in a comment
  (not re-verified here). Third-party binaries come in through `cargo install --version …
  --locked` and through tauri-action's own downloads; see M-7 and L-13.
- **Permissions**: top-level `contents: read`, with per-job escalation. See M-7 for the
  job-boundary problem. `persist-credentials: false` is set on every checkout. Release builds
  use no cache (good: no cache poisoning from PRs).
- **Secret handling**:
  - No step echoes a secret. Values go into `$GITHUB_ENV` with a random heredoc delimiter,
    which prevents environment injection.
  - The `.p8` file is mode 0600 in `RUNNER_TEMP`; the PFX is deleted after import.
  - Signing is conditional on each secret being non-empty, and forks build unsigned.
  - Accepted (R-REL): signing secrets live in the environment of the bundling step, and with it
    of npm and cargo build scripts. Tauri's bundler requires this.
- **Supply chain**: SHA256SUMS + cosign keyless + Rekor, CycloneDX SBOMs (cargo, and syft over
  the source tree) and SLSA provenance via `attest-build-provenance` (`subject-checksums`). The
  verifier identity regexp accepts exactly `release.yml@refs/tags/<tag>` or `@refs/heads/main`.
- **Homebrew tap bump**:
  - It runs on `release: published` with a read-only `GITHUB_TOKEN`.
  - It verifies `SHA256SUMS` with cosign *before* rendering, and validates the tag, version and
    identifier with regexes before they reach `sed`.
  - The fine-grained PAT is limited to `yyasar21/homebrew-mooring` with Contents RW: approved.
    See N-8.
- **`bump-version.sh`**: approved. It validates SemVer, runs Python with `-I`, never uses
  `eval`, only rewrites anchored version lines, has a `--dry-run`, and never commits, tags or
  pushes.
- **Entitlements and bundle**: empty entitlements with hardened runtime; Windows
  `allowDowngrades: false` and SHA-256 digests; NSIS per-user. The RFC 3161 timestamp URL over
  `http` is normal: the responses are signed.

### 5. `SECURITY.md`
Amended (owner: security-reviewer):
- The signing statement now matches the pipeline (cosign keyless `SHA256SUMS`; platform signing
  where configured), with a pointer to `scripts/release/verify-release.sh`.
- The release pipeline is added to scope.
- An embargo-extension clause is added.
- A note says private vulnerability reporting must be enabled.

Supported versions, reporting channel and timeline (72 h acknowledgement, 7 days triage, 30 days
critical/high, 90 days coordinated disclosure) are approved as written.

### 6. Scrub and git history
- **Tree**: clean. A grep for the private DNS zone, the old bundle id, private IPv4 ranges,
  `.local`/`.lan` names and absolute home paths finds only generic values:
  - `10.0.0.1` and `*.lan` names in `known_hosts_tests.rs`;
  - `vsphere.local`, the vendor's default SSO domain;
  - `/home/u/.kube/...` fixtures.
  The commit authors are the maintainer's public identity and `noreply@anthropic.com`, kept on
  purpose.
- **History: finding G-1 (release gate, not a merge blocker).** `git log --all -p` still
  contains **77 lines** with the private DNS zone, 14 distinct private host names, 13 distinct
  RFC 1918 addresses and 3 commit messages that name lab hosts. The values are not repeated
  here. Recommendation, in order:
  1. **Publish a new repository with one squashed initial commit** (option (a) of the scrub
     handoff): `git checkout --orphan public && git commit` from the scrubbed tree, pushed to a
     **new, empty** public repo. This is the only option that leaves nothing behind.
  2. **Do not flip the visibility of the existing private repo**, even after `git filter-repo`.
     GitHub keeps `refs/pull/*` heads, cached commit objects reachable by SHA, and fork
     networks; a force-push does not remove them. Keep the old repo private or archive it.
  3. If history must be kept: `git filter-repo --replace-text <expressions> --replace-message
     <expressions>` on a **fresh clone**. Then verify with a grep of `git log --all -p` and
     `git log --all --format=%B` (0 hits), `git reflog expire --expire=now --all && git gc
     --prune=now`, and push to a **new** repo as in step 2. The expressions file lives outside
     the repo and is never committed.
  4. Either way, rotate anything that ever appeared in history and is still live (lab
     passwords were never committed; the host names and addresses stay in the old repo).

### 7. `.gitleaks.toml`
The new rule parses as TOML and the regex is RE2-compatible (no look-around). Its keywords are
lower-case literals, as gitleaks requires. The top-level `[allowlist]` still applies on gitleaks
8.x (newer versions prefer `[[allowlists]]`; migrate when the action is bumped). See N-9.

## Conditions for merge
1. **B-3 fixed with its tests.** Re-review only the B-3 diff.
2. `security.yml` green on the PR: cargo-deny, cargo-audit, gitleaks with the new rule,
   semgrep.
3. M-5, M-6, L-10 and L-11 may land in the same or the next PR. M-6 and L-11 must land before
   the first public release, M-5 before any Kubernetes or kubeconfig consumer, and M-7 before
   the first signed release.

## Test evidence
```
CARGO_INCREMENTAL=0 cargo test --offline -p mooring-core -p mooring-store      all ok (0 failed)
CARGO_INCREMENTAL=0 cargo test --offline -p mooring-proto-ssh --lib become_    3 passed
scratch harness (mooring-core, release build):
  x509 cert_pem with a PRIVATE KEY block           accepted=true, key present in fields JSON   (B-3)
  kubeconfig user with `<<: {exec: …}`             accepted=true                               (M-5)
  kubeconfig user with `Exec:`                     accepted=true                               (M-5)
  kubeconfig flat map 30 000 keys / 349 KB         2.0 s                                       (L-10)
  kubeconfig flat map 60 000 keys / 709 KB         10.3 s                                      (L-10)
  200 000 nested flow sequences                    rejected in 1.6 ms
gitleaks regex (Python re): RFC 1918 matched; 172.32/16, 192.0.2/24, 110.0.0.1 not matched
not run: cargo-deny, cargo-audit, gitleaks, actionlint, pnpm suites, mooring-app (src-tauri)
```
