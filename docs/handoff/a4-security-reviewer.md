# A4 — security-reviewer handoff (review 7)

Date: 2026-11-06 · Worktree from `a4` @ `cfca0ff` · Range `git diff fc41747..HEAD`

## Done
- [`docs/security/a4-review-7.md`](../security/a4-review-7.md): **`APPROVE WITH NITS`** for the
  merge. The `v0.1.0` tag stays conditional. There are no blockers.
- One Medium: **M-17**. The updater private key would sit in the environment of every
  npm/cargo build script in `release.yml` `build`, and no GitHub Environment protects it.
  This is a **condition before `TAURI_SIGNING_PRIVATE_KEY` is created**.
- Five Low: L-39..L-43. Ten Nits: N-51..N-60.
- [`docs/security/threat-model.md`](../security/threat-model.md):
  - A4 assets (updater key, import plans, `known_ldap_certs`);
  - a new "Trust boundaries added in A4" section;
  - STRIDE rows for the updater, importers, LDAPS and the net tools;
  - R-REL updated; new R-UPD, R-IMPORT-SECRET, R-LDAP-STR and R-NET-PROBE;
  - open items: M-12, L-19, L-11, M-7, L-12 and N-9 closed; an A4 block added.
- [`SECURITY.md`](../../SECURITY.md):
  - supported versions are now `0.1.x`;
  - new "Verifying a download" section (unsigned v0.1.0, `verify-release.sh`, manual
    `cosign verify-blob`);
  - new "In-app updates and their trust" section (opt-in, unsigned manifest plus signed
    artifacts, key id, no elevation, second trust root);
  - A4 scope and an importers / net summary.
- Rulings asked for in the handoffs:
  - `ldap3` is dev-only and the own LDAP v3 reader with `lber` behind the iterative scan is
    approved (I2 Decision 1).
  - `TlsClient` for a non-HTTP caller is approved (I2-5).
  - `import_pick` without bytes is approved (I1-1).
  - `pick_filtered` and the `"import"` pick session are approved (I1-3).
  - The in-house CSV reader is approved instead of the `csv` crate (architect-2).
  - The `osakit` maintenance exception is approved (architect-1).
  - `update.install_failed` and the 4 KiB notes cap are approved (U0).
  - The fuzz `[patch] age` is the same commit as the root patch: approved.

## Left open (owners)
- **release-engineer:**
  - M-17 (1)–(2): build without the key, add a `sign-updater` job, put the key in an
    environment secret.
  - L-39 config (`requireSignedVersion: true` in `tauri.conf.json`; check the trusted comment
    in the rc.2 dry run and in `verify-release.sh`).
  - N-57 (one pinned toolchain).
  - N-8 (tap token in the clone URL).
- **owner:**
  - M-17 (3): a `release` environment with tag-only deployment and owner review; rulesets on
    `v*` tags and `main`.
  - G-1: a fresh squashed repository.
  - Do not create `TAURI_SIGNING_PRIVATE_KEY` before M-17.
- **rust-core:**
  - L-39 mapping (`MissingSignedVersion` → `update.signature`);
  - L-40 (download URL prefix, size cap, capped download, then `Update::install`);
  - L-41 (key files only for `known: openssh`);
  - L-43 (per-(credential, host) native confirmation for LDAP binds);
  - N-51, N-53, N-54, N-55, N-56, N-59, N-60.
- **qa-engineer:**
  - L-14 remainder (semgrep container digest);
  - per-OS runs: native dialogs including LDAPS trust, the updater leg (Q1 Decision 3), and
    Windows net tools;
  - L-28 nightly run and `rdp_reactivation` (after rust-core's entry point).
- **ui-engineer:**
  - L-42 site / README wording;
  - L-41 (key toggle only on the known-location tile);
  - L-36 VMRC help text.
- **architect:** align ADR-0019 §3 (`import_pick` returns `size`) and §4 (ldap3 dev-only,
  filter shape, 5 000 / 30 s) with what shipped.
- **Carried per-OS conditions:** L-31, the ADR-0013 E2E, the ADR-0016 §4 OIDC interception
  and the Windows L-29 E2E. L-13 applies before any Azure secret; N-50 with F1.

## Decision needed
- **Owner, M-17:** either the `sign-updater` job (recommended) or a written acceptance under
  R-UPD that keeps signing in the build job. Environment protection (3) is wanted either way.
- **Owner, L-43:** native confirmation per (credential, host), recommended, or an explicit
  acceptance that a compromised WebView can bind any password credential to any CA-valid
  LDAPS host without a dialog.
- **Owner, L-40:** fix before the tag, or accept until 0.1.1 under R-UPD. The signature still
  prevents installation; what remains is the host choice and the memory/availability risk.

## Test evidence
- `cargo deny --offline check`: advisories ok, bans ok, licenses ok, sources ok.
- `cargo audit --no-fetch` (local DB, 1409 advisories, 847 crates): RUSTSEC-2023-0071 only
  (R-RSA, ignored); unmaintained warnings are all pre-A4 edges (`pin-utils` via `sspi`).
- `cargo tree --workspace --target all -i` for every new lock entry (review 7 §7).
- Registry sources read: `tauri-plugin-updater` 2.14.1 (`updater.rs`, `config.rs`) and
  `reqwest` 0.13.5 (`redirect.rs`).
- Greps: no `updater:` in capabilities or permissions; `invoke(` only in `lib/ipc.ts`; every
  `uses:` in `security`/`ci`/`test-vectors` SHA-pinned.
- Not run: builds, tests, cargo-geiger (not installed), gitleaks, semgrep, pnpm audit,
  cargo-fuzz, actionlint, the workflows, any per-OS check.

---

## Re-review 7b (2026-11-06, `a4` @ `eec26f0`)

### Done
- [`docs/security/a4-review-7.md`](../security/a4-review-7.md) § "Re-review 7b": closure
  table for R2, F1, F2 and the L-36 / L-42 wording. **`APPROVE WITH NITS` for the merge to
  `main`.** Nothing reopened.
  - Fixed: M-17 (1)(2)(4) (the key is only in the signing step of `sign-updater`,
    `environment: release`, `contents: read`, no checkout, CLI tarballs SHA-512-pinned and
    equal to `pnpm-lock.yaml`, lint). Also N-57, N-58, N-8, L-39 (incl. the monotonic floor),
    L-40 (URL pin, 256 MiB cap, 10 min deadline), L-41, L-43, N-50..N-55, N-59, N-60, L-36.
  - Partial: L-42 (`site/index.html:218`, `:311`, `README.md:105`), L-14 (semgrep digest),
    N-56 (hand list misses part of `Cf`), L-28 (nightly run owed).
  - Decisions: **L-40 manifest cap post-parse accepted under R-UPD until 0.1.1** (needs a
    direct `reqwest` fetch, reviewed as a dependency change). **L-43 TLS probe before the
    sign-in dialog accepted** under R-LDAP-STR (no more reach than `net_port_check`; no
    secret or LDAP frame before the confirmation).
  - New nits: N-61 (lint misses `toJSON(secrets)` / `secrets[` / `secrets: inherit` /
    another `environment: release`), N-62 (`verify-release.sh` does not assert
    `version:<v>`), N-63 (settings read-modify-write can overwrite `lastVerified`), N-64
    (`caPem` not audited).
- [`docs/security/threat-model.md`](../security/threat-model.md): asset row, A4 trust
  boundaries, STRIDE rows, R-REL, R-UPD (L-40 acceptance with its 0.1.1 expiry), R-LDAP-STR
  (L-43 residual), open items (A3 N-50 / L-36 closed; A4 block rewritten).

### Left open (owners)
- **owner (tag conditions):** the `release` environment (reviewer = owner; deployment tags
  `v*` only), `TAURI_SIGNING_PRIVATE_KEY{,_PASSWORD}` as **environment** secrets with no
  repository secret of that name, a `v*` tag ruleset (bypass = owner), a `main` branch ruleset
  (PR + review, no force push). Review the `.github/workflows/` diff before each deployment
  approval. The L-14 semgrep digest. G-1.
- **orchestrator / ui-engineer:** the L-42 remainder (before the tag). The L-41 toggle only on
  the known tile, and the F2 IPC codes in the UI (not security conditions).
- **release-engineer:** N-61, N-62. Run `actionlint` before the rc tag.
- **rust-core:** N-56 remainder (reuse `mooring_core`'s `is_bidi_or_invisible`), N-63, N-64.
  The L-40 own manifest fetch for 0.1.1.
- **qa-engineer:** the "Directory sign-in" row in `docs/qa/native-dialogs.md` and the per-OS
  run. The rc.2 updater leg (add: URL outside the prefix → `update.manifest`). One green
  nightly fuzz run.

### Decision needed
- None from the reviewer. The owner may still overrule the two acceptances (L-40 manifest
  cap, L-43 probe order) and ask for the fixes before the tag.

### Test evidence
- `bash scripts/release/lint-workflows.sh .github/workflows` → `ok`.
- Greps: `TAURI_SIGNING_PRIVATE_KEY` secret references only at `release.yml:494-495`;
  `environment:` only in `sign-updater` and `pages.yml`; no `uses:` without a 40-hex SHA;
  only `security.yml:51` has a floating container.
- `pnpm-lock.yaml:755`, `:785` integrity equal `release.yml:81-82`.
- Plugin source: `tauri-plugin-updater` 2.14.1 `updater.rs:688-696` (`restore_update` forces
  `require_signed_version`), `:895-925` (`verify` / `install`).
- Not run: builds, tests, actionlint, the workflows, any per-OS check.
