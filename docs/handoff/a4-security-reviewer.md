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
