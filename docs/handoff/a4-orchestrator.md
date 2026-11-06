# A4 — orchestrator handoff (code complete; tag pending)

## Done
- ADR-0018 (release v0.1.0: cosign keyless, updater on demand, repro check, unsigned first
  release accepted), ADR-0019 (+ amendment: own LDAP reader, `ldap3` dev-only), ADR-0020
  (network tools) — accepted with owner decisions inline.
- Waves: R1 pipeline/updater config ∥ U0 updater commands ∥ I1 import crate (6 formats) ∥ N1
  network tools ∥ U3 icon + About → U2 Updates/Network cards ∥ I2 LDAPS ∥ U1 import wizard +
  onboarding ∥ site refresh → U4 LDAPS form → Q1 (18 fuzz targets, hostile suites, 10 E2E) →
  review 7 → F1 (Q1 gaps, audit split) ∥ R2 (M-17 sign-updater job + `release` environment,
  toolchain pin, tag-ref identity, tap token) → F2 (L-39..L-43, N-50..N-56, N-60) ∥ U5 → re-review
  7b: **APPROVE WITH NITS** for the merge; v0.1.0 tag conditional (below).
- Owner decisions taken: in-house CSV reader (no `csv` crate); `.rtsz` ZIP refused; `ldap3`/
  `osakit` maintenance exceptions; updater Rust-only, no window permission; Return on the
  "remember" dialog refuses; everything in review 7 fixed (no acceptances by the owner —
  the reviewer accepted L-40's manifest-cap residual and L-43's probe-before-dialog under
  R-UPD / R-LDAP-STR until 0.1.1).
- Final gate (cloud Linux): fmt, workspace clippy `-D warnings`, 1517 Rust tests, `cargo deny`,
  `--locked` (root + fuzz), 55 fuzz bins build, vitest 549, `pnpm build`, E2E 33/33.
- Updater key pair generated 2026-11-06; the private key lives only on the owner's Mac at
  `Desktop/Mooring/.ci-logs/updater/` (gitignored); the public key is in `tauri.conf.json`.

## Left open (conditions before the v0.1.0 tag)
1. **Owner GitHub settings** (before any key secret exists): environment `release` with the
   owner as required reviewer and deployment limited to tags `v*`; `TAURI_SIGNING_PRIVATE_KEY`
   + `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` (empty) as **environment** secrets only; tag ruleset
   `v*` (owner only); `main` ruleset (PR + review, no force push / deletion).
2. **L-14**: pin the semgrep container by digest (`docker buildx imagetools inspect
   semgrep/semgrep:latest --format '{{.Manifest.Digest}}'`; Docker Hub is unreachable from the
   agent sandboxes).
3. **rc.2 dry run**: `actionlint` on the Mac, then `git tag -a v0.1.0-rc.2 -m "…" <main>` and
   push → draft pre-release; `scripts/release/verify-release.sh v0.1.0-rc.2`; check the trusted
   comment (N-62); run the updater leg from `docs/handoff/a4-qa-q1.md` Decision 3 including a URL
   outside the prefix; `release-repro.yml` result.
4. **Per-OS manual gates** (owner + qa): `docs/qa/native-dialogs.md` (six dialogs incl.
   "Directory sign-in"), L-31, ADR-0013 E2E, ADR-0016 §4 OIDC interception, Windows L-29 E2E,
   net tools on Windows, fresh-install smoke on macOS / Windows 11 / Fedora.
5. Carried: G-1 (fresh squashed repository — owner's call), N-61..N-64 (0.1.1), the ADR-0018 §6
   gates, `make release VERSION=0.1.0` rolls CHANGELOG/version on the day.
6. Docs refresh at the tag: README status banner, site hero/Download, CHANGELOG `[0.1.0]`,
   user guide "Installing an unsigned build", Reddit/Medium posts (owner's launch plan).

## Decision needed
- None blocking the merge. The tag waits on the owner items above.

## Test evidence
- `docs/handoff/a4-qa-q1.md`, `a4-rust-core-f1.md`, `a4-rust-core-f2.md`, `a4-ui-u5.md`;
  CI runs of the merge commit on `main`.
