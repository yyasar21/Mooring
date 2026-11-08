# A5 release-engineer: ADR-0018 A1 signing hooks + A2 winget

Date: 2026-11-08 · branch `worktree-agent-ab29b401a022fdedd` · scope: `.github/workflows/release*.yml`,
`scripts/release/**`, `packaging/winget/**`, `docs/release.md` (signing + winget section).
No Rust, no cargo run, no signing material.

## Done

### A1. Platform signing, inert until switched on (`release.yml`)
- **`build` holds no platform signing secret any more** (ADR-0018 A1, M-17 argument): the
  `APPLE_*`, `AZURE_*`, `WINDOWS_CERTIFICATE*` exports, the PFX import, the unreviewed
  `artifact-signing-cli` install (L-13) and the `signCommand` / thumbprint config keys are gone.
  macOS builds ad-hoc (`APPLE_SIGNING_IDENTITY=-`), Windows unsigned, the `.pkg` unsigned —
  exactly what a run without secrets produced before. The rpm key stays (rpm signing happens in
  the bundler).
- **`sign-macos`** (matrix arm64 / x64 / universal, `macos-15`) and **`sign-windows`**
  (`windows-2022`): `environment: release`, `contents: read`, job-level
  `if: vars.MACOS_SIGNING == 'true'` / `vars.WINDOWS_SIGNING == 'true'`. Unset → skipped, no
  approval prompt, downstream unchanged. Secrets are never used in `if:`; Windows decides its
  method in a gate step from env booleans (`secrets.X != ''`).
  - macOS: `scripts/release/macos-sign.sh` — throw-away keychain, inside-out `codesign
    --options runtime --timestamp` with `packaging/macos/entitlements.plist`, `notarytool submit
    --wait` (API key preferred, Apple ID fallback; status must be `Accepted`, log printed on
    failure), `stapler`, `spctl`; the **same** dmg (layout, background, volume name) via a sparse
    copy with the signed app, then dmg signed + notarized + stapled; `.pkg` via `macos-pkg.sh`
    (installer cert + notarization if present), updater `.app.tar.gz`, portable zip rebuilt from
    the signed app. Refuses unknown input files so nothing unsigned passes through.
  - Windows: exe taken from the build's portable zip → `target/<triple>/release/mooring-app.exe`,
    signed with `azure/artifact-signing-action@c7ab2a863ab5f9a846ddb8265964877ef296ee82 # v2.0.0`
    (resolved with `git ls-remote` 2026-11-08; `Azure/trusted-signing-action` redirects there)
    or `scripts/release/windows-signtool.ps1` (PFX); then `tauri bundle --bundles nsis,msi`
    (pinned CLI tarballs, new `TAURI_CLI_WIN32_X64_SHA512` = pnpm-lock entry, overlay first,
    no compile), installers signed, `Get-AuthenticodeSignature` must be `Valid`, portable zip
    rebuilt.
  - Both upload the signed set as `bundles-<name>` with `overwrite: true`, same file names
    (checked), so `sign-updater`, `publish`, `finalize` consume it unchanged.
- **`mooring_signed_build`**: `src-tauri/build.rs` only declares the cfg (`rustc-check-cfg`); it is
  set by `RUSTFLAGS="--cfg mooring_signed_build"` (handoff a5-rust-core-r2 §4). New build step
  `Mark the macOS build as Developer-ID-signed` writes that to `GITHUB_ENV` only when
  `runner.os == 'macOS' && vars.MACOS_SIGNING == 'true'`; otherwise `RUSTFLAGS` stays unset.
  Because the cfg is baked in before signing, `sign-macos` **fails** on an incomplete Apple set
  (it never ships a cfg'd binary ad-hoc). Windows with an incomplete set: notice, unsigned ships.
- `sign-updater` / `publish` / `finalize` got explicit `if:` (`!cancelled()`, build success, sign
  jobs success **or skipped**) — a skipped need would otherwise skip them by default.
- `lint-workflows.sh` rules 6/7: platform signing secrets only in `sign-macos` (APPLE_*) /
  `sign-windows` (AZURE_*, WINDOWS_CERTIFICATE*), both with `environment: release`, no other
  workflow; `WINGET_TOKEN` only in `release-winget.yml` job `submit`.

### A2. winget
- `scripts/release/winget/render.py`: templates (`packaging/winget`, schema 1.10.0) + the
  release's `SHA256SUMS` → `manifests/y/yyasar21/Mooring/<v>/{yyasar21.Mooring.yaml,
  .installer.yaml, .locale.en-US.yaml}`. Stable versions only; ProductCode optional (line
  dropped without one); leftover placeholders refused. Standard library only.
- `scripts/release/winget/validate.py`: offline check (three files, names, one id/version,
  ManifestVersion 1.10.0, key whitelist per manifest type, schema patterns/limits for the
  fields used, https URLs on tag `v<version>`, sha256, GUID ProductCode). Needs PyYAML.
- `.github/workflows/release-winget.yml`: `release: published` (non-prerelease) + dispatch.
  `manifests` (ubuntu, `contents: read`): cosign-verify `SHA256SUMS` (same identity rule as
  verify-release), download + hash-check NSIS/MSI, `msiinfo` ProductCode, render, validate,
  artifact `winget-manifests` (+ job summary). `submit` (windows, `contents: read`): only if
  `WINGET_TOKEN` exists **and** both installers are Authenticode-`Valid`; `wingetcreate`
  v1.12.13.0 pinned by SHA-256 `24042bd3…fea` (computed from the release asset 2026-11-08) →
  `wingetcreate submit --token … <dir>`.
- **Not winget-releaser**: `vedantmgoyal9/winget-releaser@b7370d4d152efdce803a26cc6ca9eee58cb2ad54`
  (tag `v2`) runs `cargo-bins/cargo-binstall@main` and an unpinned `komac` next to the token, so
  a SHA pin of the outer action pins nothing that matters. wingetcreate submits our own,
  validated manifests instead.
- Templates: header notes rewritten; the NSIS installer entry gets
  `InstallerSwitches.Custom: /MOORING_INSTALL_SOURCE=winget` (see coordination below).

### Docs
- `docs/release.md`: pipeline steps (sign jobs, release-winget), "Switching on platform signing",
  secrets table (platform secrets are now `release` environment secrets; `MACOS_SIGNING`,
  `WINDOWS_SIGNING`, `WINGET_TOKEN`).

## Coordination with rust-core: `ManualReason::Winget`
What the Rust side can detect today: **nothing reliable for the NSIS (per-user) install.**
winget runs the nullsoft installer with `/S` (and `/D=` for `--location`) and then tracks it by
the ARP entry the installer itself writes; the result is byte-identical to a manual NSIS install.
The ADR's `%LOCALAPPDATA%\Microsoft\WinGet\Packages` exists only for winget *portable/zip*
packages, and Tauri's NSIS template writes no `InstallSource` value. The MSI is per-machine and
already `ManualReason::PackageManager`, so only NSIS matters.

Proposed contract (manifest side done, installer side open):
1. The manifest passes `/MOORING_INSTALL_SOURCE=winget` to the NSIS installer (done; NSIS
   ignores unknown switches, so inert today).
2. A Tauri NSIS hook (`bundle.windows.nsis.installerHooks` in `tauri.release.conf.json`,
   e.g. `packaging/windows/installer-hooks.nsh`) writes `$INSTDIR\install-source` with the
   content `winget` in `NSIS_HOOK_POSTINSTALL` when `${GetOptions} $CMDLINE
   "/MOORING_INSTALL_SOURCE="` yields `winget`, deletes it otherwise (a later manual or in-app
   install clears it), and deletes it in `NSIS_HOOK_PREUNINSTALL`.
3. rust-core: for `Bundle::Nsis`, `exe.parent()/install-source` whose trimmed content is
   `winget` → `Manual(ManualReason::Winget)` (message: `winget upgrade yyasar21.Mooring`),
   checked after `portable`, before `writable`. A missing/other file means a normal NSIS
   install. Read at most a few bytes; never follow a reparse point.

## Left open
- The NSIS hook (item 2 above): not written, because no `makensis` here to compile it and a
  syntax error would break every Windows release build — needs an rc dry run on Windows.
- Nothing in A1 has run: no certificates exist (owner decision 42). First run = an `-rc` tag
  with the variables set. Risky parts to watch: `tauri bundle` without a prior `tauri build`
  in the same job (WiX/NSIS download, `cargo metadata`), dmg sparse round-trip, notarization
  of the dmg.
- `keychain-access-groups` (ADR-0022) is still commented out in `entitlements.plist`; for a
  Developer ID app it likely also needs an embedded provisioning profile. Enable together with
  the first signed build.
- `verify-release.sh` does not yet report `signed: true|false` per OS (ADR-0018 A1 bullet 3).
- The embedded NSIS uninstaller stays unsigned (no `signCommand` hook for an Action).
- `wingetcreate submit` flags (`--token`, `--prtitle`) are from its docs, not exercised here.
- `release.yml` is ~1030 lines (over the 500-line guideline it already exceeded).

## Decision needed
1. **Two variables instead of ADR's single `SIGNING_ENABLED`**: `MACOS_SIGNING` /
   `WINDOWS_SIGNING`, so buying one certificate does not force the other platform; macOS fails
   (not skips) on an incomplete set because the cfg is compiled in. Architect to amend A1.
2. Signing secrets moved from repository secrets to the `release` environment: any existing
   repository secrets of those names are now unused and should be deleted.
3. Whether winget installs really must not self-update: winget tracks nullsoft installs via ARP
   `DisplayVersion`, which an in-app NSIS update also bumps, so self-update does not break winget
   (unlike Homebrew). If `ManualReason::Winget` stays, approve the NSIS hook + marker contract.
4. `WINGET_TOKEN` as a repository secret (like `HOMEBREW_TAP_TOKEN`) or a `release`
   environment secret (one more approval per release).

## Test evidence
Linux worktree, no cargo, no network in tests.
- `bash scripts/release/tests/run.sh`: dmg-volume 14, identity 22, lint-workflows 35 (6 new:
  Apple secret in build, Azure secret in sign-macos, sign-windows without environment, Apple
  secret in another workflow, WINGET_TOKEN ok/misplaced), macos-pkg 4, **macos-sign 12 (new,
  dry-run gates)**, portable-zip 71, updater-manifest 24, verify-release 38, **winget-render 24
  (new: byte-for-byte fixture `scripts/release/tests/fixtures/winget/`, determinism, refusals,
  validate.py on 8 tampered sets)** — all passed.
- `bash scripts/release/lint-workflows.sh .github/workflows`: ok (rule 4 also covers the new
  `tauri bundle` line).
- PyYAML parse of `release.yml` and `release-winget.yml`; every `uses:` pinned to a 40-hex SHA;
  `bash -n` on every bash `run:` block, `compile()` on every python block: 0 findings.
  actionlint was not available (download not permitted).
