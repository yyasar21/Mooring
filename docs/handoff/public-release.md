# Public release pipeline — release-engineer handoff

Date: 2026-11-03 · Phase: A4 prep (public release at github.com/yyasar21/Mooring, MIT)
Process and user-facing install docs: [docs/release.md](../release.md) (README should link it).

## Done

- `.github/workflows/release.yml` (rewritten). Runs on `v*` tags and on manual dispatch with a tag.
  Three jobs:
  1. **draft release**: checks that the tag matches the `Cargo.toml` and `tauri.conf.json`
     versions, then creates a **draft** release with GitHub-generated notes, or reuses the
     existing draft. Refuses to touch a published release.
  2. **build**, six runners: macOS `aarch64`, `x64` and `universal` (`app,dmg`, plus a `.pkg`
     from `scripts/release/macos-pkg.sh` via `pkgbuild` and `productbuild`), Windows x64
     (`nsis,msi`), Linux x64 on `ubuntu-22.04` and arm64 on `ubuntu-22.04-arm` (`deb,rpm,appimage`).
     `tauri-apps/tauri-action` uploads straight into the draft.
  3. **finalize**: downloads every asset and adds the CycloneDX SBOMs (Rust via `cargo-cyclonedx`
     0.5.9; source tree including npm via syft/`anchore/sbom-action`). It writes `SHA256SUMS`,
     signs it with **cosign keyless** (`SHA256SUMS.sigstore.json`) and attests SLSA build
     provenance for every file (`actions/attest-build-provenance`, `subject-checksums`).
  - Every action is pinned by commit SHA, with the tag in a comment. Top-level permission is
    `contents: read`; jobs get `contents: write`, and only finalize gets `id-token`/`attestations`.
    Concurrency is per tag. Release builds use no cache, so they cannot be poisoned by caches
    written in PR runs.
  - Signing is opt-in per secret. A secret is exported to the environment only when it is
    non-empty, because the Tauri bundler reads `APPLE_CERTIFICATE` with `var_os`, and set-but-empty
    would make signing fail. Without an Apple certificate, macOS builds are ad-hoc signed (`-`).
    Without `TAURI_SIGNING_PRIVATE_KEY`, `createUpdaterArtifacts` stays false and no `latest.json`
    or `.sig` is uploaded. With the key, a CI-only `--config` turns it on for the universal,
    Windows and Linux jobs. Windows signs with Azure Artifact Signing (`signCommand` +
    `artifact-signing-cli` 0.12.0) or falls back to a PFX (`certificateThumbprint`). The `.rpm`
    is GPG-signed via `TAURI_SIGNING_RPM_KEY`. A fork with no secrets builds everything unsigned.
- `.github/workflows/release-homebrew.yml`: runs on `release: published` (stable only) or on
  manual dispatch. It cosign-verifies `SHA256SUMS` and takes the dmg hashes from it. It renders
  `packaging/homebrew/Casks/mooring.rb`, reading the identifier from `tauri.conf.json` at render
  time, and pushes to `yyasar21/homebrew-mooring` with `HOMEBREW_TAP_TOKEN`. Without the token
  it skips with a notice.
- `src-tauri/tauri.conf.json`, `bundle` section only: publisher, copyright, license +
  `licenseFile`, homepage, `longDescription`; macOS 11.0 minimum, hardened runtime,
  entitlements; Windows sha256 digest, `allowDowngrades: false`, the WebView2 download
  bootstrapper (silent), WiX `en-US` with a **pinned `upgradeCode`** (same as Tauri's derived
  default, so nothing changes; it is pinned so a future `productName` change can't orphan
  installs), and NSIS `currentUser`, English. Linux: deb section/priority, `gnome-keyring` in
  recommends (Secret Service for the ADR-0006 keyring wrap), and a desktop template for deb and
  rpm. `identifier` was not touched. The Tauri CLI parses the config (`tauri inspect
  wix-upgrade-code` OK).
- `packaging/`: `icon.svg` (original monochrome bollard + mooring line; placeholder),
  `linux/mooring.desktop` (Tauri handlebars template, no MimeType), `macos/entitlements.plist`
  (empty dict, with the keychain-access-groups block commented out until a Team ID exists),
  `homebrew/Casks/mooring.rb`, `winget/` (3-file manifest, schema 1.10.0) and `scoop/mooring.json`
  templates.
- `scripts/release/`: `bump-version.sh`, `verify-release.sh`, `gen-icons.sh` (`pnpm tauri icon`)
  and `macos-pkg.sh`.
- Makefile: `bump`, `release`, `verify-release` and `icons` targets.

## Owner actions on GitHub (in this order)

1. **Make the repo public.** The Linux arm64 job uses `ubuntu-22.04-arm`, which is free only for
   public repositories. While the repo is private, drop that matrix row or use a larger runner.
2. **Settings → Actions → General**: allow GitHub Actions. `GITHUB_TOKEN` can stay read-only,
   because the workflows request what they need per job.
3. **Updater key** (recommended even before the updater UI exists):
   `pnpm tauri signer generate -w ~/.tauri/mooring-updater.key`. Keep the private key in a
   password manager, **outside the repo**. Store its contents in the secret
   `TAURI_SIGNING_PRIVATE_KEY` and its password in `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. The
   public key goes into `plugins.updater.pubkey` when rust-core adds `tauri-plugin-updater`.
4. **Homebrew tap**: create the **public** repo `yyasar21/homebrew-mooring` with a README and an
   empty `Casks/` directory. Create a fine-grained PAT limited to that repo with "Contents: read
   and write" and store it as `HOMEBREW_TAP_TOKEN`. After the first published release,
   `brew install --cask yyasar21/mooring/mooring` works.
5. **Apple** (needed to get rid of the Gatekeeper prompt): enrol in the Apple Developer Program
   (USD 99/year), create **Developer ID Application** and **Developer ID Installer**
   certificates and export each as `.p12`. Set `APPLE_CERTIFICATE`,
   `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_INSTALLER_CERTIFICATE`,
   `APPLE_INSTALLER_CERTIFICATE_PASSWORD` and `APPLE_INSTALLER_SIGNING_IDENTITY`. For
   notarization, set either `APPLE_ID` + `APPLE_PASSWORD` (app-specific password) +
   `APPLE_TEAM_ID`, or `APPLE_API_KEY` + `APPLE_API_ISSUER` + `APPLE_API_KEY_P8`.
6. **Windows** (needed to get rid of SmartScreen): Azure Artifact Signing (around USD 10/month;
   individual developers need identity validation, availability depends on country). Create an
   account and a certificate profile, then an app registration with the "Artifact Signing
   Certificate Profile Signer" role. Set the secrets `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` and
   `AZURE_TENANT_ID`, and the **variables** `AZURE_SIGNING_ENDPOINT`, `AZURE_SIGNING_ACCOUNT`
   and `AZURE_SIGNING_PROFILE`. Alternative: an OV `.pfx` in `WINDOWS_CERTIFICATE` and
   `WINDOWS_CERTIFICATE_PASSWORD`.
7. Optional: an RPM GPG key in `TAURI_SIGNING_RPM_KEY` and `TAURI_SIGNING_RPM_KEY_PASSPHRASE`
   (publish the public key in the README).
8. First run: `make release VERSION=0.1.0` needs a `CHANGELOG.md` with `## [Unreleased]`, owned by
   the docs agent; without it the script only warns. Push the tag, review the draft, run
   `scripts/release/verify-release.sh v0.1.0`, then publish.

## Decision needed

- **tauri-action v1.0.0 instead of `@v0`.** v1.0.0 (2026-06-29) is the current line; v0.6.2 is
  the last v0. The inputs used here (`releaseId`, `releaseDraft`, `uploadUpdaterJson`,
  `updaterJsonPreferNsis`, `uploadUpdaterSignatures`, `retryAttempts`, `args`) are v1 names. To
  stay on v0, pin `84b9d35b5fc46c1e45415bdb6144030364f7ebc5 # v0.6.2` and rename
  `uploadUpdaterJson` back to `includeUpdaterJson`.
- **cosign keyless instead of minisign.** A4.md and `.claude/agents/release-engineer.md` say
  "minisign-signed SHA256SUMS"; the brief said to pick cosign keyless. Keyless leaves no
  long-lived key to protect or rotate, and the signature is bound to `release.yml` in this repo
  and logged in Rekor. The cost is that verifiers need cosign. Update the agent definition and
  A4.md if this stands.
- The **"electron" request**: Mooring is Tauri (ADR-0001 rejected Electron), so there is no
  Electron build. The portable, no-install equivalent on Linux is the **AppImage**, which ships
  for x64 and arm64. Windows has no portable `.exe`; tauri-action's `uploadPlainBinary` could add
  one later, but Tauri does not officially support portable mode.
- The `publisher`/`copyright` strings use the owner's name; change them if a different
  publisher name is wanted.

## Left open / known gaps

- **Not run.** Neither workflow has executed (no `act`, no runners here). The first tag will be
  the real test; expect one or two fix-ups. Riskiest parts: the universal macOS job, `.pkg` on an
  ad-hoc-signed app, and `artifact-signing-cli` argument order.
- **Parallel `latest.json` merge.** tauri-action merges `latest.json` by downloading and
  re-uploading it from each job. Four updater jobs racing can drop a platform. If the first
  signed release shows a missing platform, re-run that job, or move manifest generation into
  finalize.
- The **per-arch macOS jobs** upload their `.app` archive only when updater artifacts are on
  (they are off there). The universal job provides the updater bundle for both architectures.
- **Updater plugin not wired up.** No `tauri-plugin-updater` and no pubkey in the app yet; that
  is rust-core work plus a capability change, so it needs security review. Until then
  `latest.json` is produced but unused.
- **Icons.** `src-tauri/icons/*` still show the old "N" (Nexus) glyph. `packaging/icon.svg` is
  the new placeholder; run `make icons` (tested: it generates the full set) and commit the result
  together with the review of the new look. It was not run here, to keep binary churn out of this PR.
- **macOS minimum.** Lowered from 12.0 to 11.0 as requested. WKWebView features used by the UI
  have not been tested on Big Sur. Raise it back if lab testing shows problems.
- **WebView2 install mode.** `downloadBootstrapper` needs internet during install. Offline or
  air-gapped sites (common in banks) would need `offlineInstaller` (+~127 MB) in a separate
  enterprise build.
- **winget/Scoop** are templates only. winget effectively requires signed installers.
- No reproducible-build check job yet (A4 item 2). SBOMs cover the Rust and source trees; the
  npm SBOM comes from syft scanning `pnpm-lock.yaml`, not from `@cyclonedx/cyclonedx-npm`.
- `ci.yml` still uses tag-pinned actions (qa-engineer / orchestrator scope; the same SHAs can be
  reused).
- `docs/handoff/index.md` row: the orchestrator should add one.

## Test evidence

- `python3 -c 'yaml.safe_load(...)'` passes for every `.github/workflows/*.yml` and every
  `packaging/winget/*.yaml`; the JSON files parse.
- `actionlint` 1.7.12 with shellcheck reports no findings on `release.yml` and
  `release-homebrew.yml`. `shellcheck -S warning scripts/release/*.sh` reports no findings.
- `tauri inspect wix-upgrade-code` (Tauri CLI 2.x) parses the new `tauri.conf.json`:
  `deny_unknown_fields` passes, and the upgrade code equals the derived default.
- `bump-version.sh 0.2.0` on a scratch clone with a sample CHANGELOG updated 12 files (Cargo.toml,
  5 crate pins, Cargo.lock, tauri.conf.json, 3 package.json, CHANGELOG with compare links);
  `--dry-run` writes nothing.
- `cargo cyclonedx --manifest-path src-tauri/Cargo.toml --spec-version 1.5`: CycloneDX 1.5,
  513 components. It also writes one file per workspace member, which the workflow removes.
- `pnpm tauri icon packaging/icon.svg` into a scratch directory produced the full icon set (png,
  icns, ico, Store logos).
- Action SHAs were resolved with `git ls-remote` against each upstream repo on 2026-11-03.
