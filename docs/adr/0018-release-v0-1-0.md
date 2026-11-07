# ADR-0018: Release v0.1.0 — signing, updater, SBOM/provenance, install matrix

Status: Accepted (owner decisions inline) · 2026-11-06 · amendments A1–A2 Proposed 2026-11-07
(Phase A4; builds on the release pipeline
in `docs/handoff/public-release.md`, R-REL, ADR-0003, ADR-0013 `AppManifest`)

## Context
`release.yml` builds six targets into a draft, split by privilege (M-7), with SBOMs, cosign-signed
`SHA256SUMS` and SLSA provenance, but no release has been published (the handoff says "not run";
`7595474`..`de22e7c` are fix-ups from partial `rc.1` runs). Open: the updater (no plugin, no
pubkey; tauri-action is build-only, so no `latest.json`), the reproducible check, the version
(`0.1.0-rc.1`), stale "minisign" wording. The owner has no Apple or Azure certificates.

## Decision

### 1. Checksums and provenance (owner decision 13: cosign keyless)
Owner decisions are numbered after ADR-0017 (12): 13–15 here, 16–18 in ADR-0019, 19 in ADR-0020.
- `SHA256SUMS` is signed with **cosign keyless** in `finalize` (`SHA256SUMS.sigstore.json`,
  Rekor-logged, identity `release.yml@refs/tags/<tag>`). Minisign wording is removed
  everywhere (README §148, `docs/developer-guide/release-process.md`, roadmap A4, the
  release-engineer agent definition). The Tauri updater's own minisign signature (§3) is a
  separate key and only signs updater bundles.
- CycloneDX 1.5 SBOMs (Rust via `cargo-cyclonedx =0.5.9`, source via syft) and
  `actions/attest-build-provenance` for every file stay as built.
- `tauri-apps/tauri-action` stays on the **v1 line pinned by SHA**:
  `1deb371b0cd8bd54025b384f1cd735e725c4060f # v1.0.0` (re-resolved 2026-11-06 with
  `git ls-remote`; `v1`, `v1.0` and `v1.0.0` all point there). Dependabot bumps it like any action.

### 2. What ships unsigned (owner decision 14)
| OS | v0.1.0 | Gate for the user |
| --- | --- | --- |
| macOS | ad-hoc signed (`-`), hardened runtime, not notarized | Gatekeeper: right-click → Open, or System Settings → Privacy & Security → "Open Anyway" |
| Windows | unsigned NSIS `.exe` + `.msi` | SmartScreen: "More info" → "Run anyway" |
| Linux | `.deb`, `.rpm` (unsigned unless `TAURI_SIGNING_RPM_KEY`), AppImage | none; verify `SHA256SUMS` |
The user guide gets "Installing an unsigned build": verify (`verify-release.sh` / `cosign
verify-blob`) **before** the Gatekeeper/SmartScreen override. Signing stays opt-in per secret, so
certificates later need no code change. winget stays a template (it needs signed installers).

### 3. Updater (owner decision 15: yes, on demand)
- `tauri-plugin-updater = { version = "=2.14.1", default-features = false, features =
  ["rustls-tls", "system-proxy"] }` in `mooring-app` only. Registered **Rust-side only** and
  only when `plugins.updater.pubkey` is non-empty; otherwise every update command returns
  `update.unconfigured`. **No `updater:*` permission in any capability**: the plugin's JS
  commands are unreachable from every window.
- Config (release-engineer, `tauri.conf.json`): `plugins.updater.pubkey` = the owner's public
  key; `endpoints = ["https://github.com/yyasar21/Mooring/releases/latest/download/latest.json"]`;
  `createUpdaterArtifacts: true` (never `"v1Compatible"`, which needs the dropped `zip` feature).
  Drafts and pre-releases are never "latest", so `rc` builds see no update.
- `latest.json` is written in `finalize` by `scripts/release/updater-manifest.sh` from the build
  artifacts' `.sig` files (no racing tauri-action jobs), listed in `SHA256SUMS` and attested.
- **In-app install only where no elevation is needed** (Mooring never elevates):
  macOS `.app` whose parent directory is writable by the user; Windows NSIS per-user install;
  Linux AppImage. Everything else (MSI, `.deb`, `.rpm`, a root-owned `/Applications` bundle,
  Homebrew) is `installMode: "manual"` (release page + package-manager command). Otherwise the
  plugin uses `pkexec`, a zenity/kdialog sudo-password prompt or `sudo` (deb/rpm), or AppleScript
  "with administrator privileges"; Mooring refuses first, so those paths are never taken.
- Dependency check: licence Apache-2.0 OR MIT; maintained (2.14.1, 2026-10-28); `unsafe` =
  5 blocks (Windows `ShellExecuteW`, macOS `renamex_np`/`statfs`), FFI to OS calls only —
  accepted like `keyring`; overlap: `reqwest` 0.13, `flate2`, `infer`, `semver`, `dirs`,
  `rustls` (ring) are already in the tree; new are `minisign-verify` (MIT, 2026-09-25,
  `forbid(unsafe_code)`), `tar` (macOS), `osakit` (macOS; last release 2025-03-01, older than
  12 months: **exception**, its only use is the elevated-install path we never take).
- Policy: checks only on demand by default; an opt-in background check runs once 60 s after
  start and then every 24 h, only shows a badge, **never downloads or installs**. Downgrades are
  refused (default comparator, plus `available > current` re-checked in Rust). Release notes are
  shown as plain text, capped at 16 KiB, bidi/control characters stripped (no Markdown/HTML).
- IPC (ADR-0008 style; all in `mooring-main` via `AppManifest`):
```
update_check() -> UpdateInfo { current, available: { version, date|null, notes } | null,
                               installMode: "in_app" | "manual", checkedAt }
update_install({ version, closeSessions: bool }) -> void   # restarts the app on success
update_settings_get() -> { backgroundCheck: bool, lastCheck: string|null }
update_settings_set({ backgroundCheck: bool }) -> UpdateSettings
```
  `update_install` re-runs the check in Rust and refuses unless the result equals `version`
  (no renderer-supplied URL or bytes, no TOCTOU swap); it refuses with open sessions unless
  `closeSessions`. The plugin verifies the minisign signature against the compiled-in pubkey
  before anything is written. Single flight per process.
- Error codes: `update.unconfigured`, `update.network`, `update.manifest`, `update.signature`,
  `update.none` (nothing newer, or `version` no longer offered), `update.manual_only`,
  `update.not_writable`, `update.sessions_open`, `update.busy`.
- Audit: `update.check { current, available|null }`, `update.install { from, to }`,
  `update.refused { code }`, `update.settings_changed { backgroundCheck }`.

### 4. Reproducible-build check (`.github/workflows/release-repro.yml`, release-engineer)
- **Scope: the Rust workspace crates on Linux x86_64** (`default-members`, i.e. everything but
  `mooring-app`, `--release --locked`). Two builds from two checkout paths with the pinned
  toolchain, `SOURCE_DATE_EPOCH` = commit time, `--remap-path-prefix` for the workspace and
  `CARGO_HOME`, then `sha256sum` over every `target/release/deps/libmooring_*.{rlib,rmeta}`; a
  difference fails the job and uploads a `diffoscope` report. Weekly, on `v*` tags, on dispatch.
- **Excluded: the Tauri bundle**: `hdiutil`, WiX, `ar`, `rpmbuild` and squashfs embed timestamps
  and host data; signatures embed time; WebView/system libraries differ by runner image; the Vite
  bundle needs its own check. Provenance covers bundles; revisit after v0.1.0.

### 5. Version and icons
- R1 bumps to `0.1.0-rc.2` (dry run) and later to `0.1.0` with `make release` (bump-version.sh:
  Cargo, tauri.conf.json, package.json, CHANGELOG). Pre-releases ship only `.deb` on Linux (the
  rpm/AppImage bundlers reject `-`), so rpm/AppImage are first built at `0.1.0`; R1 builds both
  once locally from the rc commit with a numeric override for the Fedora smoke test.
- Icons: `make icons` from `packaging/icon.svg` (done, `15c0b92`); a proper icon design is task U3.

### 6. Release gate (all before the `v0.1.0` tag is published)
1. `docs/qa/native-dialogs.md` run on macOS, Windows 11, Fedora (GTK) — the A3 condition.
2. L-31 page-raised-dialog check per OS; the other carried A3 conditions (ADR-0013 E2E per OS,
   ADR-0016 §4 OIDC interception per OS, Windows L-29 E2E, L-36 help text).
3. First **green** nightly fuzz run (L-28), including the A4 importer and net targets.
4. `security.yml` green on the release commit; `make check` green on three OSes.
5. Fresh-install smoke on clean macOS, Windows 11 and Fedora VMs: install, create vault, SSH
   connect, lock/unlock, uninstall; `verify-release.sh` on the draft.
6. Security review 7: zero critical/high; the "before the first public release" items (L-19,
   L-11, M-12, L-12..L-14, N-8, N-9, G-1 fresh squashed repo) closed or explicitly accepted.
7. A human publishes the draft (R-REL).

### 7. Owner actions (in order; secrets never in the repo or a chat)
1. Fresh public repository with one squashed commit (G-1); allow Actions; `ubuntu-22.04-arm`
   needs it public.
2. `pnpm tauri signer generate -w ~/.tauri/mooring-updater.key`; private key in a password
   manager; secrets `TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`; hand
   the **public** key to R1 for `plugins.updater.pubkey`.
3. `yyasar21/homebrew-mooring` (public, `Casks/`) + fine-grained PAT → `HOMEBREW_TAP_TOKEN`.
4. Optional: RPM GPG key → `TAURI_SIGNING_RPM_KEY` / `_PASSPHRASE`, public key in the README.
5. Later, no code change: Apple Developer ID (Application + Installer, notarization secrets)
   and Azure Artifact Signing (or an OV `.pfx`), as listed in the public-release handoff.
6. Provide clean macOS, Windows 11 and Fedora VMs for gate 5 and run the manual gates 1–2.

## Alternatives considered
- minisign for `SHA256SUMS`: a long-lived key to guard; keyless binds to this workflow. Rejected (owner).
- Plugin JS permissions (`updater:default`): any script in the main window could install. Rejected.
- Auto-install / background download: surprises users mid-session, turns the update channel
  into a push channel. Rejected (owner).
- Letting the plugin elevate (pkexec/sudo/AppleScript): a password prompt from a remote-access
  tool is phishing-shaped. Rejected; manual path. Full-bundle reproducibility: deferred.

## Security consequences
- R-UPD (new): the updater key is a second release trust root; whoever holds it can ship code
  to in-app installs. Secret store + owner's password manager only; rotation = a manual release.
- One outbound HTTPS request to github.com, on demand or opted in, carrying only version and
  target; "No telemetry" stays true. Unsigned v0.1.0 binaries rely on `SHA256SUMS` verification.

## Test plan
- Unit (src-tauri): install-mode matrix (bundle type × writability); version equals the re-check;
  downgrade refused; `closeSessions`; notes sanitiser; settings round trip; empty pubkey →
  `update.unconfigured`; single flight. Capability test: no `updater:` permission anywhere.
- Integration: loopback server with `latest.json` + bundle signed by an **ephemeral** key made in
  the test job (never committed); tampered bundle or wrong pubkey → `update.signature`.
- Pipeline: R1 `v0.1.0-rc.2` dry run → complete draft, `verify-release.sh` green, `latest.json`
  in `SHA256SUMS`; `release-repro.yml` green twice.

## Sources
crates.io 2026-11-06 (`tauri-plugin-updater` 2.14.1 source read, `minisign-verify` 0.3.0, `tar`
0.4.46, `osakit` 0.3.1); `git ls-remote tauri-apps/tauri-action` 2026-11-06.

## Amendments (A5 / v0.2.0, Proposed 2026-11-07; release-engineer owns the workflows)

### A1. Signing and notarization hooks — in the `release` environment, inert without secrets
Today `build` exports `APPLE_*` / `AZURE_*` / `WINDOWS_CERTIFICATE*` into the job that runs
npm and cargo build scripts (the M-17 argument applied only to the updater key). Change:
- `build` never sees platform signing secrets: macOS builds ad-hoc (`APPLE_SIGNING_IDENTITY=-`)
  and Windows unsigned, as v0.1.0; the job uploads the `.app`, the bare `Mooring.exe` and the
  bundler inputs as artifacts.
- New job **`sign-platform`** (`needs: build`, `environment: release`, matrix macOS/Windows,
  `if: ${{ vars.SIGNING_ENABLED == 'true' }}` + a step-level skip when the secret set is
  incomplete — never a failure). It runs **no package build scripts**: only `codesign`,
  `xcrun notarytool submit --wait` + `xcrun stapler` with `APPLE_API_KEY`/`_ISSUER`/`_P8`
  (App Store Connect key, no Apple ID password), rebuilds the `.dmg`/`.pkg` from the signed,
  stapled `.app`, and the updater `.app.tar.gz`; on Windows signs `Mooring.exe` with
  **Azure Trusted Signing** (`azure/trusted-signing-action`, pinned by SHA, replacing the
  unreviewed `levminer/trusted-signing-cli`), then runs `tauri bundle` (CLI, no build) and
  signs the NSIS/MSI with the same action. Entitlements for ADR-0022 (`keychain-access-groups`)
  live in `packaging/macos/entitlements.plist` and are applied here.
- `sign-updater`, `publish`, `finalize` consume `sign-platform` outputs when present, the
  `build` artifacts otherwise; `verify-release.sh` reports `signed: true|false` per OS from
  `codesign -dv` / `signtool verify` and `SHA256SUMS` covers whichever set shipped.
- Secrets stay in the `release` environment (reviewers required); none in `build`. Owner buys
  certificates when ready; until then the job skips with a notice (**owner decision 42**).

### A2. winget (`packaging/winget/`, `.github/workflows/release-winget.yml`)
Modelled on `release-homebrew.yml`: `on: release: published` (never pre-releases) and
`workflow_dispatch` with a tag; gated on `secrets.WINGET_TOKEN` (fine-grained PAT, fork of
`microsoft/winget-pkgs` only) **and** on `signed: true` for Windows in the release's
`verify-release` summary — unsigned installers are not submitted (winget validation and
SmartScreen). Steps: download `SHA256SUMS` + its Sigstore bundle, `cosign verify-blob`, render
`yyasar21.Mooring.{installer,locale.en-US,version}.yaml` from the templates (`@VERSION@`,
`@SHA256_NSIS@`, `@SHA256_MSI@`, `@MSI_PRODUCT_CODE@` from `msiinfo`/the build summary,
`@RELEASE_DATE@`), `winget validate`, then `wingetcreate submit --token` (pinned `wingetcreate`
release by SHA-256) → a PR to `microsoft/winget-pkgs` from the owner's fork. `ManualReason`
gains `Winget` (`winget upgrade yyasar21.Mooring`) when `install_mode.rs` detects a winget
install (`%LOCALAPPDATA%\Microsoft\WinGet\Packages` or the NSIS registry `InstallSource`).
Test: `scripts/release/tests/winget-render.test.sh` (templates render, schema validates);
`lint-workflows.sh` asserts no secret in `build` and the token only in this job.
