# Releasing and installing Mooring

This page covers how a Mooring release is made, how to install it on each OS, and how to check
that a download is genuine. Pipeline: `.github/workflows/release.yml` (build) and
`.github/workflows/release-homebrew.yml` (Homebrew tap).

## Supported platforms

| OS | Architectures | Minimum | Formats |
| --- | --- | --- | --- |
| macOS | Apple silicon (arm64), Intel (x86_64), universal | macOS 11 Big Sur | `.dmg`, `.pkg`, Homebrew Cask |
| Windows | x64 | Windows 10 1809 / Windows 11 | `-setup.exe` (NSIS, per-user), `.msi` (WiX, per-machine) |
| Linux | x86_64, arm64 | glibc 2.35 (Ubuntu 22.04, Debian 12, Fedora 36+, RHEL 9) | `.deb`, `.rpm`, `.AppImage` |

Mooring is a Tauri app. It uses the system WebView (WebKit on macOS, WebView2 on Windows,
WebKitGTK 4.1 on Linux) and does not bundle Chromium the way Electron apps do. The portable,
no-install Linux build is the **AppImage**. Windows on Arm is not built yet; the x64 build runs
there under emulation.

## Release assets

Each release on <https://github.com/yyasar21/Mooring/releases> carries:

| File | What it is |
| --- | --- |
| `Mooring_<v>_aarch64.dmg`, `_x64.dmg`, `_universal.dmg` | macOS disk images |
| `Mooring_<v>_aarch64.pkg`, `_x64.pkg`, `_universal.pkg` | macOS installer packages, install to `/Applications` |
| `Mooring_<v>_x64-setup.exe` | Windows NSIS installer, current user, no admin rights |
| `Mooring_<v>_x64_en-US.msi` | Windows MSI, per-machine, for managed deployment (Intune, GPO, SCCM) |
| `Mooring_<v>_amd64.deb`, `_arm64.deb` | Debian / Ubuntu packages |
| `Mooring-<v>-1.x86_64.rpm`, `-1.aarch64.rpm` | Fedora / RHEL / openSUSE packages |
| `Mooring_<v>_amd64.AppImage`, `_aarch64.AppImage` | Portable Linux build |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | Checksums of every file plus their Sigstore (cosign keyless) signature |
| `mooring-<v>-cargo.cdx.json`, `mooring-<v>-source.cdx.json` | CycloneDX SBOMs (Rust tree; full source tree incl. npm) |
| `*.app.tar.gz` | macOS app archives per architecture (updater manifest is not produced yet — see Update channel) |

Every file also has a GitHub build-provenance (SLSA) attestation.

Note: the AppImage bundler does not accept pre-release versions such as `0.1.0-rc.1`, so
pre-releases ship `.deb` and `.rpm` only on Linux; stable releases add the AppImage.

## Install

### macOS

**Homebrew (recommended)**

```sh
brew install --cask yyasar21/mooring/mooring
brew upgrade --cask mooring        # later updates
brew uninstall --cask --zap mooring  # remove app and its data
```

**Disk image.** Open `Mooring_<v>_universal.dmg` (or the one for your chip), drag Mooring to
Applications.

**Installer package.** Double-click `Mooring_<v>_universal.pkg`, or for scripted installs
`sudo installer -pkg Mooring_<v>_universal.pkg -target /`.

**Unsigned builds.** Until the project's Apple Developer ID is configured, macOS builds are
ad-hoc signed and not notarized, so Gatekeeper blocks the first launch:

1. Open Mooring once and dismiss the warning.
2. Go to System Settings → Privacy & Security, scroll to "Mooring was blocked", click
   **Open Anyway** and confirm. (On macOS 15 and later Control-click → Open no longer skips this.)
3. Alternatively, after verifying the download (below): `xattr -dr com.apple.quarantine /Applications/Mooring.app`.

Homebrew removed `--no-quarantine`, so the Cask install goes through the same Gatekeeper prompt
until the release is notarized. The release notes say whether a release is notarized.

### Windows

**Installer (recommended).** Run `Mooring_<v>_x64-setup.exe`. It installs for the current user
under `%LOCALAPPDATA%\Programs\Mooring` and needs no administrator rights. If the Microsoft
Edge WebView2 runtime is missing (rare: Windows 11 ships it), the installer downloads it.

**MSI.** `Mooring_<v>_x64_en-US.msi` installs per-machine and needs administrator rights:

```powershell
msiexec /i Mooring_<v>_x64_en-US.msi /qn        # silent install
msiexec /x Mooring_<v>_x64_en-US.msi /qn        # uninstall
```

Use one of the two installers, not both: they register separately.

**SmartScreen on unsigned builds.** Until Authenticode signing is configured, SmartScreen shows
"Windows protected your PC". Verify the download, then click **More info → Run anyway**.

### Linux

**Debian / Ubuntu**

```sh
sudo apt install ./Mooring_<v>_amd64.deb      # arm64: Mooring_<v>_arm64.deb
sudo apt remove mooring
```

**Fedora / RHEL / openSUSE**

```sh
sudo dnf install ./Mooring-<v>-1.x86_64.rpm   # arm64: Mooring-<v>-1.aarch64.rpm
sudo dnf remove mooring
```

Both packages pull in WebKitGTK 4.1 and GTK 3. The OS-keyring option (Secret Service) needs a
running keyring daemon such as GNOME Keyring or KWallet; Mooring works without it.

RHEL 9 needs WebKitGTK 4.1 from AppStream (`dnf install webkit2gtk4.1`); RHEL 8 is not supported.

**AppImage (portable)**

```sh
chmod +x Mooring_<v>_amd64.AppImage
./Mooring_<v>_amd64.AppImage
```

AppImages need FUSE 2 (`sudo apt install libfuse2` on Ubuntu 22.04,
`libfuse2t64` on 24.04+). Without FUSE: `./Mooring_<v>_amd64.AppImage --appimage-extract-and-run`.

## Verify a download

`SHA256SUMS` lists the hash of every release file. It is signed with
[Sigstore](https://www.sigstore.dev/) keyless signing: the signature is bound to the GitHub
Actions identity of this repository's `release.yml` workflow and logged in the public Rekor
transparency log. No long-lived key exists that could leak.

Install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3.x, download
the file you want plus `SHA256SUMS` and `SHA256SUMS.sigstore.json` into one folder, then:

```sh
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/yyasar21/Mooring/.github/workflows/release.yml@refs/tags/v<v>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

sha256sum --check --ignore-missing SHA256SUMS          # Linux
shasum -a 256 --check --ignore-missing SHA256SUMS      # macOS
```

On Windows (PowerShell), compare by hand:

```powershell
(Get-FileHash .\Mooring_<v>_x64-setup.exe -Algorithm SHA256).Hash.ToLower()
Select-String "Mooring_<v>_x64-setup.exe" .\SHA256SUMS
```

Build provenance, with the GitHub CLI:

```sh
gh attestation verify Mooring_<v>_amd64.deb --repo yyasar21/Mooring
```

Maintainers can check a whole release in one go with
`scripts/release/verify-release.sh v<v>` (or `make verify-release TAG=v<v>`).

If a release was rebuilt by hand (workflow_dispatch), its certificate identity ends in
`@refs/heads/main` instead of the tag. The script accepts both; nothing else is valid.

## Updates

In-app updates are **not enabled yet**: the updater plugin, its public key and the capability change need a security review (tracked in the roadmap). Until then, install new releases from the Releases page or your package manager. When enabled, the manifest will be published at
`https://github.com/yyasar21/Mooring/releases/latest/download/latest.json`. Each update is
verified against the public key compiled into the app before it is installed, independently of
TLS. Pre-releases (`v1.2.0-rc.1`) never reach that channel.

The in-app updater (Tauri updater plugin) is not wired up in 0.1.x. Until it is, update with
the package manager you installed from, or install the new release over the old one.

## Making a release (maintainers)

Versions follow [SemVer 2.0.0](https://semver.org/). While on `0.y.z`, a minor bump may break
the vault or storage format; the CHANGELOG says so and includes the migration.

1. On an up-to-date, clean `main` with green CI, make sure `CHANGELOG.md` has an
   `## [Unreleased]` section that describes the release.
2. `make release VERSION=x.y.z` checks the tree, runs `scripts/release/bump-version.sh`
   (workspace `Cargo.toml`, internal crate pins, `Cargo.lock`, `tauri.conf.json`, every
   `package.json`, CHANGELOG `Unreleased → [x.y.z] - date`), commits
   `chore(release): vx.y.z` and creates an annotated tag. `make bump VERSION=x.y.z` does only
   the file edits.
3. `git push origin main vx.y.z` starts `release.yml`:
   - **draft release**: checks that tag, `Cargo.toml` and `tauri.conf.json` agree, and creates a
     draft GitHub Release with generated notes (or reuses the tag's existing draft);
   - **build** (6 runners in parallel): macOS arm64/x64/universal on `macos-14`, Windows x64 on
     `windows-2022`, Linux x64 on `ubuntu-22.04` and arm64 on `ubuntu-22.04-arm`. `tauri-action`
     builds and uploads the bundles; macOS jobs add the `.pkg`. Each signing step runs only if its
     secrets exist;
   - **finalize**: downloads every asset, adds the two SBOMs, writes `SHA256SUMS`, signs it with
     cosign keyless, attests provenance for every file and uploads the lot.
4. Review the draft: notes (edit freely), asset list, the job summaries ("signed: true/false").
   Run `scripts/release/verify-release.sh vx.y.z`, then install it on at least one machine.
5. Click **Publish release**. That triggers `release-homebrew.yml`, which re-verifies
   `SHA256SUMS` and pushes the new Cask to `yyasar21/homebrew-mooring`.

To fix a failed build, re-run the failed jobs from the Actions page, or run the workflow
manually with the tag. It uploads into the same draft with `--clobber`. A published release is
never rebuilt: cut a new patch version instead. Pre-release tags (`x.y.z-rc.1`) become
GitHub pre-releases and skip Homebrew.

## Secrets and variables

Configure under Settings → Secrets and variables → Actions. Each one is optional: without it
the matching step is skipped and the build stays unsigned, so forks work as-is.

| Name | Kind | Used for |
| --- | --- | --- |
| `TAURI_SIGNING_PRIVATE_KEY` | secret | Updater signatures + `latest.json`. Generate with `pnpm tauri signer generate -w mooring-updater.key`; the content of the file, not the path. |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | secret | Password of that key |
| `APPLE_CERTIFICATE` | secret | Base64 of the "Developer ID Application" `.p12` (`openssl base64 -A -in cert.p12`) |
| `APPLE_CERTIFICATE_PASSWORD` | secret | `.p12` export password |
| `APPLE_SIGNING_IDENTITY` | secret | e.g. `Developer ID Application: Yunus Yaşar (TEAMID)` |
| `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` | secret | Notarization with an app-specific password. All three or none: ID + password without team ID fails the build. |
| `APPLE_API_KEY`, `APPLE_API_ISSUER`, `APPLE_API_KEY_P8` | secret | Alternative notarization with an App Store Connect API key (key id, issuer id, content of `AuthKey_<id>.p8`) |
| `APPLE_INSTALLER_CERTIFICATE`, `APPLE_INSTALLER_CERTIFICATE_PASSWORD`, `APPLE_INSTALLER_SIGNING_IDENTITY` | secret | "Developer ID Installer" certificate for signing the `.pkg` |
| `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` | secret | Windows signing with Azure Artifact Signing (formerly Trusted Signing), preferred |
| `AZURE_SIGNING_ENDPOINT`, `AZURE_SIGNING_ACCOUNT`, `AZURE_SIGNING_PROFILE` | **variable** | Artifact Signing endpoint URL, account name, certificate profile |
| `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD` | secret | Alternative: base64 `.pfx` OV code-signing certificate (ignored when Azure is set) |
| `TAURI_SIGNING_RPM_KEY`, `TAURI_SIGNING_RPM_KEY_PASSPHRASE` | secret | ASCII-armored GPG key to sign the `.rpm` |
| `HOMEBREW_TAP_TOKEN` | secret | Fine-grained PAT, repository `yyasar21/homebrew-mooring` only, Contents read/write |

The Sigstore signature and the provenance attestations need no secret: they use the workflow's
short-lived OIDC token (`id-token: write`, finalize job only).

## Local builds

`make bundle` builds unsigned installers for the current OS into
`target/release/bundle/`. `make icons` regenerates `src-tauri/icons/` from
`packaging/icon.svg`. Package-manager templates for later (winget, Scoop) live in
`packaging/winget/` and `packaging/scoop/`.
