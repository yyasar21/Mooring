# Releasing and installing Mooring

This page covers how a Mooring release is made, how to install it on each OS, and how to check
that a download is genuine. Pipeline: `.github/workflows/release.yml` (build) and
`.github/workflows/release-homebrew.yml` (Homebrew tap).

## Supported platforms

| OS | Architectures | Minimum | Formats |
| --- | --- | --- | --- |
| macOS | Apple silicon (arm64), Intel (x86_64), universal | macOS 11 Big Sur | `.dmg`, `.pkg`, Homebrew Cask, portable `.zip` (universal) |
| Windows | x64 | Windows 10 1809 / Windows 11 | `-setup.exe` (NSIS, per-user), `.msi` (WiX, per-machine), portable `.zip` |
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
| `Mooring_<v>_x64_portable.zip` | Portable Windows build: `Mooring.exe` + `portable` marker + `README.txt`; no installer, data in `Mooring Data/` next to the exe (ADR-0021) |
| `Mooring_<v>_universal_portable.zip` | Portable macOS build: `Mooring.app` (same ad-hoc signed bundle as the dmg) + `portable` + `README.txt`; data in `Mooring Data/` next to the app |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | Checksums of every file plus their Sigstore (cosign keyless) signature |
| `mooring-<v>-cargo.cdx.json`, `mooring-<v>-source.cdx.json` | CycloneDX SBOMs (Rust tree; full source tree incl. npm) |
| `Mooring_universal.app.tar.gz`, `*-setup.exe`, `*.AppImage` + `.sig` | In-app updater artifacts and their signatures (the `.sig` files and `latest.json` only when the release was signed with the updater key) |
| `latest.json` | In-app updater manifest: per platform the URL and signature of the artifact above (see Updates) |

Every file also has a GitHub build-provenance (SLSA) attestation.

The two portable zips are regular release assets (hashed, signed, attested) but **not** updater
artifacts: they never get a `.sig`, `latest.json` never lists them, and the in-app updater is
off in portable mode. They are built deterministically by `scripts/release/portable-zip.py`
(entries in `LC_ALL=C` order, mtimes = the tagged commit's time, Unix modes and symlinks kept),
so a rebuild from the tag gives the same bytes. Unzip, keep the `portable` file next to the
app, verify first, then start it; the `README.txt` inside has the per-OS first-run steps.
Updating a portable copy = download the new zip and replace everything except `Mooring Data`.

Note: the rpm and AppImage bundlers do not accept pre-release versions such as `0.1.0-rc.2`,
so pre-releases ship the `.deb` only on Linux; stable releases add `.rpm` and the AppImage.

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
`scripts/release/verify-release.sh v<v>` (or `make verify-release TAG=v<v>`): cosign signature,
every hash, no unlisted asset, provenance per file and, when the release carries `latest.json`,
that every manifest entry points at this release and matches its `.sig`; with `minisign`
installed it also verifies each updater artifact against the app's public key.

The certificate identity is always `release.yml@refs/tags/v<v>`, also for a release rebuilt by
hand (the workflow is then run from the tag). The script accepts nothing else and prints which
run signed (workflow commit, source commit, run URL).

## Updates

Mooring checks for updates **only when you ask** (Settings → Updates), or, if you opt in, once
a day in the background; a background check only shows a badge and never downloads anything.
The app reads `https://github.com/yyasar21/Mooring/releases/latest/download/latest.json`, which
GitHub resolves to the newest published stable release: drafts and pre-releases
(`v0.1.0-rc.2`) never appear there. Every update is verified against the public key compiled
into release builds (`plugins.updater.pubkey` in `src-tauri/tauri.release.conf.json`) before a byte is written, independently of TLS, and a
downgrade is refused.

In-app installation is offered only where it needs no elevation: a macOS `.app` in a folder you
can write to, the Windows per-user installer and the Linux AppImage. Everything else (`.msi`,
`.deb`, `.rpm`, Homebrew, an `/Applications` owned by root) shows the new version and sends you
to this page or your package manager; Mooring never asks for an administrator password.

A release without `latest.json` (built without the updater key) has no in-app channel.

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
     builds the bundles; macOS jobs add the `.pkg`, the universal one also the updater archive
     of the `.app` and the portable zip; the Windows job adds its portable zip. Each platform
     signing step runs only if its secrets exist. The build never holds the updater key;
   - **sign updater artifacts**: waits for the owner's approval of the `release` environment,
     then signs the updater archive, the Windows per-user installer and the AppImages with the
     Tauri CLI (pinned, checksum-verified) and the environment's `TAURI_SIGNING_PRIVATE_KEY`.
     The portable zips are excluded by name (`lint-workflows.sh` keeps it that way).
     No project code runs in that job. Without the secret the release gets no `.sig` files and
     no `latest.json`;
   - **finalize**: downloads every asset, adds the two SBOMs, writes `latest.json` and
     `SHA256SUMS`, signs it with cosign keyless, attests provenance for every file and uploads
     the lot.
4. Review the draft: notes (edit freely), asset list, the job summaries ("signed: true/false").
   Run `scripts/release/verify-release.sh vx.y.z`, then install it on at least one machine.
5. Click **Publish release**. That triggers `release-homebrew.yml`, which re-verifies
   `SHA256SUMS` and pushes the new Cask to `yyasar21/homebrew-mooring`.

To fix a failed build, re-run the failed jobs from the Actions page, or run the workflow
manually **from the tag** (Use workflow from → Tags → `vx.y.z`, with the same tag as input); a
manual run from a branch is refused. It uploads into the same draft with `--clobber`. A published release is
never rebuilt: cut a new patch version instead. Pre-release tags (`x.y.z-rc.1`) become
GitHub pre-releases and skip Homebrew.

## Secrets and variables

Configure under Settings → Secrets and variables → Actions, except the two updater secrets,
which belong to the **environment `release`** (Settings → Environments). Each one is optional:
without it the matching step is skipped and the build stays unsigned, so forks work as-is.

| Name | Kind | Used for |
| --- | --- | --- |
| `TAURI_SIGNING_PRIVATE_KEY` | **environment secret** (`release`) | Updater signatures + `latest.json`. Generate with `pnpm tauri signer generate -w mooring-updater.key`; the content of the file, not the path. Never a repository secret: only the `sign-updater` job, gated by the environment's required reviewer and its `v*` tag policy, may read it. |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | **environment secret** (`release`) | Password of that key; create the secret with an empty value for a key without one |
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

The environment `release` needs: required reviewer = the owner, *Deployment branches and tags*
limited to the tag rule `v*`. Recommended with it: a tag ruleset for `v*` (create/update/delete
by the owner only) and a branch ruleset on `main` (pull request + review, no force push).

## Build identity: Mooring and Mooring Dev

Every build is one of two apps (ADR-0028). They have separate identifiers, so they never share
a data directory, keychain items, WebView storage or an installer slot.

| Channel | Built by | Identifier / name | Data directory (`app_data_dir`) |
| --- | --- | --- | --- |
| Release | `release.yml` on a `v*` tag only | `io.github.yyasar21.mooring` / **Mooring** | macOS `~/Library/Application Support/io.github.yyasar21.mooring`, Windows `%APPDATA%\io.github.yyasar21.mooring`, Linux `~/.local/share/io.github.yyasar21.mooring`; portable: `Mooring Data/` |
| Dev | everything else: `make dev`, `make bundle`, `cargo tauri build`, CI, third-party pipelines | `io.github.yyasar21.mooring.dev` / **Mooring Dev** | the same paths with `io.github.yyasar21.mooring.dev`; portable: `Mooring Dev Data/` |

- `src-tauri/tauri.conf.json` is the dev identity: "Mooring Dev", DEV-ribbon icons
  (`src-tauri/icons-dev/`, from `packaging/icon-dev.svg`), no updater (the plugin is not
  registered; Settings → Updates says updates are disabled), its own WiX `upgradeCode`
  (UUIDv5 of the dev identifier), Linux package `mooring-dev`.
- `src-tauri/tauri.release.conf.json` holds only the release keys: identifier, productName,
  main window title, release icons, `createUpdaterArtifacts`, the shipped WiX `upgradeCode`,
  the updater `pubkey`/endpoint/`requireSignedVersion`. `release.yml` passes it as the first
  `--config` of every build (`lint-workflows.sh` rule 4) and sets `MOORING_RELEASE_BUILD=1`
  for `src-tauri/build.rs` (rule 5: nowhere else). The Tauri CLI merges `--config` files as
  JSON Merge Patch (RFC 7396): objects merge key by key, arrays replace, which is why the
  overlay repeats the whole `app.windows` entry. `scripts/release/merge-config.py
  check-identity` (run in CI and in the draft-release job) fails when the two drift.
- A forgotten flag yields a dev build, never a release-identity one. There is no
  `make bundle-release-local`: the release identity comes from CI only.
- The DMG window (`bundle.macOS.dmg`, both channels) uses `packaging/macos/dmg-background.png`
  (rendered from `dmg-background.svg`). The per-version volume name (`Mooring 0.2.0`) is the
  release.yml step behind the repository variable `DMG_VERSIONED_VOLUME=true`
  (`scripts/release/dmg-volume.sh`), off until an rc shows the background survives the rename.

## Local builds

`make bundle` (`cargo tauri build --no-sign`) builds unsigned **Mooring Dev** installers for the
current OS into `target/release/bundle/`; they install next to a released Mooring without
touching it. `make icons` regenerates both icon sets (`src-tauri/icons/` from
`packaging/icon.svg`, `src-tauri/icons-dev/` from `packaging/icon-dev.svg`). Package-manager
templates for later (winget, Scoop) live in `packaging/winget/` and `packaging/scoop/`.
