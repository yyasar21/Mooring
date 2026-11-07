# ADR-0028: Build identity and macOS install hygiene

Status: Accepted 2026-11-07 (owner decisions 43–48 at their recommended defaults) · 2026-11-07 (A5 wave W3; builds on ADR-0018 §3 + A1, ADR-0021 §1 + M-18,
ADR-0013 dialog slots, ADR-0020 fixed-path tools)

## Context
Owner report (macOS 26.7.3 Intel): "many Mooring versions" after a DMG drag + Replace. A
read-only diagnosis found one install (`/Applications/Mooring.app` 0.1.2) plus LaunchServices
records for `make bundle` output, an Azure DevOps agent workspace (three `0.1.0-rc.1` bundles),
a still-mounted `/Volumes/Mooring` and stale `/Volumes/Mooring 1`, `/Volumes/dmg.xGFo9z`. Every
build carries `io.github.yyasar21.mooring`, so every build shares `~/Library/Application
Support/<id>`, Caches, `~/Library/WebKit/<id>` and the keyring service (`keyring_store.rs`
hard-codes it): a dev build with newer migrations can upgrade the installed app's vault. `make
dev` runs a bare binary (hence `~/Library/WebKit/mooring-app`) but the Tauri path API still uses
the config identifier, i.e. the release data dir. `release.yml` already passes a generated
`--config tauri.ci.json`; tauri-build merges `TAURI_CONFIG` with RFC 7396 merge patch
(tauri-build 2.7.4 `lib.rs:681`) and only auto-reads `tauri.<platform>.conf.json`. M-18 today
refuses **every** translocated launch (`Dirs::locate`, before the marker lookup): a translocated
copy cannot see its marker, so "portable or not" is unknowable there.

## Decision

### 1. Two identities; the checked-in config is the dev one (secure default)
| | Release (tag builds in `release.yml` only) | Dev (everything else) |
| --- | --- | --- |
| identifier / productName | `io.github.yyasar21.mooring` / `Mooring` | `io.github.yyasar21.mooring.dev` / `Mooring Dev` |
| icons | `src-tauri/icons/` | `src-tauri/icons-dev/` from `packaging/icon-dev.svg` (DEV ribbon) |
| updater | pubkey + endpoints + `createUpdaterArtifacts` | none → plugin not registered; `ManualReason::DevBuild` |
| Windows | WiX `upgradeCode` `1f940c60-…` (unchanged, byte-identical) | new UUIDv5 of the dev id; NSIS key/dir follow productName |
| Linux | deb/rpm `mooring`, `Mooring.desktop` | `mooring-dev`, own desktop id / `StartupWMClass` |
- `src-tauri/tauri.conf.json` becomes the dev identity; `src-tauri/tauri.release.conf.json`
  (new, release-engineer) holds only the release keys. The `release.yml` cfg step merge-patches
  the overlay into the generated `tauri.ci.json` (one `--config`, overlay first, CI keys on top).
  `make dev`, `make bundle`, plain `cargo tauri build`, CI artifacts and third-party pipelines
  (the owner's Azure DevOps agent) get "Mooring Dev" without knowing about this ADR: a forgotten
  flag yields a dev build, never a release-identity one.
- Rust (rust-core): `build.rs` re-derives the effective identifier (checked-in file +
  `TAURI_CONFIG` merge, `serde_json` build-dep already in the tree) and emits
  `cargo:rustc-cfg=mooring_release` iff it equals the release id (`rustc-check-cfg`,
  `rerun-if-env-changed=TAURI_CONFIG`). New `build_identity.rs`: `Channel { Release, Dev }`
  from `cfg!(mooring_release)`; at setup `context.config().identifier` must match the channel,
  else `app.build_identity` refusal (startup.rs path, exit 2). `app_info` gains
  `channel: "release" | "dev"`.
- Everything identity-scoped follows the identifier: `app_data_dir`/`app_cache_dir` (Tauri
  path API), WKWebView `~/Library/WebKit/<id>`, WebView2 `%LOCALAPPDATA%\<id>\EBWebView`, and
  `keyring_store::SERVICE` (now `app.config().identifier`). Portable: `Dirs::ROOT` becomes
  `Dirs::root_name(channel)` = `Mooring Data` / `Mooring Dev Data`; the marker stays `portable`.
- Updater: `ManualReason::DevBuild` is checked first in `decide` (before `Portable`), code
  `update.manual_only`, message "development build: updates are disabled"; background opt-in
  refused with the same code. Homebrew cask, winget, scoop, `latest.json`, portable zips and
  the `.pkg` are release-only and unchanged; `macos-pkg.sh` reads the id from `Info.plist` and
  now fails on a `.dev` id when `GITHUB_REF` is a tag. ADR-0022's keychain group stays release.

### 2. Move to Applications (macOS, new `src-tauri/src/install_location.rs`)
- `classify(exe, located, home, downloads) -> Location` (pure): `Translocated` (M-18 rule),
  `Volume(path)` (under `/Volumes/`), `Downloads` (under Tauri `download_dir()`, canonical),
  `Installed`, `Other`. Offered only for release builds, `Located::Os` (a marker → never),
  no `--mooring-moved` in argv, no Homebrew cask (N-55 probe), and not dismissed for this version.
- Dialog (ADR-0013 slots, `vsphere_confirm::buttons`): **Cancel / Move to Applications / Not
  now**; both refusing slots continue this run, "Not now" stores `install.move_declined =
  <version>` in the settings store. Text names the target and, when replacing, its version.
- Translocated launch (replaces the bare M-18 box): same dialog, text adds "If this is a portable
  copy, choose Cancel and drag Mooring.app out of its folder and back in with Finder." Both
  refusing slots end in the existing M-18 refusal (exit 2, no window, no fallback); nothing is
  remembered. M-18 therefore keeps refusing every translocated *run*; only the offer is new.
- Target: `/Applications` if `dir_writable`, else `~/Applications` (created 0755); never elevate.
  Existing `Mooring.app`: `CFBundleIdentifier` (plist) must equal ours, else `install.not_ours`;
  same or newer `CFBundleShortVersionString` → no copy, open that copy instead (the owner's
  "re-opened the DMG" case); running (`/bin/ps -axww -o comm=` prefix match) → `install.running`.
- Copy: `/usr/bin/ditto <src> <dir>/.Mooring.app.<nonce>`, then `/usr/bin/codesign --verify
  --deep --strict` on the copy, rename old aside, rename new in, remove old (rollback on any
  failure). Fixed paths, `env_clear`, no shell, 60 s timeout (ADR-0020). Quarantine is kept;
  Gatekeeper decides. Relaunch `/usr/bin/open -n <new> --args --mooring-moved`, then exit 0.
- The relaunched copy (seeing `--mooring-moved`, used only to suppress the offer and trigger
  this step) lists `hdiutil info -plist` image mounts under `/Volumes/` whose `Mooring.app` has
  our id and runs `/usr/bin/hdiutil detach <mount>` (no `-force`); failure is non-fatal.
- Audit (in the relaunched copy; a translocated process has no data dir): `install.moved {
  target: applications | user_applications, replaced, detached }`; otherwise
  `install.move_declined { remember }`, `install.move_failed { code }`. No paths in the log.
- Dependency: `plist` 1.10.3 becomes a direct macOS dep of `mooring-app` (MIT, 2026-10-21,
  0 `unsafe`, already in the lockfile via tauri-utils). **No new crate.**

### 3. DMG polish (release-engineer, `bundle.macOS.dmg` in tauri-utils 2.10.2 `DmgConfig`)
`background: ../packaging/macos/dmg-background.png` (660×400 with an arrow and "Drag Mooring to
Applications, then eject this disk."), `windowSize 660×400`, `appPosition {180,170}`,
`applicationFolderPosition {480,170}`. `DmgConfig` has no volume-name field (the bundler uses
productName), so a per-version volume (`Mooring 0.2.0`) needs a post-step in the dmg rebuild of
ADR-0018 A1 (UDRW → `diskutil rename` → UDZO); kept only if the background survives (decision 46).

### 4. Stale registrations: guidance, not code
The app never runs `lsregister` (private tool, global effect on every app's registrations).
User guide → troubleshooting "Clean up duplicate Mooring entries": the read-only diagnose
(`lsregister -dump | grep -B2 -A8 io.github.yyasar21.mooring`, `hdiutil info`), then
`hdiutil detach /Volumes/Mooring*`, `lsregister -u <path>` per stale bundle, `lsregister -gc`,
removing old build outputs, and the note that builds from source are now "Mooring Dev" and
no longer collide; `~/Library/WebKit/mooring-app` is `make dev` UI storage (no secrets).

## Alternatives considered
- Release flag on the dev side (`--config tauri.dev.conf.json` for `make dev`): a forgotten
  flag (any third-party pipeline) produces a release-identity build. Rejected (insecure default).
- Runtime-only channel (identifier check, no `cfg`): works, but the cross-check catches a stale
  build cache or a hand-edited config; kept as the second half, not alone.
- LetsMove (MIT, Objective-C, Sparkle era): FFI/`unsafe`, strips `com.apple.quarantine` and
  elevates through Authorization Services — all three refused here. No move-to-Applications
  plugin exists in tauri-apps/plugins-workspace 2.x; a community crate would be new code to vet.
- Finder-guided move only (reveal + instructions): safest, but the owner's report is exactly
  users not doing it. Kept as the fallback if §2's copy re-translocates (test plan).
- App-driven `lsregister -u`: private, unstable flags, global side effects. Rejected.

## Security consequences
- Identity is not a trust boundary (anyone can apply the overlay); the updater key and platform
  signing stay the trust roots. It removes cross-contamination: dev builds no longer migrate,
  read or share the installed vault, keyring items or WebKit storage.
- Move: user-confirmed, never elevated, fixed-path tools without shell or inherited env, our
  bundle id checked before replace, signature verified before swap, quarantine untouched. An
  attacker who can write `/Applications` could already replace the app (no new capability).
- `--mooring-moved` carries no data; a forged flag only suppresses the offer and detaches a
  disk image that contains our own app. New codes: `app.build_identity`, `install.not_ours`,
  `install.running`, `install.copy_failed`, `install.not_writable` (ipc-codes.json).

## UI (ui-engineer; English only)
Title "Mooring — Dev" (set in `create_main_window` from the channel) and a "DEV" badge in the
title bar; About shows "Development build (io.github.yyasar21.mooring.dev)"; Settings → Updates
shows "Updates are disabled in development builds. Install a release from the Releases page."

## Test plan
- Unit: `classify` on `/Volumes/Mooring/Mooring.app/…`, `/Volumes/Mooring 1/…`, translocated
  `/private/var/folders/…/AppTranslocation/…`, `~/Downloads/…`, `/Applications/…`, portable
  marker (never offered), cask present, declined version; replace guard (foreign id, newer,
  same, running); `decide` with `DevBuild` before `Portable`; `root_name`; channel/identifier
  mismatch → `app.build_identity`; keyring service from the identifier.
- Config: Rust test reads `tauri.conf.json` + overlay: base id ends `.dev`, no pubkey, dev
  upgradeCode ≠ release; merged = release id, pubkey, release upgradeCode byte-identical.
- E2E/manual (macOS 26): each dialog slot from a mounted DMG, from Downloads and translocated;
  replace 0.1.2; `~/Applications` fallback as a standard user; relaunched copy not translocated
  (else fall back to the Finder-guided path); volume detached; audit events present.
- Pipeline: `lint-workflows.sh` rule 4 (release.yml cfg step loads `tauri.release.conf.json`,
  every tauri build in `release*.yml` passes `--config`); release.yml asserts the release id in
  `Info.plist` / `dpkg-deb -f Package`; ci.yml macOS `tauri build --debug --bundles app
  --no-sign` asserts `.dev` in `Info.plist`.

## Owner decisions (numbered after ADR-0018 A1's 42; recommended defaults)
43 Dev icon: release icon + orange diagonal "DEV" ribbon (yes). 44 `~/Applications` fallback
when `/Applications` is not writable, named in the dialog (yes, never elevate). 45 Windows and
Linux get the dev identity in the same release (yes, one overlay). 46 Per-version DMG volume
name (yes if the background survives the rename, else keep "Mooring"). 47 Offer the move in dev
builds (no). 48 Copy existing release data into the dev dir (no; dev starts empty).
