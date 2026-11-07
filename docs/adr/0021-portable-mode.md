# ADR-0021: Portable mode (Windows zip, macOS zip, `portable` marker)

Status: Accepted (owner decisions inline) · 2026-11-07 (Phase 0.1.1; builds on ADR-0003, ADR-0018 §2–3, `install_mode.rs`)

## Context
The owner needs Mooring on corporate PCs where nothing can be installed and there is no
admin: no NSIS/MSI, no `/Applications`, often no app-data policy exception for unknown apps.
Today every data path is resolved in `lib.rs` setup (`app.path().app_data_dir()`,
`app_cache_dir()`, both through `create_private_dir`) and handed to `AppState::new(data_dir,
…).with_cache_dir(cache_dir)`. Every other file location derives from those two fields: vault
header/backup, `audit.jsonl`, `mooring.db`, `known_hosts` and the `known_*_certs` stores
(`state.rs`, `commands/{sessions,sync_*,ldap_import,vsphere_login,audit}.rs`,
`secrets_runtime.rs`, `vsphere_sync.rs` copies `state.data_dir`), web profiles
(`web/mod.rs` `$APP_DATA/web/<id>`, `$APP_CACHE/web-ephemeral/<id>`, `web/sweep.rs`,
`oidc_window.rs`), the sync join temp file (`sync_join.rs`), the SFTP path guard
(`sftp_transfers.rs`). Import plans and update settings live in memory / the store, not in own
files. No module calls `app_local_data_dir`, `app_config_dir` or `temp_dir`; `tempfile` is
test-only. Two implicit locations exist: the main window's WebView2 profile
(`%LOCALAPPDATA%\<identifier>\EBWebView`, Tauri default when no `data_directory` is set) and,
on macOS, WKWebView site data under `~/Library/WebKit/<identifier>` (`Storage::Identifier`).

## Decision

### 1. Detection and refusal (`src-tauri/src/dirs.rs`, rust-core)
- Portable mode = a **regular file named `portable`** in the marker directory: Windows and
  Linux `current_exe().parent()`; macOS the parent of the `.app` bundle (`exe.ancestors()`
  up to `*.app`, then its parent — never inside the bundle: it is read-only and ad-hoc signed);
  AppImage `$APPIMAGE`'s parent (Linux gets detection for free; no Linux zip is produced).
  The marker's content is ignored. Checked with `symlink_metadata`: a symlink, a Windows
  reparse point (`FILE_ATTRIBUTE_REPARSE_POINT` via `MetadataExt::file_attributes`, no unsafe)
  or a directory is **`portable.marker_invalid`**, not "absent".
- Data root `<marker dir>/Mooring Data/` with `data/` and `cache/`; the root and both subdirs
  go through `create_private_dir` (0700; Windows §4). `Mooring Data` that exists but is a
  symlink/junction or not a directory → `portable.data_dir_invalid`. The root is by
  construction on the marker's volume; no volume-id check is needed beyond refusing reparse
  points. Network shares are allowed (README: one instance at a time; SQLite over SMB).
- Marker present but the marker directory or `Mooring Data` is **not writable** (probe =
  `install_mode::dir_writable`, create-and-remove, no `access(2)` guesswork) →
  **`portable.unwritable`**: a native message box (`tauri-plugin-dialog`, already registered
  Rust-side) naming the directory, then exit code 2. **Never** fall back to the OS app-data
  dir: a user who put the vault on a USB stick must know where it went; a silent fallback
  would create a second, empty vault in a roaming profile and leave the real one behind
  (**owner decision 2026-11-07: confirmed, no fallback**).
- One resolver, computed once in setup, so no module calls the Tauri path API:
```rust
pub struct Dirs { pub data: PathBuf, pub cache: PathBuf, pub portable_root: Option<PathBuf> }
pub enum DirsError { MarkerInvalid, DataDirInvalid, Unwritable(PathBuf), Os(tauri::Error) }
impl Dirs {
    pub const MARKER: &str = "portable";   pub const ROOT: &str = "Mooring Data";
    pub fn marker_dir(exe: &Path, appimage: Option<&Path>) -> Option<PathBuf>;   // pure
    pub fn resolve(exe: &Path, os_default: &dyn Fn() -> tauri::Result<(PathBuf, PathBuf)>,
                   probe: &dyn Fn(&Path) -> bool) -> Result<Self, DirsError>;    // tested
}
// AppState::new(dirs: Dirs, settings) replaces new(data_dir) + with_cache_dir; the
// `data_dir` / `cache_dir` fields stay, so the call sites above do not change.
```
- Main window: in portable mode `create_main_window` sets `data_directory(cache/webview)`
  (Windows, Linux). macOS cannot redirect WKWebView site data, so portable mode on macOS
  downgrades `Storage::Identifier` web profiles to ephemeral (`web.portable_ephemeral` in the
  existing storage-fallback reason; **owner decision 2026-11-07: downgrade, not document-only**) and the README states that the UI's own localStorage
  (no secrets, ADR-0003) stays under `~/Library/WebKit`.
- Audit `app.start { portable: true }` (no path in the log). `app_info` gains
  `portableDataDir: string | null`; About and Settings → Updates show
  "Portable build — data in <path>". No other UI change; UI stays English.

### 2. Updater
`InstallFacts.portable: bool` (from `Dirs.portable_root.is_some()`), checked first in
`decide`: `ManualReason::Portable` → code `update.manual_only`, message "portable build:
download the new zip and replace the folder". The background task is not installed and
`update_settings_set { backgroundCheck: true }` is refused with the same code. `update_check`
still works on demand (one HTTPS request, ADR-0018 §3). `latest.json` never lists portable
zips: `updater-manifest.sh` reads `*.sig` only and `sign-updater` signs only
`*.app.tar.gz | *-setup.exe | *.AppImage`; both get an explicit `*_portable.zip` refusal so a
future pattern change cannot widen them.

### 3. WebView2 on Windows
The plain `Mooring.exe` needs the **Evergreen WebView2 runtime**; `webviewInstallMode` only
configures the NSIS installer (`downloadBootstrapper`: needs network, per-user install
without admin; `embedBootstrapper`: same, offline bootstrapper; `offlineInstaller`: +~150 MB;
`fixedRuntime`: a runtime folder next to the exe, +~150 MB, pinned version to patch
ourselves). Decision: the portable zip bundles **no runtime** (the owner's targets are
Win10/11 with Evergreen present via Edge; a 150 MB zip would defeat the USB use case). In
portable mode the app checks `tauri::webview_version()` before any window; absent →
`portable.webview_missing` message box with the README step (Microsoft's Evergreen
bootstrapper, run unelevated → per-user install, no admin) and exit 2. A `_fixedruntime`
zip variant is possible later without code change if a site has no Evergreen at all.

### 4. Release pipeline (release-engineer, `release.yml` build job)
- `windows-x64`: after tauri-action, `target/x86_64-pc-windows-msvc/release/Mooring.exe`
  (Tauri names the binary from `productName`; R1 confirms the exact case in the dry run)
  + `portable` (empty) + `README.txt` → `Mooring_<v>_x64_portable.zip`.
- `macos-universal`: `target/universal-apple-darwin/release/bundle/macos/Mooring.app` (the
  ad-hoc signed bundle, unchanged) + `portable` + `README.txt` →
  `Mooring_<v>_universal_portable.zip`. `_CodeSignature` survives; no xattrs needed.
- One script `scripts/release/portable-zip.py` (python3 `-I`, `zipfile`, entries in
  `LC_ALL=C` order, mtime = `SOURCE_DATE_EPOCH` floored to 1980, Unix mode and symlinks in
  `external_attr`, deflate level fixed); same bytes from two runs is a test. Zips join
  "Collect release files" → `publish` → `SHA256SUMS` (cosign keyless) → provenance
  attestation, like every asset; **not** signed with the updater key (not updater artifacts);
  the Homebrew cask and `latest.json` are untouched. `verify-release.sh` accepts the two
  names and fails if either appears in `latest.json` or has a `.sig`. `docs/release.md` asset
  table + `getting-started.md` get a "Portable" row/section (docs owner).
- `README.txt` (English, ≤40 lines): what the folder is, keep `portable` next to the
  app, where the data lives, verify `SHA256SUMS` first, Gatekeeper "Open Anyway" / SmartScreen
  "Run anyway" once, Evergreen note, "update = download the new zip, replace everything
  except `Mooring Data`", back up `Mooring Data`.

## Alternatives considered
- Tauri NSIS "portable" flag: none exists; NSIS always writes an uninstaller and registry keys.
- Self-extracting exe: still an unsigned exe, unpacks to a temp dir, data location implicit.
- MSIX / App Installer (no admin): needs a trusted code-signing certificate the owner does not
  have (ADR-0018 §2) and is routinely blocked by policy. Later, with a certificate.
- `--data-dir <path>` CLI flag as the primary mechanism: on a USB stick there is no shortcut
  to edit and double-clicking loses the flag. May be added later as an override that beats
  the marker (explicit > implicit), never as the only way.
- `MOORING_DATA_DIR` env var: invisible, inherited by child processes, settable by a logon
  script → silent vault relocation. Rejected as primary; same override rule.

## Security consequences
- A co-located attacker with write access to the folder can replace `Mooring.exe` /
  `Mooring.app`; portable mode does **not** defend against that (as any portable app; an
  installed per-user NSIS copy is no better). The audit chain still detects log tampering;
  the vault stays Argon2id + XChaCha20-Poly1305 (ADR-0002); users should keep the
  calibrated KDF floor even on slow removable media.
- No OS keychain today, so nothing changes there. Lost USB stick = lost vault; README: back up.
- Windows ACL: `create_private_dir` relies on `%APPDATA%` today. On NTFS portable roots
  rust-core runs `C:\Windows\System32\icacls.exe` with fixed argv (ADR-0020 pattern, no
  shell) to make `Mooring Data` owner-only (**owner decision 2026-11-07: in 0.1.1, not later**); failure (FAT32/exFAT USB: no ACLs) is audited as
  `portable.acl_unavailable`, not fatal — the vault is encrypted at rest regardless.
- Marker and data root must be regular objects (§1); reparse points are refused so the data
  cannot be redirected to another volume or user profile.
- macOS: quarantine is the user's manual Gatekeeper step; the app never runs or suggests
  `xattr -d`. AppLocker/WDAC may block any unsigned exe: out of scope, documented.
- New error codes: `portable.marker_invalid`, `portable.data_dir_invalid`,
  `portable.unwritable`, `portable.webview_missing` (ipc-codes.json; no secret, no new crate).
## Test plan
- Unit (`dirs.rs`, scripted probe + tempdir): marker absent → OS dirs; present → `Mooring
  Data/{data,cache}` created 0700; unwritable → `Unwritable` / `portable.unwritable`;
  symlinked marker, directory named `portable`, junctioned `Mooring Data` → refused; macOS
  `marker_dir` from `…/Mooring.app/Contents/MacOS/mooring`; AppImage parent.
- Install-mode: `portable: true` beats every bundle → `Manual(Portable)`,
  `update.manual_only`; background opt-in refused; `app_info.portableDataDir`.
- Pipeline: `scripts/release/tests/portable-zip.test.sh` (two runs → identical sha256, entry
  order, 1980-floor mtimes, mode/symlink round trip); `lint-workflows.sh` (`*_portable.zip`
  never in `sign-updater`'s find); `updater-manifest.test.sh` ignores a stray zip;
  `verify-release.test.sh` accepts the two zips and rejects one listed in `latest.json`.
- Manual gate per OS, fresh non-admin account: Windows 11 (NTFS Desktop and FAT32 USB:
  unzip, SmartScreen once, vault create, SSH connect, lock, move folder, data follows);
  macOS 15 (`~/Applications`, Desktop, USB: Gatekeeper once, same flow, `~/Library/WebKit`
  holds no credentials); read-only folder → `portable.unwritable` dialog, no fallback dir.
