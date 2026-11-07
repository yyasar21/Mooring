# 0.1.1 (A4.1) — architect handoff: portable mode

Date: 2026-11-07 · docs only (`docs/adr/0021-portable-mode.md`, this note, index row)

## Done
- **ADR-0021** Portable mode (Proposed): `portable` regular-file marker next to `Mooring.exe` /
  next to the `.app` (never inside the bundle); data under `<marker dir>/Mooring Data/{data,cache}`
  with the existing `create_private_dir` tightening; marker present + unwritable directory →
  `portable.unwritable` native dialog and exit 2, **no fallback** to the OS app-data dir;
  symlink/reparse-point marker or data root refused (`portable.marker_invalid`,
  `portable.data_dir_invalid`).
- Call-site inventory: every on-disk location already derives from `AppState.data_dir` /
  `AppState.cache_dir` (vault header, audit, db, known_hosts, known_*_certs, web profiles,
  OIDC profiles, sync join temp, SFTP guard, vsphere sync ctx); only `lib.rs` setup calls the
  Tauri path API; no `app_local_data_dir` / `app_config_dir` / `temp_dir` use; `tempfile` is
  test-only. Two implicit locations found and handled: the main window's WebView2 profile
  (`%LOCALAPPDATA%\<id>\EBWebView` → `data_directory(cache/webview)` in portable mode) and
  macOS WKWebView site data (`~/Library/WebKit`, cannot be redirected → persistent web
  profiles downgraded to ephemeral in portable mode; UI localStorage documented).
- Proposed resolver `Dirs { data, cache, portable_root }` + `Dirs::resolve(exe, os_default,
  probe)` in `src-tauri/src/dirs.rs`, computed once in setup; `AppState::new(dirs, settings)`
  replaces `new(data_dir)` + `with_cache_dir`; fields unchanged so no call site moves.
- Updater: `InstallFacts.portable` → `ManualReason::Portable` → `update.manual_only` with the
  owner's message; background task not installed, opt-in refused; portable zips never in
  `latest.json` (manifest reads `*.sig` only; `sign-updater` find pattern excludes them; explicit
  `*_portable.zip` refusals added to both).
- WebView2: Evergreen dependency documented with the four `webviewInstallMode` options;
  decision = bundle nothing, detect absence via `tauri::webview_version()` before any window
  (`portable.webview_missing`), README points to Microsoft's bootstrapper (per-user, no admin);
  `_fixedruntime` variant possible later without code change.
- Pipeline: zips built in the existing `windows-x64` and `macos-universal` build jobs from the
  plain exe / the ad-hoc signed `.app`; `scripts/release/portable-zip.py` (python `-I`,
  `zipfile`, sorted entries, `SOURCE_DATE_EPOCH` mtimes, modes/symlinks in `external_attr`);
  flow through `publish` → `SHA256SUMS` → provenance like every asset; not updater-signed;
  cask untouched; `verify-release.sh` accepts the two names and rejects them in `latest.json`.
- Security deltas, five alternatives, test plan (unit, install-mode, release-script tests,
  per-OS manual gate with a fresh non-admin account) are in the ADR.

## Left open
- Exact case of the Windows binary name under `target/x86_64-pc-windows-msvc/release/`
  (`Mooring.exe` per `productName`; the release-engineer confirms in the rc dry run).
- Whether Windows `icacls` owner-only ACL on NTFS portable roots is wanted now or deferred
  (ADR §Security; today Windows relies on the `%APPDATA%` ACL even for installed builds).
- `README.txt` wording (docs owner, English, ≤40 lines; outline in ADR §4).
- Linux: detection works next to an AppImage for free; no Linux portable zip is produced.

## Decision needed (owner)
1. Confirm "refuse to start, never fall back" (ADR §1) — matches the stated expectation.
2. macOS portable: persistent web-session profiles downgraded to ephemeral (nothing of a web
   session lands in `~/Library/WebKit`), or keep `Storage::Identifier` and only document it.
3. `icacls` owner-only ACL on NTFS portable roots now (new fixed-path process call, ADR-0020
   pattern) or defer to 0.1.2.
4. Numbering: owner decisions continue at 20 if the ADR is accepted.

## Test evidence
Docs only; nothing to run. `wc -l docs/adr/0021-portable-mode.md` = 149 (limit 150).
