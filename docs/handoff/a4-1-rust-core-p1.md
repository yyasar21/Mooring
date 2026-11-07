# A4.1 · rust-core · P1: portable mode (ADR-0021 §1, §2, §3, Windows ACL)

Worktree `agent-acd0d2fcaba794cea`, branch `worktree-agent-acd0d2fcaba794cea`, from `2fdc10f`
(ADR-0021 accepted). No manifest, lockfile, capability or `tauri.conf.json` change; no new crate.
Everything under `src-tauri/src/**` and `crates/mooring-audit/**`, plus one checked-in golden
(`src-tauri/ipc-codes.json`, blessed) and one line in `src-tauri/tests/e2e_flow/a4_update.rs`
(see "Shared files").

## Done

| Area | What |
| --- | --- |
| **`src-tauri/src/dirs.rs`** (new, + `dirs_tests.rs`) | `Dirs { data, cache, portable_root }`, `DirsError { MarkerInvalid(path), DataDirInvalid(path), Unwritable(path), Os(tauri::Error) }` with `code()` → `portable.marker_invalid` / `portable.data_dir_invalid` / `portable.unwritable` / `app.data_dir`, `path()` and a `Display` that names the directory and nothing else. `MARKER = "portable"`, `ROOT = "Mooring Data"`, `WEBVIEW_DIR = "webview"`. `marker_dir(exe, appimage)` (pure): `$APPIMAGE` parent first, then the parent of a `<X>.app/Contents/MacOS/<exe>` bundle (exact shape only, so the rule is OS-independent and testable on Linux), else `exe.parent()`. `resolve(exe, appimage, os_default, probe)`: marker looked up with `symlink_metadata`; absent → `os_default()` dirs through `create_private_dir`; a symlink, Windows reparse point (`FILE_ATTRIBUTE_REPARSE_POINT` via `MetadataExt::file_attributes`), directory or unreadable marker → `MarkerInvalid`; `Mooring Data` that exists but is a link/reparse point/file → `DataDirInvalid`; root missing and marker dir fails the probe → `Unwritable(marker dir)`; create failure or `data`/`cache` failing the probe → `Unwritable(root)`. Root and both subdirs go through `create_private_dir` (0700 on unix). **No fallback to the OS dirs on any error.** `Dirs::plain(data, cache)`, `portable()`, `webview_dir()` (`cache/webview`, portable only). |
| **`src-tauri/src/startup.rs`** (new) | `Refusal { code, message }` (from `DirsError`; `webview_missing()` → `portable.webview_missing` with the README / Evergreen bootstrapper text). `resolve_dirs(app)` (= `Dirs::resolve` with `current_exe`, `$APPIMAGE`, `app.path().app_data_dir()/app_cache_dir()`, `install_mode::dir_writable` as the probe). `check_webview(dirs)`: Windows + portable + `tauri::webview_version().is_err()` → refusal. `refuse(handle, refusal)`: `tauri-plugin-dialog` error box ("Mooring cannot start", the message) whose dismiss callback calls `std::process::exit(2)`, plus a 120 s watchdog thread that exits 2 if the box can never be shown (headless). The dialog is queued on the event loop (setup runs before it), so setup returns `Ok(())` **without managing state or creating any window**. |
| **`lib.rs` setup** | `Dirs` computed once; refusal → `startup::refuse` + return. Then Windows ACL (below), `AppState::new(dirs, Settings::production())`, audit `app.start { portable }` (no path) and, when the ACL step failed, `portable.acl_unavailable`; `create_private_dir(cache/webview)` and `navigation::create_main_window(app, Some(cache/webview))` in portable mode on Windows / Linux (`None` on macOS: WKWebView has no knob; nothing is created there); `OsProbe { portable }` into the `UpdateRuntime`. |
| **`state.rs`** | `AppState::new(dirs: Dirs, settings)` replaces `new(data_dir)` + `with_cache_dir` (removed). Fields `data_dir`, `cache_dir` unchanged (no call site outside the constructor changed); new `portable_root: Option<PathBuf>`. The `testing` module moved verbatim to `state_testing.rs` (`#[path]`, the file was at 499 lines) and gained `dirs(path)`, `portable_dirs(root)`, `empty_portable()`. Every `AppState::new` call site (syslog/sync/vault tests) now passes `testing::dirs(dir)`. |
| **`navigation.rs`** | `create_main_window(app, data_dir: Option<PathBuf>)` → `WebviewWindowBuilder::data_directory` when `Some`. |
| **`web/mod.rs`** | `WebPlan.persistent_refused: Option<StorageFallback>` (was `bool`); `StorageFallback::{MacOsVersion, Portable}` with `reason()` → `web.needs_macos_14` / `web.portable_ephemeral`. `plan()`: `persistent && macOS && portable` → `Storage::Ephemeral` + `Portable` **before** the ≥ 14 `Identifier` arm (owner decision: downgrade). Windows / Linux persistent profiles stay `Directory($APP_DATA/web/<id>)`, i.e. inside `Mooring Data`. `commands/web.rs` logs the reason; `vsphere_console.rs` passes `None`. |
| **Updater** | `InstallFacts.portable: bool`, checked first in `decide` → `ManualReason::Portable` (wire `"portable"`), code `update.manual_only`, message exactly `portable build: download the new zip and replace the folder`. `OsProbe { portable }` (was a unit struct; `Default` = not portable, used by `unconfigured`). `background::install` returns early in portable mode (log line). `commands/update.rs::settings_set`: `backgroundCheck: true` in portable mode → `update.manual_only` with that message, audited as `update.refused { code }`, nothing stored; `false` is accepted; `update_check` / `update_install` unchanged (install answers the matrix). |
| **`app_info`** | `AppInfo` is now `camelCase` with public fields and `portableDataDir: string \| null`; the command takes `State<AppState>`; `vault::info(&state)` is the pure function. |
| **Audit** (`crates/mooring-audit/src/event/a4.rs`) | `AuditEvent::AppStart { portable: bool }` → `app.start`; `AuditEvent::PortableAclUnavailable` → `portable.acl_unavailable`. Both round-trip tested in `chain_tests.rs`. |
| **Windows ACL** (`src-tauri/src/portable_acl.rs`, new) | `apply(root)`: `C:\Windows\System32\icacls.exe <root> /inheritance:r /grant:r *S-1-3-4:(OI)(CI)F` — `std::process::Command`, `env_clear` (+ `SystemRoot` only), null stdin, piped stdout/stderr read on their own threads capped at 4 KiB each, `CREATE_NO_WINDOW`, `try_wait` polling with a 10 s deadline then `kill`. `AclError::{Spawn, Timeout, Failed(code)}` logged by kind; the caller audits `portable.acl_unavailable`, never fatal. Unix: no-op (`0700` already applies). Grantee = **OWNER RIGHTS** well-known SID `S-1-3-4`: the ACE binds to whoever owns the object at access time (the unelevated user who created `Mooring Data`; after a copy, the copying user), children inherit it, no account name is needed — so no `%USERNAME%` trust, no `whoami`, no Win32 crate. `argv(root)` is pure and pinned by a test; an NTFS round-trip test runs only on the Windows CI runner. |
| **Codes** | `ipc-codes.json` blessed: `+ app.data_dir, portable.data_dir_invalid, portable.marker_invalid, portable.unwritable, portable.webview_missing`. `web.portable_ephemeral` is a log reason, not an error code, so it was added to `golden.rs::NOT_CODES` (same treatment as `app.update`). |

### UI contract (ui-engineer)

- `app_info()` → `{ name, version, os, arch, debug, portableDataDir: string | null }`. All keys
  are now camelCase (the five old ones were single words, so nothing changes for them).
  Show "Portable build — data in <portableDataDir>" in About and Settings → Updates when non-null.
- `update_check()` → `manualReason: "portable"` (new `ManualReason` value, alongside
  `package_manager` / `homebrew` / `not_writable` / `not_bundled`); `installMode: "manual"`.
- `update_settings_set({ backgroundCheck: true })` in portable mode → `IpcError
  { code: "update.manual_only", message: "portable build: download the new zip and replace the folder" }`.
  Suggest disabling the toggle when `portableDataDir` is non-null and showing that text.
- Audit rows the UI may list: `app.start { portable }`, `portable.acl_unavailable`.
- Startup refusals (`portable.*`, `app.data_dir`) never reach the WebView: there is no window;
  they are native boxes + exit 2.

## Shared files touched

- `src-tauri/tests/e2e_flow/a4_update.rs` (qa-engineer scope): one line, `portable: false,` in
  the `InstallFacts` literal — without it the `e2e_flow` test crate does not compile. Nothing else.
- `src-tauri/ipc-codes.json`: blessed golden (see above).

## Left open

- **Windows and macOS compile/run**: this environment is Linux. `#[cfg(windows)]` code
  (`portable_acl::apply`, the reparse-point check) and `tauri::webview_version()` are written
  against the pinned `tauri 2.12.5` / std APIs but only the CI matrix proves them. The NTFS
  test (`portable_acl::tests::ntfs_root_becomes_owner_only_and_stays_writable`) runs there.
- The refusal dialog is shown through `run_on_main_thread` once the event loop starts; if a
  platform shows nothing (no display), the 120 s watchdog still exits 2. Manual gate per ADR-0021
  "Test plan" (read-only folder → dialog, no fallback dir) is the proof.
- `Dirs::resolve` takes `appimage: Option<&Path>` in addition to the ADR sketch's
  `(exe, os_default, probe)` so the AppImage rule is testable; semantics as specified.
- ADR §2 release-pipeline items (`updater-manifest.sh`, `sign-updater` refusals, zips) and
  README.txt are release-engineer's (P2); `docs/release.md` / `getting-started.md` are docs
  owner's.

## Decision needed

- None blocking. One note for the security reviewer: OWNER RIGHTS (`S-1-3-4`) was chosen over
  `%USERNAME%` so a logon script cannot steer the grant to another account; the trade-off is
  that an elevated first start (owner = Administrators) would make the folder admin-group-owned
  until the owner changes — the README's "run unelevated" already covers it.

## Test evidence

```
Linux x86_64 (Ubuntu, WebKitGTK toolchain present), 2026-11-07, worktree agent-acd0d2fcaba794cea

cargo fmt --all -- --check                                   → clean
cargo clippy -p mooring-app --all-targets -- -D warnings     → Finished, 0 errors
cargo clippy --workspace --all-targets -- -D warnings        → Finished, 0 errors
cargo test -p mooring-app                                    → 367 passed; 0 failed; 1 ignored (lib)
                                                               39 passed; 0 failed (e2e_flow)
cargo test -p mooring-audit                                  → 37 passed; 0 failed
MOORING_BLESS=1 cargo test -p mooring-app golden             → 6 passed (ipc-codes.json rewritten, +5)

New tests (19 selected by name, all pass):
  dirs::tests::{marker_absent_uses_os_dirs_and_creates_them, marker_present_creates_private_root_and_subdirs (0700 on unix),
    unwritable_marker_dir_is_refused_without_fallback, unwritable_existing_root_is_refused,
    directory_named_portable_is_invalid_not_absent, symlinked_marker_is_refused (unix, incl. dangling),
    symlinked_data_root_is_refused (unix), file_named_mooring_data_is_refused, marker_dir_shapes (macOS .app, AppImage, plain),
    errors_name_the_directory_only}
  startup::tests::{refusals_carry_the_code_and_name_the_directory, webview_check_only_bites_on_windows}
  portable_acl::tests::{argv_is_fixed_and_names_only_the_root, unix_is_a_no_op} (+ ntfs_… on Windows only)
  updater::tests::portable_beats_every_bundle_kind (8 bundles × writable × cask → Manual(Portable), code + message + wire name)
  commands::update::tests::portable_mode_refuses_the_background_opt_in_but_checks_on_demand
  commands::vault::tests::app_info_reports_the_portable_data_dir
  web::tests::portable_mode_downgrades_macos_persistent_profiles
  mooring-audit chain::tests::portable_events_have_stable_wire_names
```
