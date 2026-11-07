# A4.1 security review 8 — 0.1.1 portable mode (ADR-0021)

Reviewer: security-reviewer · 2026-11-07 · Range `git diff 2fdc10f..HEAD` (`main` @ `9a2f2df`,
66 files, +2 841 / −138: rust-core P1, release-engineer P1, ui P1, qa Q1, fix round F1).
Read: `src-tauri/src/{dirs,dirs_tests,startup,portable_acl,lib,state,state_testing,navigation}.rs`,
`src-tauri/src/web/{mod,window,sweep}.rs`, `src-tauri/src/updater/{install_mode,background,mod,
tests}.rs`, `src-tauri/src/commands/{update,vault,web}.rs`, `crates/mooring-audit/src/event/a4.rs`
+ `chain_tests.rs`, `src-tauri/ipc-codes.json`, `golden.rs`, `.github/workflows/release.yml`,
`scripts/release/{portable-zip.py,lint-workflows.sh,updater-manifest.sh,verify-release.sh}` and
their tests, `packaging/portable/README.txt`, `docs/user-guide/getting-started.md`,
`apps/desktop/src/{components/settings/{PortableLine,AboutCard,UpdatesCard}.tsx,stores/errors.ts,
components/audit/AuditView.tsx}` and the new tests (`dirs_tests.rs`,
`tests/e2e_flow/a4_1_portable{,_dirs}.rs`, `portable.test.tsx`).

Inputs: [ADR-0021](../adr/0021-portable-mode.md) (Accepted, owner decisions inline), handoffs
`a4-1-{architect,rust-core-p1,release-engineer-p1,ui-p1,qa-q1}.md`,
[review 7 / 7b](a4-review-7.md), the [threat model](threat-model.md).

Evidence gathered here (Linux x86_64, WebKitGTK toolchain, `CARGO_TARGET_DIR` reused):
- `git diff --stat 2fdc10f..HEAD -- Cargo.lock pnpm-lock.yaml Cargo.toml src-tauri/Cargo.toml
  package.json src-tauri/tauri.conf.json src-tauri/capabilities deny.toml` → **empty**. No new
  crate, no capability, no CSP, no config change.
- `grep -rn unsafe src-tauri/src crates/mooring-audit/src` → only the two `#![forbid(unsafe_code)]`.
- `cargo deny --offline check` → advisories ok, bans ok, licenses ok, sources ok.
- `cargo audit --no-fetch --db ~/.cargo/advisory-db/advisory-db-3157b0e258782691` → the same
  set as review 7 (RUSTSEC-2023-0071 `rsa`, R-RSA; 7 unmaintained warnings) plus
  RUSTSEC-2024-0429 `glib` unsound (Linux only, pre-A4, the accepted GHSA-wrw7-89jp-8q8g). Nothing
  from this range.
- `cargo test -p mooring-app --lib` (dirs / portable_acl / startup / web::portable /
  updater::portable / update::portable / app_info filters) → 20 passed;
  `--test e2e_flow a4_1_portable` → 12 passed, 0 ignored; `mooring-audit`
  `portable_events_have_stable_wire_names` → ok.
- `bash scripts/release/tests/run.sh` → lint-workflows 12, portable-zip 71, updater-manifest 24,
  verify-release 34 passed, 0 failed. `lint-workflows.sh .github/workflows` → ok.
- **Not run:** Windows (`icacls`, reparse points, `webview_version`), macOS (`.app`, Gatekeeper,
  App Translocation), `actionlint`, the workflow, `pnpm test` (ui P1 / Q1 evidence taken as
  reported), any per-OS gate.

## Verdict: `APPROVE WITH NITS` (merge) — the `v0.1.1` tag is conditional on M-18

No blocker. The code holds the four properties the ADR made central:

- **The marker decides, and nothing falls back.** `Dirs::resolve` consults the OS path API only
  when the marker is absent (`dirs.rs:159-166`; the E2E passes a closure that panics if it is
  called). Every error is a `Refusal` → native box → `exit(2)` with no window and no managed
  state (`startup.rs:67-79`, `lib.rs:113-121`). Symlinks, Windows reparse points, directories
  and unreadable markers are `portable.marker_invalid`, never "absent" (`dirs.rs:163-165`); a
  linked or non-directory `Mooring Data`, `data` or `cache` is `portable.data_dir_invalid`
  before anything is created or chmod'ed through it (`dirs.rs:183-202`, F1 fix of a4-1-qa-1).
  Pre-existing 0777 roots are tightened to 0700 (`lib.rs:335-336`, pinned by
  `pre_existing_world_writable_dirs_are_tightened_to_0700`). No `unsafe`.
- **Updater.** `portable` is the first arm of `decide` (`install_mode.rs:144-146`), so every
  bundle / path / writability / cask combination is `Manual(Portable)` (8 × 2 × 2 test).
  `update_install` answers the matrix before the source is touched (`commands/update.rs:273`),
  the background task is never installed (`background.rs:62-66`) and the opt-in is refused and
  audited, not stored (`commands/update.rs:192-196`). `update_check` stays on demand: one HTTPS
  request to `github.com`, as before.
- **Portable zips are never updater artifacts.** `sign-updater`'s `find` carries
  `! -name '*_portable.zip'` plus a post-check (`release.yml:557-560`), the lint pins both
  (`lint-workflows.sh:96-102`), `updater-manifest.sh:72-73` refuses any `.zip` `.sig`,
  `verify-release.sh:148-167` accepts exactly the two names for the tag's version, requires them
  in `SHA256SUMS`, and fails on any `*.zip.sig` or a `.zip` in `latest.json` (`:205`). The zips
  flow through `bundles-*` → `SHA256SUMS` → cosign → provenance like every asset
  (`release.yml:395`, `:408`). The updater key never touches them.
- **Audit.** `app.start { portable }` carries a boolean and nothing else;
  `portable.acl_unavailable` carries nothing (`a4.rs:38-47`, round-trip pinned). The path lives
  in `AppState.portable_root`, which only `app_info` reads (`state.rs:152-154`,
  `commands/vault.rs:37`); the E2E asserts no `Mooring Data` string in the log. The refusal path
  logs only the code (`startup.rs:69`).

There is **one Medium, M-18**: on macOS, App Translocation makes a quarantined `Mooring.app`
launched in place from the extracted zip run from a read-only copy under
`/private/var/folders/…/AppTranslocation/<uuid>/d/`. `current_exe()` then has no sibling
`portable` marker, so the app **silently starts in installed mode** with an empty vault under
`~/Library/Application Support` — the exact outcome owner decision 2026-11-07 ("no fallback")
forbids, on one of the two shipped platforms, in the README's own first-launch flow. Nothing in
the code detects it. The fix is small (refuse on a translocated path) and is a **tag condition**,
together with a macOS gate run that launches in place.

## Findings

Numbering continues from review 7b (last used: M-17, L-43, N-64).

| ID | Sev | Where | Finding | Exact fix | Owner |
| --- | --- | --- | --- | --- | --- |
| **M-18** | Medium (tag condition) | `src-tauri/src/dirs.rs:122-130` (`marker_dir` = parent of the `.app`), `startup.rs:45-52`; `packaging/portable/README.txt:18-20` (first launch: "Open Anyway", nothing about moving the bundle); no `AppTranslocation` handling anywhere (`grep -rn translocat src-tauri docs packaging` → none) | **App Translocation defeats the marker and triggers the forbidden silent fallback.** A `.app` that carries the quarantine attribute (every Archive Utility extraction) and was not moved with Finder is launched by LaunchServices from a translocated, read-only mount holding only the bundle. "Open Anyway" does not clear that; a Finder move of the *bundle* does. `current_exe()` is then `/private/var/folders/xx/…/AppTranslocation/<uuid>/d/Mooring.app/Contents/MacOS/Mooring`, `marker_dir` is the `d/` directory, the marker is "absent" (`dirs.rs:162`) and the app creates and uses `~/Library/Application Support/<id>` — a second, empty vault, the USB vault left behind, no message. On the next launch after a Finder move it is portable again, so the user sees two vaults alternate. Impact: data-location confusion the ADR explicitly refused, on the owner's primary macOS flow; no secret exposure | **rust-core:** in `Dirs::resolve` (or `marker_dir`), when any component of `exe` equals `AppTranslocation` (or the path starts with `/private/var/folders/` and contains `/AppTranslocation/`), return a new `DirsError::Translocated(exe dir)` → code `portable.translocated`, message "macOS started Mooring from a temporary read-only copy (App Translocation), so the folder next to the app cannot be used. In Finder, drag Mooring.app out of its folder and back in once, then start it again." Do **not** fall back, do not suggest `xattr`. The same refusal is right for a non-portable translocated launch (the dmg flow moves the bundle, the updater never quarantines, so nothing legitimate is affected). Add the code to `ipc-codes.json`; unit test `marker_dir` / `resolve` on a translocated path. **release-engineer / docs:** README.txt step 2 and `getting-started.md`: "after unzipping, drag Mooring.app out of the folder and back in with Finder once (macOS otherwise runs it from a temporary copy and cannot see `portable`)". **qa:** the macOS gate must launch in place from the extracted zip and assert the refusal and that no `~/Library/Application Support/<id>` appears | rust-core, release-engineer, qa |
| L-44 | Low | `src-tauri/src/dirs.rs:123-125`, `startup.rs:49` (`std::env::var_os("APPIMAGE")`, every OS, unvalidated) | **`$APPIMAGE` relocates the marker lookup on every OS and is not validated.** The ADR rejected an env-var data-dir override because it is "invisible, inherited by child processes, settable by a logon script → silent vault relocation"; `APPIMAGE` is exactly that, honoured on Windows and macOS too. Two real cases: (a) a bogus or inherited value (Mooring launched from a terminal or file manager that is itself an AppImage: those set `APPIMAGE` for their children) → the marker is looked up next to the *other* AppImage, found absent, and the app silently uses the OS dirs (`bogus_appimage_values_never_panic` documents this). (b) a same-user writer (T2) can point it at a folder holding a `portable` marker and relocate the vault without touching the exe. (b) is inside the accepted co-located-writer scope; (a) is a silent fallback | Honour `APPIMAGE` only on Linux (`cfg!(target_os = "linux")`), only when `symlink_metadata(appimage)` is a regular file **and** `exe` lies under `$APPDIR` or starts with `/tmp/.mount_` (the AppImage runtime's mount). Otherwise ignore the variable and use `exe.parent()`. If the variable is set but rejected, log at warn. Tests: inherited `APPIMAGE` with a marker next to the real exe → portable; non-Linux → ignored | rust-core |
| L-45 | Low (verify in the macOS gate) | `src-tauri/src/lib.rs:335-336` (`set_permissions(0o700)` after create), `dirs.rs:203-204` (any error → `Unwritable(root)`) | **FAT32 / exFAT on unix refuses with the wrong reason.** On Linux a vfat/exfat mount returns `EPERM` from `chmod` unless mounted `quiet`, so a portable AppImage on a USB stick gets `portable.unwritable` ("<root> is not writable") although the folder is writable; on macOS the behaviour of `chmod` on msdos/exfat volumes is not verified here. Fail-closed, so not a security regression, but the ADR's "USB" gate on macOS depends on it, and the message misleads | After a successful `create_dir_all` and probe, treat `set_permissions` failing with `PermissionDenied` / `Unsupported` as "mode unavailable on this volume": continue and audit `portable.acl_unavailable` (the same semantics Windows gives FAT), instead of `Unwritable`. Keep `Unwritable` for create / probe failures. Unit test with a stubbed chmod outcome; macOS gate: an exFAT **and** a FAT32 stick | rust-core, qa |
| L-46 | Low (docs, before the tag) | `packaging/portable/README.txt:4-5` ("Nothing is written to the registry, to /Applications or to your user profile: everything stays in this folder"), `:11`, `:36-38`; `dirs.rs:63-67` (marker-invalid text: "a link or a folder"); `docs/user-guide/getting-started.md` portable section | **Over-claims and a missing warning.** (1) macOS always writes `~/Library/WebKit/<id>` (the README admits it 30 lines later), `~/Library/Saved Application State/<id>.savedState`, `~/Library/Preferences/<id>.plist`, the LaunchServices / quarantine databases; Windows writes the SmartScreen decision and `Zone.Identifier` handling to the profile. "Nothing … to your user profile" is false; "no secret leaves this folder" is what we can promise. (2) OneDrive / Dropbox / iCloud "files on demand" placeholders carry `FILE_ATTRIBUTE_REPARSE_POINT` (as do `compact /exe` WOF-compressed files), so a portable folder on a Known-Folder-Moved Desktop refuses with `portable.marker_invalid` and a message that talks about links. Refusing is right (a synced vault is a second copy off the device), but the user cannot tell why. (3) "a lost USB stick is a lost vault" is fine; add that whoever finds it holds the encrypted vault and only the master password protects it (consistent with the threat model, T1) | README.txt: "Mooring's own data stays in this folder; the OS still keeps its usual per-app state (macOS: `~/Library/WebKit`, window state, preferences; Windows: the SmartScreen decision). None of it holds a secret." Add "Do not put the folder in a cloud-synced location (OneDrive, Dropbox, iCloud Drive): Mooring refuses the placeholder files it finds there, and a synced vault is a copy outside this device." Add the master-password sentence. `dirs.rs` MarkerInvalid / DataDirInvalid texts: "(a link, a folder, or a cloud-sync placeholder)". Same in `getting-started.md` | release-engineer (README), rust-core (text), docs |
| N-65 | Nit | `src-tauri/src/lib.rs:113-114` (`resolve_dirs` then `check_webview`) | On a Windows machine without WebView2, `Mooring Data/{data,cache}` is created (and probed) before the `portable.webview_missing` refusal. Empty directories only; the ACL step is skipped. Cosmetic, but the refusal should leave the folder as it found it | Split `resolve` into "find the marker" and "create the root"; run `check_webview` between them (it only needs `portable()`) | rust-core |
| N-66 | Nit | `src-tauri/src/portable_acl.rs:26` (`C:\Windows\System32\icacls.exe` literal), `:71-73` (`SystemRoot` passed through from the caller's environment), `:85` (`stdout = %out, stderr = %err` at warn) | The tool path is hard-coded to `C:\Windows`, unlike ADR-0020's `%SystemRoot%`: a Windows installed on another drive audits `portable.acl_unavailable` at every start and never gets the ACL (fail-closed, T2 same-user baseline unchanged either way). The capped `icacls` output, which contains the root path, goes to `tracing` (stdout only, no file sink), not to the audit log: acceptable | Build the path from `SystemRoot` when it is absolute and ends in a drive-rooted `Windows`, else the literal; keep `env_clear`. Log the exit code only at `warn`, the output at `debug` | rust-core |
| N-67 | Nit | `src-tauri/src/portable_acl.rs:31-38` (root only, no `/T`) | `/inheritance:r /grant:r` on the root re-propagates the inheritable ACE, but **explicit** ACEs on children survive: a `Mooring Data` restored with an Explorer copy from a folder that granted `Users:(R)` explicitly keeps that grant on `data/` and the vault files. Also note: after the grant only OWNER RIGHTS remains, so SYSTEM-level backup / indexing agents lose read access unless they use backup privilege (Defender does). Both are documentation-grade | Run with `/T /Q` under the same 10 s deadline (the tree is small: a few files plus the WebView profile), or document "restore by moving the folder, not by copying files into it" in the README | rust-core |
| N-68 | Nit (accepted under T-PORT) | `src-tauri/src/dirs.rs:183-205` (`symlink_metadata` → `create_private_dir` → `set_permissions`) | TOCTOU: a writer to the marker directory can swap `Mooring Data`, `data` or `cache` for a link / junction between the check and the create; `create_dir_all` then succeeds through the link and `set_permissions` chmods the target. Only a co-located writer (T2, or another account with write access to a shared share / stick) can do it, which ADR-0021 "Security consequences" puts out of scope. Cheap hardening exists | After `create_private_dir`, re-run the same `symlink_metadata` + `is_link` check and refuse `DataDirInvalid` if it changed; on unix compare `dev`/`ino` of the pre- and post-create metadata | rust-core |
| N-69 | Nit (residual documented) | `scripts/release/portable-zip.py:58-66` (`collect` stores a symlink and does not walk it), `:93-97` (`os.readlink` stored verbatim), no parent-is-symlink or target-escape check | **Zip-slip through symlink entries on extraction.** Our walker never puts an entry *under* a symlink entry, and the `.app`'s links are relative (`Versions/Current -> A`). But the script does not refuse (a) an absolute or `..`-escaping link target, nor (b) an explicit `NAME=PATH` entry whose parent arcname is a symlink entry. Archive Utility, `ditto` and `unzip` create the link first and then write later entries through it, so (b) would write outside the extraction folder. Inputs are our own build outputs (R-REL), so this is a self-check gap, not an exploit | Refuse symlink targets that are absolute, contain a drive letter or resolve above the archive root (normalise `dirname(arcname)/target`); refuse any arcname whose parent arcname is a symlink entry. Tests for both. Record the residual (extractor follows links; inputs trusted) in R-REL | release-engineer |
| N-70 | Nit | `scripts/release/lint-workflows.sh:100` (`-i?name\s+'([^']*)'`) | The zip-pattern check matches only single-quoted `-name` patterns; `-name "*.zip"` or an unquoted `-name *.zip` escapes it. The `! -name '*_portable.zip'` literal check still holds, so a positive `*.zip` pattern could only select *non*-portable zips, which do not exist | Match `'…'`, `"…"` and bare words; add a test with a double-quoted zip pattern | release-engineer |
| N-71 | Nit | `scripts/release/verify-release.sh:148-167` | The portable zips are accepted by name and hash only; nothing checks their content shape. A `zipfile` listing check is cheap and would catch a build-step regression (absolute names, `..`, a missing marker, a `.sig` smuggled inside) before publication | Add: every name relative, no `..` / `\` / drive prefix; exactly `portable`, `README.txt` and `Mooring.exe` or `Mooring.app/**`; no `*.sig` entry. `python3 -I`, as the manifest parser | release-engineer |

### Answers to the focus questions

1. **Marker / data root, TOCTOU, reparse points, tightening, `unsafe`.** Check order is
   `symlink_metadata(marker)` → `symlink_metadata(root)` → `symlink_metadata(data|cache)` →
   `create_private_dir` × 3 → probe (`dirs.rs:159-208`). The TOCTOU window between the last
   check and the create exists (N-68); it needs a writer to the marker directory, which is the
   co-located writer ADR-0021 accepts. `is_link` (`dirs.rs:90-99`) tests
   `FILE_ATTRIBUTE_REPARSE_POINT` (0x400) **before** `is_symlink`, so junctions, mount points,
   symlinks, cloud placeholders and WOF files are all refused on Windows; symlinks on unix; FIFOs
   and sockets fail `is_file` / `is_dir` (Q1). A reparse point created *after* the check is N-68.
   Pre-existing looser modes: `create_private_dir` always runs `set_permissions(0o700)`
   (`lib.rs:336`), pinned at 0777 → 0700 by Q1. No `unsafe` anywhere in `src-tauri/src`
   (`creation_flags` is safe std).
2. **No-fallback trace.** `resolve_dirs` → `Dirs::resolve` → `Err` → `Refusal` →
   `startup::refuse` → `return Ok(())` from setup with nothing managed and no window
   (`lib.rs:117-120`); the dialog's dismiss callback and the 120 s watchdog both `exit(2)`.
   Before setup, `tauri::Builder::build` registers `tauri-plugin-dialog` and (with a pubkey)
   `tauri-plugin-updater`; neither touches the filesystem at init (plugin sources read in
   review 7). The WebView2 user-data folder and the WebKitGTK data manager are created only when
   a `WebviewWindow` is built, which never happens on the refusal path. `app_data_dir` /
   `app_cache_dir` are called only inside the `os_default` closure (`startup.rs:50`), which the
   portable branch never invokes (E2E `never_os` panics if it does). There is no autostart
   plugin. **Two gaps found:** M-18 (macOS translocation) and L-44 (`$APPIMAGE`), both of which
   make the marker look *absent*, not an error, and so take the OS-dirs branch. The message box
   shows the path to the user; the log line carries only the code (`startup.rs:69`); nothing is
   audited (no `AppState` exists yet). On macOS the OS itself still writes app state to the
   profile (L-46 (1)).
3. **`portable_acl.rs`.** Fixed absolute path (N-66: `C:\Windows` literal, not `%SystemRoot%`;
   not user-influenceable), `env_clear` + `SystemRoot` only (same-user environment, T2
   baseline as ADR-0020), `std::process::Command` with explicit argv, no shell, root first then
   `/inheritance:r`, `/grant:r`, `*S-1-3-4:(OI)(CI)F` (`:31-38`; Q1 pins a root starting with
   `/` or `-` stays element 0). Output per stream capped at 4 KiB on its own thread (`:98-105`),
   `try_wait` polling with a 10 s deadline then `kill` + `wait` (`:114-131`), non-fatal
   (`lib.rs:128-131`). `CREATE_NO_WINDOW` via `CommandExt::creation_flags`, safe. **Grantee:**
   OWNER RIGHTS is the right choice. The ACE binds to the object's owner at access time, so no
   account name is trusted; the unelevated creator owns `Mooring Data`; a copy by another user
   makes that user the owner of the copies; a move within the volume keeps the owner. On FAT /
   exFAT `icacls` fails and the failure is audited (`portable.acl_unavailable`); the vault is
   still encrypted at rest. Caveats: an elevated first start makes Administrators the owner
   (handoff note; README says "run unelevated"), explicit child ACEs survive (N-67), SYSTEM
   agents without backup privilege lose read access (N-67).
4. **Updater.** `portable` first in `decide` (`install_mode.rs:144`): verified against every
   `Bundle` × writable × cask. Background: `background::install` returns before spawning
   (`background.rs:62-66`); `settings_set { backgroundCheck: true }` → `update.manual_only`,
   `update.refused { code }`, nothing stored (`commands/update.rs:192-196`, pinned E2E).
   `update_check` on demand only (unchanged, one request). `update_install` → matrix →
   `Manual(Portable)` before the source (`:273`). `latest.json`: the manifest reads `.sig`
   files only and refuses a `.zip` `.sig` (`updater-manifest.sh:72`); `sign-updater` excludes
   `*_portable.zip` and re-checks the selection (`release.yml:557-560`); the lint fails if either
   guard disappears (N-70 for the quoting gap). `verify-release.sh` fails on `*.zip.sig`, on a
   `.zip` in `latest.json` and on an unexpected zip name (`:148-167`, `:205`). The zips are in
   `SHA256SUMS` and the provenance because they join `files` in "Collect release files"
   (`release.yml:408`) and `finalize` is unchanged. No updater-key signature on zips: correct
   by construction and by three independent checks.
5. **`portable-zip.py`.** Invoked with `python3 -I` (`release.yml:392-393`). `check_arcname`
   refuses empty, `/`, `//`, `\\`, any backslash, drive prefix, and any `.`, `..` or empty
   component after `normpath` (`:44-55`; 19 spellings tested). Symlinks are `lstat`-detected,
   stored `S_IFLNK` with `readlink` as data and never walked (`:58-66`, `:93-97`; Q1 pins that
   the target bytes never enter the archive). No zip-slip in *our* names. Deterministic: sorted
   UTF-8 byte order, fixed `date_time`, `create_system = 3`, no extra fields, fixed deflate
   level, `allowZip64=False`, temp file + `os.replace` (`:118-125`); two-run identity is a test.
   **Residual (N-69):** the script does not refuse an escaping link target or an entry under a
   link entry; macOS extractors preserve links and would write later entries through them. Our
   inputs are the tauri-built `.app`, so this is bounded by R-REL; recorded there.
6. **WebView2 / macOS ephemeral.** `check_webview` (`startup.rs:57-62`) runs only on Windows in
   portable mode, before any window (N-65 on ordering). The macOS downgrade maps `persistent`
   → `Storage::Ephemeral` = `incognito(true)` = `WKWebsiteDataStore.nonPersistent()`
   (`web/mod.rs:285-287`, `window.rs:118`): per-window, nothing on disk, nothing shared across
   windows — **strictly stronger** than ADR-0013's `Identifier` isolation, so every ADR-0013
   guarantee holds; the reason is logged, not an error (`golden.rs` NOT_CODES). Windows / Linux
   persistent profiles stay `Directory($APP_DATA/web/<id>)`, i.e. inside `Mooring Data/data`
   (0700 / OWNER RIGHTS). The main window's profile goes to `cache/webview` (`lib.rs:146-149`,
   `navigation.rs:51-53`), created with `create_private_dir`. It is **not** swept on lock:
   `sweep::ephemeral_profiles` touches `cache/web-ephemeral/*` only (`sweep.rs:83`). That is
   expected: it replaces the `%LOCALAPPDATA%\<id>\EBWebView` profile of an installed build and
   holds the UI's localStorage (no secrets, ADR-0003), not a web session.
7. **Audit.** `app.start { portable: bool }` (`a4.rs:38-42`), `portable.acl_unavailable` with
   no fields (`:43-47`); serialisation and round trip pinned
   (`chain_tests.rs:304-316`); the E2E greps the log for the root path. `AppState.portable_root`
   is read by `app_info` only.
8. **UI.** `PortableLine` renders the path as a JSX text child of `<code>` and in `title`
   (`PortableLine.tsx:29`): React escapes it; no `<a>`, no `dangerouslySetInnerHTML`, no opener
   (Q1 pins `<b>` / `<img onerror>` as text). Copy uses `navigator.clipboard.writeText` of a
   non-secret path, the same pattern as the About links (review 7 ruling 34); the audited Rust
   clipboard path is for secrets only and is correctly not used. `describeError` now returns the
   Rust message for `update.manual_only` (`errors.ts:149-153`): the four possible strings are
   compile-time constants in `install_mode.rs:76-83`, rendered as text; `FRIENDLY[...] ??
   e.message` already returned raw messages for unknown codes, so no new class of text reaches
   the DOM. It is our own IPC error, never remote content. `app_info.portableDataDir` gives a
   T5 the absolute path (user name, drive letter): accepted, the ADR chose to show it.
9. **README.txt.** No claim contradicts the threat model except L-46 (1) ("nothing written to
   your user profile"). "A lost USB stick is a lost vault" is the right framing (T1); add the
   master-password sentence. Gatekeeper: "Open Anyway" only, and line 38 forbids `xattr`. The
   Evergreen step is per-user, no admin. Missing: the translocation step (M-18) and the
   cloud-sync warning (L-46 (2)).
10. **Supply chain.** Lockfiles, manifests, capabilities and `tauri.conf.json` unchanged (empty
    diff). `cargo deny` clean; `cargo audit` as review 7 plus the already-accepted `glib`
    advisory. Nothing new to approve.

### Closure of carried items touching this range
| ID | Status | Evidence |
| --- | --- | --- |
| L-40 in-flight manifest cap (due 0.1.1) | **still open** | `updater/download.rs` unchanged in this range. Not a portable item; remains due for the 0.1.1 tag or an explicit R-UPD extension |
| a4-1-qa-1 (linked `data` / `cache`) | **fixed** | `dirs.rs:194-202`; `symlinked_data_subdir_is_refused_and_not_followed`, E2E un-ignored |
| a4-1-qa-2 (`update.manual_only` text) | **fixed** | `errors.ts:149-153`; `portable.test.tsx` flipped to `it` |
| a4-1-qa-3 (drive-letter arcname) | **fixed** | `portable-zip.py:41-47`; 71 cases, no `gap` rows |

## Conditions for the `v0.1.1` tag
1. **M-18** fixed (refusal on a translocated path, README / guide step) and proven in the macOS
   gate by launching in place from the extracted zip.
2. L-44, L-45, L-46 before the tag (small; L-45 may instead be verified non-occurring on
   macOS exFAT + FAT32 and documented for Linux).
3. **Manual per-OS gate (ADR-0021 "Test plan"), fresh non-admin account, recorded in
   `docs/qa/`:**
   - Windows 11, NTFS Desktop: unzip, SmartScreen once, `app.start { portable: true }`, vault
     create, SSH connect, lock; `icacls "Mooring Data"` shows only `OWNER RIGHTS:(OI)(CI)(F)`;
     no `%APPDATA%\<id>` or `%LOCALAPPDATA%\<id>` created; move the folder, data follows.
   - Windows 11, FAT32 USB: the same flow; `portable.acl_unavailable` row present; no ACL
     error dialog.
   - Windows 11, OneDrive-redirected Desktop: `portable.marker_invalid` box with the L-46
     wording; nothing created.
   - macOS 15, `~/Applications` and a USB stick (exFAT and FAT32, L-45): Gatekeeper "Open
     Anyway" once, launch **in place** (M-18) and after a Finder move; `~/Library/WebKit/<id>`
     holds no credential; persistent web session → `web.portable_ephemeral` in the log.
   - Read-only folder (both OSes): `portable.unwritable` box naming the folder, exit code 2, no
     window, no OS app-data directory created.
   - Windows without WebView2 (or `HKCU` runtime key removed): `portable.webview_missing` box.
4. Carried from 7b and unchanged: M-17 (3) owner settings, L-14, L-42 remainder, the rc dry
   run items, the per-OS dialog runs, L-28, G-1. L-40 manifest cap (R-UPD expiry at 0.1.1).
5. Nits as scheduled: N-65..N-71.

## Test evidence
```
Linux x86_64, 2026-11-07, main @ 9a2f2df, CARGO_TARGET_DIR=/home/claude/nexus/target
git diff --stat 2fdc10f..HEAD -- Cargo.lock pnpm-lock.yaml Cargo.toml src-tauri/Cargo.toml package.json \
    src-tauri/tauri.conf.json src-tauri/capabilities deny.toml        (empty)
grep -rn unsafe src-tauri/src crates/mooring-audit/src                  forbid(unsafe_code) ×2 only
cargo deny --offline check                                             advisories ok, bans ok, licenses ok, sources ok
cargo audit --no-fetch --db ~/.cargo/advisory-db/advisory-db-3157b0e258782691
                                                                       RUSTSEC-2023-0071 rsa (R-RSA); unmaintained ×7 (as review 7);
                                                                       RUSTSEC-2024-0429 glib unsound (Linux, accepted GHSA-wrw7-89jp-8q8g)
cargo test -p mooring-app --offline --lib -- dirs:: portable_acl:: startup:: web::tests::portable
    updater::tests::portable commands::update::tests::portable commands::vault::tests::app_info   20 passed
cargo test -p mooring-app --offline --test e2e_flow -- a4_1_portable   12 passed, 0 ignored
cargo test -p mooring-audit --offline portable                          1 passed
bash scripts/release/tests/run.sh                                      12 / 71 / 24 / 34 passed, 0 failed
bash scripts/release/lint-workflows.sh .github/workflows               lint-workflows: ok
grep -rn translocat src-tauri/src docs packaging                       none (M-18)
```
Not run: Windows and macOS builds, `actionlint`, the workflow, `pnpm test` (taken from ui P1 /
Q1 / F1 evidence), any per-OS gate.
