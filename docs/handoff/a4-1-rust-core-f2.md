# A4.1 · rust-core (+ release-engineer, docs) · F2: review 8 fixes (M-18, L-44..L-46, N-65/66/68/70)

Worktree `agent-abca8c7d4b44407b5`, branch `worktree-agent-abca8c7d4b44407b5`. Input:
[review 8](../security/a4-1-review-8.md), ADR-0021. No manifest, lockfile, capability or
`tauri.conf.json` change; no new crate; no `unsafe`. One golden blessed (`ipc-codes.json`).

## Done

| ID | Where | What |
| --- | --- | --- |
| **M-18** | `dirs.rs`, `startup.rs`, `ipc-codes.json`, `README.txt`, `getting-started.md` | `DirsError::Translocated(bundle)` → code `portable.translocated`, message exactly "Mooring is running from a macOS translocation copy; drag Mooring.app out of its folder and back in with Finder once, then open it again." (no path, no `xattr`). `Dirs::translocated(exe)` is pure: any path component equal to `Dirs::TRANSLOCATION` (`AppTranslocation`), tested on Linux with `/private/var/folders/…` and `/var/folders/…` shapes plus five negatives. `Dirs::locate` refuses **before** the marker is looked up, gated by `cfg!(target_os = "macos")` (elsewhere the component is an ordinary folder name, pinned by a non-macOS test; the macOS-only test pins the refusal through `locate` and `resolve`). Same `Refusal` path as every other error: native box, exit 2, no window, no fallback. README step 2 and the guide gained the "drag out and back in with Finder once" step. |
| **L-44** | `dirs.rs` (`appimage_from_env`, `exe_in_appimage_mount`), `startup.rs` | `$APPIMAGE` is honoured only when `linux` (`cfg!(target_os = "linux")` at the call site), the value is absolute, `symlink_metadata` says regular file and not a link, **and** `exe` is under a non-degenerate absolute `$APPDIR` or `/tmp/.mount_*`. Otherwise `None` + one `warn` line (no value logged) and the marker is looked up next to the real executable. `Dirs::resolve` / `marker_dir` keep their signatures (they take the validated value), so the qa E2E tests are untouched. Tests: accepted case, non-Linux, missing / directory / relative / symlinked image, exe outside the mount, and the inherited-`$APPIMAGE`-with-marker-next-to-real-exe → portable case. |
| **L-45** | `lib.rs` (`create_private_dir` → `io::Result<Mode>`), `dirs.rs`, `lib.rs` setup | `create_private_dir` returns `Mode::Private` or `Mode::Unavailable` when `set_permissions(0700)` fails with `PermissionDenied` / `Unsupported` (vfat / exFAT `EPERM` / `ENOTSUP`); any create failure and any other chmod error stay errors (→ `Unwritable`). New `Dirs.mode_unavailable: bool`; in portable mode setup audits `portable.acl_unavailable` for it (same row as the Windows FAT case; `app.start` unchanged). `portable_under` takes the mkdir as a closure, so the unit test scripts the outcome: `Unavailable` → usable dirs + flag, `Private` → no flag, `Err` → `Unwritable(root)`. The real `EPERM` needs a vfat/exfat mount: **not unit-testable here**, left to the macOS exFAT + FAT32 gate (and a Linux `mount -o` check if qa has one). |
| **L-46** | `README.txt`, `getting-started.md`, `dirs.rs` texts | Over-claim removed: "Mooring's own data stays in this folder; the OS still keeps its usual per-app state (macOS: `~/Library/WebKit`, window state, preferences; Windows: the SmartScreen decision). None of it holds a secret." Cloud-sync warning (OneDrive / Dropbox / iCloud placeholders are refused; "Always keep on this device"). Master-password sentence (encrypted at rest; whoever finds the stick holds the encrypted vault, only the master password protects it). `MarkerInvalid` / `DataDirInvalid` say "(a link, a folder, or a cloud-sync placeholder)" / "(a link, a file, or a cloud-sync placeholder)", pinned by a test. |
| **N-65** | `dirs.rs` (`Located`, `Dirs::locate`, `Dirs::create`), `startup.rs`, `lib.rs` | `resolve` = `locate` (one `symlink_metadata`, nothing created) + `create`. `resolve_dirs` runs `check_webview(located.portable())` between the two, so a Windows machine without WebView2 is refused with no `Mooring Data` created. `check_webview` now takes `bool`. Test: `locate` creates no root; `create` after it equals `resolve`. |
| **N-66** | `portable_acl.rs` | Kept the `C:\Windows\System32\icacls.exe` literal and documented why (the caller's environment must not pick the tool; another system drive audits `portable.acl_unavailable`, fail-closed). Exit code at `warn`, the capped output (which names the root) at `debug` only. Verified the output never reaches audit: `AclError` carries kind + exit code only (`errors_carry_no_tool_output` pins its `Debug` form), the caller audits `PortableAclUnavailable` with no fields. |
| **N-68** | `dirs.rs` (`portable_under`) | After each `mkdir` of root / `data` / `cache` the entry is re-checked with `symlink_metadata` (plain dir, not a link / reparse point) and, when it pre-existed, compared by `dev`+`ino` on unix; any change → `DataDirInvalid(root)`, nothing written through it. Test scripts the swap-to-symlink race for all three entries and asserts the link target stays empty. |
| **N-70** | `scripts/release/lint-workflows.sh`, `tests/lint-workflows.test.sh` | The zip-pattern check matches `'…'`, `"…"` and bare `-name` words. Three new cases: double-quoted `*.zip` fails, bare `Mooring_portable.zip` fails, double-quoted `*.AppImage` still passes (15 total). |

Also: `Dirs` literal / destructure sites updated (`state.rs`, `state_testing.rs`, `startup.rs`
test); `ipc-codes.json` blessed with `portable.translocated`.

## Left open
- **L-45 real-volume evidence**: the `EPERM` → `Mode::Unavailable` mapping is exercised only
  through the scripted mkdir. qa: macOS exFAT + FAT32 stick (review 8 condition 2) must show
  a normal start with a `portable.acl_unavailable` row and no `portable.unwritable` box.
- **N-68 best-effort**: a plain directory replaced by another plain directory between check
  and create is caught only when the inode differs; ext4 / tmpfs reuse it at once, so that
  case is documented, not pinned (the symlink / reparse-point swap, the actual redirect, is).
- **M-18 macOS gate**: launch in place from the extracted zip → `portable.translocated` box,
  exit 2, no `~/Library/Application Support/<id>`; after a Finder move → portable (qa).
- `README.txt` is 48 lines (ADR-0021 §4 said ≤40); the L-46 / M-18 sentences are the
  review's own wording and were not cut further. Owner may trim.
- Not in this round (per the task): N-67 (`/T`), N-69, N-71, L-40.

## Decision needed
- None blocking. The translocation refusal is macOS-only by `cfg`; the reviewer's "the same
  refusal is right for a non-portable translocated launch" is implemented (the check runs
  before the marker lookup, portable or not). If the owner wants the dmg flow exempt, it would
  need a marker-first order instead — not recommended (that is exactly the silent path).

## Test evidence
```
Linux x86_64, 2026-11-07, CARGO_TARGET_DIR=/home/claude/nexus/target, --offline
cargo fmt --check                                                       ok
cargo clippy -p mooring-app --all-targets -- -D warnings                 0 errors (pre-existing "unknown lint" warning only)
MOORING_BLESS=1 cargo test -p mooring-app golden                         6 passed; ipc-codes.json +portable.translocated
cargo test -p mooring-app                                                lib 380 passed, 0 failed, 1 ignored; e2e_flow 51 passed
  new: dirs::tests::{locate_creates_nothing_and_create_finishes_the_job, translocated_paths_are_detected_by_component,
       translocation_component_is_an_ordinary_folder_name_elsewhere, exe_in_appimage_mount_shapes,
       appimage_env_is_validated_before_it_relocates_the_marker, inherited_appimage_keeps_the_marker_next_to_the_real_exe,
       volume_without_posix_modes_is_not_unwritable, create_private_dir_reports_the_mode_it_applied,
       entry_swapped_between_check_and_create_is_refused, invalid_texts_mention_cloud_sync_placeholders},
       portable_acl::tests::errors_carry_no_tool_output; startup test extended (translocated Refusal text)
  macOS-only (not run here): dirs::tests::translocated_exe_is_refused_before_the_marker_is_looked_up
bash scripts/release/tests/run.sh                                        lint-workflows 15, portable-zip 71, updater-manifest 24, verify-release 34 passed, 0 failed
bash scripts/release/lint-workflows.sh                                   lint-workflows: ok (.github/workflows)
```
Not run: Windows / macOS builds, `pnpm test`, any per-OS gate.
