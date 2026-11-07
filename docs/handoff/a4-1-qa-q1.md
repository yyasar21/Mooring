# A4.1 · qa-engineer · Q1: portable mode — independent verification (ADR-0021)

Worktree `agent-a2c632f54c9b50e0d`, branch `worktree-agent-a2c632f54c9b50e0d`, from `051e42e`
(rust-core P1 + release-engineer P1 + ui P1 merged). Only test files touched: `src-tauri/tests/**`,
`scripts/release/tests/**`, `apps/desktop/src/**/*.test.tsx`, this note. No product code changed.
Linux x86_64 (WebKitGTK toolchain), `CARGO_TARGET_DIR=/home/claude/nexus/target` reused,
`node_modules` symlinked from the main checkout (not committed).

## Done

| Item | Where | What is pinned |
| --- | --- | --- |
| 1 E2E flow | `src-tauri/tests/e2e_flow/a4_1_portable.rs` | `Dirs::resolve` on a tempdir with a `portable` marker (OS-dir closure panics if consulted) → `AppState::new` → `app.start { portable: true }` (no path, no `Mooring Data` string in the log) → vault create / lock / unlock / credential / connection / search → `app_info().portableDataDir` = the `Mooring Data` path, camelCase only → `update_settings_set { backgroundCheck: true }` → `update.manual_only` + exact message, nothing stored, one `update.refused { code }` row; `false` accepted → `update_check` (scripted source, probe `portable: true` with otherwise in-app facts) → `installMode: manual`, `manualReason: "portable"`, one source call; `update_install` refused with the same code before the source → lock → every path under the tempdir is `app/{mooring,portable}` or `app/Mooring Data/**`; `data`/`cache` 0700. Non-portable control: `portableDataDir: null`, opt-in accepted. |
| 1 gate matrix | `gate_matrix.rs` | No new command in `ipc-manifest.json` (diff since `2fdc10f`: codes only). `app_info` stays in `NOT_GATED`; reason now names the portable field and this test. `update_settings_set` already a matrix row. |
| 2 hostile resolver | `a4_1_portable_dirs.rs` | FIFO marker and Unix-socket marker → `MarkerInvalid` / `portable.marker_invalid`, nothing created; FIFO where `Mooring Data` should be → `DataDirInvalid`; regular file `Mooring Data` → refused and left intact; pre-existing root/`data`/`cache` at 0777 → all 0700 after resolve; exe path with `..`/`.` components and with a trailing slash → the same single root; non-UTF-8 folder name → resolves, `DirsError` texts and `Refusal` go through lossy display (U+FFFD), `app_info` string too, no panic; a > 300-char path (4 × 90-char components) → resolves; nested bundles (`Outer.app/Contents/MacOS/Inner.app/…`, `Outer.app/Contents/Resources/Mooring.app/…`) → the nearest `.app`'s parent; `.app` at `/`; `.APP`/loose shapes not treated as bundles; `$APPIMAGE` non-existent → OS dirs, nothing created, marker next to the mounted exe ignored (as ADR §1 says); `""`, `/`, `.`, `..` → no panic; marker next to the AppImage wins; two threads behind a barrier resolving the same folder → identical `Dirs`, 0700, no probe file left. |
| 3 ACL argv | `a4_1_portable.rs::icacls_argv_…` | Root with spaces and a trailing backslash is one `OsString` element; roots starting with `-`, `/`, `--inheritance:e`, `/grant:r` stay element 0 followed by exactly `/inheritance:r`, `/grant:r`, `*S-1-3-4:(OI)(CI)F` (icacls has no `--`; order is the defence). |
| 4 pipeline | `scripts/release/tests/portable-zip.test.sh` (37 → 68) | `--root` holding absolute / relative / `/` / `.` / directory symlinks pointing outside → stored as `S_IFLNK` with the literal target, the target bytes never enter the archive, a directory link is one entry (not walked); a `--root` file whose own name holds `\` → refused, no `.zip`/`.tmp` left; 15 traversal spellings (`..`, `../x`, `x/..`, `x/../y`, `x/./y`, `./x`, `x/.`, `x/`, `/x`, `//x`, `\x`, `x\..\y`, `a//b`, `""`, `.`) → non-zero, nothing written; `--root …/../hostile` yields clean names; `NAME=<dir symlink>` stored as the link; 1 000-entry root works (no cap exists, see Left open). `verify-release.test.sh` (30 → 34): `SHA256SUMS` listing `Mooring_<v>_x64_portable.zip.sig` (absent) → fails; listing `…_universal_portable.zip.sig` present on disk → fails naming the `.zip.sig`; a lone `.zip.sig` without its zip → fails. |
| 5 UI | `apps/desktop/src/components/settings/portable.test.tsx` (6) | `PortableLine` with `<b>x</b>` / `<img onerror>` in the path → text only, `title` verbatim, no link; Windows path with `\`, spaces, unicode verbatim; Updates with `portableDataDir` set **and** `backgroundCheck: true` stored → switch disabled, unchecked, zip hint, Check enabled; opt-in driven through the store with the mock refusing → `role=alert` shown, optimistic flip reverted, `update.refused { code }` audited; About before boot and with `null` → no line, no "Portable", no copy button. |
| 6 fuzz | grep | No new parser: `dirs.rs` / `startup.rs` / `portable_acl.rs` contain no `fs::read`, `read_to_string`, `parse`, `from_str`, `serde_json::from`; the marker's content is never opened (`symlink_metadata` only). The one byte conversion is `from_utf8_lossy` on ≤ 4 KiB of `icacls` output for the log. `portable-zip.py` reads only its own argv and the release tree. **No fuzz target needed.** |

## Bugs found (pinned, product code untouched)

| Id | Severity | Where | One line | Pinned by |
| --- | --- | --- | --- | --- |
| **a4-1-qa-1** | medium-low (rust-core) | `dirs.rs::portable_under` | ADR §1 refuses a linked **root** "so the data cannot be redirected"; a symlinked `Mooring Data/data` (or `cache`) inside a genuine root is followed: `create_private_dir` creates/chmods through the link and every vault file lands at the link target. Same redirect, one level down. Fix: `symlink_metadata` + `is_link` on `data`/`cache` before `create_private_dir`, refuse with `DataDirInvalid(root)`. | `a4_1_portable_dirs::symlinked_data_subdir_is_refused_like_the_root`, `#[ignore = "BUG a4-1-qa-1…"]`; `cargo test -p mooring-app --test e2e_flow symlinked_data_subdir -- --ignored` **fails today** ("linked data subdir accepted: Ok(Dirs {…})"). Remove the `#[ignore]` with the fix. |
| **a4-1-qa-2** | low (ui-engineer; acknowledged in `a4-1-ui-p1.md` Left open) | `stores/errors.ts` `FRIENDLY["update.manual_only"]` | When `update_settings_set { backgroundCheck: true }` is refused in a portable build the alert says "This install is managed by a package manager or Homebrew" — Rust's "portable build: download the new zip and replace the folder" is discarded by `describeError`. Reachable through the store (`setBackground(true)`), i.e. any path that bypasses the disabled switch. | `portable.test.tsx` `it.fails("Updates: the refusal alert carries the portable message…")` — passes while the bug exists, fails once fixed; flip to `it`. |
| **a4-1-qa-3** | info (release-engineer) | `portable-zip.py::check_arcname` | A Windows drive prefix in an archive name (`C:/x=…`) is accepted; `..`, `/`, `\` are refused. Extractors strip drive letters and the names are ours, so this is a self-check gap, not an exploit. | `portable-zip.test.sh` row `gap "drive-letter name C:/x is refused"` — passes while the gap exists, fails when closed (promote to `check`). |

Both "pins the bug" rows (`it.fails`, `gap`) and the one `#[ignore]` are the only non-`ok` markers; no
threshold was lowered, no existing test skipped or changed.

## Left open

- **`portable-zip.py` has no entry-count / total-size cap** (ADR-0021 §4 names none). The 1 000-entry
  row only shows the absence. Fine for our own release tree; note for release-engineer if the
  script is ever fed untrusted input.
- `AboutCard` hides the line for `portableDataDir === ""` (`&&`), `UpdatesCard` shows an empty line
  and disables the switch (`!== null`). Rust never sends `""`; cosmetic inconsistency only, not pinned.
- `bogus_appimage_values_never_panic` documents that a non-existent `$APPIMAGE` makes the resolver
  look in that (missing) folder and fall through to the OS dirs, ignoring a marker next to the real
  exe. That is what ADR §1 says; whether a stale/forged `APPIMAGE` should be validated
  (`is_file`) is a rust-core/security call, not a test failure.
- Windows-only behaviour (`icacls` run, reparse points, `webview_version`) and macOS `.app`
  Gatekeeper paths are not executable here; only the pure parts (`argv`, `marker_dir`) are pinned.
  Manual per-OS gate per ADR-0021 "Test plan" still owed.
- No Playwright run (no browser in this container); the UI pins are vitest against the mock.

## Decision needed

- Orchestrator: route **a4-1-qa-1** to rust-core before the 0.1.1 tag? It contradicts the ADR's
  stated reason for refusing links (data redirection) and the fix is ~6 lines plus un-ignoring the
  test. Security reviewer should weigh it against "co-located writer is out of scope".
- Orchestrator: accept the three "pinned bug" markers (`#[ignore = "BUG …"]`, `it.fails`, `gap`)
  as the convention for QA findings the owners fix later? They keep `make check` green without
  hiding the finding; the alternative is a red branch until the owners land fixes.

## Test evidence

```
Linux x86_64, 2026-11-07, worktree agent-a2c632f54c9b50e0d, CARGO_TARGET_DIR=/home/claude/nexus/target

cargo fmt --all -- --check                                → clean
cargo clippy -p mooring-app --all-targets -- -D warnings  → Finished, 0 errors
                                                            (one pre-existing env-level "unknown lint
                                                             clippy::unused_async_trait_impl" warning
                                                             from the machine's -A flag, not the code)
cargo test -p mooring-app                                 → lib: 367 passed; 0 failed; 1 ignored
                                                            e2e_flow: 50 passed; 0 failed; 1 ignored  (was 39)
  new: a4_1_portable (2: flow + icacls argv), a4_1_portable_dirs (9 + 1 ignored = a4-1-qa-1)
cargo test -p mooring-app --test e2e_flow symlinked_data_subdir -- --ignored → 1 FAILED (the bug)
bash scripts/release/tests/run.sh
  lint-workflows.test.sh     12 passed, 0 failed
  portable-zip.test.sh       68 passed, 0 failed   (was 37; includes 1 "gap" row = a4-1-qa-3)
  updater-manifest.test.sh   24 passed, 0 failed
  verify-release.test.sh     34 passed, 0 failed   (was 30)
pnpm typecheck  → tsc -b --noEmit: Done (packages/ui, apps/desktop)
pnpm lint       → eslint src: Done, 0 problems
pnpm test       → Test Files 73 passed (73) · Tests 559 passed | 1 expected fail (560)   (was 72 / 554)
  new: components/settings/portable.test.tsx (6; the expected fail = a4-1-qa-2)
grep -nE "fs::read|read_to_string|parse|from_str|serde_json::from" src-tauri/src/{dirs,startup,portable_acl}.rs
                → only doc comments and `from_utf8_lossy` on capped icacls output (no parser)
```
