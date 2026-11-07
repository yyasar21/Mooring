# A4.1 P1 — release-engineer handoff (portable zips, ADR-0021 §4 + pipeline halves of §2)

Date: 2026-11-07 · Worktree branch `worktree-agent-a80b8691e0d899124` from `main` @ `2fdc10f` · ADR-0021 (Accepted)

## Done

- **`scripts/release/portable-zip.py`** (python3 `-I`, stdlib `zipfile` only):
  `--out <zip> --epoch <SOURCE_DATE_EPOCH> [--root <dir>] [<name>=<path> ...]`. Entries in
  `LC_ALL=C` order (UTF-8 bytes, parents before children, explicit directory entries), every
  mtime = epoch floored to 1980-01-01 (zip minimum), `create_system = 3` with the Unix mode in
  `external_attr` (regular 0644/0755 kept, directories `S_IFDIR` + DOS dir bit), symlinks
  stored as `S_IFLNK` with the link target as data — never dereferenced, dangling ones kept
  (macOS `Contents/Frameworks` layout). Deflate level 9 for files, stored for symlinks and
  directories, no extra fields, `allowZip64=False`. Refuses `..`, absolute or backslash names,
  duplicates, fifos/sockets, negative epoch; writes to `<out>.tmp` and renames.
- **`release.yml`**: new step **Portable zip** in `build` for `windows-x64` and
  `macos-universal` (after "Updater archive from the .app", before "Collect release files").
  Windows: `target/<target>/release/Mooring.exe` → entry `Mooring.exe`; the step fails with a
  listing of `*.exe` in that dir when it is not there. macOS:
  `target/<target>/release/bundle/macos/Mooring.app` → entry `Mooring.app` (fails if
  `Contents/_CodeSignature` is missing). Plus empty `portable` and `README.txt`
  (`packaging/portable/README.txt`, `@VERSION@` substituted, placeholder check). Epoch =
  `git log -1 --format=%ct HEAD` = the tagged commit's committer time, the same value
  `finalize` uses for `pub_date`. `testzip()` after writing. Exported as `PORTABLE_ZIP`, picked
  up by "Collect release files" like `PKG_PATH` / `UPDATER_ARCHIVE`, so the zips flow through
  `bundles-*` → `publish` → `SHA256SUMS` + cosign → provenance → "draft holds exactly the signed
  files" unchanged. Names: `Mooring_<v>_x64_portable.zip`, `Mooring_<v>_universal_portable.zip`.
- **`sign-updater`**: the artifact `find` now carries `! -name '*_portable.zip'` before the
  positive patterns, plus a loop that fails if a portable zip is ever selected.
  **`lint-workflows.sh`** check 3: every `find … -name` in the `sign-updater` job (continuation
  lines joined) must contain `! -name '*_portable.zip'` and no positive `-name` pattern ending
  in `zip`; a job without a selector is an error.
- **`updater-manifest.sh`**: reads `*.sig` only (unchanged, so stray zips are ignored) and now
  refuses a `.sig` for `*_portable.zip` or any `*.zip` before the kind switch; header comment
  states the rule.
- **`verify-release.sh`** step 6: every `*.zip` on the release must be exactly
  `Mooring_<v>_x64_portable.zip` or `Mooring_<v>_universal_portable.zip` for the tag's version,
  in `SHA256SUMS`, without a `.sig` on disk or in `SHA256SUMS`; any `*.zip.sig` fails; the
  `latest.json` parser fails on an asset ending in `.zip`. Prints the portable names it found.
- **`packaging/portable/README.txt`** (38 lines, English): folder = no-install copy, keep
  `portable` next to the app, data in `Mooring Data/`, no fallback, verify `SHA256SUMS`,
  Gatekeeper "Open Anyway" / SmartScreen "Run anyway" once, Evergreen WebView2 bootstrapper
  per-user without admin, update = replace everything except `Mooring Data`, back it up, one
  instance on a network share, macOS `~/Library/WebKit` note, no `xattr`.
- **`docs/release.md`**: Supported-platforms formats, two "Portable" rows in the asset table,
  a paragraph on what the zips are / are not (updater), pipeline bullets. `getting-started.md`
  is the docs owner's (ADR-0021 §4).
- **Tests**: `scripts/release/tests/portable-zip.test.sh` (37 cases, new),
  `lint-workflows.test.sh` 8 → 12, `updater-manifest.test.sh` 20 → 24,
  `verify-release.test.sh` 23 → 30. `run.sh` picks the new file up automatically.

## Left open

- **R1 rc dry run must confirm the Windows binary name/case.** `tauri.conf.json` has
  `productName: "Mooring"` and no `mainBinaryName`; `src-tauri/Cargo.toml` has package
  `mooring-app` and no `[[bin]]`. Tauri 2's CLI renames the cargo binary to the product name
  before bundling, so the expected file is `target/x86_64-pc-windows-msvc/release/Mooring.exe`;
  NTFS is case-insensitive so `[[ -f ]]` passes either way, and the archive entry is the fixed
  string `Mooring.exe`. If the dry run shows `mooring-app.exe` instead (step fails and prints
  the dir listing), set `mainBinaryName` or change the one path in the step.
- Windows runner: the step runs under `shell: bash` with `python3 -I`, like "Collect release
  files" already does; not re-verified on a real `windows-2022` runner here.
- `release-scripts` artifact (`scripts/release/*.sh`) does not carry the `.py` — not needed:
  only the `build` job (which has a checkout) runs it.
- `actionlint` is not installed in this environment; YAML parsed with PyYAML, step scripts
  `bash -n` checked and replayed locally (see evidence). Run `actionlint` in CI (`ci.yml`
  unchanged) before merging.
- No `_fixedruntime` zip variant (ADR-0021 §3): possible later without script changes.

## Decision needed

- None for the pipeline. The ADR's `getting-started.md` "Portable" section is the docs owner's.

## Test evidence (exact commands, from the worktree root)

```
bash scripts/release/tests/run.sh
### lint-workflows.test.sh      12 passed, 0 failed
### portable-zip.test.sh        37 passed, 0 failed
### updater-manifest.test.sh    24 passed, 0 failed
### verify-release.test.sh      30 passed, 0 failed
bash scripts/release/lint-workflows.sh .github/workflows   # lint-workflows: ok
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"
```

Local replay of the "Portable zip" step (both branches, fake `target/` tree, stub `git`):
`Mooring_0.1.1-rc.1_universal_portable.zip` — 13 entries, `zipinfo` shows `drwxr-xr-x`
directories, `lrwxrwxrwx` for `Frameworks/F.framework/Versions/Current`, `-rwxr-xr-x` for
`Contents/MacOS/Mooring`, `_CodeSignature/CodeResources` intact, every mtime the stub epoch;
`Mooring_0.1.1-rc.1_x64_portable.zip` — 3 entries (`Mooring.exe`, `README.txt`, `portable`),
README header `Mooring 0.1.1-rc.1 - portable build`; a `release/` dir holding only
`mooring-app.exe` makes the step fail with `::error::… Mooring.exe not found; release dir
holds: …/mooring-app.exe`.
