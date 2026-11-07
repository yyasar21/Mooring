# A5 · rust-core · ADR-0028 build identity + Move to Applications (runtime half)

Branch `worktree-agent-a372875d06f1b90ab` (rebased on main 973bf8e, on top of the
release-engineer commit). Scope: ADR-0028 §1 runtime, §2, owner decisions 44, 47, 48 at defaults.
Window title: the config's "Mooring Dev" is kept (no runtime title change).

## Done
- **Tests reading the updater block** (`updater/download.rs`
  `configured_endpoint_shares_the_release_tree`, `updater/tests.rs`
  `checked_in_config_is_read_without_panicking`) now read base + `tauri.release.conf.json`
  merged under RFC 7396 (`src/test_config.rs`, test-only). The guarantees stay pinned:
  endpoint inside the release-download tree, `requireSignedVersion: true`, and the dev base has
  no `plugins.updater` at all.
- **`build.rs`** + `src/build_channel.rs` (plain code shared via `include!`, unit-tested in the
  lib): effective config = `tauri.conf.json` → `tauri.<platform>.conf.json` (if present) →
  `TAURI_CONFIG` (inline JSON, the only form tauri-build 2.7.4 accepts). Emits
  `cargo:rustc-check-cfg=cfg(mooring_release)`, `rerun-if-env-changed` for `TAURI_CONFIG` and
  `MOORING_RELEASE_BUILD`, `rustc-env=MOORING_EFFECTIVE_IDENTIFIER`, and
  `cargo:rustc-cfg=mooring_release` iff identifier == `io.github.yyasar21.mooring` AND
  `MOORING_RELEASE_BUILD=1`. Exactly one of the two → build panic naming the fix. Flag values:
  unset / empty / `0` off, `1` on, anything else a build error.
- **`build_identity.rs`**: `Channel { Release, Dev }` = `Channel::CURRENT` from
  `cfg!(mooring_release)`; setup refuses with `app.build_identity` (startup.rs box, exit 2, no
  window) when `app.config().identifier` disagrees (release ⇔ release id; any other id is dev).
- **Updater**: `ManualReason::DevBuild` (`update.manual_only`, "development build: updates come
  from your own builds", wire `dev_build`) is the FIRST check in `install_mode::decide`
  (`InstallFacts.dev_build`). Dev builds get `UpdateRuntime::development`: `update_check` /
  `update_install` answer that code instead of `update.unconfigured`; the plugin is never
  registered in dev even if a pubkey were configured; `update_settings_set{backgroundCheck:true}`
  is refused (audited `update.refused`) before the portable rule; `background::enabled()` is
  false in dev (loop never installed).
- **Dirs**: `Dirs::root_name(channel)` = `Mooring Data` / `Mooring Dev Data`;
  `Dirs::ROOT = root_name(Channel::CURRENT)`. OS data/cache dirs follow the identifier through
  Tauri's path API (no code; asserted in `build_identity_tests.rs`).
- **`state::Settings.channel`** (production `Channel::CURRENT`; test fixtures `Release`,
  `testing::with_settings` / `unlocked_dev` for dev paths).
- **Move to Applications** (macOS):
  - `install_location.rs` (pure, tested on Linux): `classify(bundle, roots)` →
    `Translocated | Volume(mount) | Downloads | Applications | Other`, `confirm_image` with the
    image mounts → `DiskImage(mount)`; `parse_hdiutil_info` (text `hdiutil info`, device lines
    `dev\thint\tmount`, only `/Volumes/<one component>`); `should_offer` (release only, no marker,
    not relaunched, no cask, not declined for this version, DiskImage/Downloads only);
    `offer_translocated`; `plan` (absent → copy; foreign → `install.not_ours`; ours same/newer →
    open that copy; ours older + running → `install.running`; else replace); `Target`
    (`/Applications`, else `~/Applications`, decision 44); dialog slots / label mapping; texts;
    relaunch flags; argv builders for every tool.
  - `install_move.rs` (I/O behind a `Tools` trait, tested with a scripted runner + temp dirs):
    `OsTools` = fixed absolute path, no shell, `env_clear` + `LC_ALL=C`, null stdin, stdout capped
    at 256 KiB, deadline then kill (60 s copy/detach, 10 s queries). `existing` reads
    `CFBundleIdentifier` / `CFBundleShortVersionString` with `/usr/libexec/PlistBuddy` (works for
    XML and binary plists) — **no `plist` dependency needed**; a symlink, file or unreadable
    plist is foreign. `running` via `/bin/ps -axww -o comm=` prefix match, fail-closed. Copy:
    `/usr/bin/ditto <src> <dir>/.Mooring.app.<nonce>` → `/usr/bin/codesign --verify --deep
    --strict` on the copy → swap (old renamed aside, new renamed in, rollback on failure, old
    removed). Never elevates; quarantine kept (ditto preserves xattrs). Relaunch:
    `/usr/bin/open -n <dst> --args --mooring-moved [--mooring-replaced]
    [--mooring-detach=/Volumes/<name>]` (plain `open` for an existing same/newer copy), then
    `exit(0)`. Detach in the new copy only when the volume is exactly `/Volumes/<name>`, listed
    by `hdiutil info`, holds `Mooring.app` with our id and has no `Mooring Data`,
    `Mooring Dev Data` or `portable` entry: `/usr/bin/hdiutil detach <vol> -quiet` (no
    `-force`; non-fatal). Note: hdiutil lives in `/usr/bin`, not `/usr/sbin`.
  - `install_flow.rs` (Tauri wiring; compiled everywhere so Linux type-checks it, called only on
    macOS): the offer dialog is shown **before** the main window exists (nothing can be unlocked
    while it is open); Cancel → this run; Not now → `app.install.move_declined = <version>` in
    the settings store; Move → worker thread copies + relaunches, failure → warning box, then the
    window. Translocated + release + not relaunched → dialog first; every refusing answer and a
    failed move end in the existing M-18 refusal; nothing remembered. A relaunched copy that is
    translocated again gets the plain M-18 refusal (no loop).
  - `navigation::create_main_window` now takes `&AppHandle` (needed from the dialog callback).
- **Audit** (`mooring-audit` `event/a5.rs`, no paths per ADR): `install.move_offered {location}`,
  `install.moved {target: applications|user_applications|other, replaced, detached}` (written by
  the relaunched copy), `install.move_declined {remember}`, `install.move_failed {code}`.
- **IPC codes** (ipc-codes.json): `app.build_identity`, `install.not_ours`, `install.running`,
  `install.copy_failed`, `install.not_writable`.
- `app_info` gains `channel` and `identifier`.
- e2e_flow `a4_1_portable.rs` / `a4_update.rs`: literal `Mooring Data` → `Dirs::ROOT`, new
  `InstallFacts.dev_build` field (minimal, mechanical; qa please re-read).

## UI contract (ui-engineer, English only)
- `app_info()` → `{ …, channel: "release" | "dev", identifier: "io.github.yyasar21.mooring[.dev]" }`.
  DEV badge and About "Development build (<identifier>)" key on `channel === "dev"`.
- Settings → Updates in dev: `update_check` / `update_install` / `update_settings_set
  {backgroundCheck:true}` reject with `{ code: "update.manual_only", message: "development
  build: updates come from your own builds" }`; `manualReason` wire value `dev_build` (add it to
  the TS union). Show "Updates are disabled in development builds. Install a release from the
  Releases page."
- No new commands or events: the move dialog, its failure box and the relaunch are native.
  Dialog title "Move Mooring to Applications?", buttons Cancel / Move to Applications / Not now.

## Left open
- **Keychain service name from the identifier** (`keyring_store::SERVICE`, ADR §1) — not touched
  (ADR-0022 replacement in parallel); the new keyring code should take
  `app.config().identifier`.
- **Manifest (orchestrator)**: this branch adds `serde_json = { workspace = true }` to
  `src-tauri/Cargo.toml` `[build-dependencies]` (already in the tree; no lockfile change
  expected). Re-apply under your ownership if you prefer. No `plist` dep needed.
- Brief said `TAURI_CONFIG=src-tauri/tauri.release.conf.json`; tauri-build only accepts inline
  JSON, so the release check runs with `TAURI_CONFIG="$(cat src-tauri/tauri.release.conf.json)"`.
- `parse_hdiutil_info` reads local tool output that carries volume names from downloaded DMGs:
  a `cargo fuzz` target is qa's (the function is total, no indexing).
- Escape / close box of the dialog land on the "Not now" slot (B-6) and are therefore
  remembered for this version.
- Manual macOS 26 plan from the ADR (each slot from DMG / Downloads / translocated, replace
  0.1.2, `~/Applications` as a standard user, relaunched copy not re-translocated — ditto keeps
  quarantine, so verify; fallback is the Finder-guided text, volume detached, audit rows).
- `codesign --verify` on the copy fails for a completely unsigned bundle (rc without signing):
  the move then answers `install.copy_failed` — fine for signed / ad-hoc-signed releases.

## Decision needed
- None blocking. Option: drop the repeated `app.windows` from the overlay by setting the title
  at runtime — not done (brief: keep config titles).

## Test evidence
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean (only the pre-existing
  `unknown lint: clippy::unused_async_trait_impl` warning from the workspace lint table on main).
- `cargo test`: NOT run to completion; the shared disk filled up (No space left on device) while
  linking the test binaries, twice. Re-run `cargo test --workspace` once space is available.
