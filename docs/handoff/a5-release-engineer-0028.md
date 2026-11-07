# A5 · release-engineer · ADR-0028 build identity (release-engineer half)

Branch `worktree-agent-a372875d06f1b90ab`. Scope: ADR-0028 §1 (config, pipeline), §3 (DMG),
owner decisions 43, 45, 46 at defaults. Nothing under `src-tauri/src/**`, `src-tauri/build.rs`
or `apps/` was touched.

## Done
- **Identity split.** `src-tauri/tauri.conf.json` is now the dev identity:
  `io.github.yyasar21.mooring.dev`, "Mooring Dev", window title "Mooring Dev", icons
  `icons-dev/`, NSIS `installerIcon` `icons-dev/icon.ico`, `createUpdaterArtifacts: false`, no
  `plugins.updater` block, WiX `upgradeCode` `9eff6699-6217-579b-8071-28cf4e556939` =
  uuid5(DNS, dev id). Linux package/binary/desktop names are not set explicitly: Tauri derives
  them from productName (`mooring-dev`; the desktop template's `StartupWMClass={{exec}}`
  follows) — confirm in the rc (ADR "left open").
- **`src-tauri/tauri.release.conf.json`** (new) holds only release keys: identifier,
  productName, the full `app.windows` entry with title "Mooring" (arrays replace under RFC 7396,
  so the window is repeated; the identity check fails if it drifts from the base window),
  release icons, `createUpdaterArtifacts: true`, WiX `upgradeCode` `1f940c60-…` (byte-identical;
  it is Tauri's uuid5(DNS, "Mooring.exe.app.x64")), NSIS icon, the updater block (pubkey,
  endpoint, `requireSignedVersion`, `windows.installMode`) moved verbatim.
- **Merge semantics verified**, not assumed: tauri-cli 2.12.4 `build --help` (repeated
  `--config`, merged in order); a real `tauri build --config overlay --config '{…}'` run dumped
  `TAURI_CONFIG` = overlay with the second value on top; tauri-build 2.7.4 `lib.rs:681`
  applies it with `json_patch::merge` (RFC 7396); tauri-action v1.0.0 (`1deb371`, source read)
  takes every `--config` (`configFlag[]`, `mergeUserConfig` per file, relative to the repo
  root) for productName/identifier → artifact names. `cargo build -p mooring-app` compiles both
  with the dev config and with `TAURI_CONFIG` = the overlay.
- **`scripts/release/merge-config.py`** (stdlib, `python3 -I`): `merge` (RFC 7396, `--get`
  JSON pointer), `check-identity` (≈30 assertions: base dev / merged release, upgradeCodes,
  pubkey/endpoints/L-39, window drift, icon files present, overlay key whitelist incl. no
  `version`, DMG block base-only and background 660×400), `self-test` (all RFC 7396
  Appendix A cases).
- **Dev icons** (decision 43): `packaging/icon-dev.svg` = `icon.svg` + orange 45° "DEV" ribbon
  (stroked paths, no fonts); `src-tauri/icons-dev/` generated offline with the repo tool chain
  (`tauri icon`, CLI 2.12.4) — same 17 files as `icons/`. `gen-icons.sh [release|dev|all]`,
  `make icons` does both. No manual step left.
- **release.yml**: tauri-action `args` = `… --config src-tauri/tauri.release.conf.json --config
  <tauri.ci.json>` (overlay first, CI keys win: `createUpdaterArtifacts:false`, MSI version,
  signing); `MOORING_RELEASE_BUILD: "1"` on that step; new step "Release identity in the built
  bundles" (merged id, `Info.plist` CFBundleIdentifier on macOS, `dpkg-deb -f Package` /
  `rpm -qp` = `mooring` on Linux, no `mooring[ _.-]dev` artifact names); draft-release job runs
  `check-identity`. Updater archive, pkg, portable zip, sign-updater, finalize already used
  release names (`Mooring.app`, `Mooring_*`) — unchanged and correct with the overlay.
- `release-homebrew.yml` takes the cask identifier from base+overlay (was the base file, which
  would now have shipped `.dev`) and refuses `*.dev`.
- `macos-pkg.sh` reads the id from `Info.plist` (it did) and now refuses `*.dev` when
  `GITHUB_REF` is a tag or `MOORING_RELEASE_BUILD=1`. `verify-release.sh` refuses any
  `SHA256SUMS`-listed asset named like the dev build (latest.json carries no identifier; asset
  names are the cheap check).
- **`lint-workflows.sh`** rule 4 (every tauri-action step / `tauri build|bundle` line in
  `release*.yml` has the overlay as its *first* `--config`, folded args and `\` continuations
  handled; release.yml must contain a build) and rule 5 (`MOORING_RELEASE_BUILD` only in
  release.yml's `build` job, value "1"; comments ignored).
- **ci.yml**: Linux step runs `merge-config.py self-test`, `check-identity`,
  `tests/identity.test.sh`; macOS step `pnpm tauri build --debug --bundles app --no-sign` and
  asserts `Mooring Dev.app` has `io.github.yyasar21.mooring.dev` (ADR test plan; adds one
  custom-protocol debug link on the macOS runner, a few minutes).
- **DMG layout** (§3): `bundle.macOS.dmg` in the base file (both channels): background
  `../packaging/macos/dmg-background.png`, 660×400, app (180,170), Applications (480,170).
  Background from `packaging/macos/dmg-background.svg` (navy `#0e1218`, teal `#5cc8b8` arrow,
  "Drag Mooring to Applications" / "then eject this disk"), PNG + `@2x` rendered with
  rsvg-convert. Icons sit on light slots because Finder draws icon labels in dark text.
- **Per-version volume** (decision 46): `scripts/release/dmg-volume.sh` (UDZO→UDRW, private
  attach, require `.DS_Store` + `.background/`, `diskutil rename`, re-read name, root listing
  unchanged, detach, UDZO zlib-9, `hdiutil verify`, atomic replace; plan and limits in the
  header). release.yml step behind repo variable `DMG_VERSIONED_VOLUME == 'true'` — **off**.
- `docs/release.md`: identity table (channel → identifier → data dir), overlay mechanics, local
  builds are "Mooring Dev". `make dev`/`make bundle` unchanged (base config); no
  `bundle-release-local` target.

## Left open
**rust-core (next, in this order matters for a green `cargo test`):**
1. `src-tauri/src/updater/download.rs` test `configured_endpoint_shares_the_release_tree`
   reads `/plugins/updater/endpoints` from `tauri.conf.json` with `.expect("endpoints")` —
   **it panics now** (the block moved). Read `tauri.release.conf.json` (or base+overlay merged)
   instead; same for any `requireSignedVersion` (L-39) assertion. `tests.rs`
   `checked_in_config_is_read_without_panicking` is conditional and still passes, but should
   also cover the overlay.
2. `build.rs`: effective identifier = base merged with `TAURI_CONFIG` (RFC 7396, as
   `merge-config.py merge`); emit `cfg(mooring_release)` iff it equals
   `io.github.yyasar21.mooring`; `rerun-if-env-changed=TAURI_CONFIG` and
   `=MOORING_RELEASE_BUILD`. Suggested cross-check: `MOORING_RELEASE_BUILD=1` with a non-release
   id → build error, and release id without the variable → build error (so neither half alone
   produces a release build). Release CI sets it on the tauri-action step only.
3. `build_identity.rs` `Channel`, `app.build_identity` refusal, `app_info.channel`;
   `ManualReason::DevBuild` first in `decide` (dev config has no updater block, so today it
   answers `update.unconfigured`); `keyring_store::SERVICE` from `app.config().identifier`;
   `Dirs::root_name(channel)` (`Mooring Dev Data`); `install_location.rs` (§2); `plist` dep via
   orchestrator; ipc-codes.json. Window title: the config already says "Mooring Dev"; ADR's UI
   section wants "Mooring — Dev" from `create_main_window` — pick one (see Decision needed).
4. Config Rust test from the ADR test plan (base `.dev`, no pubkey, upgradeCodes) — the same
   checks already run in `merge-config.py check-identity`; a Rust twin is optional.

**ui-engineer:** DEV badge in the title bar, About "Development build
(io.github.yyasar21.mooring.dev)", Settings → Updates dev text — all keyed on
`app_info.channel` once rust-core ships it. English only.

**release-engineer (later):** rc dry run: confirm deb/rpm `Package`/binary names, the release
`Info.plist` id, and the DMG background on macOS 26; then try `DMG_VERSIONED_VOLUME=true` and
look at the mounted volume (background visible → keep; else leave off, decision 46). When the
A1 `sign-platform` dmg rebuild lands, call `dmg-volume.sh` there too. `@2x` background is
committed but the config uses the 1× PNG (Finder needs a multi-resolution TIFF for Retina:
`tiffutil -cathidpicheck` on macOS) — follow-up. The troubleshooting page "Clean up duplicate
Mooring entries" (ADR §4) is not written (docs owner).

## Decision needed
- Window title: config "Mooring Dev" (done, per brief) vs ADR UI "Mooring — Dev" set at
  runtime. Both work; runtime title would let the overlay drop the repeated `app.windows`.
- `DMG_VERSIONED_VOLUME`: owner flips the repository variable for the rc only after the visual
  check.

## Test evidence (2026-11-07, Linux worktree)
- `bash scripts/release/lint-workflows.sh .github/workflows` → ok.
- `scripts/release/tests/run.sh`: dmg-volume 14/14, identity 22/22, lint-workflows 29/29,
  macos-pkg 4/4, portable-zip 71/71, updater-manifest 24/24, verify-release 38/38.
- `python3 -I scripts/release/merge-config.py self-test` → 17 passed; `check-identity` → ok.
- `cargo metadata --locked` ok; `cargo build -p mooring-app` (CARGO_TARGET_DIR=/home/claude/nexus/target,
  CARGO_INCREMENTAL=0) finished with the dev config and with `TAURI_CONFIG` = overlay.
  `target/debug/incremental` (8.1 GB) was deleted after an ENOSPC during linking.
- Workflow YAML parses (PyYAML). Not run here: any macOS/Windows step (PlistBuddy, hdiutil,
  the ci.yml debug `.app` bundle) — first real run is the next CI push / rc.
