# A4 rust-core — U0 in-app updater wiring

Branch: worktree of `a4` @ 351e30c. Spec: ADR-0018 §3 (owner decision 15), `a4-architect.md`
row U0. Not merged. `docs/handoff/index.md` row is the orchestrator's.

## Done
- **Plugin** (`src-tauri/Cargo.toml`): `tauri-plugin-updater = "=2.14.1"`,
  `default-features = false, features = ["rustls-tls", "system-proxy"]` (no `zip`: v1 bundles
  are not accepted). Plus `semver = "1"` as a direct dependency (already in the tree via tauri)
  for strict version comparison. The plugin is registered in `lib.rs` **only** when
  `updater::configured_pubkey(context.config())` finds a non-empty `plugins.updater.pubkey`;
  otherwise it is not even constructed and `UpdateRuntime::unconfigured` makes every command
  answer `update.unconfigured`. `tauri.conf.json` was not touched (R1 adds `plugins.updater`).
- **No `updater:*` permission anywhere**: the four app commands are the only way in
  (`permissions/mooring-main.toml`, `guard/table.rs`, all `Scope::Main`). Capability tests
  `no_capability_grants_an_updater_permission` (every capability file, the permission set, the
  guard for `detached-*` / `web-*`) and `no_capability_names_dialog_fs_or_shell` (now also
  rejects any `updater` substring).
- **Commands** (`src-tauri/src/commands/update.rs`; all four vault-gated by `with_ready` before
  anything else, owner decision):

  ```
  update_check() -> UpdateInfo {
      current: string,                              # running semver
      available: { version, date?, notes, size? } | null,   # notes: plain text ≤ 4 KiB
      installMode: "in_app" | "manual",
      manualReason?: "package_manager" | "homebrew" | "not_writable" | "not_bundled",
      checkedAt: string                             # RFC 3339
  }
  update_install({ version: string, closeSessions?: bool }) -> void   # restarts on success
  update_settings_get() -> UpdateSettings { backgroundCheck: bool, channel: "stable", lastCheck: string|null }
  update_settings_set({ backgroundCheck: bool, channel?: "stable" }) -> UpdateSettings
  event "update:available"  payload: UpdateInfo (background check only, `available` set)
  ```

  Error codes (all in `ipc-codes.json`): `update.unconfigured`, `update.busy`,
  `update.rate_limited` (manual checks < 60 s apart; message says how long to wait),
  `update.network`, `update.manifest`, `update.signature`, `update.none` (not newer, or the
  re-check no longer offers `version`), `update.manual_only` (deb / rpm / MSI / Homebrew /
  dev build), `update.not_writable` (root-owned `.app`, per-machine NSIS, read-only AppImage
  directory), `update.sessions_open` (without `closeSessions`), `update.install_failed`
  (writing failed after verification; not in the ADR list, added). `channel` other than
  `stable` and a non-semver `version` are `input.invalid`.
- **Install-mode matrix** (`updater/install_mode.rs`): pure `decide(&InstallFacts)` over
  `(bundle, install path, writable)`; the facts come from an injectable `InstallProbe`. The real
  `OsProbe` reads `tauri::utils::platform::bundle_type()`, resolves what the plugin would
  replace (`$APPIMAGE`, the `.app` ancestor, the NSIS directory), canonicalises symlinks (casks
  link `/Applications/Mooring.app` into the Caskroom) and probes writability by creating and
  removing a nonce-named file (and `O_APPEND`-opening the AppImage). deb / rpm / MSI →
  `package_manager`; a Caskroom path → `homebrew`; unknown bundle → `not_bundled`; AppImage /
  `.app` / NSIS → `in_app` only when writable. `update_install` evaluates the matrix **before**
  the plugin is asked, so its `pkexec` / sudo-dialog / `msiexec` / AppleScript paths are never
  reached (test: 8 manual rows, zero source calls).
- **Install flow**: semver parse → `offered > current` (strict; a pre-release of the running
  version is older) → matrix → open sessions (closed first only with `closeSessions`, via
  `sessions::close`) → single flight → the source re-runs the check, refuses unless the offer
  equals `version`, downloads, the plugin verifies the minisign signature, `update.install`
  is audited, the bundle is written, `AppHandle::restart()`. No URL, signature or bytes ever
  come from the renderer (`InstallInput` is `deny_unknown_fields`).
- **Trust chain** (`updater/source.rs` doc): pubkey compiled into the binary →
  `latest.json` over HTTPS names version + URL + signature (the manifest itself is unsigned) →
  the asset's minisign signature is verified by the plugin against the compiled-in key before
  anything is written → the version the user confirmed must equal the re-check.
- **HTTP policy**: `mooring-http` cannot carry the updater's traffic — the plugin owns its
  `reqwest` client and `UpdaterBuilder::configure_client` is the only hook. Mirrored there:
  `https_only(true)`, 30 s timeout (the `mooring-http` request deadline), `Mooring/<version>`
  user agent, the plugin's own `https`-only endpoint validation, system proxy honoured
  (`system-proxy`). Redirects stay at reqwest's default (10): GitHub redirects
  `releases/latest/download/…` to its asset host. The ADR's "one outbound request carrying only
  version and target" holds (the endpoint URL has no template variables).
- **Notes sanitiser** (`updater/notes.rs`): whole ANSI CSI / OSC / two-byte escapes removed,
  C0/C1 controls (except `\n`, `\t`), bidi overrides / isolates / marks, zero-width and BOM
  characters stripped, line endings normalised, blank runs collapsed, capped at 4 KiB on a char
  boundary with `…`. Markdown / HTML is left as text (the UI renders plain text only).
- **Background check** (`updater/background.rs`): opt-in via `backgroundCheck`; loop ticks
  every 60 s; runs only when ≥ 60 s uptime, vault unlocked and the stored `lastCheck` is ≥ 24 h
  old (or absent; a future `lastCheck` counts as recent). Fetches the manifest, emits
  `update:available` when something is newer, **never downloads or installs**. Both manual and
  background checks write `lastCheck`, so the 24 h gap survives restarts. Not spawned when
  unconfigured.
- **Rate limit / single flight** (`updater/mod.rs`): `begin_check(now, manual)` refuses with
  `update.busy` while anything is in flight and with `update.rate_limited` when a manual check
  comes < 60 s after any network check; the background path skips the gap but counts for it;
  `begin_install` is single-flight only. The flight is an RAII guard (released on `?`).
- **Audit** (`mooring-audit` event.rs, ADR-0018 names): `update.check { current, available }`
  (only on a completed check), `update.install { from, to }` (written right before the bundle
  is written), `update.refused { code }` (install refusals: `update.none`, `update.manual_only`,
  `update.not_writable`, `update.sessions_open`, `update.signature`, `update.install_failed`;
  not `busy` / `rate_limited` / `input.invalid`), `update.settings_changed { background_check }`
  (only when the flag actually changed).
- **Settings** stored as JSON under `app.update` (`setting` table; `NOT_CODES` in `golden.rs`).
  Corrupt rows fall back to the default (test).
- **Goldens** re-blessed: `ipc-codes.json` (+11), `ipc-manifest.json` (+4 rows).
  `ipc-passive.json` unchanged (`update_settings_get` is read-only but it is vault-gated and not
  a poll target; add it to `POLLED_COMMANDS` if the UI polls it).
- **Gate matrix** (`tests/e2e_flow/support.rs::vault_gated_codes_a4`): the four commands are
  real rows of the locked matrix (`vault.locked` first, before `update.unconfigured`), not
  `NOT_GATED` entries.

## Left open
- `size` is read from `platforms.<target>.size` of `latest.json` when present; the Tauri CLI
  does not write it, so `updater-manifest.sh` (R1) decides whether to add it. Absent → omitted.
- The plugin's `Update` cannot be constructed outside its crate, so `PluginSource` is covered
  by the ADR's integration test plan (loopback `latest.json` + ephemeral key, QA Q1), not by a
  unit test; everything above it is tested through the scripted `FakeSource` / `FakeProbe`.
- `crates/mooring-audit/src/event.rs` was already 672 lines (> 500) before this change; it is
  701 now. A split of the vocabulary file (by phase) is a one-file follow-up for the owner.
- The ADR's `closeSessions` closes SSH / RDP / VNC / kube sessions through `sessions::close`;
  web windows and port forwards are not sessions and are left to the app restart.
- On Windows the plugin exits the process itself after launching the NSIS installer (`/P /R`
  relaunch); on macOS / Linux `AppHandle::restart()` runs after `install`. Not exercised here.

## Decision needed
- Task brief vs ADR naming: the brief says `update.manual` and audit rows `update_checked /
  update_installed / update_refused { reason }`; the accepted ADR-0018 says `update.manual_only`
  and `update.check / update.install / update.refused { code }`. Implemented the ADR; the UI
  contract above is what U2 should mock. Say so if the brief's names were meant.
- Notes cap: the brief says ≤ 4 KiB, the ADR 16 KiB. Implemented 4 KiB (`MAX_NOTES`); one
  constant to change.
- `update.install_failed` is a new code (post-verification write failure); accept or fold into
  `update.manual_only`.
- `osakit` (macOS, last release 2025-03-01) and `minisign-verify`, `tar`, plus duplicate
  `core-foundation 0.9` / `system-configuration 0.7` (reqwest `system-proxy`) and
  `hyper-rustls` / `rustls-platform-verifier` / `webpki-root-certs` (reqwest `rustls-no-provider`)
  are new in the lock (security review 7, ADR-0018 dependency check).

## Test evidence
- `cargo fmt --all -- --check`: clean. `cargo clippy -p mooring-app --all-targets -- -D warnings`:
  clean (`-p mooring-audit` too).
- `cargo test -p mooring-app`: lib 307 passed, 1 ignored (was 303); `e2e_flow` 21 passed.
  `cargo test -p mooring-audit`: 35 passed. New tests: install-mode matrix (14 rows), manual
  reasons → codes, OS writability probes (unix), unconfigured runtime, single flight + rate
  limit, strict semver, pubkey gate (6 config shapes), checked-in config sanity, source error
  codes, notes sanitiser (5), background schedule (3), command flow (13: check / downgrade /
  notes + manual matrix / error mapping + rate limit / gate order / settings round trip +
  validation + audit / corrupt settings / install happy path / refusals audited / manual matrix
  before network / single flight / open sessions with a live SSH session / input wire shape),
  capability snapshot (updater), audit wire names (4 events).
- `cargo metadata --locked` after one `cargo metadata`: consistent. Lock diff: +17 packages
  (`tauri-plugin-updater 2.14.1`, `minisign-verify 0.3.0`, `tar 0.4.46`, `filetime 0.2.29`,
  `xattr 1.7.0`, `osakit 0.3.1`, `objc2-osa-kit 0.3.2`, `hyper-rustls 0.27.10`,
  `rustls-platform-verifier 0.7.1`, `rustls-platform-verifier-android 0.2.0`, `jni 0.22.4`,
  `jni-macros 0.22.4`, `simd_cesu8 1.2.0`, `webpki-root-certs 1.0.11`, `core-foundation 0.9.4`
  (second copy), `system-configuration 0.7.0`, `system-configuration-sys 0.6.0`); no version
  changed for an existing package. The reviewed WebView pins (`golden.rs`) are untouched.
