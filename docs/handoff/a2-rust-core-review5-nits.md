# A2 — rust-core: security review 5 remaining findings (L-29, L-30, N-30..N-38)

Branch: worktree `agent-a1ca346442ddff422` (`worktree-agent-a1ca346442ddff422`), from `a3` @
384a6ef. Not merged. Closes the rust-core rows of the "Remaining findings" table in
[review 5](../security/a2-review-5.md). No capability, manifest or golden change; one
workspace `Cargo.toml` line (N-35, allowed for this task) and the one-line `Cargo.lock`
consequence.

## Done (per finding)
- **L-29** (`web/mod.rs`, `web/window.rs`, `commands/web.rs`, `web/sweep.rs`, `state.rs`,
  `lib.rs`). `StorageOs::WindowsOrLinux` is split into `Windows` and `Linux`; the plan is a
  pure function of `(options, StorageOs)`, so the Windows case is tested on Linux. On Windows
  an ephemeral window gets `Storage::EphemeralDirectory(<cache>/web-ephemeral/<connectionId>)`
  → `incognito(true)` **and** `data_directory(dir)` (own `WebView2` environment, InPrivate
  inside it). `AppState.cache_dir` is the Tauri `app_cache_dir()` (default
  `$APP_DATA/cache` in tests). The directory is created 0700 in `web_open`, removed by
  `commands::web::destroyed` (the `Destroyed` handler; `web_close` removes it after
  `destroy()`), and `web::sweep::ephemeral_profiles` wipes everything under
  `web-ephemeral/` at setup. The vSphere Client window (`vsphere_console::client_plan`) takes
  the same `ephemeral_storage(state, id, os)`. `WebEntry.ephemeral_dir` carries the path;
  `web_list.persistent` stays `false` for it (`WebPlan::persistent()`).
- **L-30** (`commands/tree.rs`, `commands/web.rs`, `mooring-store/src/connections.rs`,
  `commands/vault.rs`). `Store::connection_ids_under(folder, protocol)` is one recursive query
  (bounded by the folder count, like `is_ancestor_or_cyclic`). `tree::delete_folder_with`
  collects the descendant web ids, deletes the folder, then `web::purge_deleted`: forget the
  registry entry (audit `web_closed`, send `closed`), `destroy(label)`, remove the ephemeral
  profile, remove the store directory. `delete_connection_with` has the same order (window
  first, then directory). The two-argument `delete_folder` / `delete_connection` keep their
  signatures (QA's `tests/e2e_flow` uses them) with a no-op destroyer; the Tauri wrappers pass
  `web::destroyer(&app)`. `vault::unlock` calls `web::sweep::orphan_stores`: every entry of
  `$APP_DATA/web/` whose name is not the UUID of an existing web connection with
  `persistent: true` is removed (an unreadable options row keeps its store). macOS identifier
  stores: unchanged, `WKWebsiteDataStore.remove(forIdentifier:)` is still unreachable from
  Tauri (left open below).
- **N-30** (`commands/web.rs`, `commands/detach.rs`). `hide_if_locked(state, hide)`: after
  `build()` and the `Destroyed` hook, `web_open` and `window_detach` hide the window when the
  vault is not unlocked now (no vault counts as locked); the lock observer shows it after the
  next unlock. The build is not serialised under the vault mutex (the builder blocks on the
  main thread), so this is the post-check variant the finding offered.
- **N-31** (`mooring-core/src/options/conn.rs`, `web/policy.rs`).
  `mooring_core::options::is_localhost_subdomain(host)`: equal to or ending in `.localhost`
  (case-insensitive, trailing dot tolerated), `localhost` itself excluded. `WebConnOptions::
  validate` refuses it for `url` and every `allowedOrigins` entry (`input.invalid`), and
  `NavPolicy::decide` blocks it regardless of the list. `is_app_url` is unchanged on purpose:
  it is the *allow* predicate of the main and detached windows, and a wider match there would
  allow `evil.localhost` in `main`. A stored `https://tauri.localhost/` start URL is now
  refused at `connection_options_set`, so the `web.origin_refused` path is reachable only
  through the dev URL (test kept).
- **N-32** (`web/window.rs`). `INIT_SCRIPT` overrides
  `HTMLInputElement.prototype.showPicker` (throws `NotAllowedError` for `type=file`, delegates
  otherwise), cancels `drop` on file inputs in the capture phase, and is installed with
  `initialization_script_for_all_frames`. Still best effort; the empty capability is the
  boundary.
- **N-35** (`Cargo.toml`, `mooring-proto-ssh/src/algos.rs`). `russh` features are
  `["ring", "rsa"]`. `cargo metadata --locked` refused (russh's `flate2` edge leaves the
  lockfile), so `cargo metadata --offline` was run once: `Cargo.lock` diff is exactly one
  removed line (`"flate2"` under `russh`), no version moved. `flate2` 1.1.10 stays in the tree
  through `mooring-testsrv` (dev) only. Test `compression_is_none_only` asserts
  `preferred().compression == [NONE]` and the same through `client_config`.
- **N-37** (`commands/web.rs`). `web_clear_data` → `clear_data_with(state, id, wipe_open)`:
  `check_clear` (`dto` id, `with_ready`, `Protocol::Web`) runs first; the window's
  `clear_all_browsing_data` closure runs only after it; the `WebView2` locked-profile
  tolerance and the `web_data_cleared` audit are unchanged.
- **N-38** (`lib.rs`). `log_filter` drops any user directive containing `[`. The L-24 test now
  emits the protected events inside an `ironrdp_connector::connection` span named `connect`
  and adds `[connect]=trace`, `ironrdp_connector[{step}]=trace,[{step}]=debug` and
  `[connect{step=1}]=trace`: `ironrdp_connector::credssp` stays at info in every case.
- **ADR-0014 amendment**: one "Amendment (2026-11-04)" section notes the shipped error code
  `kube.refused` (audit event unchanged).
- **L-24 user-guide note**: `docs/user-guide/troubleshooting.md` "Getting diagnostic output"
  gains one paragraph on the three protected `MOORING_LOG` targets and the ignored span
  directives.

## Left open
- **L-29 QA**: the Windows E2E (two ephemeral connections to one `127.0.0.1` page, a cookie set
  in one absent in the other). Not runnable here (Linux, no WebView2).
- **L-30 macOS**: identifier stores (`data_store_identifier`) cannot be removed from Rust until
  Tauri/wry expose `WKWebsiteDataStore.remove(forIdentifier:)`; `web_clear_data` on an open
  window still wipes their content. The directory sweep is Windows/Linux only by nature.
- **L-31, L-32, N-33, N-34, N-36**: other owners (QA / orchestrator / ui-engineer).
- Commits `995706d` and `3c85cd1` do not build on their own (`lib.rs` references
  `web::sweep` that lands in `57c1835`); the branch head does. Squash or reorder on merge if
  bisectability matters.

## Decision needed
- **Ephemeral profile location**: review L-29 says `<app cache>`; the persistent stores live in
  `$APP_DATA/web/`. On Windows `app_cache_dir` is `%LOCALAPPDATA%`, which is what a WebView2
  profile wants (never roamed). If the owner prefers one root, change `ephemeral_dir` to
  `state.data_dir` — one line plus the sweep root.
- `Cargo.lock` one-line change (N-35): orchestrator-owned file, included in `698fb5f` so the
  branch builds `--locked`. Drop that hunk and re-run `cargo metadata` on `main` if preferred.

## Test evidence
Linux x86_64, 2026-11-04, `CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/home/claude/nexus/target`,
HEAD 57c1835 (+ docs commit after).

```
cargo fmt --all -- --check                                               ok
cargo clippy -p mooring-app -p mooring-proto-ssh -p mooring-core --all-targets -- -D warnings
                                                                         ok (only the pre-existing
                                                                         unknown-lint note for
                                                                         clippy::unused_async_trait_impl)
cargo test -p mooring-app -p mooring-proto-ssh -p mooring-core          545 passed, 0 failed, 2 ignored
  mooring-app lib 252 passed · e2e_flow 19 · mooring-core 150 + fuzz_corpus 9
  mooring-proto-ssh 62 + auth 9 + credential_kinds 8 + forward 10 + sftp 9 + shell …
cargo test -p mooring-store                                              ok (connection_ids_under_walks_the_subtree_by_protocol)
cargo metadata --offline                                                 Cargo.lock: 1 line removed
```

New tests: `web::tests::windows_ephemeral_gets_a_per_connection_directory`,
`web::tests::start_sweeps_remove_orphans_only`,
`commands::web::tests::folder_delete_closes_windows_and_wipes_stores`,
`commands::web::tests::clear_data_checks_before_wiping_the_open_window`,
`commands::web::tests::window_built_during_a_lock_is_hidden`,
`commands::web::tests::closing_removes_the_ephemeral_profile`,
`commands::web::tests::init_script_hooks`, `web::policy::tests::app_origin_start_url_is_refused`
(rewritten) and the `*.localhost` rows in `everything_else_is_blocked_with_origin_only`,
`mooring_core::options::tests::web_url_and_origin_rules` (extended),
`mooring_store::connections::tests::connection_ids_under_walks_the_subtree_by_protocol`,
`mooring_proto_ssh::algos::tests::compression_is_none_only`, `credssp_targets_never_log_below_info`
(extended). Goldens (`ipc-codes.json`, `ipc-manifest.json`, `ipc-passive.json`) unchanged, no
re-bless.
