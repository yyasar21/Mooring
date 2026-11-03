# A1 rust-core — fixes for security review 2 and QA pass 2

Agent: rust-core · 2026-11-03 · Worktree `agent-aeb3d1ea865940b7c`, branch
`worktree-agent-aeb3d1ea865940b7c`, base `d6143cd` (ADR-0007 amendment). Not merged.

Inputs: [a1-review-2.md](../security/a1-review-2.md),
[a1-qa-engineer-2.md](a1-qa-engineer-2.md) (A1-QA-4, test-util request), ADR-0007 (amended:
`Exposure`, `Prompt.purpose`).

## Done — finding → commit

| Finding | Commit | Change | Test (fails before, passes after) |
| --- | --- | --- | --- |
| A1-QA-4 | `c3ad61d` | `mooring-core` `is_bidi_or_invisible` (U+00AD, U+061C, U+200B–200F, U+202A–202E, U+2060–2064, U+2066–2069, U+FEFF); `validate_name/host/tag` refuse them; the store inherits; credential usernames use the same predicate | `hostile_edges::bidi_and_invisible_format_characters_are_refused` un-ignored; `model::tests::bidi_and_invisible_format_characters_are_refused` (every code point × 3 validators, neighbours like U+2065/U+202F/İ still accepted); store `names_and_usernames_refuse_bidi_and_invisible_characters` |
| M-1 | `95f6299` | `AppState.pending_clipboard: Arc<Mutex<Option<ValueDigest>>>` set by `copy_password`, cleared by the timer only if still the same digest; `AppState::clear_pending_clipboard()` runs synchronously from `shutdown()` and `vault::lock()` | `vault_lock_clears_a_pending_copy_synchronously`, `shutdown_clears_a_pending_copy_synchronously`, `lock_leaves_a_newer_clipboard_value_alone` (1 h timer, so only lock/exit can clear) |
| M-2 | `5ac2077` | `pub enum Exposure { Loopback (default), External }` in new `exposure.rs`; `forward_local/remote/dynamic` take it; `Loopback` refuses non-loopback local binds and remote hosts other than `localhost`/`127.0.0.1`/`::1` with `Invalid { field: "bind" }` before any network call; `ForwardInfo.exposure`; `TrustEvent::ForwardOpened.exposure` (`loopback`/`external`) | `local_forward_refuses_non_loopback_bind_unless_external`, `remote_forward_refuses_non_loopback_bind_unless_external` (`0.0.0.0`, `*`, `::`, `10.10.0.1`), `socks5_refuses_non_loopback_bind`, `exposure::tests::exposure_policy` (lookalikes `localhost.evil`, `127.0.0.2`) |
| M-3 | `1d21287` | `sftp::MAX_IN_FLIGHT = 8`; `block_len(chunk) = min(TRANSFER_BLOCK, 8 * chunk)` used by `read_block` and the upload loop | `one_byte_server_limits_keep_requests_in_flight_bounded`: the test SFTP server advertises `limits@openssh.com` with 1-byte reads and writes and counts requests; 1 KiB up and down complete, ≤ 8 requests per block, server saw len 1 only. It fails at once with the old block size. `block_is_bounded_by_in_flight_requests` unit test |
| M-4 | `73cabf9` | xterm `linkHandler: { activate: () => {}, allowNonHttpProtocols: false }`. `src-tauri/src/navigation.rs`: the main window is built in `setup` from its config entry (`"create": false` in `tauri.conf.json`) with `on_navigation` allowing only `tauri://localhost`, `http(s)://tauri.localhost` (no port) and, in `cfg(dev)` only, the `devUrl` origin, plus `on_new_window → Deny`. Blocked URLs log only the scheme | vitest `xterm.test.ts` (real wrapper, xterm mocked: the handler is passed and is inert); Rust `navigation::tests` (app origin allowed; `https://example.com`, `tauri.localhost.evil.example`, `tauri.localhost:8080`, `tauri://evil`, `file:`, `javascript:`, `data:`, `about:blank` denied; dev origin exact match) |
| L-7 | `d15b386` | `LocalPath` refuses `:` in any component and reserved device stems (CON, PRN, AUX, NUL, COM0–9, LPT0–9 incl. ¹²³, CONIN$, CONOUT$, CLOCK$), case-insensitive, trailing spaces ignored — on every OS, not just `cfg(windows)` as the review suggested | `alternate_data_streams_are_rejected`, `reserved_device_names_are_rejected` (and `CONSOLE`, `COM10`, `x.con` still pass) |
| L-1 | `79d9639` | `ClientHandler` overrides the six channel-open callbacks (`session`, `x11`, `auth-agent`, `direct-tcpip`, `direct-streamlocal`, `forwarded-streamlocal`) → `AdministrativelyProhibited`, replied from a spawned task like the existing unknown `forwarded-tcpip` path | `shell::server_opened_channels_are_rejected`: the in-process server opens all six toward the client, each open fails, the shell keeps working. Fails on `x11` without the fix |
| L-2 | `3a7a570` | `mooring_core::PromptPurpose { HostKeyTrust, KeyboardInteractive, Other }` (serde `snake_case`) on `SessionEvent::Prompt` and `WireEvent::Prompt`; TOFU sets `host_key_trust`, keyboard-interactive sets `keyboard_interactive`. UI: `PromptPurpose` in `ipc.types.ts`, decoder maps unknown values to `other`, `PromptModal` uses `purpose === "host_key_trust"` instead of the regex; the mock backend sets purposes | `PromptModal.test.tsx` (auth prompt with "authenticity / fingerprint / Trust this host?" renders the text field; 2 of 3 fail on the old regex); `ipc.test.ts` decoder fallback; core serde test; SSH `auth.rs`/`accept_tofu` and both e2e flows assert the purpose. The existing prompt-flow component tests are unchanged and green |
| L-5 | `f4de89e` | `KnownHosts::add_and_save(path, host, port, key)` holds a process-wide per-path mutex (`OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>>`) around load → add → save; the handler calls it in `spawn_blocking` | `concurrent_adds_keep_every_entry`: 24 threads behind a barrier. It loses entries without the lock (verified) and keeps all 24 with it |
| L-6 | `7d1ee98` | `AuditEvent::TrustDecision.expected: Option<String>` (`skip_serializing_if = None`, so old lines keep their canonical bytes); mismatch records `decision: "changed"`, `fingerprint` = presented, `expected` = stored | `host_key_mismatch_is_a_hard_stop_and_audited` checks both fingerprints; audit `trust_decision_expected_is_optional_and_keeps_old_lines_verifiable` |
| N-3 | `c5d083a` | `TrustEvent::HostKeyAdded.stored: bool`; audit decision `accepted_session_only` when the write failed | `unstored_tofu_accept_is_audited_as_session_only` (known_hosts over the line cap: loads, refuses rewrite) |
| QA request | `dccde1d` | Feature `test-util` on `mooring-app`: `clipboard`, `commands`, `dto`, `error`, `sessions`, `state` become `pub`; `state::testing`, `MemoryClipboard`, `test_ssh_server`, `KdfChoice::Fixed` are compiled under `any(test, feature = "test-util")`; `tempfile`/`russh` are optional deps behind the feature (absent from a default build, checked with `cargo tree`). A self dev-dependency `mooring-app = { path = ".", features = ["test-util"] }` turns it on for this package's tests, so `cargo test --workspace` needs no flag. `tests/e2e_flow.rs` uses `mooring_app_lib::{commands, error, sessions, state, test_ssh_server}`; the `#[path]` shim is gone | e2e_flow: 9 tests, all pass; the 41+7 inline unit tests no longer run a second time |

Commits are Conventional, English, with no `Co-Authored-By` (CLAUDE.md), and end with the
`Claude-Session` trailer.

## Out-of-scope edits (for the orchestrator)

- `Cargo.lock`: +1 line (`mooring-app` → `mooring-app` self dev-dependency edge). No new
  crate. `tempfile` and `russh` were already locked for this package.
- `src-tauri/Cargo.toml`: `[features] test-util`, two optional deps, the self dev-dependency.
- `src-tauri/tauri.conf.json`: `"create": false` on the `main` window, so Rust builds it with
  the guard. CSP and capabilities are unchanged. **Security review please.** This is a window
  config change, and the window now depends on `setup` succeeding.
- `src-tauri/tests/e2e_flow.rs` and `e2e_flow/hostile_edges.rs` (QA-owned): the shim is
  replaced, `#[ignore]` is removed, the doc text is updated, and the `purpose` assertion is
  added. The test bodies are otherwise unchanged.
- `apps/desktop`: the orchestrator allowed `xterm.ts`. The L-2 UI change touched
  `ipc.types.ts`, `ipc.ts` (decoder), `ipc.mock.ts`, `stores/sessions.ts` and
  `PromptModal.tsx`, and added `xterm.test.ts` and `PromptModal.test.tsx`. These are the
  minimum needed to carry the typed field from the wire to the one component.

## Left open

- **A1-QA-4 display of existing rows.** Rows stored before this fix that contain bidi or
  invisible characters still load and render as they are. Decision for ui-engineer and
  security: show them escaped (e.g. `\u{202E}`), or run a one-off store migration that rejects
  or escapes them.
- **M-2 audit persistence.** `exposure` is in `TrustEvent::ForwardOpened` and in the
  `tracing` line. It reaches `mooring-audit` only when forwarding IPC lands, together with
  `ForwardOpened/Closed` variants (ruling (b)). The wiring gate still holds: no forwarding IPC
  yet.
- **M-4 on Windows and macOS.** `on_navigation` and `on_new_window` were tested on Linux
  (WebKitGTK) through the predicate only. The window-level hook needs a manual check with
  `make dev` on each OS: an OSC 8 link (`printf '\e]8;;https://example.com\e\\x\e]8;;\e\\\n'`)
  must do nothing, and the app must still load. The Windows origin is assumed to be
  `http://tauri.localhost` (Tauri 2 default, `useHttpsScheme: false`).
- Still open from review 2, not in this task: L-3 (KDF on a worker under the vault mutex), L-4
  (`audit_verify` sync), L-9, N-1, N-2, N-4. The SFTP IPC gate also needs L-9.
- `MAX_IN_FLIGHT` does not refuse absurd server limits. The review's optional floor of 1 KiB
  (`Protocol("server limit exceeded")`) was not added. With the cap, a 1-byte server is only
  slow (≈ 90 B/s in a debug build), not a memory or CPU problem.

## Decision needed

1. Security reviewer: accept `"create": false` + Rust-built main window (M-4), and the
   all-platform (not `cfg(windows)`) L-7 rule.
2. Orchestrator: accept the self dev-dependency pattern for `test-util`. The alternative is
   `required-features = ["test-util"]` on `[[test]] e2e_flow`, but then CI would need
   `--features test-util` or `--all-features`, or the suite would silently be skipped.

## Test evidence (2026-11-03, this worktree, Linux, WebView toolchain present)

```
cargo fmt --all                                         → no changes
cargo clippy --workspace --all-targets -- -D warnings   → clean
cargo clippy -p mooring-app [--features test-util] -- -D warnings → clean (lib without tests)
cargo test --workspace                                  → 290 passed, 0 failed, 3 ignored
  ignored: proto-ssh lab (MOORING_LAB), vault calibrate_real_host_smoke, vault regenerate_vectors
  e2e_flow: 9 passed (A1-QA-4 no longer ignored); mooring-app lib: 48 passed
  (QA's 309 included the 41 shim duplicates inside e2e_flow; they now run once)
pnpm typecheck && pnpm lint && pnpm test && pnpm build  → ok; vitest 11 files, 46 tests
cargo tree -p mooring-app -e normal                     → no tempfile / russh without test-util
```

Every new test was also run against the unfixed code and failed: A1-QA-4, M-3, L-1, L-2 UI,
L-5 and the M-4 vitest were checked explicitly. M-1, M-2, L-6 and N-3 assert behaviour that did
not exist before.

Environment note: the disk filled up during the first full build (each worktree `target/` is
about 9 GB with debug info). I deleted this worktree's `target/` and built with
`CARGO_INCREMENTAL=0 CARGO_PROFILE_{DEV,TEST}_DEBUG=0` (about 2 GB). No other worktree was
touched.
