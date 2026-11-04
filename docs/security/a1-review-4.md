# A1 security review 4 — A1 exit (ADR-0010): forwarding, SFTP, auto-lock, syslog mirror, fuzzing

Reviewer: security-reviewer · 2026-11-04 · Range `git diff main...a1-exit` (30 commits,
`ac27b8b..0a7b802`, 171 files).

Inputs:
- [ADR-0010](../adr/0010-a1-exit-ipc.md), plus ADR-0003, ADR-0007 and ADR-0008.
- Handoffs `a1-exit-rust-core-forward-sftp.md`, `a1-exit-rust-core-autolock-syslog.md`,
  `a1-exit-ui.md` and `a1-exit-qa.md`.
- Reviews [1](a1-review.md), [2](a1-review-2.md) and [3](a1-review-3.md), and the
  [threat model](threat-model.md).

Evidence gathered here (Linux, `CARGO_INCREMENTAL=0`, `CARGO_TARGET_DIR=target-int`):
- `mooring-app` **was compiled and tested**. The `mooring-audit`, `mooring-proto-ssh` and
  `mooring-store` suites are green.
- The source of `tauri-plugin-dialog` 2.8.4, `openssl-probe` 0.2.2 and `rfd` 0.17.2 was read from
  the cargo registry.
- **Not run:** `cargo deny`, `cargo audit`, `gitleaks`, `semgrep` and `pnpm audit` (not installed
  here, no advisory DB), and the macOS and Windows builds.

## Verdict: `BLOCKER`

There is one blocker, **B-4**. The SFTP transfer commands accept any absolute local path from
the WebView. Before this range, a compromised WebView (T5) had **no** local file-system reach.
Now it can do two things:
- **Read any file the user can read** and upload it to a server it opens itself.
  `connection_create` and `session_open` are both IPC, and the WebView can answer its own TOFU
  prompt. Examples: `~/.ssh/id_*`, `~/.aws/credentials`, browser profiles.
- **Write a server-chosen file into any user-writable directory**, replacing an existing file.
  Examples: `~/.bashrc`, `~/.ssh/authorized_keys`, `~/Library/LaunchAgents/*.plist`, the
  Windows Startup folder. That is local code execution.

The only Rust-side mitigation is the app-data-dir denial. `LocalPath` confines the *file name*,
but it cannot confine a *base directory* that the attacker chooses. That breaks the ADR-0003
premise that the WebView is untrusted. The fix is contained: open the dialog in Rust, not in
the WebView. It also **shrinks** the capability back to `core:default`.

Everything else is `APPROVE WITH NITS`:
- **Forwarding** follows M-2: the `Exposure` enum applies to all three kinds, binds must be IP
  literals or `localhost`, and every open is audited with its exposure.
- **The SFTP fan-out bound (M-3) holds.**
- **The syslog formatter is sound**: SD-PARAMs carry only `seq` and hex `hash`, and MSG is
  single-line JSON.
- **TLS is rustls/ring only**, with system roots and host-name verification.
- **The mirror never blocks the local write.**

There are four Medium findings:
- M-8..M-10 concern auto-lock and what survives a lock. They must land before A1 exit, together
  with B-4.
- M-11 is the kubeconfig fuzz gate from review 3, which is still not met.

None of the four stops the rest of the merge.

## Findings

Numbering continues from reviews 1–3. Review 2's gate text names "L-9", but review 2's table
ends at L-7. The gate meant L-7, which is fixed (see below). L-8 and L-9 stay unassigned so
that nothing is renumbered.

| ID | Sev | Where | Finding | Exact fix |
| --- | --- | --- | --- | --- |
| **B-4** | **Blocker** | `src-tauri/src/commands/sftp_transfers.rs:71-88` (`dialog_dir`), `:212-251`, `:271-293`; `apps/desktop/src/lib/dialog.ts:11-22`; `src-tauri/capabilities/main.json:6` | `localDir` and `localPath` are plain strings from the WebView. Rust checks only four things: absolute, exists, is a directory, and not under `app_data_dir`. A T5 therefore names any base directory. Upload gives arbitrary local file read plus exfiltration. Download gives an arbitrary file write into any user-writable directory, and `persist` replaces an existing regular file (`sftp_transfer.rs:182`). That means local code execution through shell rc files, `authorized_keys`, LaunchAgents or Startup. ADR-0010 states "the UI never types a local path", but nothing enforces it. The dialog plugin's own trust model (paths are granted to a scope only when the user picks them, `tauri-plugin-dialog` `commands.rs:160-213`) is bypassed, because the commands never consult a scope. | **ADR-0010 amendment (architect) + rust-core + ui-engineer.** 1. New command `sftp_pick_local({ sessionId, mode: "folder" \| "file" })`. Rust opens the native dialog itself with `app.dialog().file().pick_folder(cb)` / `pick_file(cb)` and a `oneshot`, not `blocking_*` on a runtime worker. It stores the `PathBuf` in `AppState` under a random 128-bit `pickId`, and returns `{ pickId, name }` (display name only, never the full path). 2. `sftp_download({ …, localDir })` becomes `({ …, pick })`, and `sftp_upload({ …, localPath })` becomes `({ …, pick })`. The pick is looked up and consumed: it is single-use, bound to the `sessionId`, expires after 10 min, and all picks are cleared on lock. An unknown pick → `input.invalid "pick"`. 3. Keep `dialog_dir`'s app-data-dir refusal and `LocalPath` as defence in depth. 4. Capability back to `["core:default"]`: drop `dialog:allow-open` and `dialog:allow-save`, and drop `@tauri-apps/plugin-dialog` from `apps/desktop`. The Rust plugin stays registered for its Rust API. 5. Tests: a download or upload with a forged or reused pick is refused. The capability file has no `dialog:` and no `fs:` permission (JSON assertion test). A pick from another session is refused. Picks are gone after `vault::lock`. |
| **M-8** | Medium | `src-tauri/src/autolock.rs:39-40`; `apps/desktop/src/components/forwards/useForwards.ts:6`, `:45` | The Forwards panel polls `forward_list` every 5 s. `forward_list` is not in `PASSIVE_COMMANDS`, so each poll counts as user activity, and **the idle lock never fires while the panel is open**. This is the same class of bug the handoff fixed for `audit_verify`. Any future poller repeats it silently. | Add `forward_list` to `PASSIVE_COMMANDS`. Then close the class: export the list of commands that the UI calls from timers (`POLLED_COMMANDS` in `lib/ipc.ts`). Add a vitest that every `setInterval` caller uses only those commands, and a Rust test that each of them `!is_activity`. Longer term (A2), drive activity from an explicit, throttled `activity` ping on real input events instead of "every non-passive command". |
| **M-9** | Medium | `src-tauri/src/autolock.rs:35` (`BLUR_GRACE = 0`), `:111-121`, `:149-152` | With the default policy (`onWindowHidden: true`), **every** focus loss locks the vault: alt-tab, a notification, and Mooring's own native file dialog. Locking during the SFTP pick wipes the UI stores (`stores/app.ts:30-37`), including the transfer the user is starting. A lock that fires on every alt-tab trains users to turn auto-lock off, which is worse than a grace period. | **Ruling: `BLUR_GRACE = 60 s`. `onWindowHidden` stays default `true`.** Today the focus loss is the only trigger behind `onScreenLock` (the lock screen takes focus), so turning it off by default would silently remove screen-lock coverage. A 60 s grace bounds that gap to one minute. Do not count focus loss while a Mooring-owned native dialog is open: after B-4, Rust opens the dialog, so set a `dialog_open` flag around the pick and skip the blur while it is set. Tests: blur shorter than 60 s → no lock; blur of 60 s or more → `window_hidden`; blur during a pick → no lock. Update ADR-0010 §Auto-lock with the grace. |
| **M-10** | Medium | `apps/desktop/src/stores/app.ts:30-37`, `:85-89`; `src-tauri/src/commands/vault.rs:128-140` | On any lock, the UI resets `useSessions`, `useTransfers` and the panels. Rust keeps every session, **forward** and transfer alive (ADR-0006: sessions survive a lock). After unlock, the UI loads only the tree and the credentials (`loadVaultData`) and never calls `session_list`. A LAN-exposed `external` forward, or a running upload, therefore keeps going **with no UI to see or close it** until the app exits. M-9 makes locks frequent, so this happens often. | 1. UI: after unlock, call `session_list` and re-adopt the live sessions as tabs. The Forwards and Files panels then list their forwards and transfers. Transfers need a `sftp_transfers({sessionId})` list command, or else they keep emitting on their channels and the UI re-keys them by `transferId`. 2. Rust (ADR-0006 amendment): on **every** lock, close the forwards with `Exposure::External`. Each one is audited by the existing `forward_closed`. Loopback forwards may survive, as sessions do. Tests: lock → an external forward's listener refuses connections and `forward_closed` is in the log; lock → unlock → the UI shows the surviving session and its loopback forward. |
| **M-11** | Medium | `fuzz/entries/kubeconfig.rs:10-25`; `fuzz/corpus/kubeconfig_parse/` | Review 3 set a hard gate: no Kubernetes consumer until `kubeconfig_parse` is a cargo-fuzz target whose seed corpus includes the M-5 cases. The target exists, but it asserts only caps and determinism, **not the security property**. The corpus has a top-level `<<` and a lower-case `exec`, but not `Exec`, `AUTH-PROVIDER`, or a merge under `users[0].user`. A bypass (for example a complex key `? exec`, a quoted or escaped key, or a tagged scalar) would never be caught: the fuzzer is not told it is wrong. | In `run`, after a successful parse, re-scan `data` with the crate's own event parser (or a `saphyr` load). Assert that no mapping key anywhere equals `<<`, and that no key under `users[]` matches `exec`, `auth-provider`, `tokenFile` or the path keys (ASCII case-insensitive). Add seeds `users-merge-inline`, `users-Exec`, `users-AUTH-PROVIDER`, `complex-key-exec` (`? exec\n: {command: x}`) and `quoted-exec` (`"ex\x65c": …`). The gate is met only when these exist. |
| L-15 | Low | `crates/mooring-proto-ssh/src/sftp_transfer.rs:182`; `src-tauri/src/commands/sftp_transfers.rs:212-230` | A download **silently replaces** an existing local file. The name comes from the server listing (T4), for example `.bashrc` or `authorized_keys`, and the UI has no overwrite prompt (UI handoff, "Left open"). On Windows, trailing dots and spaces (`notes.txt.`) are stripped by the OS, so the name the user sees differs from the file that gets replaced. | Add `overwrite: bool` (default `false`) to `sftp_download`. When the target exists and `overwrite` is false, return `sftp.exists`. The UI asks "Replace *name*?" and retries with `true`. In `LocalPath::check_component`, refuse names that end in `.` or space. Tests for both. |
| L-16 | Low | `crates/mooring-proto-ssh/src/sftp_transfer.rs:204` | An upload opens the target with `CREATE \| TRUNCATE`. A cancelled or failed upload therefore **destroys the existing remote file** and leaves a partial one, not only a partial new file as the handoff says. The remote handle also stays open until the session ends. | Upload to `<dir>/.<name>.mooring-part-<8 hex>`. On success, use `posix-rename@openssh.com` when advertised, otherwise `remove` + `rename`. On cancel or failure, run a best-effort cleanup task that owns a clone of the `SftpClient`, closes the handle and removes the part file. Test: cancel mid-upload over an existing file → the original is intact and no part file remains. |
| L-17 | Low | `src-tauri/src/commands/syslog.rs:174-176` | When the mirror is **redirected** (enabled → enabled with another host), the new mirror is installed *before* `audit_syslog_changed` is recorded. The old collector never learns that the stream moved, and a redirect is exactly what a T5 or an insider would do to hide later events. The disable branch has the right order. | Record the event first, so the old mirror queues it, and then `set_mirror(new)`. The dropped `SyslogMirror` drains its queue. Also record a second `audit_syslog_changed` on the new mirror so both collectors hold it. Test with two loopback collectors: both receive the change entry. |
| L-18 | Low | `src-tauri/src/commands/syslog.rs:131-145` (`start_stored`); `app.syslog` setting | The mirror is the only defence against a same-user T2 rewriting the local chain (T2 holds no key). Its configuration is plaintext in `mooring.db`, and starting from the stored config is not audited. A T2 that edits `app.syslog` (disable it, or point it elsewhere) gets **silence** at the real collector and no entry in the chain. | 1. `start_stored` records `audit_syslog_started { host, port, transport }` (new variant), or a "disabled at startup" entry when a previously enabled config is now off. The old collector then sees the last entry before the silence. 2. Add an hourly `audit_heartbeat { seq }` while the mirror is enabled. 3. Document in `SECURITY.md` that collectors must alert on a missing heartbeat. Recorded as R-SYSLOG below. |
| N-10 | Nit | `src-tauri/capabilities/main.json:6` | `dialog:allow-save` is granted but unused: the UI calls only `open`. Moot after B-4, which removes both permissions. | If B-4 lands in a later PR than this merge, drop `dialog:allow-save` now. |
| N-11 | Nit | `tauri-plugin-dialog` `init-iife.js` (injected by `tauri_plugin_dialog::init()`) | The plugin replaces `window.alert` and `window.confirm` with calls to `plugin:dialog\|message`, which the capability does not grant. `confirm()` now returns a **Promise**, which is truthy, so any `if (confirm(…))` passes without asking. No code uses it today (grepped), and xterm's OSC 8 path is inert (review 2, M-4). | ESLint: `no-alert: error` and `no-restricted-globals: ["confirm", "alert", "prompt"]` in `apps/desktop`. |
| N-12 | Nit | `crates/mooring-audit/src/syslog/format.rs:28` | `SD-ID = "mooring@0"`. Enterprise number 0 is IANA-reserved. | **Ruling:** the owner requests an IANA Private Enterprise Number now (free, about two weeks). Until it is assigned, use `mooring@32473` (RFC 5612 documentation PEN): syntactically valid and not reserved, but not ours. Switch to the registered PEN before the first public release, and state the SD-ID in `SECURITY.md` so collectors can key on it. Changing it does not touch the hash chain (the SD is not hashed). |
| N-13 | Nit | `crates/mooring-audit/src/syslog/format.rs:105-121` | MSG is `redact(json)` capped at 8 KiB. If either changed the line, `SHA-256(MSG) ≠ hash`, and the collector cannot tell that apart from tampering. The handoff's "a collector can re-verify the chain from the mirror alone" holds only for `prev`→`hash` linkage. | Add `trunc="1"` and/or `redacted="1"` SD-PARAMs when either applied. Document in the module doc that content verification needs the local entry for those lines. Test: an oversized entry carries `trunc="1"`. |
| N-14 | Nit | `apps/desktop/src/stores/errors.ts:12-31`, `lib/ipc.mock.exit.ts:140` | The error codes have drifted from Rust: the UI maps `forward.bind_failed`, `forward.refused`, `sftp.permission`, `session.failed` and `sftp.local_path`, but Rust emits `forward.bind`, `sftp.denied`, `session.not_connected`, `input.invalid` and `transfer.limit`. The fallback shows Rust's fixed, path-free message, so nothing leaks; only the friendly text is lost. The mock throws the UI's codes, so the tests pass. | Generate the code list from Rust (a `#[test]` that writes `ipc-codes.json`, checked in), and add a vitest that `FRIENDLY` keys ⊆ that list and that the mock throws only listed codes. |
| N-15 | Nit | `src-tauri/src/commands/sftp_transfers_tests.rs:200` | `cancel_stops_a_download_and_leaves_no_partial_file` failed in 1 of 3 full `cargo test -p mooring-app` runs here: the "no partial file" check polls for only 2 s. The property (the temp file is deleted when the dropped write returns) holds; the test is timing-dependent. | Wait for the transfer task to finish (its `sftp_transfer` audit entry, or a join handle exposed under `cfg(test)`), then assert once. |
| N-16 | Nit | `src-tauri/src/commands/forward.rs:160-165` | `host()` refuses control characters and spaces, but not Unicode format characters (`U+202E` and other bidi controls, zero-width characters). Those reach the Forwards panel, the confirmation dialog for `external`, and the audit log, where they can spoof the displayed target. | Reuse the `mooring-core` host validator (review 1 "Validators"), or also refuse `char::is_control` plus the Unicode `Cf` category. The bind side is already IP-or-`localhost`. |

### Carried forward
- **Wiring gates from review 2 are cleared.**
  - **M-2 is fixed.** `crate::exposure::check_exposure` covers all three kinds; `forward.rs:346`,
    `:365` and `:383` are tested.
  - **M-3 is fixed.** `block_len` makes `block_len(c).div_ceil(c) ≤ MAX_IN_FLIGHT`, with a test.
  - **L-7 is fixed.** `local_path.rs:34-63` covers `:` and the device names, including the
    superscript digits and `CONIN$`, on every OS, with tests.
- **M-5 is fixed in code** (`kubeconfig.rs:129`, `:174`). The gate stays shut on **M-11**.
- **Fuzz targets still owed (CLAUDE.md rule):** `fingerprint::{ssh_public_key, ssh_certificate,
  ssh_private_key, x509_pem}`, `otp::decode_seed`, `parse_account`, and `export_json` (QA
  decision 4).
- **Keyring HOLD (M1, R-T2-KR):** unchanged.
- **Review 2 and review 3 items:** open as scheduled. This range does not touch them.

## Rulings on open decisions

### `a1-exit-rust-core-forward-sftp.md`
1. **Capability change and `tauri-plugin-dialog`: conditionally approved**, superseded by B-4.
   - The plugin itself is approved: tauri org, MIT/Apache-2.0, one `tauri` 2.12.5 in the lock.
   - `tauri-plugin-fs` 2.7.1 is compiled in **but inert**:
     - it is never `.plugin()`-registered (grepped `src-tauri/src`);
     - no capability grants `fs:*` (only `main.json` exists);
     - the dialog's `window.try_fs_scope()` returns `None`.
   - The dialog also calls `Scopes::allow_file`/`allow_directory` on the asset-protocol scope.
     That is inert too, because the `tauri` features are `[]` (no `protocol-asset`) and
     `tauri.conf.json` has no `assetProtocol`.
   - **Conditions:**
     - Never register `tauri-plugin-fs`. Never enable `protocol-asset` without a review.
     - The B-4 capability test also asserts that there is no `fs:` permission.
   - `rfd` 0.17.2: GTK3 on Linux (already in the tree through wry), objc2 on macOS, Win32 on
     Windows. It has about 250 `unsafe` sites of platform FFI, which is the same class as
     wry/tao. Accepted.
2. **Trust in dialog paths: BLOCKER.** The Rust-side dialog is required (B-4). The mitigations
   in place (app-data-dir denial, one confined name) do not bound the base directory, and B-4
   explains why that is not an acceptable residual risk for A1.
3. **Audit names:** snake_case `forward_opened` / `sftp_transfer` **approved** (as in review 2,
   ruling (b)). A remote path in `sftp_transfer` is **not** added for A1, so the log stays free
   of server-chosen strings. If forensics needs it later, add it as a SHA-256 of the remote
   path.
4. **Shared `CARGO_TARGET_DIR`:** not a security matter. Per-worktree target dirs are
   recommended; the final gate must be a clean build.

### `a1-exit-rust-core-autolock-syslog.md`
1. **Blur grace:** 60 s, `onWindowHidden` default stays `true`, and the dialog is exempt (M-9).
2. **SD-ID:** request an IANA PEN, use `32473` meanwhile (N-12).
3. **Syslog host in the audit log:** **approved.** The host is inventory-class, and a
   redirected mirror must be visible in the chain (see L-17 for the ordering).

### `a1-exit-ui.md`
1. **`dialog:allow-save` unused:** drop it (N-10). It goes anyway with B-4.
2. **Facility as a keyword:** approved. `FacilityArg` accepts both; the stored form is the
   keyword (`0a7b802`).
3. **Remote-forward target host names:** Rust refuses them with `input.invalid`, so there is no
   implicit DNS. Approved.
4. **Audit `syslog_set`:** done, including disable (`AuditSyslogChanged`). See L-17 and L-18.
5. **Idle bounds 1–1440:** enforced in Rust (`src-tauri/src/commands/autolock.rs`, `MAX_IDLE_MINUTES`), and unknown fields are
   refused. Approved.

### `a1-exit-qa.md`
1. **`playwright` 1.63.0 as an exact devDependency: approved.** Dev only, never bundled, with
   lockfile integrity. Browsers are installed explicitly in CI.
2. **Workflow names:** not a security matter. The ownership table was updated in `0a7b802`.
3. **`socks::handshake` reachable from the fuzz crate: approved, with conditions.**
   - Expose it as `pub` only under a non-default cargo feature `fuzz-api`
     (`#[cfg(feature = "fuzz-api")] pub use socks::handshake as fuzz_socks_handshake;`).
   - Enable that feature from `fuzz/Cargo.toml` and the corpus-replay test only.
   - `mooring-app` must never enable it. Add a `cargo tree -e features -i mooring-proto-ssh`
     check in CI.
   - A bare `#[doc(hidden)] pub` is **not** approved: it puts the state machine into the stable
     API.
4. **`ExportDocument::from_json` for an `export_json` target: approved** under the same
   `fuzz-api` pattern in `mooring-vault`.
5. **QA-F1 fix (strip every trailing CR): approved, no trust impact.**
   - The key and marker fields are split on ASCII whitespace, and `\r` was already a separator.
     The CR-suffixed entry matched before the fix, and the probe test confirms it.
   - The fix changes only the bytes written back. The fuzz invariant is now exact equality, and
     the trust-decision equality across write + parse is asserted for four probes.
   - A T2 that can edit `known_hosts` can already add keys (accepted, as with OpenSSH).

## Checklist results

### 1. Capability, CSP and dependencies
- **Capability:** `core:default`, `dialog:allow-open` and `dialog:allow-save`, for the `main`
  window only. `dialog:allow-message` (`ask`/`confirm`/`message`) is **not** granted. B-4
  returns the capability to `core:default`.
- **CSP:** byte-identical. `withGlobalTauri: false`.
- **Dependencies:**

| Crate / package | Version | License | Reached from | Ruling |
| --- | --- | --- | --- | --- |
| `tauri-plugin-dialog` (+ `tauri-plugin` 2, `tauri-plugin-fs` 2.7.1, `rfd` 0.17.2) | 2.8.4 | MIT OR Apache-2.0 | mooring-app | Approved with the conditions above (fs inert). Rust-side use only after B-4 |
| `rustls` (`ring`, `std`, `tls12`, no default features) | 0.23.46 | Apache-2.0 / ISC / MIT | mooring-audit | **Approved** (ADR-0001 allow-list). `cargo tree -i aws-lc-rs` and `-i aws-lc-sys`: *did not match any packages*. Provider built explicitly (`builder_with_provider(ring)`), safe default protocol versions |
| `rustls-native-certs` (+ `openssl-probe` 0.2.2, `schannel` on Windows, `security-framework` on macOS) | 0.8.5 | Apache-2.0 / ISC / MIT | mooring-audit | **Approved.** `openssl-probe` is a path probe; its only `unsafe fn` (`try_init_openssl_env_vars`, `set_var`) is not called by `rustls-native-certs`. Not the banned `openssl`/`openssl-sys` |
| `rcgen` (`crypto`, `ring`, `pem`) | 0.14.10 | MIT OR Apache-2.0 | mooring-audit **dev only** | **Approved.** `cargo tree -i rcgen -e normal`: nothing |
| `sysinfo` in mooring-app | 0.40 (already in the tree) | MIT | mooring-app | Approved; `host_name()` only |
| `@tauri-apps/plugin-dialog` | 2.8.4 | MIT OR Apache-2.0 | apps/desktop | Approved for now; **to be removed** with B-4 |
| `playwright` / `playwright-core` | 1.63.0 (exact) | Apache-2.0 | apps/desktop dev | Approved |

### 2. SFTP
- **Local paths:** see B-4 and L-15.
- **`LocalPath`:**
  - Lexical checks plus the L-7 rules.
  - A canonical `starts_with(base)` check for both the source and the target parent.
  - Symlink and directory targets are refused.
  - Download goes to a `NamedTempFile` in the target directory, then `sync_all`, then `persist`.
    `rename` replaces the directory entry and never follows a symlink.
  - A cancelled download leaves nothing behind (tested; see N-15 for the flaky timing).
- **Audit and progress:**
  - `SftpTransfer { connection, transfer, direction, bytes, outcome }` carries no path and no
    contents.
  - `Progress.error` is `sftp_error(..).message`. These are fixed crate sentences
    (`sftp.rs:143-161`), and `NotFound` maps to the constant "remote path not found".
  - `LocalPath`'s `Debug` prints only the relative part.
  - No new `tracing` line in this range logs a path. All 14 added `tracing` calls were grepped.
- **Partial uploads:** a cancelled upload truncates the existing remote file (L-16).
- **Not vault-gated:** forwards and SFTP keep working while the vault is locked. This is
  consistent with ADR-0006, but see M-10.

### 3. Forwarding
- **Bind side:** for local and dynamic forwards, `local_addr` accepts only an IP literal or
  `localhost` (→ `127.0.0.1`); brackets are trimmed. The remote-forward target follows the same
  rule.
- **Exposure:**
  - Enforced in the crate: `is_loopback()` for local and dynamic binds, a host ∈ {`localhost`,
    `127.0.0.1`, `::1`} for remote binds.
  - IPv4-mapped `::ffff:127.0.0.1` is not treated as loopback, so it fails closed.
  - `external` is accepted only with the explicit `exposure` string. The UI confirmation is
    advisory (a T5 skips it), but every open is audited with `exposure`, and `external`
    also logs a warning.
- **Limits:** 64 forwards and 128 connections each (crate). The `forwardId` and `sessionId`
  lengths are capped.
- **Errors:** `forward.limit` uses a fixed text with the constant. `forward.bind` uses
  `"bind failed: {ErrorKind}"` or fixed protocol strings. No host, port or server text is
  echoed. `input.invalid` names only the field.
- Bidi characters in the target host: N-16.

### 4. Auto-lock
- **Activity hook:** one wrapper around `generate_handler!`, so every app command counts as
  activity. Plugin commands (`plugin:dialog|open`) bypass the app handler, so they are not
  activity, which is correct. The passive list misses `forward_list` (M-8).
- **Sleep detection:**
  - A wall-clock jump of more than 30 s beyond `Instant` (Linux/macOS, where `Instant` stops in
    suspend), or a tick that is more than 30 s late (Windows, where it does not).
  - Wall time running backwards is ignored, and a forward NTP or user jump locks. Both fail
    safe.
  - Suspended time is added to the idle clock. Tests cover all four cases.
  - Residual: a runtime stall of more than 30 s (for example a blocked worker) also locks.
    Accepted, because it fails safe.
- **Focus:** `BLUR_GRACE = 0` (M-9). Focus loss is evaluated on `spawn_blocking`, never on the
  event loop.
- **`vault:locked`:**
  - Emitted only after a successful lock.
  - The UI wipes the session, tree, credential, UI and transfer stores and shows the reason.
  - The orphaned Rust-side sessions, forwards and transfers are M-10.
  - Signals that arrive while the vault is locked are discarded, so a stale blur cannot lock
    right after an unlock.
- **Policy:** stored as plaintext `app.autolock`, validated on load (an invalid value falls
  back to the default), and changes are audited (`vault_policy_changed`). A T2 can turn
  auto-lock off at rest. That is inside T2's existing power (same user), so it is recorded in
  the threat model, not as a finding.

### 5. Syslog mirror
- **Formatting with hostile content:**
  - HOSTNAME and MSGID are reduced to PRINTUSASCII and capped at 255 and 32 bytes.
  - The SD element holds only `seq` (u64) and `hash` (hex), and `sd_escape` is applied anyway.
  - MSG is `serde_json`, which escapes CR, LF, NUL and every C0 character.
  - The 8 KiB cap is applied on a UTF-8 boundary and can never reach the SD element (the
    header is at most about 450 bytes).
  - Tests cover CR/LF/NUL/ESC, `]"\`, the bidi override, redaction and multi-byte truncation.
  - `redact` stops values at `"` and `}`, so the JSON stays well-formed.
  - U+2028/2029 and bidi controls pass through MSG unescaped. That is a collector-UI matter;
    see N-13 for marking.
- **TLS:**
  - rustls with the explicit ring provider and safe defaults (TLS 1.2 and 1.3), with
    `ServerName` taken from the configured host, so host-name verification is on (IP literals
    are verified against IP SANs).
  - System roots are loaded once, and an empty store is an error. There is no custom CA and no
    "accept invalid" switch.
  - Tests: an untrusted certificate is refused, and a name mismatch is refused.
- **Plaintext UDP and TCP:**
  - **Accepted as an explicit opt-in, so the UI warning is enough for A1.** The default is
    TLS/6514. Choosing UDP or TCP shows "Entries travel unencrypted …".
  - The data is inventory-class (R-INV): hosts, names, usernames and fingerprints. Secrets
    never enter audit events, and `redact` is defence in depth.
  - Condition: the warning stays visible while a plaintext transport is saved, not only while
    it is being edited. Recorded as R-SYSLOG.
- **Audit of `syslog_set`:** audited for enable, disable and change, with the host (L-17 for
  the order, L-18 for startup).
- **Queue:**
  - `sync_channel(1024)` + `try_send`. `send` never blocks the local write, which is fsynced
    first.
  - Connect failure → 2 s backoff, with drops counted.
  - `dropped` is a lower bound: a TCP write accepted by the kernel and then lost counts as
    `sent`. Documented here; no fix needed.
- **`syslog_test`:** `spawn_blocking`, 5 s connect and write timeouts. DNS uses the system
  resolver without our own timeout, but it runs off the UI thread. `syslog_set` does no network
  I/O on the main thread (`SyslogMirror::start` only spawns the thread).
- **Errors:**
  - `SyslogError` names the step, an `io::ErrorKind`, or rustls's error text (for example
    certificate-name mismatches). That text contains no secret and is shown verbatim, which is
    acceptable.
  - The host is validated as an IP or as LDH labels: URLs, ports, brackets and IDN are refused.

### 6. UI
- **Transfer store:** holds file names, the remote dir, ids and byte counts. It holds no local
  path and no contents, and it is wiped on lock. The SFTP panel keeps the picked full local
  path in component memory until it is used. This goes away with B-4 (`pickId` + name only).
- **`Modal` portal to `document.body`:** no security change. `aria-modal`, the focus trap and
  Escape behave as before. It renders only React children, with no `innerHTML` anywhere
  (grepped).
- **Unknown error codes:** the raw message is shown. Rust messages are fixed and path-free
  (`IpcError` mapping, section 3), and React renders them as text. Drift: N-14.
- **No drag-and-drop:** good. A drop would hand the WebView an unpicked path.

### 7. QA
- **Fuzz targets:**
  - The five targets each assert more than "no panic":
    - `known_hosts`: exact byte fixed point, plus trust-decision equality.
    - `vault_header`: round trip.
    - `import_age`: caps, plus the re-accepted header.
    - `socks5`: request length, port, printable host, idempotent re-encode.
    - `kubeconfig`: caps only (M-11).
  - The nightly job is least-privilege: `contents: read`, `persist-credentials: false`,
    SHA-pinned.
  - Corpora hold only fake hosts and public vectors.
- **Thin coverage:** `import_age` (scrypt-bound) → the `export_json` target (ruling 4).
  `socks5` covers the parser only → `fuzz-api` (ruling 3).
- **E2E:** runs against the mock transport, so it does not exercise the Rust trust boundary.
  Acceptable for A1. A2 needs `tauri-driver` for the native flows (dialog, focus, lock).

## Conditions for merge (A1 exit)
1. **B-4 fixed with its tests**, together with the ADR-0010 amendment and the capability
   reverted to `core:default`. Re-review only that diff.
2. M-8, M-9 and M-10 land with B-4 or before the A1 tag. M-11 before any Kubernetes consumer.
3. L-15..L-18 and N-10..N-16 as scheduled. L-15 and L-16 before the first public release.
4. `security.yml` green: cargo-deny (the new crates are all on the license allow-list),
   cargo-audit, gitleaks and semgrep. `mooring-app` built on macOS, Windows and Linux.

## Test evidence
```
Linux x86_64, 2026-11-04, CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=target-int, --offline
cargo test -p mooring-audit -p mooring-proto-ssh -p mooring-store          all ok (0 failed)
cargo test -p mooring-app   run 1: lib 95 passed, 1 FAILED
                              (sftp_transfers_tests.rs:200 "no partial file", N-15)
                            runs 2, 3: lib 96 passed; e2e_flow 13 passed
                            the failing test alone: 3/3 passed
cargo tree -i aws-lc-rs / -i aws-lc-sys --workspace        "did not match any packages"
cargo tree -i rustls        rustls 0.23.46 <- mooring-audit only
cargo tree -i tauri-plugin-fs                              <- tauri-plugin-dialog only
cargo tree -i rcgen -e normal                              nothing (dev only)
grep tauri_plugin_fs src-tauri/src                         no registration
tauri-plugin-dialog 2.8.4 src/commands.rs:120-258          scope grants read (fs scope None; asset scope inert)
apps/desktop: grep confirm(/alert(/innerHTML               none outside tests
```
Not run: cargo-deny, cargo-audit, gitleaks, semgrep, pnpm audit, the vitest and E2E suites
(the UI handoff reports them green), and the macOS and Windows builds.
