# A1 · qa-engineer · pass 2 (SSH, Tauri command layer, UI v2, exit audit)

Branch `worktree-agent-a3940a29ffd3bd61b`, on top of `2003ec8` (main). Not merged.
Linux host, cargo 1.97.0, Linux WebView toolchain installed (`mooring-app` compiles and its
tests run here), `age` 1.1.1. Not installed here: cargo-deny, cargo-audit, gitleaks,
cargo-fuzz / nightly, tauri-driver.

## Done

| File | What |
| --- | --- |
| `src-tauri/tests/e2e_flow.rs` | A1 item 6 flow through the command plain functions. Covers vault create → folder → password credential set as the folder default → SSH connection that inherits it → `connection_search` → `session_open` against the in-process russh server → TOFU prompt answered `yes` → `connected` → `uname -a\n` sent as base64 and echoed back → `session_close` → `closed` event and empty registry → `session_send` returns `session.not_found` → `vault_lock` → **all 20 vault-gated commands return `vault.locked`**; `vault_change_password` with a wrong current password returns `vault.unlock` and the vault stays locked → wrong password stays locked → unlock → data back, audit chain verifies, the 7 expected events are present, and no secret appears in the log. Second test: a live session survives `vault_lock` (ADR-0006): send and close still work, and a new `session_open` returns `vault.locked`. |
| `src-tauri/tests/e2e_flow/hostile.rs` | Hostile IPC input. Every string argument of every command plain function (folder, connection and credential CRUD, search, copy, lock reason, unlock, change password, session ids) gets: a 23-entry corpus and 60 seeded random strings. The corpus includes empty and blank strings, NUL, ANSI escapes, bidi override, zero-width characters, path traversal, SQL and FTS5 syntax, format strings, `-oProxyCommand`, near-UUIDs, the nil UUID, 130 crabs, 121, 2049, 64 KiB+1 and 1 MiB strings, and 500 combining marks. The random strings use a xorshift generator over a hostile alphabet. Each call is checked for: no panic, a code from the documented set, `message` ≤ 256 bytes, and `message` never echoing the input. Afterwards no mutex is poisoned, the audit chain still verifies, and every stored name is free of control characters and within 120 characters. Replay a failure with `MOORING_HOSTILE_SEED` and `MOORING_HOSTILE_ROUNDS`. |
| `src-tauri/tests/e2e_flow/hostile_edges.rs` | Ports 0, 65536 and `u32::MAX`. 51 tags and 1 M tags. Search limits 0 to `u32::MAX` are clamped. `audit_tail` limits and `before` values 0 and `u64::MAX`. Sizes 0, 16385 and `u32::MAX` for both open and resize. Wire shapes serde must refuse: negative numbers, `1e20`, `buttons: 256`, unknown fields, wrong case, arrays and null. Twelve base64 garbage cases, including bad padding, the URL-safe alphabet, an inner space, a trailing newline, one block over the cap and 10 MiB, plus 2000 random ASCII strings. The 64 KiB boundary and empty input are accepted. Vault inputs: 1025-byte password, weak password, missing vault, existing vault, a hostile lock reason that is not echoed into the audit log, and NUL plus bidi in a password. On a live session: pointer and key input, answers with no open prompt, and bad base64 return `input.invalid`, while raw control bytes are forwarded and the session keeps working. **One `#[ignore]`d bug test (A1-QA-4).** |
| `src-tauri/tests/e2e_flow/support.rs` | Event sink, `read_until`, a registry wait, and `vault_gated_codes`, which calls each gated command with valid arguments. |
| `Makefile` | `make e2e-ipc` (`cargo test -p mooring-app --test e2e_flow`). |

**How the test reaches the commands.** `mooring_app_lib` exports only `run()`; every module
is private. The test crate compiles the app modules in with `#[path = "../src/…"]`, so no
`src-tauri/src` file changed. Side effect: the 41 inline unit tests run a second time inside
`e2e_flow`, which adds about 3 s. A rust-core follow-up should expose the command layer (for
example `pub mod commands` behind a `test-api` feature) and then delete the shim.

`.gitleaks.toml`, `ci.yml` and `test-vectors.yml` are unchanged. `ci.yml` already runs
`cargo test --workspace` with the WebView toolchain on all 3 OSes, so it picks up `e2e_flow`
on its own and needs no new step. A1-QA-3 is fixed on main: all four workflows parse.

## Exit criteria (docs/prompts/A1.md)

| # | Item | Result | Evidence / gap |
| --- | --- | --- | --- |
| 1 | **Vault** | **PARTIAL** | |
| 1a | create / unlock / lock / change password | PASS | `commands::vault::tests::*`, `e2e_flow::create_vault_…` |
| 1b | auto-lock (idle, screen lock, sleep) | PARTIAL | Pure policy is tested (`autolock_table`). There is no idle timer or OS-signal wiring in src-tauri (rust-core tauri handoff, Left open); `vault_lock` only records the reason the UI sends |
| 1c | keyring "Touch ID / Windows Hello" opt-in | FAIL (not wired) | Library and mock are tested. The IPC commands are held (M1), no biometric ACL exists, and real OS keyrings have never run |
| 1d | `mooring vault export --age` | PARTIAL | Library round trip PASS; no CLI binary, no IPC command (held, N3) |
| 1e | vectors verifiable with `age` CLI | PASS | `make test-vectors` → `OK: header + 6 sealed vectors verified with the age CLI; tamper rejected` |
| 1f | Argon2 calibration ≈ 500 ms, params in header | PASS | `KdfChoice::Calibrate` used by create/change password; `calibration_props`; B2 ceiling fixed (`77342e2`) |
| 2 | **Data model** | **PASS** | folders, connections, tags, 3 credential kinds, inheritance + override, FTS, SQLite bundled, sealed columns, migrations: store suites (46 tests) + `commands::tree::*`, e2e inheritance |
| 3 | **SSH session** | **PARTIAL** | |
| 3a | russh, TOFU + known_hosts, hashed writes, mismatch hard stop | PASS | `proto-ssh/tests/trust.rs` (5), `commands::sessions::tests::host_key_mismatch…`, e2e TOFU |
| 3b | publickey, keyboard-interactive, agent, password | PASS (agent: unit only) | `tests/auth.rs` (9). The agent path has no integration test because CI has no agent socket |
| 3c | weak algorithms disabled | PASS | `algos::tests::no_forbidden_algorithm_is_offered`, `adr_algorithms_are_all_offered` |
| 3d | port forwarding L/R/D | PARTIAL | Crate level PASS (`tests/forward.rs`, 8). **No Tauri command exposes it**, and there is no UI for it |
| 3e | SFTP panel (browse, up/down with progress, drag-drop) | PARTIAL | Crate level PASS (`tests/sftp.rs`, 7). **No Tauri command and no panel** |
| 3f | xterm.js + WebGL, streaming over Tauri channels | PASS (Linux, no display) | `xterm.ts` loads `WebglAddon` with a DOM fallback. Channel streaming is covered by `e2e_flow` and the session tests. WebGL rendering was never run on a real GPU |
| 4 | **UI** | **PARTIAL** | three-pane, command palette, inspector with credential reference, copy-password with 30 s clear + audit, dark/light: Vitest 41 + Rust `credentials::tests::copy_*`. **Detach-to-window is deferred to A2** (`window_detach` → `ipc.unknown`, ADR-0008). Real clipboard never exercised on a display |
| 5 | **Audit viewer; syslog mirror to a syslog server** | **PARTIAL** | Viewer + `audit_tail` / `audit_verify` PASS. **The syslog mirror does not exist**: there is no code and no setting |
| 6 | **Tests** | **PARTIAL** | |
| 6a | proptest vault round trip + tamper | PASS | `proptest_round_trip.rs`, store and core proptests |
| 6b | cargo-fuzz: vault header, SSH packets, 1 h nightly | FAIL | No `fuzz/` directory or targets and no nightly job. Proptest stand-ins only (`known_hosts`, `socks`, `export`). The nightly toolchain is not available here |
| 6c | Vitest for stores | PASS | `stores/{credentials,ui,sessions,tree}.test.ts` + `lib/ipc.test.ts` |
| 6d | Playwright E2E via tauri-driver to `<lab-host>` | PARTIAL | The same flow runs at IPC level against a loopback server (`e2e_flow`, PASS). The real Playwright + tauri-driver run is a TODO: there is no `tests/e2e` scaffold to update (`make e2e` points at a missing path). Selectors for it are below. The lab leg (`proto-ssh/tests/lab.rs`, `MOORING_LAB_HOST`) has never been run |
| X | All green on 3 OSes | UNKNOWN | Linux green (below). `ci.yml` now parses, but no 3-OS CI run has been observed |
| X | `docs/security/a1-review.md` sign-off | PARTIAL | `APPROVE WITH NITS` covers **items 1–2 only**. SSH, Tauri commands, `arboard` and the `age` git pin have not been reviewed |
| X | threat model updated | FAIL | `threat-model.md` "Last change: A1 items 1–2"; SSH/IPC/clipboard not reflected |
| X | handoff notes | PASS | all roles have A1 notes |

**Overall: A1 exit is not met.** The blocking gaps are: fuzz targets (6b), forwarding and
SFTP not exposed (3d/3e), the syslog mirror (5), auto-lock wiring (1b), keyring (1c), the
Playwright run (6d), and the security review plus threat model for items 3–5.

## Bugs found

- **A1-QA-4 (security, mooring-core validators).** `validate_name`, `validate_host` and
  `validate_tag` reject only `char::is_control` (category Cc). Bidi controls and zero-width
  format characters (category Cf: U+202E, U+2066–2069, U+200B, U+FEFF) are accepted, stored,
  and rendered in the tree, the palette and tab titles. A shared or imported tree can show a
  name or host that reads differently from what it is (the Trojan Source class,
  CVE-2021-42574). Test:
  `src-tauri/tests/e2e_flow/hostile_edges.rs::bidi_and_invisible_format_characters_are_refused`,
  `#[ignore]`d. With `--ignored` it fails at the first folder-name assertion. Fix: refuse the bidi
  controls (U+061C, U+200E/F, U+202A–202E, U+2066–2069) and the zero-width characters
  (U+200B–200D, U+FEFF) in all three validators, then remove the `#[ignore]`. The fix should also
  decide whether the UI shows existing rows with escapes.
- No panics, unknown error codes, echoed values, poisoned locks or audit-chain breaks turned up
  across about 3 000 hostile calls.

Observations (not bugs, for the record):
- Tauri reports serde failures (wrong types, negative numbers, unknown `kind`) as a plain
  string, not an `IpcError`. `ipc.ts` maps them to `ipc.unknown`, which is acceptable, but the
  ADR-0008 promise that every failure is `IpcError { code, message }` does not hold for
  malformed shapes.
- `session_list` is not vault-gated. It returns session ids, connection ids and states while the
  vault is locked. This is consistent with "sessions survive lock", but security-reviewer
  should confirm it.
- An empty `Bytes` input is accepted and forwarded as a zero-length write.

## Cross-crate notes

- **Forwarding and SFTP are not reachable from IPC.** `SshSession::forward_*` and `sftp()` exist
  and are tested at crate level. There are no Tauri commands, no ADR-0008 entries and no UI, so
  no IPC-level test is possible yet. ADR-0008 needs an amendment (ssh-b handoff, Decision 1)
  before rust-core can wire them.
- **`age` git pin and cargo-deny.** `deny.toml` `[sources]` sets `unknown-git = "deny"` with
  `allow-git = ["https://github.com/str4d/rage"]`, which matches `Cargo.lock`
  (`git+https://github.com/str4d/rage?rev=b5b68c4#b5b68c4f…`, used by 2 packages). By reading the
  config, the pin is allowed. **cargo-deny is not installed here, so I could not run it.**
  `cargo deny check` (in `make audit` and `security.yml`) must confirm it, and it must also check
  that the git crates' licences resolve, since `age`/`age-core` are MIT OR Apache-2.0.

## Playwright / tauri-driver TODO (selectors from UI v2)

There is no `tests/e2e` directory, and `make e2e` targets a path that does not exist. When a
WebView driver is available (Linux `webkit2gtk-driver`, Windows `msedgedriver`; macOS has no
tauri-driver), the scenario should be, with v2 accessible names:
1. `getByLabel("Master password")`, `getByLabel("Repeat password")`, then button `"Create vault"`.
2. Palette (`role=combobox`), then option `"New folder"`, then the dialog `"New folder in All connections"` with `getByLabel("Name")`, then submit.
3. Button `"New connection"`, then the dialog `"New connection"` with `Name`, `Host`, `Port`, then the credential via the dialog `"Credentials"`, `"New credential"`, `Username`, `Password` and `"Create credential"`, then `"Create connection"`.
4. Open the `treeitem` and the `tab` named after the connection. On the TOFU prompt choose `"Trust and connect"`.
5. Type `uname -a⏎` into the xterm. Assert `Linux` in `role=tabpanel`. Lab only: `<lab-host>`, read-only, `.env` account.
6. Button `"Lock"`, then the `"Unlock"` gate is visible.

## Must run on macOS / Windows

1. `make app-check` and `make e2e-ipc`. The in-process server binds loopback only. Watch the
   Windows firewall prompt and macOS socket timing in the 20 s event timeouts.
2. Real clipboard: copy a password, paste it, check it is gone after 30 s and absent from
   clipboard history (Win+V, macOS clipboard managers).
3. Keyring and Touch ID / Windows Hello once wired. Calibration on Apple Silicon (pass 1, item 3).
4. ssh-agent auth against a real agent (macOS launchd agent, Windows OpenSSH agent pipe).
5. `cargo deny check`, `cargo audit`, `gitleaks detect --no-banner --redact` (any OS that has them).
6. Lab: `MOORING_LAB_HOST=<lab-host> … cargo test -p mooring-proto-ssh --test lab -- --ignored` (read-only).

## Decision needed

- rust-core: expose the command layer to integration tests (feature-gated) so the `#[path]`
  shim can be removed.
- orchestrator / architect: ADR-0008 amendment for forwarding and SFTP commands, then QA
  extends `e2e_flow`.
- security-reviewer: A1-QA-4 fix scope; whether `session_list` should be gated; the review of
  items 3–5 and the threat model update.

## Test evidence (2026-11-03, this worktree)

Baseline before my changes (main `2003ec8`): the same gate was green, with 261 Rust tests passed
and 3 ignored, and 41 Vitest tests.

```
cargo fmt --all -- --check                                   → clean
cargo clippy --workspace --all-targets -- -D warnings        → clean
cargo test --workspace                                       → 309 passed, 0 failed, 4 ignored
  new: e2e_flow 48 passed + 1 ignored (A1-QA-4), of which 7 are new tests and
       41 the shimmed inline unit tests; 3 consecutive runs green, ~25 s each
  ignored: vault 2 (on purpose), proto-ssh lab 1, A1-QA-4 1
cargo test -p mooring-app --test e2e_flow -- --ignored        → FAILED (A1-QA-4, expected)
pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm test && pnpm build
                                                             → ok; vitest 9 files, 41 tests
make test-vectors → OK: header + 6 sealed vectors verified with the age CLI; tamper rejected
YAML parse of .github/workflows/*.yml                         → ci, release, security, test-vectors OK
Not run (not installed): cargo-deny, cargo-audit, gitleaks, cargo-fuzz, tauri-driver
```
