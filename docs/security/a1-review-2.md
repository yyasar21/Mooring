# A1 security review 2 — SSH, forwarding, SFTP, Tauri commands, UI v1/v2, rename

Reviewer: security-reviewer · 2026-11-03 · Range `git diff 1e76c3a..2003ec8 -- crates src-tauri
apps packages Cargo.toml deny.toml` (plus `Cargo.lock`, `pnpm-lock.yaml`).

Inputs: ADR-0003, ADR-0004, ADR-0007, ADR-0008, the handoffs `a1-rust-core-ssh.md`,
`a1-rust-core-ssh-b.md`, `a1-rust-core-tauri.md`, `a1-ui-engineer.md`, `a1-ui-engineer-v2.md`,
and the previous review [a1-review.md](a1-review.md).

`mooring-app` **was compiled and tested** here (Linux; WebView toolchain present). There was no
display, so the clipboard was exercised through `MemoryClipboard` only.

## Verdict: `APPROVE WITH NITS`

No blocker. The trust boundary holds:
- Every new command validates its input and caps sizes.
- Errors map to `IpcError` without secrets or internals.
- No command returns a secret.
- Capabilities are still `core:default` only, and the CSP is byte-identical to A0.

The SSH core follows ADR-0007: TOFU with a hard stop on a changed key, the ADR algorithm set only,
generic authentication failure, and sanitised prompts.

There are four Medium findings:
- M-1 and M-4 are reachable today. Both must be fixed **before A1 exit**.
- M-2 and M-3 are in `mooring-proto-ssh` APIs that IPC does not expose yet. They are
  **wiring gates**, the same pattern as B1/B2 in the first review.

**Wiring gates (hard):**
- No forwarding IPC command until **M-2** is fixed and tested.
- No SFTP IPC command until **M-3** and **L-9** are fixed and tested.
- Keyring commands stay on **HOLD** (M1, R-T2-KR), unchanged.

## Findings

| ID | Sev | Where | Finding | Exact fix |
| --- | --- | --- | --- | --- |
| **M-1** | Medium | `src-tauri/src/commands/credentials.rs:177-184`, `src-tauri/src/state.rs:240` (`shutdown`), `src-tauri/src/commands/vault.rs:106` (`lock`) | The 30 s clear runs only in a spawned Tokio task. If the app exits before it fires (quit, crash, `RunEvent::Exit` → runtime gone), the password **stays on the clipboard indefinitely** on Windows and macOS. On X11 it stays too whenever a manager ignores the history hint. Locking the vault does not clear it either. Both break the "clears in 30 s" promise the UI shows. | Keep the pending digest in `AppState` (`Mutex<Option<ValueDigest>>`, set by `copy_password`, taken by the timer). In `AppState::shutdown()` and in `vault::lock()`, call `clipboard::clear_if_unchanged` synchronously with it. Tests (MemoryClipboard): copy → `lock()` → clipboard empty; copy → `shutdown()` → clipboard empty; copy → user copies something else → `lock()` leaves it alone. |
| **M-2** | Medium (latent) | `crates/mooring-proto-ssh/src/forward.rs:278-291` (`forward_local`), `:317-323` (`forward_remote`) | Only `forward_dynamic` refuses non-loopback binds. `forward_local` binds any `SocketAddr`, so `0.0.0.0:8080` exposes the tunnel to the LAN with no opt-in (OpenSSH's client default is loopback). `forward_remote` passes `0.0.0.0` / `*` / `::` to the server (decision 2 in the ssh-b handoff). Once IPC exposes these, a T5 WebView could open a LAN-reachable tunnel into the lab. | Replace the `allow_external: bool` with `pub enum Exposure { Loopback, External }` on **all three** forward kinds. With `Loopback`: `forward_local`/`forward_dynamic` require `bind.ip().is_loopback()`; `forward_remote` requires the bind host ∈ {`localhost`, `127.0.0.1`, `::1`}. Return `Invalid { field: "bind" }` otherwise. The IPC layer defaults to `Loopback`, and `External` must be audited (`session.forward.open` gains `exposure`). Tests: a non-loopback local bind is refused, `0.0.0.0` remote bind is refused, and both are allowed with `External`. |
| **M-3** | Medium (latent) | `crates/mooring-proto-ssh/src/sftp.rs:211-224`, `src/sftp_transfer.rs:243` (`read_block`), `:405` (`write_block`) | `limits@openssh.com` from the **server** can set `max_read_len`/`max_write_len` to 1. That gives `read_chunk = write_chunk = 1`. Each 256 KiB block then spawns `TRANSFER_BLOCK.div_ceil(1)` = **262 144** Tokio tasks and in-flight SFTP requests, each holding a request, a reply slot and (writes) a `Vec`. A hostile server (T4) turns one transfer into hundreds of MB and a CPU spike. | Bound the in-flight requests, not just the block. Set `const MAX_IN_FLIGHT: usize = 8` and make the per-call block `min(TRANSFER_BLOCK, MAX_IN_FLIGHT * chunk)` in both `read_block` and `write_block` (the loops already advance by the bytes actually moved). Optionally refuse `limits` below 1 KiB as `Protocol("server limit exceeded")`. Test: an SFTP test server that advertises `max_read_len = 1` and `max_write_len = 1`, then assert that a 4 KiB up/download completes and that no more than 8 requests are outstanding (count in the test server). |
| **M-4** | Medium | `apps/desktop/src/components/terminal/xterm.ts:23-31` | xterm 6 parses OSC 8 hyperlinks from **remote terminal output** (T4). With no `linkHandler`, it uses its built-in activation: `confirm("Do you want to navigate to …")` then `window.open()` + `location.href = url` for any http(s) URL. A server can thus get a remote page opened from inside the app's WebView. That contradicts ADR-0003 ("remote web content … in a window with its own label", A2). The popup gets no IPC (no capability matches it), but it is an in-app phishing surface. | Pass `linkHandler: { activate: () => {}, allowNonHttpProtocols: false }` to `new Terminal({...})`. That is a no-op until A2 adds an audited Rust `open_url` that uses the system browser. In `src-tauri`, add a navigation guard to the main webview that denies any URL that is not the app origin, via an inline `tauri::plugin::Builder::on_navigation` (and deny new windows where the Tauri API exposes it). Tests: a vitest that `createTerminal` passes a `linkHandler`, and a Rust unit test of the navigation predicate (`tauri://localhost`/`http://tauri.localhost` allowed, `https://example.com` denied). |
| L-1 | Low | `crates/mooring-proto-ssh/src/handler.rs:120-164` | `ClientHandler` keeps russh 0.65's defaults for server-opened `session`, `x11`, `auth-agent@openssh.com`, `direct-tcpip`, `direct-streamlocal` and `forwarded-streamlocal` channels, and **every one of those defaults is `reply.accept()`**. We never request X11 or agent forwarding, so nothing is connected to them and no local resource leaks. But a hostile server can open an unbounded number of accepted channels (memory/CPU DoS), and a future change that keeps a channel would silently expose something. | Override the six handler methods to `reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await` (as `accept_forwarded` does for unknown routes). Test: in-process server opens an `x11` and an agent channel → open fails. |
| L-2 | Low | `apps/desktop/src/components/terminal/PromptModal.tsx:14` | The UI decides "host-key trust dialog" by running `/trust\|authenticity\|fingerprint/i` over `prompt.message`. A keyboard-interactive prompt is server-controlled (name + instructions + prompt). The server can therefore render the official "Verify host identity / Trusting records it in the audit log" dialog. No secret flows (the answer is `yes`/`no`), but it is UI spoofing on a trust surface. | Add `purpose: "host_key" \| "auth"` to `SessionEvent::Prompt` in `mooring-core` (an ADR-0008 amendment) and set it in `handler.rs:83` / `auth.rs:233`. The UI switches on `purpose`, never on message text. Test: an auth prompt containing "trust" renders the text field, not the trust buttons. |
| L-3 | Low | `src-tauri/src/commands/vault.rs:158-189` | `vault_create`/`unlock`/`change_password` are `async` commands, but they run Argon2id (calibrated, up to 1 GiB, about 1 s) inline on a Tokio worker **while holding the `std::sync::Mutex` vault guard**. Every command that needs the vault (`session_open`, `credential_copy_password`, the tree) blocks behind it. Availability only. | Move the KDF work into `tokio::task::spawn_blocking` (clone what is needed and re-lock to commit), or at least wrap the body of each async wrapper in `spawn_blocking`. |
| L-4 | Low | `src-tauri/src/commands/audit.rs:71-85`, `apps/desktop/src/components/Telemetry.tsx:8` | `audit_verify` is a **sync** command, so it runs on the main thread. It re-hashes the whole chain while holding the audit mutex, and the UI calls it every 60 s and on every view change. With a large log, this stalls the UI and blocks every `record_audit` (session tasks block a worker on the std mutex). | Make it `async` + `spawn_blocking`. Cache `(file len, last seq, result)` in `AppState` and verify only the appended tail when the file grew (the chain allows that). Keep the 60 s poll, or raise it to 5 min with on-demand verify in the audit view. |
| L-5 | Low | `crates/mooring-proto-ssh/src/handler.rs:98-104` | Concurrent TOFU accepts (two new hosts at once) each do load → add → save. Last writer wins, so one entry is lost. This fails closed (that host is prompted again next time), but the audit log says "accepted" for a key that is not stored. | Serialise `known_hosts` read-modify-write with a process-wide `tokio::sync::Mutex` (static `OnceLock`) around the `spawn_blocking` closure. |
| L-6 | Low | `src-tauri/src/sessions.rs:207-209` | `trust_decision` for a mismatch records only the presented fingerprint. ADR-0007 asks for `trust.host_key.mismatch` with both, and the expected one is what an investigator needs. | Add `expected` to the audit details (a new optional field on `AuditEvent::TrustDecision`, or a dedicated variant with the audit-vocabulary change, ruling (b) below). |
| L-7 | Low (latent) | `crates/mooring-proto-ssh/src/local_path.rs:40-49` | On Windows, `Component::Normal("file.txt:stream")` passes the lexical check and writes an **alternate data stream**. Reserved device names (`CON`, `NUL`, `COM1`, …) also pass. Once IPC passes the relative path from the WebView (T5), this is a confinement gap. | `#[cfg(windows)]`: reject any component containing `:` and any whose stem (case-insensitive, before the first `.`) is a reserved DOS device name. Unit tests are `cfg(windows)`. Gate: with M-3, before SFTP IPC. |
| N-1 | Nit | `src-tauri/src/commands/sessions.rs:153-158`, `src-tauri/src/commands/credentials.rs:172-175` | `String::from_utf8(bytes.to_vec())` makes a second, non-zeroized copy of the secret. On the error path (`FromUtf8Error`), that copy is freed without wiping. | `let v = std::mem::take(&mut *bytes); String::from_utf8(v).map_err(\|e\| { drop(Zeroizing::new(e.into_bytes())); IpcError::… })`. |
| N-2 | Nit | `src-tauri/src/commands/sessions.rs:210` vs `src-tauri/src/sessions.rs:191-194` | The `MAX_SESSIONS` check and the registry insert are not atomic: concurrent `session_open` calls can exceed 64. | Re-check `len()` under the lock in `sessions::spawn` and refuse there (closing the fresh `SshSession`). |
| N-3 | Nit | `crates/mooring-proto-ssh/src/handler.rs:106-114` | When the `known_hosts` write fails, `HostKeyAdded` is still pushed and audited as "accepted", which is indistinguishable from a stored key (see ruling D4). | Add `stored: bool` to `TrustEvent::HostKeyAdded` and record `decision: "accepted_session_only"` when it is false. |
| N-4 | Nit | `Cargo.toml:100` | The `age` patch pins `rev = "b5b68c4"` (short). `Cargo.lock` records the full hash, so builds are reproducible, but the manifest is the reviewed artefact. | Use the full 40-char SHA `b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f`. |

### Carried forward from review 1 (still open)
- **N5** (`crates/mooring-vault/src/vault.rs:155-156`): still maps every `derive_kek` error to
  `Unlock`. This is unchanged in this range.
- **N6** (`crates/mooring-store/src/lib.rs:83-85`, `:147`): there is still a double checkpoint
  on `close()` + `Drop`. `AppState::shutdown` now calls `close()`, so this runs on every exit.
- **M1** / keyring HOLD (R-T2-KR).
- Fuzz targets owed: `known_hosts_parse` (`KnownHosts::parse_bytes`), `socks_parse_request`
  (`socks::parse_request`), `Header::from_bytes`, `import_age`. Only proptest stand-ins exist.
- **L2** (durable header write): **Fixed.** See the checklist below.

## Rulings on open decisions

### `a1-rust-core-ssh.md`
1. **age ↔ russh conflict:** option (a), approved by the owner. Accepted as **R-AGE-PIN**, see
   below. I checked the pin against the cargo git database:
   - `b5b68c4f…` is the "Merge pull request #634 (release-0.12.1)" commit, dated 2026-07-14.
   - It is reachable from `origin/main` of `str4d/rage`, and it contains `f7c95f4` ("Migrate to
     latest Rust Crypto crate stack").
   - `Cargo.lock` resolves a single `ml-kem 0.3.4`.
   - `deny.toml` allows exactly that one git source.
2. **Algorithm deviations:** **approved.**
   - `mlkem768x25519-sha256` first: the ADR anticipates PQ hybrids.
   - `ext-info-c` and `kex-strict-c-v00@openssh.com`: these are required (`server-sig-algs`, Terrapin).
   - Compression `none` only, no GEX, no certificate algorithms.
   - `algos.rs` tests assert both the deny-list and the full ADR list.
   - Missing `sntrup761x25519-sha512` is acceptable.
3. **russh plain-`String` secrets:** **accepted** as **R-SSH-STR**. Conditions:
   - Our copies stay `SecretString` / `Zeroizing`. This is verified at `auth.rs:125`, `:228-243`.
   - No other API that takes a plain `String` secret is added.
   - On every russh upgrade, rust-core checks whether a `SecretString`/`Zeroizing` API exists and
     switches to it. Track it upstream; do not fork.
4. **TOFU store failure:** **accept** "trusted for this session only". Failing closed would
   lock users out on a full disk. The file is still not rewritten when over the caps. Condition:
   N-3 (make it visible in the audit log).
5. **`@cert-authority` ignored, certificate host keys refused:** **approved**. This fails closed
   (`handler.rs:127-130`). Host-CA trust needs its own ADR addendum and review.

### `a1-rust-core-ssh-b.md`
1. **`forward_dynamic` API shape:** use an `Exposure` enum applied to all three kinds (M-2), not a
   bare `bool` on one of them.
2. **Remote-forward bind policy:** **yes**. Refuse non-loopback remote binds unless
   `Exposure::External`, which is audited (M-2).
3. **russh-sftp limitations:** **accepted**, with M-3:
   - Using `RawSftpSession` with our own listing cap is the right call.
   - The upstream per-reply allocation up to `max_packet_len` (256 KiB) is accepted. With M-3, at
     most 8 replies are in flight, so about 2 MiB transient.
   - The 10 s upstream request timeout is accepted. A stalled server costs 10 s per request,
     never a hang.
   - `russh-sftp` logging through `log` is accepted, because client paths do not log server
     strings. `tracing-log` is not installed, so they are dropped anyway.
   - Server error text is never surfaced (`sftp.rs:138-156`, tested).

### `a1-rust-core-tauri.md`
1. **Dependencies `arboard 3.7` and `base64 0.22`:** **approved**. See the dependency section.
2. **Audit vocabulary:** keep the existing `AuditEvent` variants for A1. When forwarding is
   wired over IPC, add `ForwardOpened/Closed` (with `exposure`, M-2) and the `expected`
   fingerprint (L-6) in one change. Until then, `2003ec8` tracing forward events is acceptable,
   because nothing can open a forward. Failed authentication is already visible as
   `session_closed { reason: "authentication failed" }`, which is sufficient.
3. **Unlock gating for every tree, credential, session and audit command:** **approved and
   required**. The tree and audit log reveal inventory (R-INV), so the lock must hide them.
4. **ssh-agent on in production:** **approved** (ADR-0007 default). Residual risk: when no
   credential resolves, the agent's public keys (up to 16) are offered to the server, which can
   link identities across hosts, as with OpenSSH. Agent *forwarding* is never requested (L-1
   rejects it even if a server tries).

## Checklist results

### 1. Trust boundary (ADR-0003, ADR-0008)
- **30 commands** are registered (`src-tauri/src/lib.rs:40-71`). Each wrapper is thin over a
  plain function, and every function validates its input:
  - ids: length ≤ `MAX_ID_LEN`, then parsed as UUIDs;
  - names, hosts and tags go through the `mooring-core` validators;
  - query ≤ 1 KiB, limit clamped;
  - secrets ≤ 64 KiB and non-empty;
  - password ≤ 1024 B;
  - lock `reason` ≤ 32;
  - size 1..=16384;
  - `Bytes` ≤ 64 KiB, with the base64 length checked **before** decode (`sessions.rs:103`);
  - `Answer` ≤ 4 KiB;
  - `sessionId` ≤ 64;
  - `audit_tail` limit ≤ 500.
- `IpcError` mapping (`error.rs`):
  - Store and SQL internals become `store.io` with a fixed message.
  - `NotFound` never echoes ids (tested).
  - `VaultError` messages are fixed strings.
  - `MooringError::Protocol`/`Transport` reasons come from the protocol crate, are built from
    fixed text plus `io::ErrorKind`, and contain no secret.
- **No secret outward:**
  - `CredentialDto` has no secret field. `round_trip_metadata_only` asserts the JSON contains
    no secret.
  - `WireEvent` carries no secret.
  - `WireInput` has `deny_unknown_fields`, a redacted `Debug`, and wraps `Answer.text` into
    `SecretString` at deserialisation.
- **base64:** STANDARD engine both ways, decode errors give `input.invalid`, and the UI
  `base64ToBytes` only decodes strings produced by Rust.
- **Channel lifecycle** (`sessions.rs`):
  - One task per session.
  - A sink failure (UI gone) closes the session.
  - `Closed` is always last.
  - The registry entry is removed on every exit path, and queued commands are answered.
  - `session_closed` is always audited.
  - `RunEvent::Exit` aborts every session and closes the store (`lib.rs:74-80`).
  - Sessions survive a vault lock, per ADR-0006.
- **Capabilities:** `src-tauri/capabilities/main.json` is unchanged, `core:default` only, no
  plugin. Custom app commands need no permission entry.
- **CSP:** identical to A0. Only `productName`, `identifier` (`io.github.yyasar21.mooring`) and
  `title` changed in `tauri.conf.json`. `freezePrototype: true`, `withGlobalTauri: false`,
  `devtools: false`.
- `window_detach` returns `ipc.unknown` (A2), as amended in ADR-0008.

### 2. Secrets
- **`session_open`:** the vault is unlocked, then the store opens `secret`/`secret2`
  (`Zeroizing<Vec<u8>>`), then `SecretString` (N-1 for the copy). That goes into
  `ConnectSecret`, then `ConnectParams`, which is moved into `SshSession::connect`. From there,
  `Credentials` is moved into `authenticate` and dropped when it returns (`driver.rs:289-290`).
  An early TCP failure drops `params`, which zeroizes it. `credential_used{connect}` is audited
  before any network I/O, and no secret is in the audit (test `sessions` checks the log).
- **`credential_copy_password`:**
  - Only password credentials can be copied.
  - It goes through `arboard` from Rust, so the UI never touches the clipboard.
  - It is excluded from history:
    - Linux: the KDE `x-kde-passwordManagerHint`.
    - macOS: `org.nspasteboard.ConcealedType`.
    - Windows: history and cloud clipboard exclusion.
  - The clear task holds only a SHA-256 digest.
  - The comparison is plain equality of two digests, which is fine: neither digest is secret
    from the process that owns the clipboard.
  - The plaintext is `Zeroizing` and dropped before the spawn.
  - Not cleared on exit or lock: **M-1**.
  - Manual per-OS check still owed: GNOME/Wayland managers may ignore the KDE hint, and macOS
    Universal Clipboard (Handoff) may sync the value to other devices. arboard's concealed type
    does not obviously stop Handoff.
- **`SessionInput::Answer`:** core `Debug` and `Serialize` redact it (tests in `mooring-core`).
  The IPC-side `WireInput` `Debug` is redacted, and the broker passes `SecretString` end to end.
  Known residue: the serde/IPC JSON buffer holding the raw answer, like every inward secret,
  is accepted as **R-IPC-BUF**.
- **L2 header write** (`state.rs:206-220`): **Fixed.**
  - Copies the old header to `.bak`.
  - Writes a 0600 temp file, runs `sync_all`, renames it, then fsyncs the directory (unix).
  - The `.bak` is dropped after a successful unlock or password change, so an old-password
    header does not linger.
  - `change_password` restores the persisted header (locked) if the write fails.
  - Test `header_write_is_private_keeps_backup_and_backup_can_be_dropped`.
- **UI:**
  - Secret fields are `type=password`, never prefilled, and cleared before the request is
    awaited (`CredentialDialog.tsx:32-35`, `VaultGate.tsx:25`, `PromptModal.tsx:22-25`).
  - The mock seed holds metadata only.
  - `localStorage` holds the theme only.
  - There is no `console.*`.

### 3. SSH (ADR-0007)
- **known_hosts parser** (`known_hosts.rs`):
  - Caps: 8 KiB per line, 10 000 lines, and a byte cap on read.
  - Rejects non-UTF-8 and malformed lines; warnings carry the line number only.
  - Unknown key types are ignored.
  - Lines are kept verbatim.
  - **Save refuses after a cap hit.**
  - `|1|` salt is capped at 128 b64 chars and the hash at 64; the hash must decode to 20 B.
  - Matching uses `Mac::verify_slice` (constant-time).
  - Globbing is iterative.
  - `@revoked` forces a mismatch.
  - New entries are hashed with a 20 B OS-random salt.
  - Writes are atomic (temp + fsync + persist, 0600).
  - HMAC-SHA1 here is a name-hiding format, not a security primitive, so approved (dependency
    section).
- **TOFU/mismatch:**
  - Unknown host → `Prompt` (secret=false).
  - Only a case-insensitive `yes` stores the key.
  - A mismatch or revoked key is a hard stop with no prompt.
  - A re-key accepts only the key already accepted in this connection.
  - Certificate keys are refused.
  - The host string is validated (no control characters), so the TOFU message cannot carry
    escapes.
  - Five trust scenarios are tested.
  - A compromised WebView (T5) can auto-answer `yes` to TOFU. That is within ADR-0003's stated
    consequence (it can do what the user can), it is audited, and it can **not** override a
    mismatch.
- **Algorithms:** compliant (ruling D2). The negotiated set is logged at `info`.
- **Keyboard-interactive:**
  - Name, instructions and prompt text are passed through `sanitize` (control characters
    stripped, 256 chars).
  - Limited to 8 rounds × 16 prompts.
  - `secret = !echo`.
  - Vault password autofill applies to the first `/password/i` prompt only, and only when the
    credential is a password for this connection.
  - The answer vector is `Zeroizing`.
  - The banner is ignored (russh default), so there is no injection path.
- **Auth failure genericity:** the reason is always `authentication failed`, `closed by user`
  or `connection lost`. Detail goes to `debug!` without secrets. A method the server no longer
  offers is skipped. SHA-1 RSA signatures are never used (`rsa_hash`).
- **russh `String` secrets:** ruling D3 (R-SSH-STR).
- **Server-opened channels:** L-1.
- **Forwarding:**
  - SOCKS5: no-auth, CONNECT only, IPv4/IPv6/domain. The domain goes through `validate_host`.
  - Each request is bounded at 262 B, with a 10 s handshake timeout and a pure parser
    (proptest).
  - Limits: 64 forwards, 128 connections per forward, 32 KiB buffers.
  - Unknown `forwarded-tcpip` channels are rejected.
  - Everything is released on every session end and audited.
  - Loopback default exists for dynamic forwards only: **M-2**.
  - Dynamic targets are unrestricted. Accepted: `ssh -D` semantics, and any same-user process
    (T2) can use a loopback SOCKS port. The UI must list live forwards when they are wired.
- **SFTP:**
  - `LocalPath`: lexical check (no `..`, root or prefix), canonical base, a canonical
    parent/file prefix check, and symlink/dir targets refused. A rename does not follow a
    final-component symlink, so the check-to-persist window is safe. Windows gap: **L-7**.
  - Downloads stream to a `NamedTempFile` and persist on success only.
  - Listing cap 10 000; hostile names dropped; oversized read replies refused; server error
    text hidden.
  - Server-driven request fan-out: **M-3**.
  - Remote paths are length- and NUL-checked only. That is correct: the user may browse what
    their account can reach.

### 4. UI (v1 + v2)
- `invoke(` appears only in `apps/desktop/src/lib/ipc.ts`, grepped.
- No `dangerouslySetInnerHTML`, `innerHTML`, `eval` or `new Function`. Every server-derived
  string (prompt messages, close reasons, peer identity, audit details) is rendered as React
  text.
- Write-only secret fields (above). The UI holds credential ids only, and the inspector shows
  name, kind, username and the folder it is inherited from.
- **Terminal:**
  - `allowProposedApi: false`.
  - No ClipboardAddon (no OSC 52 clipboard write from the server).
  - No title subscription.
  - No WebLinksAddon.
  - App shortcuts are filtered before `onData`.
  - Output is buffered at most 1 MiB per tab.
  - OSC 8 link activation: **M-4**.
- `base64ToBytes` decodes only Rust-produced strings. Unknown event kinds become `closed`.
- Audit-verify polling: **L-4**. The 1 Hz clock is not a security matter.
- Trust-dialog detection by regex: **L-2**.
- v2 (tokens, CSS, fonts) adds no script and no remote resource. Fonts are bundled
  (`font-src 'self'`).

### 5. Dependencies
| Dependency | Ruling | Notes |
| --- | --- | --- |
| `arboard 3.7.0` (`default-features = false`) | **Approved** | 1Password, MIT/Apache-2.0. Transitive: `x11rb` (pure Rust), `objc2*` (macOS), `clipboard-win`/`windows-sys`; Wayland data-control is off. All of its unsafe is in arboard, not in our code. Text only. |
| `base64 0.22` | **Approved** | Already transitive. |
| `russh 0.65.0` (`ring`, `rsa`, `flate2`) | **Approved** | `Cargo.lock` has **no `aws-lc-rs` / `aws-lc-sys`**, grepped. `ring 0.17.14`. |
| `rsa 0.10.0-rc.18` (via russh `rsa`) | **Accepted risk R-RSA** | RUSTSEC-2023-0071 (Marvin timing side channel) affects every `rsa` version and has no fix. Our use: RSA host-key verification (public-key ops, unaffected) and **client-side** signing with a vault RSA key, one signature per login. Network timing of a single client-side signature is not a practical Marvin oracle. **`cargo deny check advisories` will fail on it:** the orchestrator adds `{ id = "RUSTSEC-2023-0071", reason = "russh rsa: client-side signing only, no decryption oracle; see docs/security/threat-model.md R-RSA" }` to `deny.toml` `ignore`. Removal: when a patched `rsa` ships, or when Ed25519-only is enforced. |
| `russh-sftp 3.0.1` | **Approved** with ruling ssh-b D3 and M-3. | |
| `hmac 0.13`, `sha1 0.11` | **Approved** | RustCrypto, same versions russh pulls in. Used only for OpenSSH `\|1\|` host-name hashing (format compatibility, not a security primitive). Must not be used anywhere else; the manifest comment says so. |
| `@xterm/xterm 6.0.0`, `@xterm/addon-fit 0.11.0`, `@xterm/addon-webgl 0.19.0` | **Approved** with M-4 | MIT, no runtime dependencies. The parser handles remote bytes; keep it updated. |
| `@fontsource/chakra-petch 5.3.0` | **Approved** | OFL-1.1, font files only, no JS. |
| `age` git pin `str4d/rage@b5b68c4` | **Accepted risk R-AGE-PIN** (owner-approved) | See the threat model. N-4 (full SHA). |

`pnpm audit --prod`: no known vulnerabilities. **Not run (not installed here):** `cargo-deny`,
`cargo-audit`, `gitleaks`, `semgrep`, `cargo-geiger`. The advisory DB is not present either.
CI `make check` / `make audit` must be green before A1 exit; with R-RSA, that needs the
`deny.toml` ignore above.

### 6. Rename (Nexus → Mooring)
- The header magic is now `MOORINGVAULT` (`crates/mooring-vault/src/format.rs:16`). Vectors
  (`header.json`, `sealed.json`, `export.age`) were regenerated. A0 dev vaults with the old
  magic no longer open, which is acceptable: no release exists.
- **`make test-vectors`:** `OK: header + 6 sealed vectors verified with the age CLI; tamper
  rejected`. `cargo test -p mooring-vault --test vectors`: 3 passed.
- The vector passphrases still read `nexus-…`. That is cosmetic; leave it, since changing it
  would mean regenerating the vectors. `.gitleaks.toml` allow-lists only
  `^crates/mooring-vault/tests/vectors/`, so the renamed path is right.
- The keyring service and the app identifier are now `io.github.yyasar21.mooring`. The data directory
  moves with it.

## Test evidence

```
worktree agent-ac9df847a40ab8dd8, HEAD 2003ec8, Linux, 2026-11-03
CARGO_TARGET_DIR=<repo>/target cargo test --workspace         exit 0
  mooring-app        lib 41
  mooring-audit 7 · mooring-core 10
  mooring-proto-ssh  lib 43 · auth 9 · forward 8 · sftp 7 · shell 8 · trust 5 · lab 1 ignored
  mooring-store      lib 18 · credentials 7 · crud 7 · migrations 6 · search 4 · tree_edges 8
                     vault_store_integration 6
  mooring-vault      lib 52 · autolock_table 3 · calibration_props 7 · proptest_round_trip 2
                     vectors 3
make test-vectors                                                         OK (age CLI)
grep aws-lc Cargo.lock                                                    no match
pnpm audit --prod                                                         no known vulnerabilities
git -C ~/.cargo/git/db/rage-* merge-base --is-ancestor f7c95f4 b5b68c4    true; b5b68c4 on origin/main
russh 0.65 client/mod.rs + encrypted.rs read: default server-opened channel handlers accept (L-1)
xterm 6.0.0 lib/xterm.js read: default OSC 8 activate = confirm + window.open (M-4)
russh-sftp 3.0.1 read: limits() clamps only to >= 1 (M-3)
```
Not run: cargo-deny, cargo-audit, gitleaks, semgrep (not installed); clipboard on a real display
(manual per-OS check owed); `mooring-app` on macOS and Windows.
