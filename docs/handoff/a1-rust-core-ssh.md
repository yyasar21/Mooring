# A1 · rust-core · Mooring SSH core (item 3, part a)

Branch `worktree-agent-ad5717a28bbb7cb01`, on top of `1d8c660` (ADR-0007). Not merged.
Inputs: ADR-0004, ADR-0007, `crates/mooring-core/src/session.rs`. Linux host; `mooring-app` was
not compiled. The product name is now Mooring: it is used in user-visible strings, doc prose and
the SSH client id (`SSH-2.0-Mooring_0.1.0`). Crate names and `nexus_*` identifiers (renamed to `mooring_*` by the orchestrator afterwards) are
unchanged so the orchestrator can rename everything in one pass.

## BLOCKER: merging this branch breaks `mooring-vault`

`age 0.12.1` (mooring-vault, ADR-0006) depends on `ml-kem ^0.2`, which pins
`kem =0.3.0-pre.0`. Every russh from 0.60 to 0.65 depends on `ml-kem ^0.3`, which needs
`kem ^0.3`. Cargo treats `0.3.0-pre.0` and `0.3.0` as the same semver slot, so the resolver
fell back to `ml-kem 0.2.1` for age, and that version **does not compile** against
`kem 0.3.0`. `cargo build --workspace --exclude mooring-app` fails in `ml-kem-0.2.1/src/kem.rs`.
`cargo test -p mooring-proto-ssh -p mooring-core` is green. russh 0.59, the last release on
ml-kem 0.2, no longer compiles because of `rsa 0.10.0-rc` drift, and it lacks APIs used here.
No `age` release on ml-kem 0.3 exists yet (latest is 0.12.1). See Decision 1.

## Done

| Commit | What |
| --- | --- |
| `989fa2c` | **core:** `SessionInput::Answer { id, text: SecretString }`. `Debug` for `SessionInput` is hand-written: the other variants print as before, and `Answer` prints `text: "<redacted>"`. `Serialize` writes `"text":"<redacted>"`; `Deserialize` reads the real text. Tested: Debug, Serialize and Clone never leak the text, and the other variants keep their Debug and wire format. |
| `3fcb808` | **build:** adds `russh`, `secrecy`, `zeroize`, `tempfile`, `rand_core` (all workspace deps), plus `hmac 0.13` and `sha1 0.11` (RustCrypto, the versions russh already pulls in) with the comment "OpenSSH \|1\| hashed known_hosts compatibility (not for security)". This commit's Cargo.lock change causes the BLOCKER. |
| `ffd761a` | **known_hosts.rs:** reads plain and `\|1\|` HMAC-SHA1 hashed entries, `[host]:port` for ports other than 22, `*`/`?`/`!` patterns (iterative glob, no recursion), and `@revoked`; `@cert-authority` lines are kept but ignored. Caps: 8 KiB per line, 10 000 lines, and a byte cap on read. Malformed or non-UTF-8 lines are skipped with a `warn!` that gives only the line number. Unknown lines are kept verbatim on rewrite. New entries are hashed with a 20-byte OS-random salt. Writes are atomic (`NamedTempFile` in the same directory, `sync_all`, `persist`), with mode 0600 from tempfile. A store that hit a cap **refuses to save**, so entries are never silently dropped. Fingerprints are `SHA256:<base64 no pad>`. `TrustDecision { Known, Unknown, Mismatch { expected_fp } }`. Tests: unit tests (including the RFC 2202 HMAC-SHA1 vector), and proptests for random bytes, random lines and hashed round trips. |
| `e046987` | **SshSession** (modules `algos`, `audit`, `shared`, `handler`, `auth`, `agent`, `channel`, `driver`, `session`; all under 400 lines). Details below. |
| `90b6e2e` | **tests/**: an in-process russh server (`tests/common/mod.rs`) plus 22 scenarios and the ignored lab test. |
| `a3041b1` | **build:** declares `russh-sftp` so part b can land without a manifest change. |

### SshSession design
- `SshSession::connect(params, SshOptions)` validates the host, port and user, opens TCP with a
  15 s timeout, and spawns a **driver task**. It returns right away, before the handshake.
  Events then arrive as `Prompt`* → `Connected` → `Bytes`* → `Closed`. `Closed` is always last;
  `next_event` returns `Ok(None)` after it.
- **TOFU** runs in `ClientHandler::check_server_key`. A `PromptBroker` emits `Prompt` and parks
  on a oneshot channel until `send(Answer { id, .. })`. The state machine is that driver task
  plus the broker. Answering with the wrong id is an `Invalid` error and the prompt stays open.
  "yes" (case-insensitive) stores a hashed entry and audits `HostKeyAdded`. Anything else gives
  `Closed { "host key not trusted" }` and audits `HostKeyRejected`. A mismatch or revoked key
  gives `Closed { "HOST KEY CHANGED for <host>: expected <fp>, got <fp>" }` with no prompt.
  A host certificate is refused, because CA trust is not in A1.
- **Auth** order: vault publickey (RSA only with SHA-2, chosen through `server-sig-algs`) →
  agent (when `allow_agent`, and only when the secret is `None` or the key failed) → password →
  keyboard-interactive. A method the server stopped offering is skipped. Keyboard-interactive
  prompts are sanitised (control characters stripped, 256 characters max) with
  `secret = !echo`. The first `/password/i` prompt is filled from the vault password. Limits:
  8 rounds, 16 prompts per round. Failure is always `"authentication failed"`; the detail goes
  to `debug!` without the secret. `Credentials` is moved into `authenticate` and dropped when it
  returns. `SecretString` and ssh-key private keys zeroize on drop.
- **Shell:** PTY `xterm-256color` at `params.size`, then `request_shell`. Output (stdout and
  stderr) arrives in ≤ 64 KiB `Bytes` over a bounded mpsc(256); while the UI does not read,
  russh stops granting window. `Resize` sends `window_change`. Pointer and Key inputs are
  refused.
- **Algorithms:** `algos.rs` contains only what ADR-0007 allows; a test asserts that no
  sha1/cbc/3des/md5/group1/GEX/`ssh-rsa` algorithm is offered and that every ADR algorithm is.
  **Keepalive** is 30 s with 3 misses (russh `keepalive_interval`/`keepalive_max`).
- **close()** is idempotent. It cancels any open prompt, sends EOF and close on the channel,
  disconnects, waits up to 5 s and then aborts the task. Later `next_event` calls return one
  `Closed { "closed by user" }` and then `None`. `Drop` aborts the task.
- **Extension points for part b:** `SshSession::handle() -> Option<Arc<Handle<ClientHandler>>>`
  (set once the session is authenticated and the shell is open), `ClientHandler` (add
  `server_channel_open_forwarded_tcpip`) and `TrustEvent` (add forward variants). Add `forward`
  and `sftp` modules beside the existing ones.
- **Audit:** `take_audit_events() -> Vec<TrustEvent>` returns `HostKeyAdded`,
  `HostKeyRejected`, `HostKeyMismatch`, `AuthSucceeded { method }` and `AuthFailed`, each with
  `action()` names such as `trust.host_key.added`. The crate does not depend on mooring-audit.

## Left open

- **Fuzz target** `known_hosts_parse` (QA, needs nightly): the entry point is
  `KnownHosts::parse_bytes(&[u8])`.
- **Agent auth is untested in CI**: tests set `allow_agent = false` so they don't depend on the
  developer's agent. A test with russh's `agent::server` over a temporary UDS is possible on
  unix.
- **Windows agent** (Pageant, then `\\.\pipe\openssh-ssh-agent`) has not been compiled here.
- The TOFU message for an IPv6 host prints `host:port` unbracketed, exactly as in the ADR text.
- A verbose-mode `Bytes` line with the negotiated algorithms (ADR) is not implemented; the
  algorithms are logged at `info` in `kex_done`.
- Before the first event arrives, `next_event` cannot tell a slow handshake from a stuck one.
  russh has no handshake timeout; the UI should apply one.

## Decision needed

1. **(BLOCKER) age ↔ russh dependency conflict.** Options for the orchestrator and the
   security-reviewer:
   a) Change the root manifest to `[patch.crates-io] age = { git = ..., rev = <main with
   ml-kem 0.3> }` until age 0.13 ships;
   b) Gate `age` export/import in mooring-vault behind a feature that is off in builds that
   include SSH (this hurts: the app needs both);
   c) Fork age with ml-kem bumped to 0.3, its API change being small;
   d) Switch to an older russh. Not viable: 0.59 does not compile today and lacks
   `PublicKeyOffer`, `Names` in `kex_done` and `host_key_certificates`.
   I did not edit the root `Cargo.toml` (out of scope).
2. **Algorithm deviations from ADR-0007** (`algos.rs` module docs): `mlkem768x25519-sha256` is
   offered first (the ADR allows PQ hybrids "when russh exposes them"); `ext-info-c` and
   `kex-strict-c-v00@openssh.com` are protocol markers needed for `server-sig-algs` and the
   Terrapin countermeasure. Compression is `none` only. `sntrup761x25519-sha512` is not
   implemented by russh 0.65. The ADR's `ecdh-sha2-nistp256/384/521` and
   `hmac-sha2-*-etm@openssh.com` names map one-to-one.
3. **russh 0.65 secret-handling limitation:** `authenticate_password` and
   `authenticate_keyboard_interactive_respond` take plain `String`s. Our copies are zeroized
   (`Zeroizing<Vec<String>>` for keyboard-interactive answers), but russh's internal copy is
   only dropped, not wiped. Security-reviewer: accept or track upstream.
4. **TOFU store failure:** if the user says "yes" but the `known_hosts` write fails (disk full,
   or the file is over the cap), the session continues, trusts the key for this connection only,
   and logs `warn!`. The alternative is to abort. Is that acceptable?
5. `@cert-authority` lines are read and ignored, and certificate host keys are refused. Host-CA
   trust needs an ADR addendum.

## Test evidence

```
cargo fmt --all --check                                                     OK
cargo clippy -p mooring-proto-ssh -p mooring-core --all-targets -- -D warnings  OK
cargo test -p mooring-proto-ssh -p mooring-core
  mooring-core unit                  10 passed
  mooring-proto-ssh unit             24 passed  (known_hosts 14 incl. 3 proptests, algos 3,
                                               shared 3, channel 3, audit 1)
  tests/auth.rs                     9 passed  (password / publickey / undecodable key /
                                               kbd-int autofill+OTP / kbd-int secret prompt /
                                               kbd-int failure / wrong prompt id)
  tests/shell.rs                    8 passed  (pty type+size, echo + 200 KiB chunking, resize,
                                               remote exit status, idempotent close, key input
                                               refused, param validation, refused TCP)
  tests/trust.rs                    5 passed  (TOFU accept hashed, TOFU decline nothing written,
                                               known host silent, mismatch hard stop unchanged,
                                               close during TOFU prompt)
  tests/lab.rs                      1 ignored (MOORING_LAB_HOST <lab-host> uname; never run here)
5 consecutive runs: all green, under 3 s per run after the build.
cargo build --workspace --exclude mooring-app   FAILS in ml-kem 0.2.1 (see BLOCKER)
```
