# A5 — rust-core R4: FIDO2 / hardware-key SSH (`ssh_sk_key`, ADR-0024)

Branch `worktree-agent-a6ffbb422fc8cc994`, worktree
`/home/claude/nexus/.claude/worktrees/agent-a6ffbb422fc8cc994`, on `main` 11a2518 (R3
merged). ADR-0024 still says *Proposed*. I applied the owner's accepted defaults from the
a5-architect decision table:

- **29**: agent-only first. The `ssh-sk-helper` backend exists but is off by default, behind
  the app setting `app.ssh_sk_helper` (`sshSkHelper`).
- **30**: never a password (or keyboard-interactive) fallback after an `ssh_sk_key` attempt.

**No new crate, no new dependency, no manifest, lockfile, workflow or capability change.**

## Done

### Core (`mooring-core`)
- New kind **`ssh_sk_key`**, inserted before `bitwarden_access_token` in
  `CredentialKind::ALL`. That is the ADR order: 18th `ssh_sk_key`, 19th `bitwarden_access_token`.
  - In the display table it sits after `ssh_agent`, in the SSH group.
  - Fields: `username`, `public_key` (an `sk-*` line, required), `certificate?`,
    `backend: agent|helper` (default `agent`) and `resident` (bool; the UI's enum text
    `"true"`/`"false"` is accepted too).
  - Derived fields: `application`, `fingerprint`. Both are refused on input (`application` was
    added to `DERIVED_KEYS`).
  - Secrets: `private_key` holds the key-handle file (label "Key handle file", optional), plus
    `passphrase`. I reused the `private_key` name on purpose instead of the ADR's `key_handle`.
    The handle file *is* the OpenSSH private key file of an `sk-*` key, and the AAD is
    id ‖ secret name, so a converted `ssh_key` row keeps its sealed values unchanged.
  - No TOTP slot.
  - Matrix: SSH primary only.
- The `certificate` must certify `public_key`. A stored handle must be the handle of the same
  key; when the handle is in clear text, its flags set `resident` (0x20).
- `ssh_key` now refuses `sk-*` material with **`CredentialError::UseSkKind`**
  (`credential.use_sk_kind`, a "create an SSH security key (FIDO2) credential" hint). This
  covers the public key, the certificate and the private key.
- `credential::sk_key` is a hand-written, bounded parser:
  - It reads the public blob, the public line and the certificate line.
  - It reads the `openssh-key-v1` key-handle file. The PEM is read leniently because OpenSSH
    wraps at 70 columns.
  - The private section is checked against the public blob: check ints, application, a
    non-empty handle, the reserved field, the comment and the padding.
  - `sk_helper_key_blob` gives the `sshkey_private_serialize` bytes that the helper needs.
  - Caps: blob 4 KiB, application 256 B (must be `ssh:…`), handle 1024 B. Trailing bytes are
    refused.
  - Fuzz entry: **`mooring_core::credential::fuzz_sk_key_parse`** (`sk_key_parse`).
- `ConnectSecret::SecurityKey(SkLogin { public_key, fingerprint, certificate, backend,
  key_handle?, passphrase? })` has a redacting `Debug`.
- New `SessionEvent` variants: **`TouchRequired { id, fingerprint, timeout_seconds, hop? }`**,
  **`TouchCleared { id, hop? }`** and **`TouchTimeout { id, hop? }`**. The `id` comes from the
  prompt id space and is never answered.
- Audit: `AuthMethod::SecurityKey` (`publickey-sk`) and
  `SessionAudit::SecurityKeyAuth { fingerprint, backend, outcome }`.
- Testdata: `sk_ed25519_public`, `sk_ecdsa_public`, `public_line` and `sk_key_handle_pem`
  (public material only).

### Store (`mooring-store`)
- Migration **`0010_ssh_sk_keys.sql`** (FK-off rebuild, `LATEST = 10`). The `credential.kind`
  CHECK gains `ssh_sk_key`, and the script sets `credential_sk_scan_pending` when `ssh_key`
  rows exist.
- `Store::convert_sk_keys(vault)` runs after unlock. It opens each `ssh_key` `private_key`;
  when that is an `sk-*` handle, the row becomes `ssh_sk_key` with backend `agent`. The
  public line and fingerprint are derived, and the certificate is kept if it certifies that
  key.
  - It runs in one transaction and clears the flag.
  - It skips rows with a TOTP seed and migrated rows without a username, so no data is lost.
    Those stay `ssh_key` and are logged.

### SSH (`mooring-proto-ssh`)
- `sk_auth`: the `ssh_sk_key` round. It is the only method tried; there is never a password
  or keyboard-interactive fallback.
  1. Parse the key.
  2. Connect to the agent. `SshOptions.agent_path` is the override; otherwise
     `SSH_AUTH_SOCK`, or the OpenSSH pipe `\\.\pipe\openssh-ssh-agent` on Windows. Pageant
     is not used, because it has no `sk-*` support.
  3. Find the identity whose **blob equals** the key, or a certificate identity that certifies
     it.
  4. Try a certificate first (the stored one, or one held by the agent), then the plain key.
- The signer is `SkSigner`, a russh `Signer`.
  - It emits `TouchRequired` **before** the sign request.
  - It waits up to `SshOptions.sk_touch_timeout` (30 s). Then it emits `TouchCleared`, or
    `TouchTimeout` on timeout.
  - It checks the reply before anything is sent to the server:
    - the algorithm is `sk-*` of the key,
    - the signature length,
    - the **UP flag** is set,
    - flags and counter are present, with no trailing bytes,
    - the signature **verifies** over the request with the key, so an agent that signs with
      another key is refused.
- Failures end with `Closed { auth_failed }` and a fixed reason. Each has its audit outcome:
  - `not_in_agent`: "security key not in ssh-agent; run `ssh-add -K` … or `ssh-add
    ~/.ssh/id_ed25519_sk`"
  - `no_agent`, `touch_timeout`, `no_presence`, `bad_signature`, `refused`, `bad_key`
  - `helper_*`
- `agent_wire` and `sk_agent` are our own agent framing and parsers (message ≤ 256 KiB,
  ≤ 64 identities, blob ≤ 16 KiB, signature ≤ 1 KiB). Fuzz entry:
  **`mooring_proto_ssh::fuzz_agent_identities`** (`agent_identities`).
  - `mooring_proto_ssh::agent_holds(line, path)` is used by the app pre-flight.
- `agent.rs` (the `ssh_agent` kind):
  - It now implements **certificate identities of every key type**
    (`authenticate_certificate_with`, pinned by the certified key's fingerprint).
  - `sk-*` identities get the same touch banner and deadline.
- `sk_helper` (stretch, off): the `ssh-sk-helper` client.
  - Fixed paths (`SK_HELPER_PATHS`, `system_helper()`): Windows
    `%SystemRoot%\System32\OpenSSH\ssh-sk-helper.exe`; Linux
    `/usr/lib/openssh/ssh-sk-helper` and `/usr/libexec/openssh/ssh-sk-helper`; none on macOS.
  - Process pattern: `env_clear`, so `SSH_SK_PROVIDER` is never passed and only the built-in
    `internal` provider is used; `SystemRoot` and `CREATE_NO_WINDOW` on Windows. stdin/stdout
    pipes, stderr null, a 30 s deadline, the reply capped at 64 KiB, `kill_on_drop`.
  - Protocol **version 5** only. A reply with another version fails with `helper_version`.
  - The key handle is decrypted with its passphrase in memory (`Zeroizing`) and never goes
    into argv or env.
  - Fuzz entry: **`mooring_proto_ssh::fuzz_sk_helper_reply`** (`sk_helper_reply`).
- `SshOptions` gains `agent_path`, `sk_touch_timeout` and `sk_helper`.

### App (`src-tauri`)
- `connect_plan`:
  - `ssh_sk_key` maps to `ConnectSecret::SecurityKey`. The handle and passphrase are opened
    for the helper backend only.
  - The **`certificate` role** now works with an `ssh_sk_key` primary: Vault signs the `sk-*`
    line, the certificate is checked by `check_signed_certificate`, and the
    `sk-ssh-ed25519-cert-v01` certificate is attached.
  - Hops use the same mapping.
- `sk_keys.rs`:
  - **Pre-flight before any network I/O**, for the target and every hop:
    - agent backend and the key not held, or no agent → **`ssh.sk_key_not_in_agent`**
    - helper backend and the setting off → **`ssh.sk_helper_disabled`**
    - setting on and no binary → **`ssh.sk_helper_missing`**
  - The setting `app.ssh_sk_helper` (`true` = on).
  - `convert_on_unlock`, called from `after_unlock` next to the legacy reseal.
- `Settings.ssh_agent_path` (tests only; `None` in production). `HopSettings` carries the agent
  override and the helper.
- `WireEvent` gains `touch_required`, `touch_cleared` and `touch_timeout`.
- Audit rows:
  - `session.auth_sk { connection, fingerprint, backend, outcome }`: the key fingerprint
    only.
  - `credential.sk_converted { id }`.
- `ipc-codes.json` was blessed (+4: `credential.use_sk_kind`, `ssh.sk_helper_disabled`,
  `ssh.sk_helper_missing`, `ssh.sk_key_not_in_agent`). `app.ssh_sk_helper` was added to
  `NOT_CODES`.
- `kinds.snapshot.json`: the new row only, after `ssh_agent`, in the original 1-space format.

### Outside my strict scope (small, flagged for qa)
- `crates/mooring-proto-ssh/tests/credential_kinds.rs`: the FIDO refusal test now expects the
  new "SSH security key (FIDO2)" reason.
- `crates/mooring-testsrv/src/vault/dynamic.rs`: `ssh/sign` accepts `sk-` public keys as well
  as `ssh-` ones (one condition).
- New tests: `crates/mooring-proto-ssh/tests/sk_keys.rs` and `tests/sk_support/fake_agent.rs`,
  a minimal fake agent on a Unix socket. It signs with an Ed25519 key under the sk wire format.

## UI contract (U4)
- **Kind picker**: "SSH security key (FIDO2)" (`ssh_sk_key`) under SSH. Render the form from
  `credential_kinds()`:
  - `public_key` (required, multiline)
  - `backend` (enum `agent|helper`)
  - `resident` (enum `false|true`)
  - `private_key` "Key handle file" (optional secret)
  - `passphrase`
  - `certificate`
- Show the derived `fingerprint` and `application` read-only from `CredentialDto.fields`.
- Grey out `helper` with the reason on macOS, and when `ssh.sk_helper_disabled` /
  `ssh.sk_helper_missing` comes back.
- `ipc.kinds.ts` must gain the row, or the kinds snapshot vitest fails.
- **Session banner**:
  - On `touch_required { id, fingerprint, timeout_seconds, hop? }`, show "Touch your
    security key" with the fingerprint and a countdown. With `hop`, title it "Hop N".
  - Hide it on `touch_cleared { id }`.
  - On `touch_timeout { id }`, show "Not touched in time"; `closed { auth_failed }` follows.
  - None of these takes an answer.
- **Error copy** (English):
  - `credential.use_sk_kind`: "This is a FIDO2 security key. Create an SSH security key
    (FIDO2) credential."
  - `ssh.sk_key_not_in_agent`: show the message, plus help text for `ssh-add -K` (resident
    key) and `ssh-add ~/.ssh/id_ed25519_sk`.
  - `ssh.sk_helper_disabled`, `ssh.sk_helper_missing`.
- `Closed.reason` of an sk failure is safe to show verbatim.

## Left open
- **No IPC command for the `sshSkHelper` setting.** A new command needs a capability /
  permission entry (`src-tauri/capabilities`, outside rust-core). Today the row
  `app.ssh_sk_helper` can only be set from Rust or tests. The orchestrator should decide
  between a `ssh_settings_get/set` pair and folding it into an existing settings command.
- **Helper PIN**: the ADR's native PIN dialog cannot come from `tauri-plugin-dialog`, which
  has no text input. So the helper request carries an empty PIN, and `verify-required` keys
  fail with `helper_failed`. The agent path handles PINs through OpenSSH's own askpass.
- The helper protocol was checked against `ssh-sk-client.c` from memory (OpenSSH 8.9–9.9
  framing). Run the manual gate (Windows 11 non-admin, Fedora) before the setting is
  exposed. A helper that refuses our version usually exits without replying; we report that
  as `helper_failed`, which is still fail-closed.
- On-curve validation of P-256 points is not done in Rust, because there is no P-256
  arithmetic in `mooring-core`. The agent and the server reject bad points.
- `ssh_sk_key` has no TOTP slot, so a partial-success keyboard-interactive second factor
  after the key is not answered (decision 30 reading). `ssh_key` rows with a seed are not
  converted.
- No test migrates a v9 database file that holds an `sk-*` `ssh_key`. The conversion itself
  is tested on a v10 store with the flag set.
- `ssh_sk_key` is not an `external_ref` target (`is_ref_target` excludes it).
- Disk: target at 8 GB free at the end; nothing was deleted.

## Decision needed
- ADR-0024 → *Accepted* with 29 and 30 as applied. The architect should also note two
  deviations from the ADR: the secret name `private_key` instead of `key_handle`, and the
  dedicated `touch_*` events instead of `Prompt { purpose: SecurityKeyTouch }` +
  `PromptCleared`. I chose them because of the task brief, and because the UI must not treat
  the banner as a prompt that needs an answer.
- The `sshSkHelper` IPC surface (see Left open).
- qa: wire the fuzz targets `sk_key_parse` → `mooring_core::credential::fuzz_sk_key_parse`,
  `agent_identities` → `mooring_proto_ssh::fuzz_agent_identities` and `sk_helper_reply` →
  `mooring_proto_ssh::fuzz_sk_helper_reply`. Seed them from `testdata::sk_key_handle_pem`
  and the `agent_wire` tests.
- security review: the R-SK-HELPER surface is `sk_helper.rs`. The agent-reply checks are in
  `sk_auth.rs` (`SkSigner::sign`).

## Test evidence
```
cargo fmt --all --check                                   clean
cargo clippy --workspace --all-targets -- -D warnings     clean
cargo test -p mooring-core       lib 184 (sk_key 9, sk_fields 4, touch events, kinds/matrix), fuzz_corpus 17, hostile_kubeconfig 8
cargo test -p mooring-store      lib 57 (sk_convert 3), integration 51
cargo test -p mooring-proto-ssh  lib 76 (agent_wire 4, sk_helper 6), sk_keys 10 (fake agent E2E), auth 11,
                                 credential_kinds 8, forward 10, hops 8, sftp 9, shell 9, trust 6, fuzz_corpus 3
cargo test -p mooring-audit      41 (security_key_events_have_stable_wire_names)
cargo test -p mooring-secrets    68 · mooring-testsrv 92 (ssh/sign accepts sk-)
cargo test -p mooring-app        lib 448 / 1 ignored (sk_keys 6), e2e_flow 55
MOORING_BLESS=1 cargo test -p mooring-app golden          ipc-codes.json re-blessed (+4)
```
sk_keys.rs E2E (Unix): agent sign-in with touch_required → touch_cleared; key not in agent
(no prompt, no password); no agent; agent signing with another key; UP flag unset; touch
timeout (300 ms override); agent FAILURE; stored sk certificate; agent-held sk certificate;
`agent_holds`.
