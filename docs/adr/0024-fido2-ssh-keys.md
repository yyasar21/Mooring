# ADR-0024: FIDO2 / hardware-key SSH authentication (`sk-*` keys)

Status: Accepted 2026-11-08 (owner decisions 29 → agent-only first, ssh-sk-helper behind an off-by-default flag; 30 → never a password fallback) · 2026-11-07 (Phase A5 / v0.2.0; amends ADR-0007 §Authentication, ADR-0009 §1–2;
builds on ADR-0017 §7, ADR-0020 §3 process pattern)

## Context
OpenSSH 8.2+ keys of type `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`
hold only a **key handle** on disk; every signature needs the FIDO2 authenticator (touch, and a
PIN when `verify-required`). ADR-0009 stores such handles in `ssh_key.private_key` and
`auth.rs::is_security_key` refuses them (`credential.kind_unsupported`, `AuthError::Unsupported`).
What already works, verified in `crates/mooring-proto-ssh/src/agent.rs`: `try_agent` lists the
agent's identities, skips certificates, and calls `handle.authenticate_publickey_with(user, key,
hash, &mut agent)`; russh 0.65 lists `Algorithm::SkEd25519` and `SkEcdsaSha2NistP256` among
the client algorithms (`keys/key.rs`) and relays the agent's signature blob (which carries the
`sk` flags and counter) unchanged. So an `sk-*` key loaded into `ssh-agent` with `ssh-add`
(the agent calls `ssh-sk-helper`/libfido2 and handles touch and PIN itself) authenticates
through Mooring today — only the UI does not say "touch your key". No test proves it yet.
Direct authenticator access (ADR-0017 §7) needs OS FFI or C everywhere: Windows allows
non-admin FIDO access only through `webauthn.dll` (since 10 1903), and macOS/Linux need raw HID.

## Decision

### 1. Credential kind `ssh_sk_key` (amends ADR-0009 §1/§2; 18th kind)
| kind | fields (plain) | secrets (sealed) |
| --- | --- | --- |
| `ssh_sk_key` | `username`, `public_key` (`sk-*` line, required), `application` (`ssh:` by default, derived from the key), `fingerprint` (derived), `backend: agent \| helper`, `resident: bool`, `certificate?` | `key_handle?` (the OpenSSH private file; absent for a resident key used through the agent), `passphrase?`, `otp_seed?` |
- Matrix row: `ssh ✓`, everything else `—`. `ssh_key` stops accepting `sk-*` material
  (`credential.use_sk_kind` with a "convert" hint); the migration moves existing rows whose
  `private_key` parses as `sk-*` (`ssh-key` crate, already pinned) into `ssh_sk_key` with
  `backend: agent`.
- `fingerprint`, `application` and `resident` are derived in Rust from `public_key` /
  `key_handle` with the hardened OpenSSH key parser (fuzz target `sk_key_parse`).

### 2. Backend `agent` — ships in 0.2.0 on every OS
- Auth order (ADR-0007) gains a rule: an `ssh_sk_key` credential **only** tries the agent,
  pinned to `fingerprint` (the existing `pin` path), never password fallback unless the user
  allowed it on the connection. No agent or no matching identity → `Closed { code:
  auth_failed, reason: "security key not in ssh-agent" }` with a help link ("run `ssh-add
  -K`" for resident keys, `ssh-add ~/.ssh/id_ed25519_sk` otherwise).
- Touch indication: when the identity being tried is `sk-*`, `try_agent` emits
  `SessionEvent::Prompt { purpose: SecurityKeyTouch, id }` **before** the sign request and
  `SessionEvent::PromptCleared { id }` after the agent answers (new event, informational, no
  answer expected; the UI shows a banner "Touch your security key"). PIN prompts for
  `verify-required` keys are raised by the agent's helper (OpenSSH's own askpass), not by us.
- Windows: the OpenSSH agent named pipe already works (`agent.rs`); Pageant has no `sk`
  support. macOS: `SSH_AUTH_SOCK` of the user's launchd agent; Linux: `SSH_AUTH_SOCK`.
- Certificates (`sk-*-cert-v01@openssh.com`) in the agent: the `AgentIdentity::Certificate`
  arm that `try_agent` skips ("not in A1") is implemented for all key types in the same task.

### 3. Backend `helper` — stretch, Windows and Linux only, owner decision
Direct signing without the agent, for stored `key_handle` files and resident keys, by driving
OpenSSH's own **`ssh-sk-helper`** (fixed absolute paths, ADR-0020 §3 pattern: no shell, cleared
environment, `stdin`/`stdout` pipes, 30 s deadline, output cap 64 KiB):
Windows `%SystemRoot%\System32\OpenSSH\ssh-sk-helper.exe` (Win32-OpenSSH ≥ 8.9, uses
`webauthn.dll` itself, so **non-admin works and no `unsafe` enters our tree**); Linux
`/usr/lib/openssh/ssh-sk-helper` (Debian/Ubuntu), `/usr/libexec/openssh/ssh-sk-helper`
(Fedora/RHEL); macOS: Apple's OpenSSH ships no helper → not offered. The helper speaks
OpenSSH's internal sk-helper protocol (`SSH_SK_HELPER_VERSION`, `sk-api.h`), which has **no
stability promise**: rust-core implements version 5 (OpenSSH 8.4–9.9) behind a version check
and refuses others (`ssh.sk_helper_version`). PIN: the helper takes the PIN in its request, so
Mooring asks with a **native dialog from Rust** (`tauri-plugin-dialog`, ADR-0013 B-6 three-slot
rules), `Zeroizing`, never cached, never through IPC. Touch: same banner as §2.

### 4. Direct FIDO2 in-process — rejected for 0.2.0
`ctap-hid-fido2` 3.6.1 (MIT, 2026-11-02, maintained, 0 `unsafe` in its own code, `ring`
feature available) builds on `hidapi` 2.6.7 (**C**, `linux-static-hidraw`), and on Windows raw
HID to a FIDO device needs administrator since 1903, so Windows would still need
`WebAuthNAuthenticatorGetAssertion` from the `windows` crate — an **`unsafe fn`** with raw
pointer structs (`Win32_Networking_WindowsWebServices`), i.e. an `unsafe` exception ADR plus
a C exception (R-RDP-FFI class). `ctap-types` / `fido-authenticator` (Trussed) are for building
authenticators, not clients. `webauthn-authenticator-rs` 0.6.2 is MPL-2.0 (not on the licence
allow-list) with 35 `unsafe` sites. Revisit after 0.2.0 if the helper path proves unreliable.

### 5. IPC and audit
`credential_kinds()` serves the new schema; no new command. `SessionEvent` gains
`PromptPurpose::SecurityKeyTouch` and `PromptCleared`. Audit `session.auth { method:
"publickey-sk", backend: agent|helper }`, `credential.sk_converted { id }`, `ssh.sk_helper_refused
{ version }`. Error codes: `credential.use_sk_kind`, `ssh.sk_not_in_agent`,
`ssh.sk_helper_missing`, `ssh.sk_helper_version`, `ssh.sk_pin_cancelled`.

## Alternatives considered
- Keep refusing `sk-*` (status quo): the agent path already works; refusing it is a UX bug.
- `ssh-agent` only, no kind: users cannot record which key to pin, and resident-key discovery
  (`ssh-add -K`) needs documentation per connection. The kind is cheap.
- Spawning `ssh` itself as the transport (ProxyCommand style): loses TOFU control, PTY and
  forwarding integration (ADR-0007 rejected `openssh` subprocess).
- Implementing CTAP2 over HID ourselves: C/`unsafe` on every OS (§4). Rejected.

## Security consequences
- T2: the agent socket/pipe is reachable by every same-user process already; Mooring adds no
  listener. The helper path spawns a fixed OpenSSH binary with a cleared environment; the key
  handle and PIN go over a pipe (not argv, not env), zeroized after (new residue
  **R-SK-HELPER**: an internal, versioned protocol — fail closed on version mismatch).
- T4: agent and helper replies are untrusted (length-prefixed parsers with caps, fuzz targets
  `agent_identities`, `sk_helper_reply`).
- T5: never receives a PIN or key handle; sees only the touch banner events.
- No new crate for §1–§3; §4 would need two exception ADRs and is not proposed.

## UI
Kind picker gains "SSH security key (FIDO2)" under SSH; form shows the public key, fingerprint,
application, resident flag, backend radio (helper greyed with the reason on macOS or when the
binary is missing); session header banner "Touch your security key"; help text for `ssh-add`.

## Test plan
- Unit: kind schema snapshot, migration of `sk-*` rows, parser vectors (sk ed25519/ecdsa,
  resident with empty handle, certificate), matrix row.
- Integration: a fake agent on a Unix socket / named pipe that returns an `sk` signature blob
  for an `sk-ssh-ed25519` identity, against the in-process russh server with the matching
  public key → success; non-sk identity pinned → refused. Helper: a scripted fake
  `ssh-sk-helper` binary (test-only path override) covering version mismatch, PIN required,
  touch timeout.
- Fuzz: `sk_key_parse`, `agent_identities`, `sk_helper_reply`.
- Manual gate: YubiKey 5 (non-resident + resident, `verify-required`) on macOS/Windows/Fedora
  through the agent; Windows 11 helper path as a non-admin user.

## Owner decisions needed
29. Backend `helper` (ssh-sk-helper, Windows + Linux, internal protocol) in 0.2.0, or agent-only
    in 0.2.0 and helper in 0.2.x. Default: agent-only ships first; helper as a stretch task
    behind a feature flag, fail-closed on version.
30. Password fallback after a failed `ssh_sk_key` attempt: never (default) or per connection.
