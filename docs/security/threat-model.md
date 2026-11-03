# Threat model — Mooring (v1, Phase A1)

Owner: security-reviewer. Updated at every phase exit and whenever the attack surface changes.
Last change: A1 items 3–5. These cover the ADR-0007 SSH core, forwarding and SFTP, the ADR-0008
Tauri commands, UI v1/v2 and the Nexus→Mooring rename; see review
[a1-review-2.md](a1-review-2.md). Earlier: A1 items 1–2, [a1-review.md](a1-review.md).

## Assets
| Asset | Where it lives | Impact if lost |
| --- | --- | --- |
| Vault secrets (passwords, keys, tokens) | `credential.secret`/`secret2` in `mooring.db`, sealed per field; DEK in RAM while unlocked | Compromise of every managed host |
| Master password | Nowhere (derived into KEK, zeroized) | Vault compromise |
| Vault header (`vault.header.json`) | Plaintext, authenticated; the only copy of the wrapped DEK | Loss = vault loss (availability); tamper = unlock fails |
| Keyring `WrapKey` (opt-in) | OS keyring, service `io.github.yyasar21.mooring`, account = `vault_id` | With the header: DEK (see R-T2-KR) |
| Export file (`*.age`) | Wherever the user puts it; age scrypt + per-field sealing inside | Offline guessing of export passphrase, then master password |
| Open sessions (terminal, screen) | Process memory, WebView | Live access to targets |
| Connection inventory (hosts, IPs, names, usernames, tags, topology) | `mooring.db` **plaintext** (ADR-0005) | Reconnaissance |
| Audit log | `audit.jsonl`, hash-chained, carries `vault_id` | Loss of accountability |
| SSH trust store (`known_hosts`) | `$APP_DATA/known_hosts` in OpenSSH format. New entries are written `\|1\|`-hashed, mode 0600. **Not** in the vault | Tamper (T2): MITM keys silently accepted for the hosts the attacker picks. Read: the host list (hashing hides the names of new entries) |
| RDP/TLS cert pins | Vault (A2) | MITM |
| Copied password | OS clipboard for ≤ 30 s, excluded from clipboard history where the OS allows | While it is there, any process in the same session and any clipboard manager can read it |
| Live port forwards | Loopback listeners in our process; remote listeners on the server | Anyone who reaches the bound address uses the tunnel into the target network |

## Attackers
| ID | Attacker | Capability |
| --- | --- | --- |
| T1 | Stolen device / backup | Reads vault header, `mooring.db`, audit log, export files offline |
| T2 | Malicious local process (same user) | Reads files, reads the OS keyring where no ACL applies, may read process memory on some OSes |
| T3 | Network MITM | Intercepts/alters SSH, RDP, VNC, HTTPS, LDAPS traffic |
| T4 | Malicious remote server / hostile file | Sends hostile protocol bytes to our parsers: SSH transport, keyboard-interactive prompts, terminal escape sequences (OSC 8), SFTP replies and `limits`, server-opened channels. Hands the user a crafted export or header |
| T5 | Compromised WebView (XSS, malicious remote page in A2) | Runs JS inside the app, calls any exposed IPC command |
| T6 | Poisoned dependency (cargo/npm) or CI | Code execution at build time |

## Mitigations (STRIDE)
| Threat | Mitigation | Status |
| --- | --- | --- |
| Spoofing: SSH server identity (T3) | TOFU through `SessionEvent::Prompt`; only `yes` stores the key. A changed or `@revoked` key is a hard stop with no prompt. Host certificates are refused. A re-key accepts only the key already accepted in this connection. Audited as `trust_decision` | A1 ✓ (open: L-5 concurrent-write race, L-6 expected fingerprint in the audit entry, N-3 session-only trust visibility) |
| Spoofing: TLS/RDP server identity (T3) | TLS 1.2+/rustls with system + optional private CA; RDP NLA default on | A2 |
| Spoofing: trust UI (T4) | Server prompt text is sanitised (control characters stripped, 256 chars). The trust dialog must be chosen by prompt purpose, not by message text | A1 partial (L-2 open) |
| Tampering: SSH algorithms / downgrade (T3) | Only the ADR-0007 set is offered: mlkem768x25519, curve25519, ecdh and DH16/DH14-sha256 kex; ed25519, ecdsa and rsa-sha2 host keys; chacha20, AES-GCM and AES-CTR; SHA-2 (ETM) MACs. Strict kex (Terrapin) is on. No compression, CBC, SHA-1 or `ssh-rsa`. A test asserts the deny-list | A1 ✓ |
| Tampering: `known_hosts` file (T1, T2) | Atomic write, mode 0600; a file that hit a cap is never rewritten. Parser caps: 8 KiB per line, 10 000 lines. Property-tested | A1 ✓ (fuzz target owed). A same-user T2 can still edit the file; accepted, as with OpenSSH |
| Tampering: vault header (T1) | Header v2 is AAD of the DEK wrap, including `vault_id` and `keyring_wrap`; v1 AAD unchanged; v1↔v2 relabel fails; KDF floor on read | A0 ✓ / A1 ✓ |
| Tampering: sealed fields (T1) | XChaCha20-Poly1305 per field, random 24 B nonce, AAD = record id ‖ 0x1F ‖ field; store binds credential id + column (row/column swap → `Tampered`) | A0 ✓ / A1 ✓ |
| Tampering: keyring wrap (T1, T2) | Second wrap's AAD = header AAD (without wrap) ‖ 0x1F ‖ `keyring`; bound to KDF params, salt, vault id; enable/disable need master password | A1 ✓ (B1 fixed; OS commands on HOLD per R-T2-KR) |
| Tampering: audit log (T1, T2) | SHA-256 hash chain, `verify()`; file 0600; syslog mirror to a syslog server optional | A0 ✓ (mirror open) |
| Repudiation | Audit entries for vault + credential + session + trust events; `vault.lock` carries `reason ∈ {user, idle, screen_lock, sleep, window_hidden}` | A0 ✓ / A1 partial (lock reasons ✓; keyring/export/credential events with wiring) |
| Information disclosure: secrets in UI/logs (T5) | Credential ids only over IPC; hand-written `Debug`; error variants carry fixed strings, never values; `mooring_audit::redact` on sinks; no `println!` (lint); `SessionInput::Answer` is redacted in `Debug` and `Serialize` and is a `SecretString` end to end; IPC DTOs have no secret field (tested) | A0 ✓ / A1 ✓ |
| Information disclosure: SSH credentials in flight (T2) | Vault → `Zeroizing` → `SecretString` → `ConnectParams`, which is moved into the auth round and dropped after it. Auth failure is reported generically | A1 ✓ (R-SSH-STR: russh keeps internal `String` copies; N-1: one extra copy on our side) |
| Information disclosure: clipboard (T2) | Rust-side only (`arboard`), password credentials only, history and cloud exclusion, cleared after 30 s if unchanged (digest compare), audited as `credential_used{copy}` | A1 partial: **M-1** open (not cleared on exit or lock); manual check on each OS owed |
| Information disclosure: SFTP local writes (T4, T5) | `LocalPath` confined to a caller-chosen base: no `..` or absolute paths, canonical prefix check, symlink and directory targets refused, temp file persisted only on success | A1 ✓ on unix (L-7 open: Windows alternate data streams and device names; gate for SFTP IPC) |
| Information disclosure / elevation: remote content in the WebView (T4) | No remote content in `main`; terminal output is rendered by xterm only | A1 partial: **M-4** open (xterm's default OSC 8 handler opens links with `window.open`) |
| Information disclosure: memory (T2) | `Zeroizing` for DEK/KEK/WrapKey/plaintexts; DEK dropped on lock; pure auto-lock clock (idle 15 min, screen lock, sleep, window hidden) | A1 partial: clock ✓, Argon2 `zeroize` ✓ (L3); Tauri tick + OS signals open; `mlock` open |
| Information disclosure: inventory at rest (T1, T2) | Accepted plaintext (R-INV); data dir 0700 / db 0600 (M2); `secure_delete=ON`; FTS5 `optimize` + WAL truncate on close, rebuild on open (L4) | A1 ✓ (residue bound: deleted rows may persist in FTS segments until close / next open) |
| Information disclosure: export (T1) | age v1 scrypt (cap 2^20 on import; export pinned 2^18 — L5), passphrase ≥ 12 chars, fields stay sealed inside | A1 ✓ |
| Brute force on stolen header (T1) | Argon2id; calibrated cost 64 MiB–1 GiB (≤ RAM/4, never below floor 8 MiB/1/1), `t=3`, `p≤4` | A1 ✓ (calibration not yet wired into `vault_create`) |
| Denial of service: hostile header / import (T4) | Header ≤ 64 KiB; import ≤ 64 MiB in and out; scrypt `log_n ≤ 20` checked before work; KDF ceiling 4 GiB / t 16 / p 16 on read, `m ≤ RAM/2` before derive | A1 ✓ (B2 fixed) |
| Denial of service: hostile SSH server (T4) | Bounded event mpsc(256) for back-pressure, `Bytes` ≤ 64 KiB; keepalive 30 s × 3; keyboard-interactive 8 rounds × 16 prompts; SFTP listing cap 10 000; forward caps (64 forwards, 128 connections each, 32 KiB buffers); SOCKS handshake 10 s | A1 partial. Open: **M-3** (SFTP `limits` drive request fan-out); L-1 (russh's defaults accept server-opened x11, agent and session channels); no handshake timeout (the UI applies one) |
| Denial of service: hostile protocol parsers (T4) | `forbid(unsafe)`, size caps, fuzz targets per parser | A1: proptest only for known_hosts and SOCKS (fuzz targets owed). RDP/VNC: A2 |
| Elevation: port forwards expose internal networks (T5, LAN) | Dynamic forwards bind to loopback only unless the user opts in; local and remote forwards must follow the same rule (M-2). All forwards close with the session; open and close are audited | A1 latent (no IPC yet): **M-2** gate |
| Injection: store (T5 via future IPC) | Parameterised SQL only; FTS input quoted per token, operator-only tokens dropped, 256 chars / 16 tokens / limit ≤ 200; names/hosts/tags validated and capped | A1 ✓ |
| Elevation: WebView → OS (T5) | Capabilities `core:default` only (re-checked for A1 items 3–5: 30 app commands, no plugin); CSP unchanged; `freezePrototype`; every command validates and caps its input and maps errors to `IpcError`; `invoke()` only in `ipc.ts`; no `innerHTML`; remote content in a separate window and capability | A0 ✓ / A1 ✓ (M-4 navigation guard open) / A2 |
| Supply chain (T6) | cargo-deny (licenses, bans, advisories), cargo-audit, lockfiles, Dependabot, pinned Actions by SHA, SBOM + provenance; exactly one allowed git source (age). A1 dependencies reviewed: age, keyring 4, sysinfo, rusqlite (bundled), russh (ring only; no aws-lc in the lockfile), russh-sftp, hmac/sha1, arboard, base64, @xterm/*, @fontsource/chakra-petch | A0 (CI) / A1 reviewed (R-AGE-PIN, R-RSA) / A4 |

## Risks

### R-T2-KR — Keyring unlock widens T2 (new, A1)
With keyring unlock on, `WrapKey` + header = DEK. Whether a same-user process can read the
`WrapKey` without the user noticing depends on the platform:

| Platform | A1 implementation (`keyring` v1 API) | Silent read by T2? | Required before shipping |
| --- | --- | --- | --- |
| macOS | Legacy file keychain item, app is on the item's ACL | Other apps get a Keychain prompt; code running inside our process does not | Data-protection keychain + `BiometryCurrentSet` (or `UserPresence` with an ADR amendment), signed with an access-group entitlement |
| Windows | Credential Manager, `CRED_PERSIST_ENTERPRISE` | **Yes** (`CredRead` as the user); also roams with the profile | Windows Hello-derived key (KeyCredentialManager signature → HKDF), or stays off; `persistence=Local` minimum |
| Linux | Secret Service collection | **Yes**, once the collection is unlocked (normal after login) | Off by default; explicit opt-in with a warning |

Status: **HOLD** wiring the keyring commands per platform until the right-hand column is done.
The vault-side wrap is approved.

### R-CAL — Calibration and hostile cost parameters
Calibration keeps creation-time cost between 64 MiB and 1 GiB. The *reader* accepts any
parameters above the floor, though: a planted or imported header with a 4 TiB memory cost
aborted the process (B2, fixed in the A1 fix round): a ceiling of 4 GiB / t 16 / p 16 in
`validate`, plus a host-RAM check in `derive_kek`. A header calibrated on a big machine may then refuse to unlock on a
small one. That is intended: it gives a clear error instead of swapping, and the user can
re-encrypt with the master password on the big machine.

### R-INV — Inventory metadata in plaintext (accepted, A1)
`mooring.db` holds connection names, hosts, ports, protocols, tags, folder names and credential
names and usernames in clear text. A T1 or T2 attacker gets the network topology and the
usernames without any password. Accepted per ADR-0005: the SQLCipher alternative duplicates
the vault AEAD and adds C crypto. Conditions: the file and directory modes from M2, FTS5
secure-delete / merge on close (L4; deleted rows may persist in FTS segments until close or
next open), and a revisit if T1 is upgraded (for example, for a laptop-loss policy) or
before A3 S3 sync uploads the DB.

### R-AGE-PIN — `age` built from a git commit, not crates.io (accepted, owner-approved, A1)
`age 0.12.1` on crates.io pins `ml-kem 0.2`. russh 0.65 needs `ml-kem 0.3`, and the two cannot
be in one build. The root `Cargo.toml` therefore patches age:
`[patch.crates-io] age = { git = "https://github.com/str4d/rage", rev = "b5b68c4" }`.
- `Cargo.lock` records the full hash `b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f`.
- That commit is the release-0.12.1 merge on `origin/main` of the official repository.
- It already contains the RustCrypto migration `f7c95f4`.
- `deny.toml` allows exactly that one git source.

Risk:
- The code is unreleased: no crates.io checksum and no release review by the author.
- Builds depend on the git source staying reachable.

Mitigations:
- The commit is pinned by hash in the lockfile.
- We use only the scrypt recipient (encrypt and decrypt). The vectors cover it:
  `make test-vectors` verifies them with the reference `age` CLI. The import caps (B2) also
  apply.

**Removal condition:**
- In the first PR after `age` ≥ 0.13 (on ml-kem ≥ 0.3) is published on crates.io, drop the
  patch and the `allow-git` entry, then re-run `make test-vectors`.
- If it is not published by A1 exit, revisit then.
- Do not move the pin to a newer commit without a security review.

### R-SSH-STR — russh takes some secrets as plain `String` (accepted, A1)
`Handle::authenticate_password` and `authenticate_keyboard_interactive_respond` take a `String`
by value. russh frees its internal copy but does not wipe it. Our own copies are `SecretString`
or `Zeroizing`.

Residue: one heap copy per login, until the allocator reuses the memory. Reading it needs a T2
with ptrace rights, which "no memory encryption while unlocked" already covers.

Conditions:
- No further APIs that take a secret as a plain `String`.
- On every russh upgrade, switch if a zeroizing API is available.

### R-RSA — `rsa` crate Marvin advisory (accepted, A1)
RUSTSEC-2023-0071 affects every `rsa` version and has no fix. russh uses `rsa` in two places:
- RSA host-key verification, which uses only public-key operations.
- Signing with a vault RSA key: one client-side signature per login.

Mooring has no RSA decryption oracle. `deny.toml` needs an `ignore` entry with this reason.
Revisit when a patched `rsa` ships. Docs should recommend Ed25519 keys.

### R-IPC-BUF — inward secrets pass through the IPC JSON buffer (accepted, A1)
`vault_unlock.password`, `credential_create.secret` and `session_send`'s `Answer.text` arrive
as JSON strings. The WebView's JS heap and Tauri's deserialisation buffer hold them unwiped
until they are garbage-collected. This is inherent to a WebView UI (ADR-0003); the Rust side
wraps each secret at the IPC edge. A T5 that already runs script could read these values as
the user types them anyway.

## Accepted risks (revisit)
- `style-src 'unsafe-inline'` for Tailwind/Vite. No script vector; revisit with nonces.
- No memory encryption while unlocked: an attacker with ptrace/debug rights on the same user
  session can read the DEK. OS-level mitigations (SIP, Windows protected process) are out of scope.
- R-INV (above).
- `sysinfo` (large FFI unsafe surface) used only to read total RAM; `forbid(unsafe_code)` rules
  out a local syscall. `age` pulls unused recipient code (hpke, ml-kem, p256).
- Password change does not rotate the DEK (ADR-0002): an old header + old password still opens
  records sealed before the change. The keyring wrap is dropped on change for the same reason.
- R-AGE-PIN, R-SSH-STR, R-RSA and R-IPC-BUF (above).
- TOFU itself: the first connection to a host is unauthenticated. A T5 can answer "yes" on the
  user's behalf; that is audited and cannot override a mismatch. The mitigation is to pre-seed
  `known_hosts`.
- Dynamic (SOCKS) forwards reach any host the server can reach, as `ssh -D` does. While the port
  is open, any same-user process (T2) can use the loopback SOCKS port.
- The ssh-agent is on by default. When no vault credential applies, the agent's public keys
  are offered to the server, which can link identities across hosts, as with OpenSSH. Agent
  forwarding is never requested.
- TOFU accepted but `known_hosts` not writable: the key is trusted for this session only. N-3
  makes that visible in the audit log.

## Open items
- [x] **A1 blockers:** B1, B2 fixed and tested (re-review, `1e76c3a`).
- [ ] **A1 exit (review 2):**
      - M-1: clear the clipboard on exit and on lock.
      - M-4: xterm `linkHandler` and a navigation guard.
      - L-1..L-6 and N-1..N-4, as scheduled in [a1-review-2.md](a1-review-2.md).
      - `deny.toml` ignore entry for RUSTSEC-2023-0071 (R-RSA).
- [ ] **Wiring gates (review 2):** no forwarding IPC before M-2 is fixed; no SFTP IPC before M-3
      and L-7 are fixed.
- [x] A1: L2 (durable header write + `.bak`) fixed in the Tauri layer (review 2).
- [ ] A1: fuzz targets `known_hosts_parse` and `socks_parse_request` (proptest only today).
- [ ] A1: manual clipboard check on each OS:
      - paste works, and the value is cleared after 30 s;
      - the value is absent from history managers, including GNOME/Wayland;
      - macOS Universal Clipboard (Handoff) behaviour.
- [ ] A1: remaining work:
      - Tauri auto-lock tick and the OS sleep/lock/window signals.
      - KDF work off the async worker (L-3).
      - Keyring commands per R-T2-KR.
      - Export/import commands with the `vault_id` merge policy.
      - `mlock`, best effort.
      - Already done: calibration in `vault_create` and change password ✓; clipboard clear after
        30 s ✓, except M-1.
- [x] A1: M2, L1, L3, L4, L5, N1, N2, N4 fixed (re-review).
- [ ] A1: still open from review 1:
      - M1: `keyring-core` + explicit stores, `persistence=Local`.
      - N3: lands in the `vault_export` PR.
      - N5: a KDF refusal is surfaced as `Unlock`.
      - N6: double checkpoint on close.
      - Done: `Store::close()` is called from `RunEvent::Exit` ✓ (review 2).
- [ ] A1: `cargo-fuzz` targets for `import_age` and `Header::from_bytes` (proptest stand-in
      only today); `.gitleaks.toml` allow-list for `crates/mooring-vault/tests/vectors/`.
- [ ] A1 exit: cargo-deny, cargo-audit, gitleaks green in CI (not run in the A1-1/2 review
      environment); `mooring-app` built on macOS, Windows, Linux.
- [ ] A2: separate WebView + capability for remote pages; RDP certificate pinning UX.
- [ ] A3: LDAP injection review, S3 sync integrity (version counters inside AEAD); revisit
      R-INV before the DB leaves the device; import `--merge` must re-check `vault_id`.
