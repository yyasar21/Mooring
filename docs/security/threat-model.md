# Threat model — Nexus Remote (v1, Phase A1)

Owner: security-reviewer. Updated at every phase exit and whenever the attack surface changes.
Last change: A1 items 1–2 (ADR-0005 store, ADR-0006 vault lifecycle), review
[a1-review.md](a1-review.md).

## Assets
| Asset | Where it lives | Impact if lost |
| --- | --- | --- |
| Vault secrets (passwords, keys, tokens) | `credential.secret`/`secret2` in `nexus.db`, sealed per field; DEK in RAM while unlocked | Full lab compromise |
| Master password | Nowhere (derived into KEK, zeroized) | Vault compromise |
| Vault header (`vault.header.json`) | Plaintext, authenticated; the only copy of the wrapped DEK | Loss = vault loss (availability); tamper = unlock fails |
| Keyring `WrapKey` (opt-in) | OS keyring, service `xyz.homelab.nexus`, account = `vault_id` | With the header: DEK (see R-T2-KR) |
| Export file (`*.age`) | Wherever the user puts it; age scrypt + per-field sealing inside | Offline guessing of export passphrase, then master password |
| Open sessions (terminal, screen) | Process memory, WebView | Live access to targets |
| Connection inventory (hosts, IPs, names, usernames, tags, topology) | `nexus.db` **plaintext** (ADR-0005) | Reconnaissance |
| Audit log | `audit.jsonl`, hash-chained, carries `vault_id` | Loss of accountability |
| Trust store (host keys, cert pins) | Vault (A2) | MITM |

## Attackers
| ID | Attacker | Capability |
| --- | --- | --- |
| T1 | Stolen device / backup | Reads vault header, `nexus.db`, audit log, export files offline |
| T2 | Malicious local process (same user) | Reads files, reads the OS keyring where no ACL applies, may read process memory on some OSes |
| T3 | Network MITM | Intercepts/alters SSH, RDP, VNC, HTTPS, LDAPS traffic |
| T4 | Malicious remote server / hostile file | Sends hostile protocol bytes to our parsers; hands the user a crafted export/header |
| T5 | Compromised WebView (XSS, malicious remote page in A2) | Runs JS inside the app, calls any exposed IPC command |
| T6 | Poisoned dependency (cargo/npm) or CI | Code execution at build time |

## Mitigations (STRIDE)
| Threat | Mitigation | Status |
| --- | --- | --- |
| Spoofing: server identity (T3) | TLS 1.2+/rustls with system + lab CA; SSH host-key TOFU with change = hard stop; RDP NLA default on | A2 |
| Tampering: vault header (T1) | Header v2 is AAD of the DEK wrap, including `vault_id` and `keyring_wrap`; v1 AAD unchanged; v1↔v2 relabel fails; KDF floor on read | A0 ✓ / A1 ✓ |
| Tampering: sealed fields (T1) | XChaCha20-Poly1305 per field, random 24 B nonce, AAD = record id ‖ 0x1F ‖ field; store binds credential id + column (row/column swap → `Tampered`) | A0 ✓ / A1 ✓ |
| Tampering: keyring wrap (T1, T2) | Second wrap's AAD = header AAD (without wrap) ‖ 0x1F ‖ `keyring`; bound to KDF params, salt, vault id; enable/disable need master password | A1 ✓ (B1 fix pending: failed enable/disable must not leave DEK in RAM) |
| Tampering: audit log (T1, T2) | SHA-256 hash chain, `verify()`; file 0600; syslog mirror to xlog01 optional | A0 ✓ (mirror open) |
| Repudiation | Audit entries for vault + credential + session + trust events; `vault.lock` carries `reason ∈ {user, idle, screen_lock, sleep, window_hidden}` | A0 ✓ / A1 partial (lock reasons ✓; keyring/export/credential events with wiring) |
| Information disclosure: secrets in UI/logs (T5) | Credential ids only over IPC; hand-written `Debug`; error variants carry fixed strings, never values; `nexus_audit::redact` on sinks; no `println!` (lint) | A0 ✓ / A1 ✓ |
| Information disclosure: memory (T2) | `Zeroizing` for DEK/KEK/WrapKey/plaintexts; DEK dropped on lock; pure auto-lock clock (idle 15 min, screen lock, sleep, window hidden) | A1 partial: clock ✓, Tauri tick + OS signals open; Argon2 internals not wiped (L3); `mlock` open |
| Information disclosure: inventory at rest (T1, T2) | Accepted plaintext (R-INV); data dir 0700 / db 0600 required (M2); `secure_delete=ON`; FTS rebuilt on open | A1 partial (M2, L4 open) |
| Information disclosure: export (T1) | age v1 scrypt (cap 2^20 on import; export pinned 2^18 — L5), passphrase ≥ 12 chars, fields stay sealed inside | A1 ✓ (L5 open) |
| Brute force on stolen header (T1) | Argon2id; calibrated cost 64 MiB–1 GiB (≤ RAM/4, never below floor 8 MiB/1/1), `t=3`, `p≤4` | A1 ✓ (calibration not yet wired into `vault_create`) |
| Denial of service: hostile header / import (T4) | Header ≤ 64 KiB; import ≤ 64 MiB in and out; scrypt `log_n ≤ 20` checked before work; **KDF ceiling missing (B2)** | A1 **blocker B2** |
| Denial of service: hostile protocol parsers (T4) | `forbid(unsafe)`, size caps, fuzz targets per parser | A2 |
| Injection: store (T5 via future IPC) | Parameterised SQL only; FTS input quoted per token, operator-only tokens dropped, 256 chars / 16 tokens / limit ≤ 200; names/hosts/tags validated and capped | A1 ✓ |
| Elevation: WebView → OS (T5) | Capabilities `core:default` only; CSP strict; `freezePrototype`; no new commands in A1-1/2; remote content in separate window/capability | A0 ✓ / A2 |
| Supply chain (T6) | cargo-deny (licenses, bans, advisories), cargo-audit, lockfiles, Dependabot, pinned Actions by SHA, SBOM + provenance; A1 deps reviewed (age, keyring 4, sysinfo, rusqlite bundled) | A0 (CI) / A1 reviewed / A4 |

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
aborts the process (B2). Fix: a ceiling of 4 GiB / t 16 / p 16 in `validate`, plus a host-RAM
check in `derive_kek`. A header calibrated on a big machine may then refuse to unlock on a
small one. That is intended: it gives a clear error instead of swapping, and the user can
re-encrypt with the master password on the big machine.

### R-INV — Inventory metadata in plaintext (accepted, A1)
`nexus.db` holds connection names, hosts, ports, protocols, tags, folder names and credential
names and usernames in clear text. A T1 or T2 attacker gets the lab topology and the
usernames without any password. Accepted per ADR-0005: the SQLCipher alternative duplicates
the vault AEAD and adds C crypto. Conditions: the file and directory modes from M2, FTS5
secure-delete (L4), and a revisit if T1 is upgraded (for example, for a laptop-loss policy) or
before A3 S3 sync uploads the DB.

## Accepted risks (revisit)
- `style-src 'unsafe-inline'` for Tailwind/Vite. No script vector; revisit with nonces.
- No memory encryption while unlocked: an attacker with ptrace/debug rights on the same user
  session can read the DEK. OS-level mitigations (SIP, Windows protected process) are out of scope.
- R-INV (above).
- `sysinfo` (large FFI unsafe surface) used only to read total RAM; `forbid(unsafe_code)` rules
  out a local syscall. `age` pulls unused recipient code (hpke, ml-kem, p256).
- Password change does not rotate the DEK (ADR-0002): an old header + old password still opens
  records sealed before the change. The keyring wrap is dropped on change for the same reason.

## Open items
- [ ] **A1 blockers:** B1 (state restore on failed keyring enable/disable), B2 (KDF ceiling on
      read). Both must be fixed before the keyring, export and import commands are wired.
- [ ] A1: Tauri auto-lock tick + OS sleep/lock/window signals; calibration in `vault_create`
      and change password (blocking thread); keyring commands per R-T2-KR; export/import
      commands with the `vault_id` merge policy; clipboard clear (30 s); `mlock` best effort.
- [ ] A1: M1 (`keyring-core` + explicit stores, `persistence=Local`), M2 (0700/0600), L1
      (lock on header-persist failure), L2 (durable header write + `.bak`), L3 (argon2
      `zeroize`), L4 (FTS5 secure-delete, WAL checkpoint on close), L5 (export log N = 18).
- [ ] A1: `cargo-fuzz` targets for `import_age` and `Header::from_bytes` (proptest stand-in
      only today); `.gitleaks.toml` allow-list for `crates/nexus-vault/tests/vectors/`.
- [ ] A1 exit: cargo-deny, cargo-audit, gitleaks green in CI (not run in the A1-1/2 review
      environment); `nexus-app` built on macOS, Windows, Linux.
- [ ] A2: separate WebView + capability for remote pages; RDP certificate pinning UX.
- [ ] A3: LDAP injection review, S3 sync integrity (version counters inside AEAD); revisit
      R-INV before the DB leaves the device; import `--merge` must re-check `vault_id`.
