# Threat model — Nexus Remote (v0, Phase A0)

Owner: security-reviewer. Updated at every phase exit and whenever the attack surface changes.

## Assets
| Asset | Where it lives | Impact if lost |
| --- | --- | --- |
| Vault secrets (passwords, keys, tokens) | `vault.*` on disk (encrypted), DEK in RAM while unlocked | Full lab compromise |
| Master password | Nowhere (derived into KEK, zeroized) | Vault compromise |
| Open sessions (terminal, screen) | Process memory, WebView | Live access to targets |
| Connection inventory (hosts, IPs, topology) | Vault (encrypted fields in A1) | Reconnaissance |
| Audit log | `audit.jsonl`, hash-chained | Loss of accountability |
| Trust store (host keys, cert pins) | Vault (A1) | MITM |

## Attackers
| ID | Attacker | Capability |
| --- | --- | --- |
| T1 | Stolen device / backup | Reads vault file and audit log offline |
| T2 | Malicious local process (same user) | Reads files, may read process memory on some OSes |
| T3 | Network MITM | Intercepts/alters SSH, RDP, VNC, HTTPS, LDAPS traffic |
| T4 | Malicious remote server | Sends hostile protocol bytes to our parsers |
| T5 | Compromised WebView (XSS, malicious remote page in A2) | Runs JS inside the app |
| T6 | Poisoned dependency (cargo/npm) or CI | Code execution at build time |

## Mitigations (STRIDE)
| Threat | Mitigation | Status |
| --- | --- | --- |
| Spoofing: server identity (T3) | TLS 1.2+/rustls with system + lab CA; SSH host-key TOFU with change = hard stop; RDP NLA default on | A1/A2 |
| Tampering: vault file (T1) | AEAD per field with record/field AAD; header authenticated as AAD of DEK wrap; KDF floor | A0 ✓ |
| Tampering: audit log (T1, T2) | SHA-256 hash chain, `verify()`; file 0600; syslog mirror to xlog01 optional | A0 ✓ (mirror A1) |
| Repudiation | Audit entries for vault + credential + session + trust events | A0 ✓ (events wired in A1) |
| Information disclosure: secrets in UI/logs (T5) | Credential ids only over IPC; redacted `Debug`; `nexus_audit::redact` on sinks; no `println!` (lint) | A0 ✓ |
| Information disclosure: memory (T2) | `Zeroizing`/`SecretBox`; DEK dropped on lock; auto-lock on idle/screen lock/sleep (A1); `mlock` best effort (A1) | partial |
| Denial of service: hostile parsers (T4) | `forbid(unsafe)`, size caps, fuzz targets per parser | A1/A2 |
| Elevation: WebView → OS (T5) | Capabilities `core:default` only; CSP strict; `freezePrototype`; remote content in separate window/capability | A0 ✓ / A2 |
| Supply chain (T6) | cargo-deny (licenses, bans, advisories), cargo-audit, lockfiles, Dependabot, pinned Actions by SHA, SBOM + provenance | A0 (CI) / A4 |

## Accepted risks (revisit)
- `style-src 'unsafe-inline'` for Tailwind/Vite. No script vector; revisit with nonces.
- No memory encryption while unlocked: an attacker with ptrace/debug rights on the same user
  session can read the DEK. OS-level mitigations (SIP, Windows protected process) are out of scope.
- Argon2 parameters are fixed at 256 MiB until A1 calibrates per host.

## Open items
- [ ] A1: auto-lock triggers, OS keyring wrap, clipboard clear, `age` export vectors.
- [ ] A2: separate WebView + capability for remote pages; RDP certificate pinning UX.
- [ ] A3: LDAP injection review, S3 sync integrity (version counters inside AEAD).
