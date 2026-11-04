# Threat model — Mooring (v1, Phase A1)

Owner: security-reviewer. Updated at every phase exit and whenever the attack surface changes.
Last change: A2 (ADR-0011, ADR-0012): RDP (IronRDP) and VNC (own RFB 3.8) sessions, certificate
TOFU, the Rust framebuffer and MFR1 frame path, the cliprdr/cut-text clipboard and screenshots.
See review [a2-review-5.md](a2-review-5.md). Earlier: A1 exit (ADR-0010) in
[a1-review-4.md](a1-review-4.md);
ADR-0009 typed credentials, the public release pipeline and the public scrub in
[a1-review-3.md](a1-review-3.md); A1 items 3–5 (SSH core, forwarding, SFTP,
ADR-0008 commands, UI, rename) in [a1-review-2.md](a1-review-2.md); A1 items 1–2 in
[a1-review.md](a1-review.md).

## Assets
| Asset | Where it lives | Impact if lost |
| --- | --- | --- |
| Vault secrets (passwords, keys, tokens, TOTP seeds, kubeconfigs, become passwords) | `credential_secret(credential_id, name, sealed)` in `mooring.db`, one row per secret, AAD = credential id ‖ 0x1F ‖ secret name (ADR-0009); migrated v2 rows keep legacy names `secret`/`secret2` until the reseal; DEK in RAM while unlocked | Compromise of every managed host; with `otp_seed` stored beside the password, of the second factor too |
| Credential metadata (`credential.fields_json`) | `mooring.db` **plaintext**, served to the WebView: usernames, domains, UPNs, OAuth client ids and token URLs, kubeconfig context names, SSH public keys and certificates, X.509 certificates, fingerprints, external references, become user, secret *names* | Account enumeration and key linkage (R-INV-CRED) |
| Master password | Nowhere (derived into KEK, zeroized) | Vault compromise |
| Vault header (`vault.header.json`) | Plaintext, authenticated; the only copy of the wrapped DEK | Loss = vault loss (availability); tamper = unlock fails |
| Keyring `WrapKey` (opt-in) | OS keyring, service `io.github.yyasar21.mooring`, account = `vault_id` | With the header: DEK (see R-T2-KR) |
| Export file (`*.age`) | Wherever the user puts it; age scrypt + per-field sealing inside | Offline guessing of export passphrase, then master password |
| Open sessions (terminal, screen) | Process memory, WebView | Live access to targets |
| Connection inventory (hosts, IPs, names, usernames, tags, topology) | `mooring.db` **plaintext** (ADR-0005) | Reconnaissance |
| Audit log | `audit.jsonl`, hash-chained, carries `vault_id` | Loss of accountability |
| SSH trust store (`known_hosts`) | `$APP_DATA/known_hosts` in OpenSSH format. New entries are written `\|1\|`-hashed, mode 0600. **Not** in the vault | Tamper (T2): MITM keys silently accepted for the hosts the attacker picks. Read: the host list (hashing hides the names of new entries) |
| RDP/VNC certificate pins | `$APP_DATA/known_rdp_certs`, `$APP_DATA/known_vnc_certs`: one line per pin, `\|2\|`-hashed `host:port` (HMAC-SHA256, 32-byte salt), SHA-256 of the leaf, mode 0600. **Not** in the vault (as `known_hosts`) | Tamper (T2): MITM certificates accepted, or the VNC downgrade guard removed, for the hosts the attacker picks. Read: the number of pinned hosts only |
| Remote screen content | Rust `FrameSink` (≤ 8192² RGBA per session), MFR1 messages in the WebView, a screenshot on the OS clipboard until the next lock | Disclosure of whatever the remote desktop shows |
| Remote clipboard text | OS clipboard (written by Rust from cliprdr / `ServerCutText`); its digest is tracked and the text is cleared on lock if unchanged | Any same-user process (T2) reads it; a hostile server can plant text to paste (R-CLIP) |
| Copied secret or OTP code | OS clipboard for ≤ 30 s (OTP: at most the code's remaining validity), excluded from history and cloud sync where the OS allows; cleared on lock and on exit | While it is there, any process in the same session and any clipboard manager can read it |
| Release signing identity | GitHub OIDC → Sigstore certificate for `release.yml` in this repo (cosign keyless); Apple, Azure, RPM and updater keys as GitHub secrets | Whoever can sign as `release.yml` ships trusted binaries to every user (R-REL) |
| Live port forwards | Loopback listeners in our process; remote listeners on the server | Anyone who reaches the bound address uses the tunnel into the target network |
| User's local files (SFTP) | Anywhere the OS user can read/write; reached through `sftp_upload` / `sftp_download` | Read: exfiltration of keys and tokens outside Mooring (`~/.ssh`, cloud CLIs). Write: code execution through rc files, `authorized_keys`, autostart entries (B-4) |
| Syslog mirror stream + config | Network to the collector (UDP/TCP/TLS); config plaintext under `app.syslog` in `mooring.db` | Inventory-class audit content on the wire; a silenced or redirected mirror removes the only off-host copy of the chain (R-SYSLOG) |

## Attackers
| ID | Attacker | Capability |
| --- | --- | --- |
| T1 | Stolen device / backup | Reads vault header, `mooring.db`, audit log, export files offline |
| T2 | Malicious local process (same user) | Reads files, reads the OS keyring where no ACL applies, may read process memory on some OSes |
| T3 | Network MITM | Intercepts/alters SSH, RDP, VNC, HTTPS, LDAPS traffic |
| T4 | Malicious remote server / hostile file | Sends hostile protocol bytes to our parsers: SSH transport, keyboard-interactive prompts, terminal escape sequences (OSC 8), SFTP replies and `limits`, server-opened channels. Hands the user a crafted export or header |
| T5 | Compromised WebView (XSS, malicious remote page in A2) | Runs JS inside the app, calls any exposed IPC command |
| T6 | Poisoned dependency (cargo/npm), GitHub Action or CI | Code execution at build time; inside the release workflow, access to that job's token, OIDC identity and signing secrets |

## Trust boundaries added in A2 (ADR-0011, ADR-0012)
- **App → RDP server.** TCP → X.224 → our rustls (ring) client with `TofuVerifier` → CredSSP
  (NTLM only; Kerberos off, `NoNetwork`) → IronRDP active stage. Everything after X.224 is
  hostile T4 input to IronRDP. NLA is required unless `allowTlsWithoutNla` is set (audited per
  connect). Standard RDP Security (RC4) is never offered.
- **App → VNC server.** Our RFB 3.8 client. The version, the security list and the VeNCrypt
  negotiation are pre-TLS and reachable by a T3. VeNCrypt X509 uses the same verifier and pin
  store as RDP. `prefer_tls` (default) may fall back to plaintext (R-VNC-PLAIN).
- **Rust → WebView (pixels).** Raw MFR1 over a per-session `Channel`, decoded strictly on both
  sides, with credit flow control (2 in flight). Clipboard text and screenshots never cross IPC.
- **Rust ↔ OS clipboard (remote text, screenshots).** Rust only. Remote text is tracked by
  digest and cleared on lock and exit; screenshots are cleared on lock (L-23: without decoding
  foreign images).
- **Trust decisions.** The Tauri `Gate` is the only writer of pins and the only auditor of
  answers. The protocol crates audit only `CertMismatch` and `CertCaValid`.

## Trust boundaries added in A1 exit (ADR-0010)
- **WebView → local file system (SFTP).** Before ADR-0010 the WebView had no local file reach.
  The local side of a transfer must be chosen by the user in a native dialog opened **by Rust**.
  The WebView receives only an opaque, single-use `pickId` and a display name (B-4 ✓, review 4
  re-review). The `main` capability is back to `core:default`.
- **App → syslog collector.** Outbound only. TLS (rustls/ring, system roots, host-name
  verification) is the default. UDP and TCP are explicit plaintext opt-ins with a UI warning.
  The collector is trusted to receive inventory-class data, and nothing is read back from it.
- **OS → app (auto-lock signals).** Window focus and clock jumps. A wrong signal only ever
  locks early (fail safe); a missed one is covered by the idle timer.
- **Dialog plugin.** `tauri-plugin-dialog` is registered. `tauri-plugin-fs` is compiled in
  but never registered, and no `fs:` permission exists. The asset-protocol scope that the
  dialog extends is inert (`protocol-asset` off).

## Mitigations (STRIDE)
| Threat | Mitigation | Status |
| --- | --- | --- |
| Spoofing: SSH server identity (T3) | TOFU through `SessionEvent::Prompt`; only `yes` stores the key. A changed or `@revoked` key is a hard stop with no prompt. Host certificates are refused. A re-key accepts only the key already accepted in this connection. Audited as `trust_decision` | A1 ✓ (open: L-5 concurrent-write race, L-6 expected fingerprint in the audit entry, N-3 session-only trust visibility) |
| Spoofing: RDP/VNC server identity (T3) | rustls 0.23 (ring, TLS 1.2+, no resumption). `TofuVerifier`: the pin is checked first (a match accepts whatever the chain; a different pin is a hard stop, `trust_mismatch`, audited), then webpki against the OS roots + `caPem` (certificate blocks only), which includes the name check (CA-valid → accept, audited, no pin); otherwise the handshake fails and the user is prompted with `CertificateInfo`, and `yes` pins and reconnects on a new TCP connection. Handshake signatures are always verified (loopback test). `trusted_once` lasts one connect. RDP: NLA required, CredSSP binds the TLS key. VNC: a pin makes the connection `require_tls` (downgrade guard) | A2 partial (review 5): **M-13** (no guard for CA-validated VNC hosts), L-20 (VNC trust store fails open), L-27 (VNC None with a configured password), N-23..N-25, N-27 (T5 can remove a pin + answer `yes`, audited) |
| Spoofing: trust UI (T4) | Server prompt text is sanitised (control characters stripped, 256 chars). The trust dialog must be chosen by prompt purpose, not by message text | A1 partial (L-2 open) |
| Tampering: SSH algorithms / downgrade (T3) | Only the ADR-0007 set is offered: mlkem768x25519, curve25519, ecdh and DH16/DH14-sha256 kex; ed25519, ecdsa and rsa-sha2 host keys; chacha20, AES-GCM and AES-CTR; SHA-2 (ETM) MACs. Strict kex (Terrapin) is on. No compression, CBC, SHA-1 or `ssh-rsa`. A test asserts the deny-list | A1 ✓ |
| Tampering: `known_hosts` file (T1, T2) | Atomic write, mode 0600; a file that hit a cap is never rewritten. Parser caps: 8 KiB per line, 10 000 lines. Property-tested | A1 ✓ (fuzz target owed). A same-user T2 can still edit the file; accepted, as with OpenSSH |
| Tampering: vault header (T1) | Header v2 is AAD of the DEK wrap, including `vault_id` and `keyring_wrap`; v1 AAD unchanged; v1↔v2 relabel fails; KDF floor on read | A0 ✓ / A1 ✓ |
| Tampering: sealed fields (T1) | XChaCha20-Poly1305 per field, random 24 B nonce, AAD = record id ‖ 0x1F ‖ field; store binds credential id + column (row/column swap → `Tampered`) | A0 ✓ / A1 ✓ |
| Tampering: keyring wrap (T1, T2) | Second wrap's AAD = header AAD (without wrap) ‖ 0x1F ‖ `keyring`; bound to KDF params, salt, vault id; enable/disable need master password | A1 ✓ (B1 fixed; OS commands on HOLD per R-T2-KR) |
| Tampering: audit log (T1, T2) | SHA-256 hash chain, `verify()`; file 0600; optional RFC 5424 mirror (`[mooring@… seq hash]`, the hash is the next entry's `prev`) over TLS/TCP/UDP, bounded non-blocking queue, drops counted; enable/disable/change audited with the host | A1 ✓ mirror (review 4); L-17, L-18 (start entry + hourly heartbeat), N-12 (`mooring@32473` until the PEN), N-13 ✓ (re-review). Open: registered IANA PEN before the first public release |
| Repudiation | Audit entries for vault + credential + session + trust events; `vault.lock` carries `reason ∈ {user, idle, screen_lock, sleep, window_hidden}` | A0 ✓ / A1 partial (lock reasons ✓; keyring/export/credential events with wiring) |
| Information disclosure: secrets in UI/logs (T5) | Credential ids only over IPC; hand-written `Debug`; error variants carry fixed strings, never values; `mooring_audit::redact` on sinks; no `println!` (lint); `SessionInput::Answer` is redacted in `Debug` and `Serialize` and is a `SecretString` end to end; IPC DTOs have no secret field (tested) | A0 ✓ / A1 ✓ |
| Information disclosure: RDP/VNC credentials in flight (T2, T3) | Vault → `SecretString` → IronRDP `String` only right before `connect_finalize`; activation factory rebuilt without the password; `creds` dropped after NLA; re-resolved from the vault on each reconnect. VNC: DES key in `Zeroizing`, `X509Plain` only inside TLS, `vnc_user_password` never sent outside TLS. Key/Unicode input redacted in `Debug` | A2 ✓ with R-RDP-STR. Open: **L-24** (CredSSP NTLM messages at `MOORING_LOG=debug`), N-29 (DES schedule not zeroized); plaintext VNC auth under R-VNC-PLAIN |
| Information disclosure: SSH credentials in flight (T2) | Vault → `Zeroizing` → `SecretString` → `ConnectParams`, which is moved into the auth round and dropped after it. Auth failure is reported generically | A1 ✓ (R-SSH-STR: russh keeps internal `String` copies; N-1: one extra copy on our side) |
| Information disclosure: clipboard (T2) | Rust side only (`arboard`). Copyable: secrets the kind schema flags `copyable` (passwords, passphrase, become password, tokens, client secret) and computed TOTP codes. Never copyable: `private_key`, `key_pem`, `kubeconfig_yaml`, `otp_seed`, `refresh_token`. History and cloud exclusion. Cleared if unchanged (digest compare) after 30 s (OTP: at expiry), on lock and on exit. Audited as `credential_copied {credential, name}` | A1 ✓ (M-1 fixed). Manual check on each OS owed |
| Information disclosure: credential fields (T1, T2, T5) | Fields are typed, `deny_unknown_fields`, and re-validated on every read. Secrets are never in `fields_json`. Derived values (fingerprint, contexts) cannot be set over IPC | A1: **B-3 open**. `x509.cert_pem` accepts non-certificate PEM blocks, so a private key can land in plaintext; the legacy reseal can be steered to write a secret into that field |
| Elevation: an imported kubeconfig runs code or reads files (T4) | Event-level YAML parser with caps: 1 MiB, depth 32, 100k nodes, one document. Refused: anchors, aliases, tags, duplicate keys, `exec`, `auth-provider`, `tokenFile`, cert/key paths and CA paths. The whole file is sealed | A1 partial: M-5 ✓, L-10 ✓, QA-F2 ✓ (ASCII case variants of section keys and duplicates), M-11 ✓ (fuzz oracle). **Open: M-12** (Unicode simple folding: `U+212A`→`k`, `U+017F`→`s`; refuse non-ASCII keys). Gate: no Kubernetes consumer before M-12 and the ASan fuzz run (R-YAML-DEQ) |
| Elevation / disclosure: `become` (T4) | Target user is shell-safe and checked before connect; the command is fixed; the password is sent once, only on a detected prompt, within 4 KiB, and never echoed by us | A1 partial: **M-6** (prompt matched in the command echo; failed escalation not detected) |
| Spoofing: a credential used with the wrong protocol (T5) | The compatibility matrix in `mooring-core` is enforced in Rust on connection create and update, on role set, and at resolve time (inherited credentials included). UI filtering is advisory | A1 ✓ |
| Information disclosure / elevation: SFTP local reads and writes (T4, T5) | `LocalPath` confined to a base: no `..` or absolute paths, `:` and DOS device names refused on every OS (L-7 ✓), canonical prefix check, symlink and directory targets refused, temp file persisted only on success; app data dir refused as a base; transfer audit and progress carry no path or contents | A1 ✓: B-4 (Rust-side dialog, single-use session-bound `pickId`, cleared on lock), L-15 (`overwrite` + `persist_noclobber`, trailing `.`/space refused), L-16 (part file + rename) (re-review). Open: L-19 (an upload replace resets the remote mode), N-17 (`overwrite` is WebView-asserted), N-18, N-19 |
| Information disclosure / elevation: remote content in the WebView (T4) | No remote content in `main`; terminal output is rendered by xterm only | A1 partial: **M-4** open (xterm's default OSC 8 handler opens links with `window.open`) |
| Information disclosure: memory (T2) | `Zeroizing` for DEK/KEK/WrapKey/plaintexts; DEK dropped on lock; auto-lock: activity = non-passive IPC, 5 s tick, sleep by clock jump, focus loss → `window_hidden`, `vault:locked` wipes the UI stores; policy changes audited | A1 partial: wiring ✓ (review 4); M-8 ✓ (passive list exported, polled-command guard), M-9 ✓ (`BLUR_GRACE` 60 s, Mooring dialog exempt), M-10 ✓ (external forwards closed on lock, UI re-adopts sessions and transfers) (re-review). Open: N-20 (dialog exemption unbounded); no native screen-lock/pre-sleep hook; `mlock` open |
| Information disclosure: inventory at rest (T1, T2) | Accepted plaintext (R-INV); data dir 0700 / db 0600 (M2); `secure_delete=ON`; FTS5 `optimize` + WAL truncate on close, rebuild on open (L4) | A1 ✓ (residue bound: deleted rows may persist in FTS segments until close / next open) |
| Information disclosure: export (T1) | age v1 scrypt (cap 2^20 on import; export pinned 2^18 — L5), passphrase ≥ 12 chars, fields stay sealed inside | A1 ✓ |
| Brute force on stolen header (T1) | Argon2id; calibrated cost 64 MiB–1 GiB (≤ RAM/4, never below floor 8 MiB/1/1), `t=3`, `p≤4` | A1 ✓ (calibration not yet wired into `vault_create`) |
| Denial of service: hostile header / import (T4) | Header ≤ 64 KiB; import ≤ 64 MiB in and out; scrypt `log_n ≤ 20` checked before work; KDF ceiling 4 GiB / t 16 / p 16 on read, `m ≤ RAM/2` before derive | A1 ✓ (B2 fixed) |
| Denial of service: hostile SSH server (T4) | Bounded event mpsc(256) for back-pressure, `Bytes` ≤ 64 KiB; keepalive 30 s × 3; keyboard-interactive 8 rounds × 16 prompts; SFTP listing cap 10 000; at most 8 SFTP requests in flight per block whatever `limits` says; 8 transfers per session; forward caps (64 forwards, 128 connections each, 32 KiB buffers); SOCKS handshake 10 s | A1 partial. M-3 ✓ (review 4). Open: L-1 (russh's defaults accept server-opened x11, agent and session channels); no handshake timeout (the UI applies one) |
| Denial of service: hostile protocol parsers (T4) | `forbid(unsafe)`, size caps, fuzz targets per parser (cargo-fuzz nightly + stable corpus replay in `cargo test`) | A1: fuzz targets ✓ for `known_hosts`, SOCKS request, vault header, `import_age`, kubeconfig. Owed: `fingerprint::*`, `otp::decode_seed`, `parse_account`, `export_json`, SOCKS handshake (`fuzz-api` feature). M-11 ✓; the kubeconfig oracle must also refuse non-ASCII keys (M-12). A2: targets ✓ for MFR1, `known_certs`, RFB server messages, ZRLE, Tight, RDP fast-path, certificate info, cliprdr text, input; owed **L-28** (RFB handshake, VeNCrypt, cut text, framebuffer ops, RDP reactivation, upstream IronRDP targets) |
| Denial of service / tampering: hostile RDP/VNC server (T4) | `panic = "unwind"`; each protocol driver runs in its own task and `FrameSink` recovers from poison. Caps: framebuffer ≤ 8192², every rect inside it, MFR1 n ≤ 256, VNC zlib ≤ 64 MiB per rect with exact Tight sizes and a ZRLE per-rect bound, cut text and cliprdr text ≤ 1 MiB, cursor ≤ 384², ServerInit/reason ≤ 4 KiB, Tight JPEG refused | A2 **partial**: **B-5** (RDP desktop size allocated before the 8192² check: a 17 GiB allocation aborts the process), **M-14** (IronRDP SVC/DVC/fast-path reassembly unbounded), **M-15** (C zlib inflates VNC streams in the app), L-21 (a panic is reported as `server_ended` and retried). Allocation failure aborts even under `unwind`. Worst case of one 8192² session ≈ 1 GiB (N-28) |
| Elevation: WebView → remote session (T5) | `session_open` only from the `main` label; inputs validated (`SessionInput::validate`, pointer and desktop bounds); view-only enforced in Rust; frame acks passive and credit-bounded; screenshot and clipboard audited | A2 partial: L-22 (`connection_options_set` unaudited: `caPem`, `allowTlsWithoutNla`, `allow_plaintext` …), L-25 (`ClipboardOffer` sends whatever the OS clipboard holds, including a copied vault secret), L-26 (screenshot / view-only while locked; the view-only toggle unaudited), N-26 (label check on `session_open` only; R5 must deny app commands to remote windows) |
| Elevation: port forwards expose internal networks (T5, LAN) | `Exposure::{Loopback, External}` on all three kinds, enforced in the crate; Mooring-side addresses must be IP literals or `localhost` (no implicit DNS); `external` needs the explicit flag (UI confirmation is advisory) and every open/close is audited with `exposure`; all forwards close with the session | A1 ✓ (M-2 fixed, review 4); M-10 ✓ (external forwards closed and audited on every lock), N-16 ✓ (target host refuses all Unicode `Cf`) (re-review) |
| Injection: store (T5 via future IPC) | Parameterised SQL only; FTS input quoted per token, operator-only tokens dropped, 256 chars / 16 tokens / limit ≤ 200; names/hosts/tags validated and capped | A1 ✓ |
| Elevation: WebView → OS (T5) | Capabilities `core:default` only (re-checked for A1 items 3–5: 30 app commands, no plugin; A1 exit: back to `core:default` with B-4 ✓, asserted by a test (no `dialog:`, no `fs:`); `tauri-plugin-dialog` registered for its Rust API only; `tauri-plugin-fs` never registered); CSP unchanged; `freezePrototype`; every command validates and caps its input and maps errors to `IpcError`; `invoke()` only in `ipc.ts`; no `innerHTML`; remote content in a separate window and capability | A0 ✓ / A1 ✓ (M-4 navigation guard open) / A2 |
| Supply chain (T6) | cargo-deny (licenses, bans, advisories; `aws-lc-rs`/`aws-lc-sys` banned in A2), cargo-audit, lockfiles, Dependabot (cargo, npm, actions); exactly one allowed git source (age). Reviewed in A2: the IronRDP set, `sspi` + R-RDP-FFI, `tokio-rustls`, `x509-parser`, `socket2`, `des`, `arboard` `image-data` (`image`, `moxcms`, `pxfm`, macOS `tiff`/`zune-jpeg`, R-IMG). Reviewed in A1: age, keyring 4, sysinfo, rusqlite (bundled), russh (ring only; no aws-lc in the lockfile), russh-sftp, hmac/sha1, arboard, base64, @xterm/*, @fontsource/chakra-petch. Reviewed for ADR-0009: saphyr-parser (+ arraydeque, R-YAML-DEQ), ssh-key rc, pem-rfc7468, data-encoding, hmac 0.13, sha1 0.11, sha2 0.11 (`sha2-next`) | A1 reviewed (R-AGE-PIN, R-RSA, R-YAML-DEQ). `ci.yml`/`security.yml` still tag-pinned (L-14) |
| Supply chain: release pipeline (T6) | Releases are drafts, published by hand. Every release action pinned by SHA; no cache; `persist-credentials: false`; secrets exported only when set and never echoed. `SHA256SUMS` signed with cosign keyless (Rekor), SLSA provenance per file, CycloneDX SBOMs. The Homebrew bump cosign-verifies before rendering; the tap PAT is scoped to one repo | A4 prep: **M-7** (build jobs hold `contents: write`; `finalize` runs `cargo install` and syft with `id-token: write`), L-12, L-13. Workflows not yet executed |

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

### R-INV-CRED — credential metadata in plaintext (accepted, ADR-0009)
Extends R-INV. `credential.fields_json` is readable by T1/T2 and served to the WebView (T5). It
holds:
- usernames, NetBIOS domains, UPNs and vSphere accounts;
- OAuth `client_id`, `token_url` and `scope`, and API header names;
- the become method and user, and kubeconfig context names;
- OpenSSH public keys and certificates (principals, key id, signing CA);
- X.509 certificates (subject and SANs, often internal host names);
- `SHA256:` fingerprints, which link one key across hosts and services;
- `external_ref` references (vault paths, item names);
- OTP parameters, and `secretNames` (which accounts have a second factor or a passphrase).

A stolen `mooring.db` therefore gives account enumeration and identity linkage, not only
topology.

Conditions:
- No key material, token or password may ever be a plain field. B-3 is the test case:
  `cert_pem` holds certificates only.
- `fields_json` is not authenticated. A DB writer can change a username or a kind, but cannot
  read or move a secret: the AAD binds id and name, and kind and name are re-validated on read.
  A MAC over fields is a candidate ADR before A3 sync.
- Revisit together with R-INV before the DB leaves the device.

### R-YAML-DEQ — `arraydeque` unsafe in the YAML scanner (accepted, ADR-0009)
`saphyr-parser` has no `unsafe` of its own. Its lookahead buffer, `arraydeque` 0.5.1, has 72
`unsafe` sites and is rarely released. It parses hostile kubeconfigs (T4).

Mitigations:
- The input is capped at 1 MiB before parsing.
- The parser runs only on an explicit user import.
- A cargo-fuzz target under ASan is owed before any Kubernetes consumer.

Removal: when saphyr drops the dependency.

### R-REL — release signing trust (accepted with conditions, A4 prep)
Users trust what `release.yml` in `yyasar21/Mooring` signs: `verify-release.sh` and the
Homebrew job accept the Sigstore identity `release.yml@refs/tags/<tag>` or `@refs/heads/main`.
Anything that runs inside a job with `id-token: write` can sign as that identity. The platform
signing secrets sit in the environment of the bundling step, and so in the environment of npm
and cargo build scripts (Tauri's bundler reads them from there).

Conditions:
- M-7: split the jobs by privilege; no third-party installs in the signing job.
- L-12: the verifier fails closed.
- L-13: review or replace `artifact-signing-cli`.
- A human publishes each draft, after running `verify-release.sh`.

### R-SYSLOG — the audit mirror (accepted with conditions, A1 exit)
- **Plaintext transports.** UDP and TCP send inventory-class audit content (hosts, names,
  usernames, fingerprints; never secret values) in clear, and anyone on the path can drop or
  forge messages. They are accepted only as an explicit opt-in:
  - TLS is the default;
  - the settings card warns while a plaintext transport is selected and must keep warning while
    one is saved.
- **The mirror bounds tampering only after an entry is shipped.** A T2 can stop future shipping
  by editing or deleting `app.syslog` or by killing the process. Mitigations:
  - L-18 ✓: `audit_syslog_started` on every start that has a stored config, and an hourly
    `audit_heartbeat` while the mirror runs;
  - **collectors alert on a missing heartbeat.** This is the control that works against T2: a
    start entry for a disabled or deleted config reaches only the local chain, which T2 can
    rewrite;
  - `dropped` is a lower bound.
- **SD-ID.** `mooring@32473` (RFC 5612 documentation PEN) until Mooring's IANA PEN is assigned
  (N-12 ✓); switch before the first public release.

### R-SFTP-LOCAL — local files reachable through SFTP (accepted, A1 exit)
With B-4 fixed (re-review), the residual risk is this: a user who picks a folder can be
handed server-named files there, and a user who picks a file sends it to the server they
chose. Both are the intended function.
- The WebView can open the picker (IPC), but only the user's choice in the OS dialog yields a
  pick.
- A pick is single-use, bound to its session and mode, valid for 10 min, and cleared on lock.
- `overwrite` is asserted by the WebView (N-17). A T5 can replace one single-component name
  inside the folder the user picked; a Rust-side native confirm follows in A2.
- L-15 ✓ and L-16 ✓.
- Open: L-19 (keep the remote mode on replace), N-18 (bound the `sftp.exists` retries) and
  N-19 (no pick while locked).

The app data dir stays refused as a base.

### R-RDP-FFI — `sspi/scard` C and FFI tree (accepted by the owner, ADR-0011 decision 2)
`ironrdp-connector` turns on `sspi/scard`, which pulls in `winscard` 0.4.0, `cryptoki` 0.12.1
(+ `libloading`: dlopen of PKCS#11 modules), `async-dnssd` 0.5.1 (macOS, FFI to dns_sd) and,
through `winscard` → `flate2/zlib`, `libz-sys` 1.1.31 (C zlib, the system library where
pkg-config finds it).
- **Not executed:** smart-card credentials are never built (`creds.rs` maps only password
  kinds), and Kerberos/KDC discovery is off (`kerberos_config: None`, `NoNetwork`).
- **Executed:** C zlib. Feature unification makes every `flate2` user in the app use it,
  including VNC's ZRLE and Tight inflate of hostile bytes (**M-15**). The fix is to inflate
  with `miniz_oxide` directly.
- Removal: the upstream pull request that makes `scard` an opt-in feature (tracked here). When
  it lands, `cargo tree -p mooring-app -i libz-sys` must be empty.

### R-RDP-STR — IronRDP takes the password as a plain `String` (accepted, ADR-0011)
`Credentials::UsernamePassword.password` is built from our `SecretString` right before
`connect_finalize`, which consumes the connector. It is dropped there and not wiped. `sspi`
then holds the password as its own zeroizing `Secret<String>`. The activation factory
(IronRDP's clone of the config) is rebuilt from the password-free config, so no copy lives for
the session. The residue is one heap copy per connect, as in R-SSH-STR.
- Conditions: the same as R-SSH-STR; upstream ask: `Credentials` over `Zeroizing<String>`.
- IronRDP's `Credentials` derives a plaintext `Debug`. Neither IronRDP nor Mooring formats it
  today (review 5); re-check on every IronRDP upgrade. The CredSSP `TsRequest` debug lines
  carry the NTLM exchange: L-24 caps them at `info`.

### R-CLIP — remote clipboard text on the OS clipboard (accepted, ADR-0011)
With the default policy `both`:
- Remote → local is automatic. The server's copied text lands on the OS clipboard, where any
  same-user process (T2) and every clipboard manager can read it. A hostile server can also
  plant text that the user later pastes into a local terminal (pastejacking).
- Local → remote: `ClipboardOffer` (on tab focus) makes Rust read the OS clipboard and announce
  it. That includes a vault secret placed there by `credential_copy` within its 30 s, which is
  the intended "copy the password, paste it remotely" flow, and a T5 can trigger it on any
  session.

Mitigations:
- Text only, ≤ 1 MiB, and history/cloud exclusion where the OS allows.
- `session.clipboard { direction, bytes }` is audited, at most once per second per direction.
- Remote text is cleared on lock and exit if it is unchanged.
- The policy is per connection (`off`, `to_remote`, `from_remote`, `both`), enforced in Rust.

Open: L-25 (no remote writes while locked; audit a vault secret sent to a remote).

### R-VNC-PLAIN — VNC without TLS (accepted per connection, ADR-0012 decision 4)
`allow_plaintext`, and `prefer_tls` when the server offers no usable VeNCrypt, run RFB in the
clear. The framebuffer, the input and the type-2 DES response (an 8-byte password,
offline-crackable) are readable and modifiable on the path, and a MITM can strip VeNCrypt.
Mitigations:
- A permanent "Unencrypted" badge and `session.vnc.plaintext` on every connect.
- `vnc_user_password` is never sent outside TLS.
- The downgrade guard: a pin makes the host `require_tls`.

The badge appears only after the DES response has been sent, so the guard is the real control.
- Open: **M-13** (the guard must also cover CA-validated hosts), L-27 (no None with a
  configured password).
- U2 shows the fallback risk in the connection form while `prefer_tls` is selected.

### R-IMG — the `image` stack in the app (accepted for encoding only, review 5)
`session_screenshot` puts our own RGBA on the clipboard through `arboard` `image-data`. That
brings in `image` 0.25.10, `moxcms` 0.8.1 (ICC profiles, 356 `unsafe` sites) and `pxfm` 0.1.30
(SIMD math, 225), plus `tiff`/`zune-jpeg` on macOS and the BMP/PNG codecs on Windows.
- Accepted only for **encoding our own framebuffer**.
- Decoding foreign clipboard images is refused (L-23). Today the lock path calls `get_image`
  and so decodes what a T2 put there, inside the process that holds the DEK.
- Revisit in A3: per-OS clipboard set with `png` 0.18 (`forbid(unsafe)`) alone.

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
- R-AGE-PIN, R-SSH-STR, R-RSA, R-IPC-BUF, R-INV-CRED, R-YAML-DEQ and R-REL (above).
- A2: R-RDP-FFI, R-RDP-STR, R-CLIP, R-VNC-PLAIN and R-IMG (above).
- Certificate TOFU (RDP/VNC), as for SSH: the first connection to a self-signed host is
  unauthenticated. A T5 can answer `yes` and can remove a pin first (N-27). Both are audited,
  and a mismatch is never overridable without the removal. CA-validated hosts are not pinned,
  so a CA reissue never stops a connection.
- A TOTP seed stored beside the password (ADR-0009): whoever opens the vault holds both
  factors. The UI warns on attach, and `credential_otp_attached` is audited.
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
- GHSA-wrw7-89jp-8q8g (`glib` 0.18, Linux only): pulled in by Tauri's GTK/WebKitGTK bindings,
  which pin the gtk-rs 0.18 line; no Mooring code calls `glib` directly. Fixed upstream in
  gtk-rs 0.20, which Tauri has not adopted yet. Revisit at every Tauri minor; the alert is left
  open on purpose until then.

## Open items
- [ ] **A1 exit (review 4, re-review after fix round 4: `APPROVE WITH NITS`):**
      - [x] **B-4 (blocker):** dialog opened in Rust with single-use `pickId`; capability back
        to `core:default`; ADR-0010 amendment.
      - [x] M-8, M-9, M-10, M-11, QA-F2, L-15..L-18, N-10..N-16.
      - [ ] **M-12:** refuse non-ASCII kubeconfig keys, and extend the oracle and seeds
        (Kubernetes gate).
      - [ ] L-19 before the first public release; N-17..N-22 as scheduled.
- [ ] **ADR-0009 (review 3):**
      - **B-3 (blocker):** `cert_pem` holds certificates only; `move_certificate` fails
        closed; a UI paste of certificate + key is split.
      - M-5 ✓ and L-10 ✓ (review 4), and the fuzz target with its oracle ✓ (M-11). Gate: no
        Kubernetes session or kubeconfig import before M-12 is fixed.
      - M-6: the `become` prompt is matched in the command echo; detect a failed escalation.
      - L-11: call `reseal_legacy` from `vault_unlock`, before the first public release.
      - Fuzz targets: `kubeconfig_parse`, `ssh_public_key`, `ssh_certificate`,
        `ssh_private_key`, `x509_pem`, `otp_decode_seed`, `parse_account`.
      - N-5..N-7.
- [ ] **Release (review 3):**
      - M-7: split the jobs by privilege before the first signed release.
      - L-12, L-13, L-14, N-8, N-9.
      - **G-1:** publish from a fresh repository with one squashed commit. Never make the
        existing repository public: its history still holds the scrubbed lab identifiers.
- [x] **A1 blockers:** B1, B2 fixed and tested (re-review, `1e76c3a`).
- [ ] **A1 exit (review 2):**
      - [x] M-1: clear the clipboard on exit and on lock (confirmed fixed in review 3).
      - [x] M-4: xterm `linkHandler`. The inert handler was seen in review 3; the navigation
        guard still needs confirming.
      - L-1..L-6 and N-1..N-4, as scheduled in [a1-review-2.md](a1-review-2.md).
      - `deny.toml` ignore entry for RUSTSEC-2023-0071 (R-RSA).
- [x] **Wiring gates (review 2):** M-2, M-3 and L-7 are fixed (review 4).
- [x] A1: L2 (durable header write + `.bak`) fixed in the Tauri layer (review 2).
- [x] A1: fuzz targets `known_hosts_parse` and `socks5_handshake` (request parser) (review 4).
- [ ] A1: manual clipboard check on each OS:
      - paste works, and the value is cleared after 30 s;
      - the value is absent from history managers, including GNOME/Wayland;
      - macOS Universal Clipboard (Handoff) behaviour.
- [ ] A1: remaining work:
      - Tauri auto-lock tick ✓ (review 4); native OS screen-lock / pre-sleep hooks still open.
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
- [ ] A1: `cargo-fuzz` targets for `import_age` and `Header::from_bytes` ✓ (review 4); `.gitleaks.toml` allow-list for `crates/mooring-vault/tests/vectors/`.
- [ ] A1 exit: cargo-deny, cargo-audit, gitleaks green in CI (not run in the A1-1/2 review
      environment); `mooring-app` built on macOS, Windows, Linux.
- [ ] **A2 (review 5, `BLOCKER`):**
      - [ ] **B-5 (blocker):** validate the RDP desktop size before `DecodedImage::new`.
      - [ ] M-13 (VNC TLS-seen marker), M-14 (IronRDP reassembly cap, upstream + interim),
        M-15 (VNC inflate with `miniz_oxide`) before the A2 tag.
      - [ ] L-20..L-28 before the A2 tag; N-23..N-29 as scheduled.
      - [ ] Upstream: `sspi/scard` opt-in (R-RDP-FFI), IronRDP `Zeroizing` credentials
        (R-RDP-STR), reassembly limits (M-14).
- [ ] A2: separate WebView + capability for remote pages (R5, ADR-0013; N-26); full RDP/VNC
      certificate pinning UX and known-certs manager (U2).
- [ ] A3: LDAP injection review, S3 sync integrity (version counters inside AEAD); revisit
      R-INV before the DB leaves the device; import `--merge` must re-check `vault_id`.
