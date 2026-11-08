# Threat model — Mooring (v1, Phases A1–A5, 0.2.0)

Owner: security-reviewer. Updated at every phase exit and whenever the attack surface changes.
Last change: A5 / 0.2.0 (ADR-0022..0028, ADR-0018 A1–A2): jump hosts, biometric unlock, backup
export/import, dynamic secrets, 1Password Connect, Bitwarden `bws`, FIDO2 keys, RD Gateway,
smart cards, build identity and Move to Applications, platform signing jobs and winget. See
review [a5-review-9.md](a5-review-9.md). Before that: 0.1.1 (ADR-0021): portable mode (marker-resolved data root, Windows ACL, portable
zips). See review [a4-1-review-8.md](a4-1-review-8.md). Before that: A4 (ADR-0018..0020): the
v0.1.0 release pipeline and the in-app updater, the file
importers and the LDAPS directory importer, and the OS network tools. See review
[a4-review-7.md](a4-review-7.md). Earlier: A3 (ADR-0014..0017) in
[a3-review-6.md](a3-review-6.md); A2
(ADR-0011..0013) in [a2-review-5.md](a2-review-5.md); A1 exit (ADR-0010) in
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
| Kubernetes bearer tokens / client keys (A3) | Vault (kubeconfig, `kube_token` credentials); in RAM only for an open cluster session, dropped on lock | API access to the cluster as that identity (read-only through Mooring, unrestricted elsewhere) |
| vCenter session token, VMRC tickets (A3) | RAM only (`Zeroizing`); the session is logged out on lock; a VMRC ticket lives ≤ 60 s and is handed to the OS URL handler | Inventory and power control as that account; one console on one VM (ticket) |
| Vault / OpenBao tokens (A3) | RAM only (`TokenCache`, `Zeroizing`); ours revoked on lock and exit | Read of every KV path the token's policy allows |
| Sync objects (A3) | S3 bucket: MSY1 blobs (AEAD under an HKDF subkey of the DEK), `history/`, and the vault **header** as its own object | Header: offline guessing of the master password (as T1). Blobs: none without the DEK; rollback and fork are detected, withholding is not |
| Updater signing key (A4) | GitHub **environment** secret `TAURI_SIGNING_PRIVATE_KEY` (+ password) of `release`, read only by the `sign-updater` job, and the owner's password manager; public half compiled into the app (`plugins.updater.pubkey`) | Code execution on every in-app install whose manifest the holder can also serve (R-UPD, M-17) |
| Import plans (A4) | RAM only (`ImportPlans`, ≤ 8, 10 min, single use, cleared on lock); opted-in plaintext secrets `Zeroizing` | The secrets of one import (Termius passwords/keys, opted-in `~/.ssh` keys) |
| LDAP certificate pins (A4) | `known_ldap_certs`, same format and sync as the other pins | A pinned hostile directory receives bind passwords |
| Kube / vSphere / Vault / sync certificate pins (A3) | `known_{kube,vsphere,vault,sync}_certs`, same format as the RDP/VNC pins; **synced** to every device of the vault (owner decision 10) | A pin accepted on one device is trusted on all (L-35) |

## Attackers
| ID | Attacker | Capability |
| --- | --- | --- |
| T1 | Stolen device / backup | Reads vault header, `mooring.db`, audit log, export files offline |
| T2 | Malicious local process (same user) | Reads files, reads the OS keyring where no ACL applies, may read process memory on some OSes |
| T3 | Network MITM | Intercepts/alters SSH, RDP, VNC, HTTPS, LDAPS traffic |
| T4 | Malicious remote server / hostile file | Sends hostile protocol bytes to our parsers: SSH transport, keyboard-interactive prompts, terminal escape sequences (OSC 8), SFTP replies and `limits`, server-opened channels. Hands the user a crafted export or header |
| T5 | Compromised WebView (XSS, malicious remote page in A2) | Runs JS inside the app, calls any exposed IPC command |
| T6 | Poisoned dependency (cargo/npm), GitHub Action or CI | Code execution at build time; inside the release workflow, access to that job's token, OIDC identity and signing secrets |
| T7 | Sync storage operator (S3 provider, bucket admin, anyone with the bucket keys) (A3) | Reads, replays, withholds, deletes or replaces any object, serves an old generation, logs request URLs; cannot forge MSY1 without the DEK |
| T8 | Compromised jump host or RD Gateway (A5) | Sees and alters the plaintext of protocols it relays when they carry no end-to-end protection (VNC `none`, HTTP in a web-via window), sees target names and timing, can drop or delay; cannot pass the target's own SSH / TLS / NLA pin. A gateway terminating TLS also receives the gateway sign-in (NTLM, or Basic when allowed) |

## Trust boundaries added in A5 (ADR-0022..0028, ADR-0018 A1–A2) — review 9

- **T-BIO, App → OS biometric store.** macOS: `WrapKey` in a data-protection keychain item
  (`BiometryCurrentSet`, `WhenUnlockedThisDeviceOnly`), Developer-ID builds only. Windows:
  `WrapKey = HKDF(Hello signature over a fixed per-vault challenge)`, key in the TPM/KSP. Linux:
  not offered. No process reads the key without a gesture. **R-BIO-PROMPT** (accepted,
  opt-in): a T2 process can *trigger* the OS prompt (on Windows, an unpackaged app's
  `KeyCredentialManager` key is reachable by any same-user process) and a user who approves it
  hands over a wrap key that stays valid until re-enrolment (the challenge is fixed).
  3 failures in 10 min, password change, biometry change and vault rotation suspend and delete
  the OS item.
- **Jump hosts (T8).** Each hop: own TOFU, own credential, own keepalive; failures end before
  the target is contacted. No listener for SSH / SFTP / RDP / VNC / kube. **R-WEB-VIA**
  (accepted with review 9 L-47 / L-48): a web window behind hops uses an unauthenticated SOCKS5
  port on `127.0.0.1` for its lifetime; any local process can use it; the engine bypasses it for
  loopback and (WebView2) WebRTC UDP. macOS refuses web-via in this build.
- **RD Gateway (T3, T8).** Own MS-TSGU WebSocket transport, bounded parsers with fuzz targets,
  `known_rdg_certs` TOFU with mismatch hard stop. NTLM without channel binding until review 9
  M-19 lands (relay by a first-contact impostor; EPA gateways refuse); Basic only per
  connection, audited. Kerberos unsupported.
- **External tools (R-SEC-CLI, R-SK-HELPER).** `bws` (fixed paths, cleared env, token in the
  child env only, own TLS without our pins, change detection per process — review 9 L-50);
  `ssh-sk-helper` off by default. A T2 writer of the tool path receives the token: same class as
  T2 everywhere else.
- **Agents (R-PIV-AGENT).** FIDO2 and PIV signing go through the user's ssh-agent; Mooring
  verifies every signature against the pinned key and the FIDO2 UP flag. A PIN-unlocked card
  stays loaded in the agent until review 9 L-49 adds a lifetime; any same-user process can use
  the agent socket (as with OpenSSH).
- **Backups (T1, T4).** `age` v2 documents: caps before reading, scrypt ceiling, header floor
  before any KDF, whole-file refusal. **R-IMPORT-TRUST**: importing a file is trusting it;
  `merge` unions trust stores (review 9 L-52 narrows that to hosts not pinned locally).
- **Dynamic secrets.** Leases in memory only, renewed at 2/3 TTL, revoked on close / lock /
  exit with the issuing token; a crash leaves them to Vault's TTL.
- **Install hygiene (ADR-0028).** Dev and release identities never share a data dir, updater
  or identifier; Move to Applications uses fixed-path tools, never elevates, never strips
  quarantine. Writers of `/Applications` (admin = the user) can race the swap: no privilege
  boundary is crossed.
- **Release (T6).** Platform signing only in `environment: release` jobs; `build` holds no
  platform secret; winget submission token: review 9 L-54.

## Trust boundaries added in 0.1.1 (ADR-0021, portable mode) — T-PORT

Portable mode moves every file Mooring owns from the per-user OS directories to
`<marker dir>/Mooring Data/{data,cache}`, next to the executable, on whatever volume the user
chose. The marker (`portable`, a regular file) is the only switch; its content is ignored.
Nothing changes in the vault format (Argon2id + XChaCha20-Poly1305, ADR-0002), the audit chain,
the IPC surface, the capabilities or the CSP. What changes is **who else can reach the folder**:

- **T-PORT-1 Co-located writer (T2, or another account with write access to the folder: a
  shared USB stick, a network share, a shared Desktop).** Can replace `Mooring.exe` /
  `Mooring.app`, swap `Mooring Data` or a subdirectory for a link or junction between the
  resolver's check and its create (N-68), or edit `portable`. Portable mode does **not** defend
  against this and the ADR accepts it (any portable application has the same property; an
  installed per-user copy is only marginally better). The resolver refuses links, reparse points
  and non-directories at every level *before* creating or chmod'ing anything (`dirs.rs`), so a
  redirect must win a race, not merely pre-exist. The audit chain still detects log tampering;
  the vault stays encrypted at rest.
- **T-PORT-2 Removable media (T1).** A lost stick is a lost vault: the finder holds the header,
  `mooring.db`, the audit log and `known_hosts`. Only the master password and the KDF floor
  protect it (R-CAL: keep the calibrated floor even on slow media). README and the user guide
  say so; no claim of "safe if lost" is made (L-46).
- **T-PORT-3 No ACL on FAT / exFAT.** On NTFS the root gets `OWNER RIGHTS:(OI)(CI)F` with
  inheritance removed (`portable_acl.rs`: fixed path, fixed argv, `env_clear`, no shell, 10 s,
  killed, non-fatal). On FAT32 / exFAT the volume has no ACLs, `icacls` fails and
  `portable.acl_unavailable` is audited: every account on that machine that can mount the stick
  reads the (encrypted) files. On unix, `0700` applies where the volume supports modes (L-45 for
  FAT on Linux / macOS).
- **T-PORT-4 WKWebView site data on macOS.** WebKit's persistent store cannot be redirected,
  so in portable mode persistent web profiles are downgraded to ephemeral
  (`web.portable_ephemeral`, `incognito(true)` = nonPersistent data store): nothing of a web
  session lands in `~/Library/WebKit`. The main window's own localStorage (UI state, no
  secrets, ADR-0003) still does, as do the OS's per-app state files (saved application state,
  preferences, LaunchServices); none holds a secret. Windows / Linux: the main window's profile
  moves to `Mooring Data/cache/webview`.
- **T-PORT-5 Reparse points and cloud placeholders (Windows).** `FILE_ATTRIBUTE_REPARSE_POINT`
  on the marker, the root or `data` / `cache` is refused, which covers symlinks, junctions,
  mount points, OneDrive / Dropbox / iCloud placeholders and WOF-compressed files. The refusal
  is deliberate: a redirect to another volume or profile, and a synced vault is a copy off the
  device. The message must say so (L-46).
- **T-PORT-6 Silent fallback.** The owner's decision is "refuse, never fall back". Two
  mechanisms make the marker look *absent* rather than invalid and so take the installed-mode
  branch: macOS App Translocation of a quarantined bundle launched in place (**M-18**, tag
  condition) and an inherited or forged `$APPIMAGE` (L-44). Both are fixes in `dirs.rs`.
- **Release side.** The two portable zips are regular release assets (SHA256SUMS, cosign,
  provenance) and never updater artifacts: excluded from `sign-updater` (lint-pinned), refused
  by `updater-manifest.sh`, rejected by `verify-release.sh`, and the client's matrix answers
  `Manual(Portable)` before any bundle check, so a portable copy never downloads or installs.
  `portable-zip.py` is deterministic and validates its own archive names; symlink targets are
  stored verbatim (N-69 residual, inputs are our own build outputs: R-REL).
- Unchanged by ADR-0021 and re-checked: N-12 (syslog SD-ID), the audit mirror, the import
  plans, the B-6 Gate, the updater trust chain (R-UPD, L-40 manifest cap still due 0.1.1).

## Trust boundaries added in A4 (ADR-0018..0020)
- **Release workflow → users.** `release.yml` builds in `contents: read` jobs, hashes the
  workflow artifacts in `finalize` (no checkout, pinned cosign / attest only), signs
  `SHA256SUMS` keyless and attests every file; a human publishes the draft. The updater key is a
  second root. It is read only by `sign-updater` (`environment: release`, no checkout, pinned
  CLI; M-17 ✓), behind the owner's deployment approval.
- **GitHub → updater (T3, T6, repo write).** `latest.json` is unsigned. It is fetched over
  `https` from the fixed `releases/latest/download` endpoint: platform verifier, OS proxy
  honoured, redirects `https` only. The offered version must be greater than the running one,
  the artifact must carry a minisign signature by the compiled-in key, and the plugin installs
  only where no elevation is needed. The signature must carry the offered version (L-39 ✓), the
  download URL must be this repository's release of that version, and the download is capped
  (L-40 ✓). The manifest itself is capped only after parsing (accepted until 0.1.1, R-UPD).
- **Import files (T4).** Royal TS, RDM, Termius, mRemoteNG, PuTTY and OpenSSH exports are
  picked in Rust (a `pickId`, never a path over IPC) or read from `~/.ssh/config` /
  `~/.putty/sessions/`. They are parsed under caps into a plan held in Rust. Secrets are read
  only with the opt-in and only from plaintext formats. The opt-in key read is confined to
  `~/.ssh` and to the known `~/.ssh/config` source (L-41 ✓). The apply is one transaction into
  a new folder.
- **App → LDAPS directory (T3, T4).** Our own LDAP v3 reader (bind, paged search, abandon,
  unbind) over tokio-rustls, with the `mooring-http` verifier and `known_ldap_certs` TOFU
  through the B-6 Gate. Every server frame is scanned iteratively (≤ 256 KiB, depth ≤ 32)
  before `lber` parses it. The bind password leaves only after a trusted handshake **and** a
  native sign-in confirmation per (credential, host) per unlocked session (L-43 ✓).
- **App → OS network tools.** `ping`, `traceroute` / `tracepath` / `TRACERT.EXE` and
  `wg show` run from fixed absolute paths with explicit argv, no shell and a cleared
  environment; output is capped and sanitised, and the tool is killed at the deadline. There
  is also a TCP connect check (no bytes sent), at most 1/s. No elevation, no raw sockets
  (owner decision 19).

## Trust boundaries added in A3 (ADR-0014..0017)
- **App → HTTPS APIs (`mooring-http`).** One client for kube, vCenter, Vault and S3: our
  rustls (ring) verifier (pin before CA, webpki name check, signatures always verified,
  resumption off), per-protocol pin stores, anchored mode for an explicit CA, no proxy, no
  environment, redirects refused, body caps and (buffered calls) a body deadline. `http://` only
  to a loopback IP literal. Everything after the handshake is T4 input.
- **App → Kubernetes API.** `kube::Client → ReadOnlyGuard → Bearer → HttpService`. The guard is
  a closed allow-list of 13 literal routes (reads, three self-reviews, exec and port-forward
  upgrades) checked before any byte leaves. Exec opens one of five shells (owner decision 3,
  R-KUBE-EXEC); pod forwards bind loopback only; logs are sanitised. Kubeconfig resolution is
  ours: exec plugins, auth-providers, proxies and basic auth are refused. Everything ends on
  lock.
- **App → vCenter.** REST session from a vault credential; inventory (capped, names cleaned)
  into a read-only, device-local subtree; power actions behind an opt-in **and** a Rust-native
  dialog (M-16); VMRC tickets to the OS URL handler (R-VMRC-ARGV); the vSphere Client in a
  `web-*` window (ADR-0013 rules, vCenter origin only).
- **App → Vault / OpenBao.** Token, AppRole or OIDC login; root tokens refused; tokens in RAM
  only and revoked on lock (L-34). `external_ref` credentials resolve at connect time into
  zeroized buffers; tests return names only.
- **IdP page → app (`oidc-*` window).** Empty capability, Rust label guard, navigation = IdP
  origin + `allowedOrigins`; the `http://localhost:8250` redirect is intercepted in
  `on_navigation`, never loaded, bound to `state`, and useless without the `client_nonce` that
  never leaves Rust. Per-OS interception is still to be verified (ADR-0016 §4 E2E).
- **App ↔ sync storage (T7).** MSY1: AAD = the 125-byte header (vault, device, counter,
  parent hash, header hash), random XChaCha20 nonce, key = HKDF(DEK, vault_id). Rollback and
  fork are sticky hard stops; the remote header must equal the local one byte for byte. Trust
  stores are synced (owner decision 10); secret sources, audit log, web stores, keyring wrap and
  vSphere subtrees are not.
- **Native confirmations.** Power, VMRC, certificate trust (vSphere, sync) and fork resolution
  are answered only in Rust-opened dialogs; the WebView has no `dialog:` permission. A T5 still
  chooses *when* they appear (M-16). Since fix round 7, one dialog at a time
  (`confirm.busy`) and a 10 s cool-down after a cancelled destructive one (`confirm.cooldown`).
  Neither Return nor Escape/close may confirm. `tauri-plugin-dialog` remaps rfd's positional
  results to slot labels (B-6, review 6b), so every dialog is `YesNoCancelCustom("Cancel",
  <ok>, "Not now")`. Return (slot 1) and Escape/close (the plugin's cancel slot) both carry a
  refusing label, and only the middle button confirms (fix round 8, re-review 6c; per-OS QA
  owed). The sync trust prompt is two dialogs: "Trust once" first, then "Trust and remember".
  A bump of `tauri-plugin-dialog` or `rfd` needs a re-read (`golden.rs` pins both).
- **Synced trust stores (L-35).** A host with more than one distinct pin (or two SSH keys of
  one type) fails closed with `http.trust_conflict` / `CloseCode::TrustConflict`, never
  prompted. Trust-once cannot override it. The conflict is listed in `sync_status.conflicts`
  until the user removes the pins.

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

## Trust boundaries added in A2 R5 (ADR-0013)
- **Remote web page → app.** Each web connection opens its own `web-<connectionId>` window.
  The bridge is still injected (Tauri 2.12.5), so the isolation comes from three things:
  - the `AppManifest` (every app command needs an explicit grant);
  - the empty `web` capability with no `remote` block;
  - the Rust label guard (`guard::with_guard`), which refuses every command from `web-*` and
    from unknown labels before the auto-lock hook.

  Top-level navigation is limited to the start origin and `allowedOrigins`. The app origin,
  non-http(s) schemes and userinfo are always refused. Downloads, new windows and permission
  requests are denied natively.
- **Detached session window → app.** `detached-<sessionId>` loads the bundled UI, so it has
  the same trust as `main`. It is granted six session commands, for its own `sessionId` only.
- **Web storage → disk.** Ephemeral by default. A per-connection persistent store
  (`$APP_DATA/web/<uuid>`, or the macOS ≥ 14 identifier) is opt-in and audited (R-WEB-COOKIE).
- **Lock → secondary windows.** Every `web-*` and `detached-*` window is hidden on lock and
  shown after unlock.

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
| Spoofing: RDP/VNC server identity (T3) | rustls 0.23 (ring, TLS 1.2+, no resumption). `TofuVerifier`: the pin is checked first (a match accepts whatever the chain; a different pin is a hard stop, `trust_mismatch`, audited), then webpki against the OS roots + `caPem` (certificate blocks only), which includes the name check (CA-valid → accept, audited, no pin); otherwise the handshake fails and the user is prompted with `CertificateInfo`, and `yes` pins and reconnects on a new TCP connection. Handshake signatures are always verified (loopback test). `trusted_once` lasts one connect. RDP: NLA required, CredSSP binds the TLS key. VNC: a pin makes the connection `require_tls` (downgrade guard) | A2 ✓ (review 5 re-review): M-13 ✓ (Gate-written `tls-required` marker for CA-valid VeNCrypt hosts), L-20 ✓, L-27 ✓ (`allowNoAuth` opt-in, audited), N-23..N-25 ✓; `once` answer = `trusted_once` for one connect, audited. Accepted: N-27 (T5 can remove a pin + answer `yes`, audited) |
| Spoofing: trust UI (T4) | Server prompt text is sanitised (control characters stripped, 256 chars). The trust dialog must be chosen by prompt purpose, not by message text | A1 partial (L-2 open) |
| Tampering: SSH algorithms / downgrade (T3) | Only the ADR-0007 set is offered: mlkem768x25519, curve25519, ecdh and DH16/DH14-sha256 kex; ed25519, ecdsa and rsa-sha2 host keys; chacha20, AES-GCM and AES-CTR; SHA-2 (ETM) MACs. Strict kex (Terrapin) is on. No compression, CBC, SHA-1 or `ssh-rsa`. A test asserts the deny-list | A1 ✓ |
| Tampering: `known_hosts` file (T1, T2) | Atomic write, mode 0600; a file that hit a cap is never rewritten. Parser caps: 8 KiB per line, 10 000 lines. Property-tested | A1 ✓ (fuzz target owed). A same-user T2 can still edit the file; accepted, as with OpenSSH |
| Tampering: vault header (T1) | Header v2 is AAD of the DEK wrap, including `vault_id` and `keyring_wrap`; v1 AAD unchanged; v1↔v2 relabel fails; KDF floor on read | A0 ✓ / A1 ✓ |
| Tampering: sealed fields (T1) | XChaCha20-Poly1305 per field, random 24 B nonce, AAD = record id ‖ 0x1F ‖ field; store binds credential id + column (row/column swap → `Tampered`) | A0 ✓ / A1 ✓ |
| Tampering: keyring wrap (T1, T2) | Second wrap's AAD = header AAD (without wrap) ‖ 0x1F ‖ `keyring`; bound to KDF params, salt, vault id; enable/disable need master password | A1 ✓ (B1 fixed; OS commands on HOLD per R-T2-KR) |
| Tampering: audit log (T1, T2) | SHA-256 hash chain, `verify()`; file 0600; optional RFC 5424 mirror (`[mooring@… seq hash]`, the hash is the next entry's `prev`) over TLS/TCP/UDP, bounded non-blocking queue, drops counted; enable/disable/change audited with the host | A1 ✓ mirror (review 4); L-17, L-18 (start entry + hourly heartbeat), N-12 ✓ (`mooring@67553`, IANA PEN assigned 2026-11-06), N-13 ✓ (re-review) |
| Repudiation | Audit entries for vault + credential + session + trust events; `vault.lock` carries `reason ∈ {user, idle, screen_lock, sleep, window_hidden}` | A0 ✓ / A1 partial (lock reasons ✓; keyring/export/credential events with wiring) |
| Information disclosure: secrets in UI/logs (T5) | Credential ids only over IPC; hand-written `Debug`; error variants carry fixed strings, never values; `mooring_audit::redact` on sinks; no `println!` (lint); `SessionInput::Answer` is redacted in `Debug` and `Serialize` and is a `SecretString` end to end; IPC DTOs have no secret field (tested) | A0 ✓ / A1 ✓ |
| Information disclosure: RDP/VNC credentials in flight (T2, T3) | Vault → `SecretString` → IronRDP `String` only right before `connect_finalize`; activation factory rebuilt without the password; `creds` dropped after NLA; re-resolved from the vault on each reconnect. VNC: DES key in `Zeroizing`, `X509Plain` only inside TLS, `vnc_user_password` never sent outside TLS. Key/Unicode input redacted in `Debug` | A2 ✓ with R-RDP-STR. L-24 ✓ (CredSSP/sspi targets pinned at `info`; N-38 span directives to check; user-guide note owed), N-29 ✓; plaintext VNC auth under R-VNC-PLAIN |
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
| Denial of service / tampering: hostile RDP/VNC server (T4) | `panic = "unwind"`; each protocol driver runs in its own task and `FrameSink` recovers from poison. Caps: framebuffer ≤ 8192², every rect inside it, MFR1 n ≤ 256, VNC zlib ≤ 64 MiB per rect with exact Tight sizes and a ZRLE per-rect bound, cut text and cliprdr text ≤ 1 MiB, cursor ≤ 384², ServerInit/reason ≤ 4 KiB, Tight JPEG refused | A2 ✓ (review 5 re-review): B-5 ✓ (size checked before any allocation), M-14 ✓ interim (8 MiB reassembly cap before IronRDP; upstream open), M-15 ✓ (VNC inflates with `miniz_oxide`), L-21 ✓ (a panic → one `protocol_error`). Allocation failure aborts even under `unwind`, so every server-sized allocation must be checked first. Worst case of one 8192² session ≈ 1 GiB (N-28) |
| Elevation: WebView → remote session (T5) | `session_open` only from the `main` label; inputs validated (`SessionInput::validate`, pointer and desktop bounds); view-only enforced in Rust; frame acks passive and credit-bounded; screenshot and clipboard audited | A2 ✓ (review 5 re-review): L-22 ✓ (`connection_options_changed`, `weakened` → warning), L-25 ✓ (no remote writes or offers while locked; `credential_sent_to_remote`), L-26 ✓, N-26 ✓ (central label guard, R5) |
| Elevation: remote web page → Mooring IPC (T5 in `web-*`) | `AppManifest` + empty `web` capability (no `remote`) + Rust guard on every command (`ipc.forbidden`, not counted as activity); the only ACL-exempt command is the per-webview channel `fetch`. Navigation guard: exact origins, app origin / non-http(s) / userinfo always refused; new windows, downloads and permission requests denied; `devtools(false)`; zoom hotkeys off; the native title shows the real origin; the page title reaches `main` sanitised | A2 ✓ (re-review of R5). Open: N-31 (`*.localhost`), N-32 (init script), L-31 (page-raised native dialogs, unverified per OS); runtime E2E per OS owed (ADR-0013 test plan); R-WEB-ENGINE |
| Information disclosure: cookies and site data across web connections (T5, T1, T2) | Ephemeral by default; persistent per connection (`$APP_DATA/web/<uuid>` 0700, or the macOS ≥ 14 identifier; macOS 11–13 falls back to ephemeral, audited); the path is built from the canonical UUID only; `web_clear_data` and `connection_delete` wipe it | A2 partial: **L-29** (Windows: ephemeral windows share one InPrivate session), **L-30** (`folder_delete` cascade and the Windows lock leave stores on disk); R-WEB-COOKIE |
| Elevation: detached session window (T5 in `detached-*`) | Bundled UI, the same CSP and navigation guard as `main`; capability = six session commands, own `sessionId` only (Rust); the route is fixed at boot; hidden on lock; closing re-attaches to `main` | A2 ✓. N-30 (lock race on create), N-36 (UI manifest test may skip) |
| Spoofing / disclosure: windows outside the lock screen (T2 bystander, T5) | `vault::lock` hides every `web-*` and `detached-*` window, and unlock shows them; `web_focus`, `web_print`, `web_open` and `window_detach` refuse while locked; focus of web and detached windows counts for the blur grace only (the idle timer still runs) | A2 ✓; L-31 (dialogs raised by a hidden page), N-30 |
| Elevation: port forwards expose internal networks (T5, LAN) | `Exposure::{Loopback, External}` on all three kinds, enforced in the crate; Mooring-side addresses must be IP literals or `localhost` (no implicit DNS); `external` needs the explicit flag (UI confirmation is advisory) and every open/close is audited with `exposure`; all forwards close with the session | A1 ✓ (M-2 fixed, review 4); M-10 ✓ (external forwards closed and audited on every lock), N-16 ✓ (target host refuses all Unicode `Cf`) (re-review) |
| Injection: store (T5 via future IPC) | Parameterised SQL only; FTS input quoted per token, operator-only tokens dropped, 256 chars / 16 tokens / limit ≤ 200; names/hosts/tags validated and capped | A1 ✓ |
| Elevation: WebView → OS (T5) | Capabilities `core:default` only (re-checked for A1 items 3–5: 30 app commands, no plugin; A1 exit: back to `core:default` with B-4 ✓, asserted by a test (no `dialog:`, no `fs:`); `tauri-plugin-dialog` registered for its Rust API only; `tauri-plugin-fs` never registered); CSP unchanged; `freezePrototype`; every command validates and caps its input and maps errors to `IpcError`; `invoke()` only in `ipc.ts`; no `innerHTML`; remote content in a separate window and capability | A0 ✓ / A1 ✓ (M-4 navigation guard open) / A2 ✓: `AppManifest` (R5); `main` = `core:default` + `mooring-main`, `detached` = six commands, `web` = none; no `dialog:`/`fs:`/`shell:`/`http:`/`opener:`/`core:window`/`core:webview` anywhere (tested). Open: L-32 (Tauri not pinned to the reviewed 2.12.5) |
| Supply chain (T6) | cargo-deny (licenses, bans, advisories; `aws-lc-rs`/`aws-lc-sys` banned in A2), cargo-audit, lockfiles, Dependabot (cargo, npm, actions); exactly one allowed git source (age). Reviewed in A2: the IronRDP set, `sspi` + R-RDP-FFI, `tokio-rustls`, `x509-parser`, `socket2`, `des`, `arboard` `image-data` (`image`, `moxcms`, `pxfm`, macOS `tiff`/`zune-jpeg`, R-IMG). Reviewed in A1: age, keyring 4, sysinfo, rusqlite (bundled), russh (ring only; no aws-lc in the lockfile), russh-sftp, hmac/sha1, arboard, base64, @xterm/*, @fontsource/chakra-petch. Reviewed for ADR-0009: saphyr-parser (+ arraydeque, R-YAML-DEQ), ssh-key rc, pem-rfc7468, data-encoding, hmac 0.13, sha1 0.11, sha2 0.11 (`sha2-next`) | A1 reviewed (R-AGE-PIN, R-RSA, R-YAML-DEQ). `ci.yml`/`security.yml` still tag-pinned (L-14) |
| Supply chain: release pipeline (T6) | Releases are drafts, published by hand. Every release action pinned by SHA; no cache; `persist-credentials: false`; secrets exported only when set and never echoed. Jobs split by privilege (M-7 ✓); `finalize` hashes workflow artifacts and refuses unsigned draft assets. `SHA256SUMS` signed with cosign keyless (Rekor), SLSA provenance per file, CycloneDX SBOMs, `latest.json` inside `SHA256SUMS`. `verify-release.sh` fails closed (L-12 ✓) and checks the manifest. The Homebrew bump cosign-verifies before rendering; the tap PAT is scoped to one repo | A4 (review 7 / 7b): M-17 ✓ in the workflow (`sign-updater`, environment secret, lint); **owner:** `release` environment, `v*` / `main` rulesets. N-57 ✓, N-58 ✓, N-8 ✓; N-61 (lint gaps). Carried: L-13 (before Azure secrets), L-14 (semgrep digest, owner). Workflows not yet executed (rc.2 dry run pending) |
| Tampering / elevation: in-app updates (T3, T6) | Rust-only plugin, registered only with a pubkey; no `updater:*` permission anywhere (test); main-only, vault-gated commands; strict semver upgrade only; minisign verification against the compiled-in key before any write; install only where the user can write (deb/rpm/MSI/Homebrew/unwritable → manual); `https_only` incl. redirects; notes plain text, sanitised, 4 KiB; single flight, 60 s gap; background check opt-in, badge only | A4 (review 7 / 7b): L-39 ✓, L-40 ✓ (manifest in-flight cap accepted until 0.1.1), N-51 ✓, N-55 ✓; N-56 partial; N-62, N-63. R-UPD |
| Denial of service / disclosure: hostile import files (T4) | Caps before allocation (16 MiB input, gzip 64 MiB and 20:1, XML depth 64 / 200 000 elements / 4 KiB values, item caps); `DOCTYPE` refused; predefined + numeric entities only; ZIP refused; errors carry offsets, never content; one fuzz target per parser + `detect`; secrets only with the opt-in, never mRemoteNG; plan in Rust; one transaction | A4 (review 7 / 7b): L-41 ✓, N-53 ✓, N-59 ✓, N-60 ✓. R-IMPORT-SECRET |
| Spoofing / disclosure: LDAPS directory (T3, T4, T5) | `ldaps://` only; our verifier + `known_ldap_certs` TOFU through the B-6 Gate; bind after a trusted handshake; four operations only; iterative BER pre-scan; caps on entries, pages, frames, values; referrals ignored; errors carry result codes only | A4 (review 7 / 7b): L-43 ✓ (sign-in confirmation; TLS probe before the dialog accepted), N-54 ✓; N-64 (`caPem` audit). R-LDAP-STR |
| Elevation / probing: OS network tools (T5, T4) | Fixed absolute paths, explicit argv with `--` where accepted, `Target` never starts with `-`/`/`, `env_clear`, no shell, kill on cap/deadline, parsers capped and fuzzed, read-only `WgQuery`, ≤ 2 processes, 1 port check/s, vault-gated, no elevation | A4 (review 7 / 7b): N-52 ✓. R-NET-PROBE |
| Tampering / disclosure: portable data root (T1, T2, T-PORT) | Regular-file marker checked with `symlink_metadata`; symlink / reparse point / directory → refusal, never "absent"; `Mooring Data`, `data`, `cache` refused when linked or not a directory before anything is created; `0700` + re-tighten on unix, `OWNER RIGHTS` ACL with inheritance removed on NTFS (fixed argv, `env_clear`, 10 s, non-fatal, audited when unavailable); no fallback to the OS dirs on any error (native box, exit 2, no window); `app.start { portable }` without a path; `app_info` is the only reader of the path | 0.1.1 (review 8): ✓ with **M-18** (macOS App Translocation → silent fallback, tag condition), L-44 (`$APPIMAGE`), L-45 (FAT on unix), L-46 (docs); N-65..N-68. R-PORT |
| Tampering: portable zips vs the updater (T3, T6) | Zips are release assets only: `sign-updater` excludes `*_portable.zip` (lint-pinned), `updater-manifest.sh` refuses a `.zip` `.sig`, `verify-release.sh` fails on a `.zip.sig` or a `.zip` in `latest.json`; the client's matrix returns `Manual(Portable)` first; background check never installed, opt-in refused and audited | 0.1.1 (review 8): ✓; N-69 (symlink self-check), N-70 (lint quoting), N-71 (zip content check) |

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
Homebrew job accept only the Sigstore identity `release.yml@refs/tags/<tag>` (N-58 ✓, re-review
7b; a run that does not come from the tag ref is refused in `create-release`).
Anything that runs inside a job with `id-token: write` can sign as that identity. The platform
signing secrets sit in the environment of the bundling step, and so in the environment of npm
and cargo build scripts (Tauri's bundler reads them from there).

Conditions:
- M-7 ✓ (review 7): jobs split by privilege; no third-party installs in the signing job.
- L-12 ✓ (review 7): the verifier fails closed.
- L-13: review or replace `artifact-signing-cli` before the Azure secrets are created.
- A human publishes each draft, after running `verify-release.sh`.
- M-17 (3) — **owner action, tag condition** (re-review 7b): the updater secrets are
  environment secrets of a protected `release` environment (tags `v*` only, owner as
  reviewer), no repository secret of that name, rulesets on `v*` tags and on `main`. The owner
  reviews the `.github/workflows/` diff since the last tag before approving the deployment
  (anything merged there runs next to the key). Platform secrets stay repository secrets
  (R2 owner action 4).
- L-14: the `semgrep` container digest (owner, Docker Hub access needed). N-61: widen the
  workflow lint (`toJSON(secrets)`, `secrets[`, `secrets: inherit`, other `environment:
  release`).

### R-PORT — a portable folder is only as private as its volume (accepted, ADR-0021)
In portable mode the vault, the audit log, `known_hosts` and the web profiles live next to the
executable. Accepted, as the ADR states:
- A co-located writer (T-PORT-1) can replace the executable or race the resolver (N-68). No
  portable application defends against this; the installed per-user copy is only marginally
  better (`%LOCALAPPDATA%` is the same user). Mitigation: the README's "verify `SHA256SUMS`
  first" and the audit chain.
- FAT32 / exFAT volumes carry no ACL or mode (T-PORT-3): every local account that mounts the
  stick reads the encrypted files. `portable.acl_unavailable` makes that visible in the audit
  log; the KDF floor and the master password are the protection (R-CAL).
- macOS keeps the UI's localStorage and the OS's per-app state under `~/Library` (T-PORT-4);
  neither holds a secret. Persistent web profiles are downgraded to ephemeral rather than
  written there.
- `app_info.portableDataDir` shows the absolute path (user name, drive) to the WebView; a T5
  learns it. Accepted: the owner chose to display it; it is never audited.
- The on-demand `update_check` still contacts `github.com` from a portable copy (one request,
  R-UPD); nothing is ever downloaded or installed there.
Conditions: M-18 (translocation refusal) before the 0.1.1 tag; L-44..L-46 as review 8 lists.
Revisit if a `--data-dir` override or a `_fixedruntime` zip variant is added.

### R-UPD — the updater key is a second release root (accepted with conditions, ADR-0018)
Whoever holds `TAURI_SIGNING_PRIVATE_KEY` **and** controls the response of
`github.com/yyasar21/Mooring/releases/latest/download/latest.json` ships code to every in-app
install (AppImage, user-writable `.app`, per-user NSIS) the next time the user clicks
"Install". Controlling that response takes one of:
- repo write;
- a GitHub compromise;
- a TLS MITM with a CA the OS trusts. Corporate proxies count: the plugin uses the platform
  verifier and honours the OS proxy.

The manifest is unsigned. The client trusts the artifact signature, the version inside the
signature (L-39 ✓: `requireSignedVersion`, forced again through `restore_update`), the version
order and a monotonic `lastVerified` floor. Rotating the key means a new key pair, a new
pubkey, and a release that carries it, signed with the old key.

Conditions:
- M-17 ✓ (re-review 7b): the key is referenced only in the signing step of `sign-updater`
  (`environment: release`, `contents: read`, no checkout, Tauri CLI pinned by SHA-512);
  the lint enforces it. Environment protection as above (owner).
- L-39 ✓: `requireSignedVersion: true`, `MissingSignedVersion` → `update.signature`, floor.
  N-62: `verify-release.sh` should also assert `version:<v>` in the trusted comment.
- L-40 ✓ for the download: the URL is pinned to `releases/download/v<offered>/<asset>` of this
  repository, a 256 MiB cap and a 10 min deadline. **Accepted until 0.1.1:** the manifest is
  capped (64 KiB) only after the plugin's `res.json()`, so in flight only the 30 s timeout
  bounds it. A hostile manifest (repo write or trusted-CA MITM) costs at most 30 s of memory
  growth on one check and installs nothing. Expiry: an own capped fetch + `restore_update`
  (direct `reqwest`, reviewed as a dependency change) in 0.1.1. The plugin honours the OS /
  env proxy (`system-proxy`), unlike `mooring-http`: accepted.
- In-app installs never elevate: the install-mode matrix keeps the plugin's `pkexec` / sudo /
  AppleScript paths unreachable. One residual remains: if permissions change between the probe
  and the macOS swap, the genuine OS authorisation dialog appears, and the user can cancel it.
- The check runs only on demand or when opted in, at most once per 24 h in the background,
  and sends only a version string and the user agent.

### R-IMPORT-SECRET — opted-in plaintext secrets pass the import buffers (accepted, ADR-0019)
With "import plaintext secrets" on, Termius passwords and keys pass through several buffers
once without zeroization: the raw file bytes, the `serde_json::Value` / CSV / XML strings and
the parse buffers. With the OpenSSH key opt-in, private keys from `~/.ssh` pass the same way.
Only the plan's `SecretBundle` is `Zeroizing`. The source file stays on disk, and the wizard
says so.
- mRemoteNG passwords are dropped at parse (owner decision 17).
- RDM and Royal TS secrets are never read.
- Encrypted or obfuscated values are never decrypted.
- The opt-in is off by default, and offered only for formats that can hold plaintext secrets.

### R-LDAP-STR — the bind password in `lber` buffers (accepted, ADR-0019 §4)
`BindCredential.password` is `Zeroizing`. The bind frame copies it once into an unzeroized
`lber` `Vec` / `BytesMut` and the rustls write buffer. It is sent only after the server
certificate is trusted (pin, CA or the native TOFU dialog). Simple bind sends the password to
the server by design, so a hostile directory that the user trusted receives it.

L-43 ✓ (re-review 7b): the first bind of a (credential, `host:port`) pair in an unlocked
session needs a native "Directory sign-in" confirmation (B-6 Gate, destructive, cool-down),
remembered in memory until lock. Order: TLS probe (no LDAP frame) → certificate TOFU if needed
→ sign-in confirmation → bind. **Accepted residual:** before any dialog, a T5-chosen host sees
one TCP connect and a TLS ClientHello (client IP, SNI the T5 chose). That is no more than
`net_port_check` already allows (R-NET-PROBE), and no secret leaves. A confirmed pair is keyed
by host, not by trust anchor. N-64: audit a per-call `caPem` by fingerprint.

### R-NET-PROBE — network probes from the app (accepted, ADR-0020)
`net_port_check` connects to any host and port the WebView names, loopback included, at most
once per second, and reports open / closed / timeout. `ping` and `traceroute` run the OS tools
with whatever rights the distribution gave them. A T5 can therefore map reachable services
slowly, but it learns no banner and sends no payload. The commands are vault-gated and
audited; the audit budget is still owed (N-52). Mooring adds no capability, no setuid helper
and no elevation. `wg show` reads only public keys, endpoints and counters; Mooring never runs
`showconf`, `dump` or `private-key`.

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
- **SD-ID.** `mooring@67553` — the Mooring Project's IANA PEN, assigned 2026-11-06 (N-12 ✓; the
  RFC 5612 documentation number 32473 was used before v0.1.0).

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
- **No longer executed on hostile bytes (M-15 ✓):** feature unification still makes every
  `flate2` user in the app use C zlib. But VNC now inflates with `miniz_oxide` directly, and
  no path from `mooring-proto-vnc` to `libz-sys` remains (`cargo tree`, review 5 re-review).
  `russh` links it through its `flate2` feature, but SSH negotiates compression `none` only,
  so it is not reachable (N-35 drops the feature). `png`/`image` use flate2 only to
  **encode** our own pixels.
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

L-25 ✓: remote writes and offers are refused while the vault is locked
(`session_clipboard_blocked`), every offer is audited (`session_clipboard_offer`), and an offer
of a `credential_copy_*` secret adds `credential_sent_to_remote` (warning).

### R-VNC-PLAIN — VNC without TLS (accepted per connection, ADR-0012 decision 4)
`allow_plaintext`, and `prefer_tls` when the server offers no usable VeNCrypt, run RFB in the
clear. The framebuffer, the input and the type-2 DES response (an 8-byte password,
offline-crackable) are readable and modifiable on the path, and a MITM can strip VeNCrypt.
Mitigations:
- A permanent "Unencrypted" badge and `session.vnc.plaintext` on every connect.
- `vnc_user_password` is never sent outside TLS.
- The downgrade guard: a pin makes the host `require_tls`.

The badge appears only after the DES response has been sent, so the guard is the real control.
- M-13 ✓: a CA-valid VeNCrypt X509 connect writes a host-only `tls-required` marker (by the
  Gate), so the guard covers CA-issued certificates too.
- L-27 ✓: a password credential never takes a None-only offer unless `allowNoAuth` is set
  (audited as weakening).
- U2 shows the fallback risk in the connection form while `prefer_tls` is selected.

### R-IMG — the `image` stack in the app (accepted for encoding only, review 5)
`session_screenshot` puts our own RGBA on the clipboard through `arboard` `image-data`. That
brings in `image` 0.25.10, `moxcms` 0.8.1 (ICC profiles, 356 `unsafe` sites) and `pxfm` 0.1.30
(SIMD math, 225), plus `tiff`/`zune-jpeg` on macOS and the BMP/PNG codecs on Windows.
- Accepted only for **encoding our own framebuffer**.
- Decoding foreign clipboard images is refused (L-23 ✓): the lock path clears a screenshot
  without reading the clipboard image.
- Revisit in A3: per-OS clipboard set with `png` 0.18 (`forbid(unsafe)`) alone.

### R-WEB-ENGINE — OS WebView engine bugs (accepted, ADR-0013)
Remote pages run in WKWebView, WebView2 or WebKitGTK, the same engine as `main`. The page
cannot call Mooring (no capability, `AppManifest`, label guard). A memory-safety bug in the
engine is mitigated only by OS WebView updates and the engines' own process sandboxes. On
Linux, WebKitGTK updates come from the distribution.
- Condition: `tauri`/`wry` pinned to a reviewed version (L-32). The ACL semantics are
  re-checked on every upgrade.

### R-WEB-COOKIE — persistent web stores (accepted per connection, ADR-0013 decision 7)
`persistent: true` keeps cookies and site data, often session tokens for admin consoles, in
plaintext under `$APP_DATA/web/<uuid>` (Windows/Linux) or in a WebKit identifier store (macOS
≥ 14). They are readable by T1 and T2, and they live **outside the vault**, so a lock does not
protect them.
- Mitigations: opt-in per connection, audited as weakening; an "Ephemeral/Persistent" badge;
  wiped by `web_clear_data` and `connection_delete`.
- Open: L-30 (`folder_delete`, Windows lock, orphan sweep). A closed macOS identifier store
  cannot be removed yet.

### R-WEB-UPLOAD — file uploads are blocked by script only (accepted, ADR-0013)
`INIT_SCRIPT` disables file inputs and the File System Access pickers in the top frame. It is
best effort and not a boundary. A page can still raise a picker from an iframe or through
paths the script misses (N-32). The user chooses the file, so the residue is a user-driven
upload to a console the user opened.

### R-WEB-UI — native UI raised by a remote page (open, L-31)
`alert`/`confirm`/`prompt`, HTTP authentication and print dialogs are native and need no IPC.
They can phish for credentials outside the page's frame, and whether they show while the window
is hidden for a lock is unverified on every OS.

### R-IPC-BUF — inward secrets pass through the IPC JSON buffer (accepted, A1)
`vault_unlock.password`, `credential_create.secret` and `session_send`'s `Answer.text` arrive
as JSON strings. The WebView's JS heap and Tauri's deserialisation buffer hold them unwiped
until they are garbage-collected. This is inherent to a WebView UI (ADR-0003); the Rust side
wraps each secret at the IPC edge. A T5 that already runs script could read these values as
the user types them anyway.

### R-KUBE-EXEC — an exec shell is not read-only (accepted, ADR-0014 decision 3)
The `ReadOnlyGuard` keeps Mooring's own API calls read-only. A shell opened in a pod runs
whatever the user types with the pod's privileges and service-account token. Only the five
allow-listed shells can be started, each `kube_exec_opened` is audited, and RBAC
(`pods/exec`) is the server-side control.

### R-KUBE-CFG — kube's config/auth code is compiled but not executed (accepted, review 6)
`kube-client`'s `client` feature forces `config`, which pulls `serde-saphyr` (with
`encoding_rs`/`simdutf8`, SIMD `unsafe`), `jsonpath-rust` → `pest` → `stacker`/`psm` (a
cc-assembled stack-switching shim). None of it runs: the loaders are banned by clippy
`disallowed-methods`, and the client is built by hand over `mooring-http`. Revisit when kube-rs
makes `config` optional.

### R-VMRC-ARGV — VMRC tickets pass through process arguments (accepted, review 6 L-36)
The `vmrc://clone:<ticket>@…` URL is an argv of the OS URL handler and of VMRC. Other local
users can read argv on Linux without `hidepid`; same-user processes can on every OS. The ticket
is single-use, ≤ 60 s, opt-in per vCenter and confirmed natively.

### R-SYNC-OP — the sync storage operator (accepted, ADR-0017)
A T7 holds the password-wrapped header and can attack the master password offline (same
strength as T1 with a stolen vault file: Argon2id with the calibrated floor). It can withhold
updates or serve an old generation to a device that has never synced (first sync / join is
TOFU on the generation); any later rollback or fork is a hard stop. Presigned request URLs it
logs are valid for 300 s (N-44).

### R-EXT-STR — external API secrets in third-party buffers (accepted, ADR-0016)
hyper, rustls, `HeaderValue`, `serde_json` scratch buffers, the rusty-s3 session token and the
presigned path hold copies of tokens that we cannot zeroize. Our own copies are `Zeroizing`.

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
- A2 R5: R-WEB-ENGINE, R-WEB-COOKIE and R-WEB-UPLOAD (above). R-WEB-UI stays open until the
  L-31 checks.
- A3: R-KUBE-EXEC, R-KUBE-CFG, R-VMRC-ARGV, R-SYNC-OP and R-EXT-STR (above). Certificate TOFU
  now also covers kube, vCenter, Vault and the sync endpoint, and pins are synced across the
  vault's devices.
- A4: R-UPD (with conditions), R-IMPORT-SECRET, R-LDAP-STR and R-NET-PROBE (above). TOFU now
  also covers LDAPS directories (`known_ldap_certs`, synced). Maintenance exception:
  `osakit` (updater; its macOS elevation path is never taken). `ldap3` is a dev-dependency only.
- 0.1.1: R-PORT (above). No new dependency; the Windows ACL is `icacls.exe` run the ADR-0020
  way.
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
      - [x] **M-12:** non-ASCII kubeconfig keys refused (review 7).
      - [x] L-19: the remote mode is kept on replace (review 7); N-17..N-22 as scheduled.
- [ ] **ADR-0009 (review 3):**
      - **B-3 (blocker):** `cert_pem` holds certificates only; `move_certificate` fails
        closed; a UI paste of certificate + key is split.
      - M-5 ✓ and L-10 ✓ (review 4), and the fuzz target with its oracle ✓ (M-11). Gate: no
        Kubernetes session or kubeconfig import before M-12 is fixed.
      - M-6: the `become` prompt is matched in the command echo; detect a failed escalation.
      - L-11 ✓ (review 7): `reseal_legacy` runs after unlock.
      - Fuzz targets: `kubeconfig_parse`, `ssh_public_key`, `ssh_certificate`,
        `ssh_private_key`, `x509_pem`, `otp_decode_seed`, `parse_account`.
      - N-5..N-7.
- [ ] **Release (review 3):**
      - M-7 ✓, L-12 ✓, N-9 ✓ (review 7).
      - L-13 (before the Azure secrets), L-14 (semgrep container digest), N-8 (tap token in
        the clone URL).
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
- [ ] **A2 (review 5, re-review after fix round 6 + R5/U2/U3: `APPROVE WITH NITS`):**
      - [x] **B-5 (blocker):** the RDP desktop size is validated before any allocation.
      - [x] M-13, M-14 (interim), M-15; L-20..L-27; N-23..N-26, N-29.
      - [ ] L-28 remainder (`cut_text`, `framebuffer_ops`, `rdp_reactivation`, upstream
        IronRDP targets, a green nightly run) before the A2 tag; N-28 (c).
      - [ ] Upstream: `sspi/scard` opt-in (R-RDP-FFI), IronRDP `Zeroizing` credentials
        (R-RDP-STR), reassembly limits (M-14).
- [x] A2: separate WebView + capability for remote pages (R5, ADR-0013; N-26 ✓); RDP/VNC
      certificate dialog and known-certs manager (U2).
- [ ] **A2 R5 (re-review):** L-29 (Windows ephemeral isolation), L-30 (store wipe on folder
      delete, orphan sweep), L-31 (native dialogs from a page, per-OS check), L-32 (pin Tauri)
      before the A2 tag; QA E2E for the ADR-0013 test plan on each OS; N-30..N-38 as
      scheduled.
- [ ] **A3 (review 6: `APPROVE WITH NITS`; re-review 6b: `BLOCKER`; re-review 6c after fix
      round 8: `APPROVE WITH NITS`, tag conditional on the per-OS runs):**
      - [x] **B-6 (was M-16):** slot invariant `YesNoCancelCustom("Cancel", ok, "Not now")`,
        label-only mapping, plugin remap replayed in tests, two-dialog sync trust prompt.
        [ ] The per-OS `docs/qa/native-dialogs.md` run (Return / Escape / close / Alt+F4 /
        Cmd+W refuse, a click confirms). Upstream report to tauri-apps/plugins-workspace:
        owner's call.
      - [x] M-16 single flight, cool-down (incl. guest shutdown/reboot), Cancel first.
      - [x] L-33, L-34 (a)(b)(c), L-35 (fail closed), L-37 (a)(b), L-38; N-39..N-49.
      - [x] L-36 documented (R-VMRC-ARGV); [x] the VMRC option help text (re-review 7b).
      - [ ] Per-OS: OIDC redirect interception (ADR-0016 §4), L-31, the Windows L-29 E2E.
      - [ ] U5: security look at the `sync_status.conflicts` / `trust_conflict` UI decoding.
      - [x] N-50: `SecretsError::prompt_decision()` (Prompt verdict only); `secret_source_trust`
        must use it when it is built.
      - [ ] Upstream: kube-rs `config` optional (R-KUBE-CFG).
      - [x] S3 sync integrity: counters, parent hash and header hash inside the AEAD (MSY1).
- [ ] A3/A4: LDAP injection review ✓ (review 7); revisit R-INV now that the DB leaves the device (sync:
      inventory is inside the AEAD, so T7 does not read it); import `--merge` must re-check
      `vault_id`.
- [ ] **A4 (review 7: `APPROVE WITH NITS`; re-review 7b after R2 / F1 / F2: `APPROVE WITH
      NITS`, the `v0.1.0` tag is conditional):**
      - [x] **M-17** (1)(2)(4) in `release.yml`: `sign-updater`, no key in build jobs, pinned
        CLI, lint. [ ] **(3) owner:** `release` environment (reviewer = owner, tags `v*`),
        environment secrets only, `v*` tag ruleset, `main` branch ruleset. Due before
        `TAURI_SIGNING_PRIVATE_KEY` is created; the rulesets are due for v0.1.0 regardless.
      - [x] L-39, L-40 (download; the in-flight manifest cap is accepted until **0.1.1**), L-41,
        L-43 (TLS probe before the dialog accepted), N-50..N-55, N-57..N-60, L-36.
      - [ ] L-42 remainder: `site/index.html:218`, `:311`, `README.md:105` (+ `:96`, `:22`).
      - [ ] L-14: the semgrep container digest (owner).
      - [ ] N-56 remainder (full `Cf` set), N-61..N-64 as scheduled.
      - [ ] rc.2 dry run: first run of the new `release.yml` (`actionlint` first), trusted
        comment `version:<v>` checked by hand (N-62), the Q1 Decision 3 updater leg.
      - [ ] Per-OS: native dialogs including the LDAPS trust **and sign-in** dialogs, Windows
        net tools, and the carried A3 per-OS runs.
      - [ ] Also owed: the L-28 nightly run (now including `rdp_reactivation`) and the G-1
        fresh repository.
- [ ] **0.1.1 portable mode (review 8: `APPROVE WITH NITS`, the `v0.1.1` tag is conditional
      on M-18):**
      - [ ] **M-18:** refuse a translocated `.app` (`portable.translocated`), README / guide
        step, macOS gate launched in place from the extracted zip.
      - [ ] L-44 (`$APPIMAGE` Linux-only and validated), L-45 (FAT on unix: audit, not
        refuse), L-46 (README over-claim, cloud-sync warning, marker-invalid wording).
      - [ ] Per-OS gate (fresh non-admin account): Windows 11 NTFS Desktop + FAT32 USB +
        OneDrive Desktop + no-WebView2; macOS 15 `~/Applications` + exFAT / FAT32 USB, in place
        and after a Finder move; read-only folder → `portable.unwritable`, exit 2, no OS
        app-data directory.
      - [ ] N-65..N-71 as scheduled. L-40 manifest cap still due for 0.1.1 (R-UPD).
