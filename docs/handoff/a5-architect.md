# A5 (v0.2.0) — architect handoff

Date: 2026-11-07 · on `main`, docs only (`docs/adr/0022..0027`, ADR-0018 amendments A1–A2,
`docs/roadmap.md` §A5, this note, index row). Nothing committed.

## Done
- **ADR-0022 Biometric unlock**: `WrapKey` of ADR-0006 in a macOS data-protection keychain item
  with `BiometryCurrentSet` + `WhenUnlockedThisDeviceOnly` through `security-framework` 3.7.0
  (safe API, already in the tree; `keyring`'s Apple store knows only `UserPresence`, so it is
  bypassed and `keyring`/`zbus` leave `mooring-app`); Windows Hello derives `WrapKey` from a
  deterministic `KeyCredentialManager.RequestSignAsync` over a fixed challenge (safe WinRT
  projection in `windows` 0.62.2, feature `Security_Credentials`; no header change, HKDF);
  Linux not offered. Hold lifted because no process, ours included, obtains the key without a
  fresh gesture. Auto-disable (3 failures / password change / biometry change / vault id change)
  deletes the OS item without the password; stale wrap cleared on next password unlock.
  **Gate found:** the data-protection keychain needs an application-identifier entitlement →
  Touch ID only in Developer-ID-signed builds (ties to ADR-0018 A1). T-BIO, R-BIO-PROMPT.
- **ADR-0023 Export/import UI**: document v2 = header (without `keyring_wrap`) + the sync
  `Snapshot` (new `mooring_sync::export` over `mooring_vault::export`; vault crate keeps the age
  container and the committed v1 vectors); pick/save dialogs from Rust (B-4 pattern,
  `pickId`); export needs master password + distinct passphrase; import inspects first; same
  vault = open under our DEK, foreign vault = source master password → reseal; `merge` via
  `mooring_sync::merge` with the conflict list, `replace` behind typed confirmation, one
  transaction; caps and codes.
- **ADR-0024 FIDO2 SSH keys**: verified in `agent.rs`/`auth.rs` that `sk-*` identities already
  flow through `authenticate_publickey_with` with the agent as signer (russh 0.65 lists
  `SkEd25519`/`SkEcdsaSha2NistP256`), so **agent passthrough works today** minus the UI and a
  test; new kind `ssh_sk_key` (18th), migration of `sk-*` rows out of `ssh_key`, touch banner
  events, agent certificates implemented. `ssh-sk-helper` fixed-path backend (Windows: uses
  `webauthn.dll` itself → non-admin, no `unsafe` for us; Linux paths; no macOS) as a stretch
  with a fail-closed protocol-version check. In-process FIDO2 (`ctap-hid-fido2` → `hidapi` C;
  Windows `WebAuthN*` are `unsafe fn`; `webauthn-authenticator-rs` MPL) rejected for 0.2.0.
- **ADR-0025 Jump hosts**: `connection_via` table (explicit chain ≤ 3 on the leaf, hops' own
  `via` ignored → no recursion, validation refuses self/duplicates/non-SSH/depth), `HopChain`
  + `HopStream` built on `connect_stream`/`channel_open_direct_tcpip`/`into_stream` (all in
  russh 0.65), no local listener for SSH/SFTP/RDP/VNC/kube/vSphere (`RdpStream`, VNC and
  `mooring-http` connector become stream-generic); web sessions through a loopback SOCKS
  forward + Tauri `proxy_url` (`macos-proxy` feature, macOS 14+); per-hop trust, credentials,
  events tagged `hop`, audit per hop; T8 (hop operator), R-WEB-VIA.
- **ADR-0026 Dynamic secrets + 1Password + Bitwarden**: `external_ref.engine ∈ {kv2, database,
  ssh_sign, ssh_otp, pki}`, `LeaseRegistry` (renew at 2/3 TTL, revoke on close/lock/exit),
  `ssh_sign` as secondary role `certificate` on the SSH key credential; 1Password via Connect
  (REST on `mooring-http`, `op://` references; `op` CLI and the 23-download SDK rejected);
  Bitwarden Secrets Manager via the `bws` CLI in the ADR-0020 fixed-path pattern (SDK is
  GPL-3/Bitwarden licence, its `EncString` format would be our-own-crypto); new kind
  `bitwarden_access_token` (19th); R-SEC-CLI.
- **ADR-0027 RD Gateway + smart card**: `ironrdp-mstsgu` 0.1.0 read in full — MIT/Apache, 0
  `unsafe`, but its `rustls` feature = `aws-lc-rs` (banned) twice, `sspi/network_client`
  (`reqwest` KDC traffic), sync cert callback, two weeks old → **own MS-TSGU WebSocket
  transport** on `tokio-tungstenite` 0.30 `handshake` (already in the tree) + our ring TLS +
  `sspi::Ntlm` we already link; `known_rdg_certs`; RPC-over-HTTP legacy out; two upstream
  issues/PRs filed at A5 start so mstsgu can replace it if they land. Smart card: kind
  `smart_card` (20th) with a Rust-side PIN dialog and SSH PIV via `ssh-add -s`; RDP smart-card
  logon (needs `pcsc` FFI, stale since 2024-12, + Kerberos PKINIT) and direct `cryptoki` are
  stretch with explicit exception rulings.
- **ADR-0018 A1–A2**: `sign-platform` job in the `release` environment (notarytool + stapler,
  Azure Trusted Signing action pinned by SHA, `tauri bundle` without a build), skipped without
  secrets, secrets removed from `build`; `release-winget.yml` gated on `WINGET_TOKEN` and a
  signed Windows build, `wingetcreate submit`, `ManualReason::Winget`.
- Roadmap §A5 with exit gate; earlier rows re-pointed.

## Proposed wave plan (rust-core ≤ 2 worktrees + ui; qa and security after each wave)
| Wave | rust-core A | rust-core B | ui-engineer | Why this order |
| --- | --- | --- | --- | --- |
| **W1** | **R1 streams**: `HopStream` + `HopChain`, `RdpStream`/VNC/`mooring-http` stream-generic, `connection_via` migration (ADR-0025 §1–2) | **R2 vault**: biometric store + commands (ADR-0022), export/import document v2 + commands (ADR-0023) | U1: `via` picker, hop chips, per-hop dialogs; U2: Settings Security toggle, Backup card (mock IPC first) | R1 is the foundation RDG (ADR-0027) and web-via need; R2 is independent of R1 |
| **W2** | **R3 secrets**: engines, leases, Connect client, `bws` runner, kinds 19 (ADR-0026) | **R4 ssh keys**: `ssh_sk_key`, migration, agent certs, touch events, helper backend behind a flag (ADR-0024) | U3: secret-source forms, lease chip, engine fields; U4: sk kind form, touch banner | Both touch `mooring-core` kinds → the orchestrator merges R3 before R4 rebases (kind numbering 18/19/20 fixed in the ADRs) |
| **W3** | **R5 RDG**: WebSocket transport, PDUs, NTLM/Basic, `known_rdg_certs`, `smart_card` kind + PIN dialog (ADR-0027) | **R6 web-via**: SOCKS forward + `proxy_url`, `macos-proxy` feature; `ManualReason::Winget` | U5: RD Gateway section, smart-card kind, "via RDG" chip | R5 depends on R1 (`HopStream::Gateway`); R6 on R1 + U1 |
| **W3 ∥** | release-engineer: ADR-0018 A1 `sign-platform`, A2 `release-winget.yml`, entitlements plist, `lint-workflows.sh` rules | | | Independent of code; dry run on an rc tag |
| **W4** | qa: fuzz targets (`sk_key_parse`, `agent_identities`, `sk_helper_reply`, `export_document_json`, 6 secrets shapes, `rdg_pdu`, `rdg_http_response`), mocks (fake agent, fake `ssh-sk-helper`, fake `bws`, Connect mock, RDG mock, Vault dynamic engines), E2E per ADR | | | then security review 9, threat model (T-BIO, T8, R-BIO-PROMPT, R-WEB-VIA, R-SK-HELPER, R-SEC-CLI, RDG), per-OS manual gates |

Dependencies: R1 → R5, R6; R3 → R4 (core kinds); U1 → R6; everything → W4. Cargo.toml edits
for the orchestrator: `security-framework` as a direct dep of `mooring-app` (macOS), `windows`
feature `Security_Credentials` (Windows), drop `keyring`, Tauri `macos-proxy` feature,
`tokio-tungstenite` for `mooring-proto-rdp`, `hkdf` for `mooring-app`.

**New crates: none.** Every ADR builds on crates already in the lockfile. For the security
reviewer, the feature/edge changes instead: `security-framework` 3.7.0 becomes direct (MIT/
Apache, FFI inside the crate, 0 `unsafe` ours); `windows` 0.62.2 + `Security_Credentials`
(safe WinRT projections only — the `Win32_Networking_WindowsWebServices` WebAuthn surface is
*not* enabled); `tokio-tungstenite` 0.30 `handshake` gains a second consumer; `keyring` 4.2.0
and its `zbus` tree are removed. Stretch items that would need new crates/exceptions and are
**not** proposed for 0.2.0: `ctap-hid-fido2` (+ `hidapi` C), `pcsc` (FFI, stale), direct
`cryptoki`, `ironrdp-mstsgu` (banned `aws-lc-rs` via `ironrdp-tls`).

## Left open
- ADR-0022 Windows: whether the Hello RSA signature is deterministic for every KSP/TPM
  (PKCS#1 v1.5 is; PSS would not be) — rust-core verifies on real hardware before relying on it;
  fallback is a stored random challenge in a header v3 (then a format bump).
- ADR-0024 helper protocol version coverage (`SSH_SK_HELPER_VERSION` per OpenSSH release) and
  whether Apple's OpenSSH ever ships `ssh-sk-helper`.
- ADR-0025 web-via on macOS < 14 refused; Linux WebKitGTK SOCKS support to be confirmed in E2E.
- ADR-0026: `bws` self-signed server certificates (its own TLS, not our pins) — document only.
- ADR-0027: MS-TSGU WebSocket availability on the owner's gateway (Server 2016+); legacy RPC
  gateways unsupported.
- Kerberos (KDC discovery, PKINIT) remains its own post-A5 ADR; RDP smart-card logon waits for it.

## Decision needed (owner) — numbered after ADR-0021's three inline decisions (20–22)
| # | ADR | Question | Recommended default |
| --- | --- | --- | --- |
| 23 | 0022 | Touch ID only in Developer-ID-signed builds (buy the certificate) | Gate both OSes; ship Windows Hello first |
| 24 | 0022 | Auto-disable after 3 failures within 10 min | Yes |
| 25 | 0022 | Remove `keyring` (+ `zbus`) from `mooring-app` | Yes |
| 26 | 0023 | Import default `merge` with conflict report; keep `replace` behind typed confirmation | Yes, keep both |
| 27 | 0023 | Foreign-vault import requires the source master password | Yes |
| 28 | 0023 | Trust stores exported and unioned on import | Yes (matches decision 10) |
| 29 | 0024 | `ssh-sk-helper` backend in 0.2.0 or 0.2.x | Agent-only first; helper as a flagged stretch |
| 30 | 0024 | Password fallback after a failed `ssh_sk_key` | Never |
| 31 | 0025 | Chain depth limit | 3 |
| 32 | 0025 | Folder-level default `via` inheritance | Later; explicit per connection now |
| 33 | 0025 | Shared/multiplexed hop sessions | Later; one chain per session |
| 34 | 0025 | Web sessions via SOCKS with `macos-proxy` (macOS 14+ only) | Ship with refusal on older macOS |
| 35 | 0026 | 1Password via Connect, or not at all | Connect |
| 36 | 0026 | Bitwarden via `bws` CLI (R-SEC-CLI), or defer | `bws` |
| 37 | 0026 | PKI `revokeCertOnDisconnect` default | Off |
| 38 | 0026 | `ssh_sign` as secondary role `certificate` on the SSH key credential | Yes |
| 39 | 0027 | Own MS-TSGU WebSocket transport vs waiting for upstream mstsgu vs a second git source | Own transport; swap if upstream lands before freeze |
| 40 | 0027 | Smart card in 0.2.0 = kind + PIN dialog + SSH PIV via agent only | Yes |
| 41 | 0027 | Legacy RPC-over-HTTP gateways | Unsupported in 0.2.0 |
| 42 | 0018 A1 | Buy Apple Developer ID + App Store Connect API key and an Azure Trusted Signing account now, or leave the jobs inert | Buy before 0.2.0 if Touch ID is wanted; jobs are safe inert either way |

## Test evidence
Docs only; nothing to run. Line counts (limit 160): 0022 = 138, 0023 = 120, 0024 = 120,
0025 = 141, 0026 = 138, 0027 = 128; ADR-0018 grows to 189 with the two amendments (the
amendment block is 40 lines). Crate facts from crates.io (2026-11-07) and sources read locally:
`security-framework` 3.7.0 (`access_control.rs`, `passwords_options.rs`),
`apple-native-keyring-store` 1.0.2 (`protected.rs`), `windows` 0.62.2 (`Security/Credentials`,
`WindowsWebServices`), `russh` 0.65.0 (`client/mod.rs`, `channels/mod.rs`, `keys/key.rs`),
`tauri` 2.12.5 (`proxy_url`), `ironrdp-mstsgu` 0.1.0, `ironrdp-tls` 0.3.0, `ironrdp-rdpdr` 0.9.0,
`ctap-hid-fido2` 3.6.1, `pcsc` 2.9.0, `winscard` 0.4.0, `webauthn-authenticator-rs` 0.6.2,
`bitwarden` 2.1.0 / `bitwarden-core` 4.0.0 / `bws` 2.1.0 licences.
