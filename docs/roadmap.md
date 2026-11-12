# Roadmap

Mooring is built in phases. Phase A delivers a full remote-access manager; Phase B adds
Mooring's own remote-desktop agent and relay. Each phase ends with exit criteria, a written
security review and an updated threat model. Dates are not promised; order is.

Legend: ✅ done · 🚧 in progress · 🗓 planned

## A0 — Foundation ✅

Cargo workspace and crates, Tauri 2 shell with strict CSP and minimal capabilities, React UI
shell, vault cryptography, hash-chained audit log, `make check`, CI on three operating systems,
security workflow, ADR-0001 to ADR-0004, threat model v0.

## A1 — Vault, connection tree and SSH ✅ (exit 2026-11-04)

| Item | Status |
| --- | --- |
| Vault: create, unlock, lock, change password, Argon2id calibration | ✅ |
| Vault: auto-lock wired to idle, sleep, screen lock, hidden window ([ADR-0010](adr/0010-a1-exit-ipc.md)) | ✅ |
| Vault: opt-in Touch ID / Windows Hello unlock | → A5 ([ADR-0022](adr/0022-biometric-unlock.md)) |
| Vault: `age` export and import in the app | library done, vectors verified with the `age` CLI; UI → A5 ([ADR-0023](adr/0023-vault-export-import-ui.md)) |
| Data model: folders, connections, tags, credentials, inheritance, overrides, search | ✅ |
| Typed credential model, 15 kinds ([ADR-0009](adr/0009-credential-model.md)) | ✅ |
| SSH: TOFU + `known_hosts`, password, key, keyboard-interactive, agent, strict algorithms | ✅ |
| SSH: terminal with WebGL, streaming | ✅ |
| SSH: port forwarding (L/R/D) in the app, audited exposure, closed on lock | ✅ |
| SSH: SFTP panel with progress; Rust-side file picker (review 4, B-4) | ✅ (drag-and-drop → A5 carried) |
| UI: three panes, palette, tabs, inspector, copy password, themes, keyboard-first | ✅ |
| Audit log viewer | ✅ |
| Syslog mirror (RFC 5424 udp/tcp/tls, heartbeat) | ✅ |
| Fuzz targets with a nightly job; Playwright E2E against the dev server with the mock transport | ✅ |

## A2 — RDP, VNC and web sessions ✅ (exit 2026-11-04; ADR-0011/0012/0013, review 5)

- **RDP** via IronRDP: NLA/CredSSP, TLS with system and custom CA roots, certificate TOFU with
  explicit approval, dynamic resolution, text clipboard both ways, keyboard layouts, audio off
  by default, efficient frame path (target 30 fps at 1080p).
- **VNC**: RFB 3.8, Tight/ZRLE/Raw, VeNCrypt TLS, password and no-auth, view-only toggle.
- **Web sessions**: an isolated WebView per connection with its own capability set and
  partitioned storage, for admin consoles such as vCenter, Grafana, OPNsense, Rancher and Argo
  CD.
- **Shared**: reconnect with backoff, metadata-only session recording in the audit log,
  screenshot to clipboard, fullscreen, detach tab to window, per-connection legacy SSH
  algorithms (audited).
- Security focus: parser hardening and fuzzing, WebView isolation, clipboard leakage,
  certificate handling.

## A3 — Infrastructure integrations ✅ (exit 2026-11-05; ADR-0014/0015/0016/0017, review 6)

- **vSphere**: import datacenters, clusters, hosts and VMs into a synced folder; VM console;
  power state; scheduled refresh.
- **Kubernetes**: contexts from kubeconfig, namespaces and pods, `exec` shells,
  port-forward, logs — read-only, never mutates the cluster.
- **External secrets**: credentials resolved at connect time from HashiCorp Vault / OpenBao
  (KV v2) with short-lived tokens; nothing cached on disk.
- **Directory lookup** (LDAPS) moved to A4 as an importer; the OS-keyring biometric ACL is
  A5 ([ADR-0022](adr/0022-biometric-unlock.md)); FIDO2 `hmac-secret` as a vault second factor
  stays deferred because in-process FIDO2 access is rejected for now
  ([ADR-0024 §4](adr/0024-fido2-ssh-keys.md), [ADR-0017](adr/0017-vault-sync-and-signin.md)).
- **Vault sync**: client-side encrypted blob to S3-compatible storage with conflict detection.
- **Network tools** (TCP port check, ping/traceroute/WireGuard via OS tools) move to A4 (own ADR).
- Security focus: token lifetimes, read-only Kubernetes guard, native-dialog defaults, sync integrity
  (AEAD with version counters, fork/rollback hard stops) — review 6 APPROVE WITH NITS.

## A4 — Release v0.1.0 ✅ (released 2026-11-07; review 7 APPROVE WITH NITS; rc.2 dry run green; per-OS manual gates owner-run)

- Signed bundles: macOS universal `.dmg`/`.pkg` with notarization; Windows `.exe`/`.msi` with
  Authenticode (when certificates exist); Linux `.deb`, `.rpm`, AppImage; `SHA256SUMS` signed with
  Sigstore (cosign keyless); signed updater manifests ([ADR-0018](adr/0018-release-v0-1-0.md)). Homebrew tap; winget and the signing jobs → A5 (ADR-0018 A1–A2).
- CycloneDX SBOMs, SLSA provenance, reproducible-build check.
- **Exit gate also covers the public face**: README, `site/` (GitHub Pages), CHANGELOG, user guide and
  the comparison table must describe the released state — every phase exit updates them, not
  only the code.
- Full security pass: zero critical/high findings; mediums documented.
- Onboarding and importers: Royal TS, Termius, mRemoteNG, PuTTY sessions. No telemetry.
- Exit: clean installs on fresh macOS, Windows 11 and Fedora machines.

## A5 — v0.2.0: unlock factors, hardware keys, jump hosts, dynamic secrets, RD Gateway 🚧

Every planned technical feature of the connection manager lands before the public launch;
Phase B stays after it. Each row is one ADR (Proposed 2026-11-07); items carried from earlier
phases are listed where they now live.

| Item | ADR | Status |
| --- | --- | --- |
| Opt-in Touch ID / Windows Hello unlock with a biometric ACL (lifts the A1 hold; Linux not offered; Touch ID needs a Developer-ID-signed build) | [ADR-0022](adr/0022-biometric-unlock.md) | 🚧 |
| Vault `age` export and import in the app (native dialogs from Rust, merge with conflict report or replace) | [ADR-0023](adr/0023-vault-export-import-ui.md) | 🚧 |
| FIDO2 `sk-*` SSH keys: `ssh_sk_key` kind, agent passthrough with touch indication; `ssh-sk-helper` backend as a stretch | [ADR-0024](adr/0024-fido2-ssh-keys.md) | 🚧 |
| Jump hosts / bastions: `via` chains (≤ 3) over `direct-tcpip`, no local listener, for SSH, SFTP, RDP, VNC, Kubernetes and vSphere; web sessions through a loopback SOCKS proxy | [ADR-0025](adr/0025-jump-hosts.md) | 🚧 |
| Dynamic Vault engines (`database`, `ssh/sign`, `ssh/creds`, `pki`) with lease renew/revoke; 1Password Connect; Bitwarden Secrets Manager via `bws` | [ADR-0026](adr/0026-dynamic-secrets-1password-bitwarden.md) | 🚧 |
| RD Gateway over MS-TSGU WebSocket (NTLM/Basic over TLS, own pin store); `smart_card` kind with a Rust-side PIN dialog; SSH PIV via the agent — RDP smart-card logon and direct PKCS#11 wait for the Kerberos ADR | [ADR-0027](adr/0027-rd-gateway-and-smart-card.md) | 🚧 |
| Signing hooks: notarization (`notarytool`) and Authenticode (Azure Trusted Signing) in the `release` environment, inert until certificates exist; winget submission once Windows builds are signed | [ADR-0018 A1–A2](adr/0018-release-v0-1-0.md) | 🚧 |
| Build identity and macOS install hygiene: every non-release build is "Mooring Dev" (`.dev` identifier, own data dirs, DEV icon, no updater) via a release-only config overlay; "Move to Applications" from a DMG, Downloads or translocation; DMG layout; duplicate-entry cleanup guide (wave W3: release-engineer, rust-core, ui) | [ADR-0028](adr/0028-build-identity-and-macos-install-hygiene.md) | 🚧 |
| Carried from A1: SFTP drag-and-drop | — | 🗓 |
| Carried from A2/A3: Kerberos (KDC discovery), EGFX H.264 via WebCodecs, VeNCrypt X.509, DEK rotation / password-change rework (owner decision 11) | own ADRs after A5 | 🗓 |

Exit gate: security review 9 with zero critical/high findings and the threat model extended
(T-BIO, T8 hop operator, R-SEC-CLI, RDG); per-OS manual gates (biometric enrolment and
suspension, native export/import dialogs, YubiKey through the agent, bastion chain, RD Gateway
lab, winget dry run); public docs refreshed (README, `site/`, CHANGELOG, user guide, comparison
table) to the released state.

## B — Mooring agent and relay 🗓

Mooring's own remote-desktop agent and relay service, so machines without SSH, RDP or VNC
exposure can be reached through an end-to-end encrypted relay. [ADR-0029](adr/0029-mooring-agent-and-relay.md)
defines the architecture, E2E key exchange, agent binary and stateless relay design.
Phase B starts after A5 exit.

## Influencing the roadmap

Open a feature request or start a discussion. Security-relevant features land only with an
ADR and a review.
