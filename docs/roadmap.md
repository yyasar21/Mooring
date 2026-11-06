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
| Vault: opt-in Touch ID / Windows Hello unlock | 🚧 held until each platform has a biometric ACL |
| Vault: `age` export and import in the app | 🚧 library done, vectors verified with the `age` CLI |
| Data model: folders, connections, tags, credentials, inheritance, overrides, search | ✅ |
| Typed credential model, 15 kinds ([ADR-0009](adr/0009-credential-model.md)) | ✅ |
| SSH: TOFU + `known_hosts`, password, key, keyboard-interactive, agent, strict algorithms | ✅ |
| SSH: terminal with WebGL, streaming | ✅ |
| SSH: port forwarding (L/R/D) in the app, audited exposure, closed on lock | ✅ |
| SSH: SFTP panel with progress; Rust-side file picker (review 4, B-4) | ✅ (drag-and-drop 🗓) |
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
- **Directory lookup** (LDAPS) moves to A4 as an importer; FIDO2 `hmac-secret` moves to a
  post-A4 "unlock factors" ADR together with the OS-keyring biometric ACL
  ([ADR-0017](adr/0017-vault-sync-and-signin.md)).
- **Vault sync**: client-side encrypted blob to S3-compatible storage with conflict detection.
- **Network tools** (TCP port check, ping/traceroute/WireGuard via OS tools) move to A4 (own ADR).
- Security focus: token lifetimes, read-only Kubernetes guard, native-dialog defaults, sync integrity
  (AEAD with version counters, fork/rollback hard stops) — review 6 APPROVE WITH NITS.

## A4 — Release v0.1.0 🗓

- Signed bundles: macOS universal `.dmg`/`.pkg` with notarization; Windows `.exe`/`.msi` with
  Authenticode (when certificates exist); Linux `.deb`, `.rpm`, AppImage; `SHA256SUMS` signed with
  Sigstore (cosign keyless); signed updater manifests ([ADR-0018](adr/0018-release-v0-1-0.md)). Homebrew tap, winget later.
- CycloneDX SBOMs, SLSA provenance, reproducible-build check.
- **Exit gate also covers the public face**: README, `site/` (GitHub Pages), CHANGELOG, user guide and
  the comparison table must describe the released state — every phase exit updates them, not
  only the code.
- Full security pass: zero critical/high findings; mediums documented.
- Onboarding and importers: Royal TS, Termius, mRemoteNG, PuTTY sessions. No telemetry.
- Exit: clean installs on fresh macOS, Windows 11 and Fedora machines.

## B — Mooring agent and relay 🗓

Mooring's own remote-desktop agent and relay service, so machines without SSH, RDP or VNC
exposure can be reached through an end-to-end encrypted relay. Scope and design will start
with a dedicated ADR after v0.1.0.

## Influencing the roadmap

Open a feature request or start a discussion. Security-relevant features land only with an
ADR and a review.
