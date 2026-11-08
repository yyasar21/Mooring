# Changelog

All notable changes to Mooring are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until v1.0 a
minor version may contain breaking changes; they are called out under **Changed**.

## [Unreleased]

Planned as **0.2.0** (Phase A5: unlock factors, hardware keys, jump hosts, dynamic secrets,
RD Gateway, and the "Harbor" interface). The tag waits for the per-OS manual gates listed in
the [roadmap](docs/roadmap.md).

### Added

- **Jump hosts.** A connection can go through up to three SSH jump hosts ("Connect via" in the
  connection dialog). Works for SSH, SFTP, port forwards, RDP, VNC and Kubernetes. Each hop has
  its own host-key check and its own credential, the tree shows "via bastion01", and a chip
  per hop shows its progress. Nothing listens on your machine for these chains; a hop that
  fails stops the session before the target is contacted
  ([ADR-0025](docs/adr/0025-jump-hosts.md), [guide](docs/user-guide/jump-hosts.md)).
- **Web sessions through jump hosts** on Windows and Linux: the web window uses a loopback
  SOCKS proxy on the last hop, limited to the start page's host and the connection's allowed
  origins. Not available on macOS in this release (opening is refused, never bypassed).
- **Unlock with Touch ID or Windows Hello** (opt-in, Settings → Security). The OS keeps the
  unlock key behind a fresh biometric check; it is turned off automatically after three failed
  attempts, a master-password change, a change of enrolled fingers or faces, or a vault
  replacement. Touch ID needs a Developer-ID-signed build; Linux is not offered
  ([ADR-0022](docs/adr/0022-biometric-unlock.md)).
- **Backup export and import** (Settings → Backup): an `age`-encrypted backup of folders,
  connections, credentials and trusted keys, protected by a separate passphrase. Import shows
  what the file holds first, then **merges** (both copies kept when an item changed on both
  sides) or **replaces** after you type `REPLACE`; backups of another vault need that vault's
  master password ([ADR-0023](docs/adr/0023-vault-export-import-ui.md),
  [guide](docs/user-guide/backup-and-restore.md)).
- **Dynamic Vault secrets**: Secret manager references can use the Vault `database`,
  `ssh` (sign and OTP) and `pki` engines. Leases are renewed while the session is open and
  revoked when it closes or the vault locks; a session tab shows the lease state. An SSH
  connection can have its key signed by a Vault SSH CA at connect time ("Certificate (Vault SSH
  CA)") ([ADR-0026](docs/adr/0026-dynamic-secrets-1password-bitwarden.md)).
- **1Password Connect and Bitwarden Secrets Manager** as secret sources, next to HashiCorp
  Vault and OpenBao. 1Password is read through your Connect server (`op://vault/item/field`);
  Bitwarden through the `bws` CLI from a fixed location, with a cleared environment and its
  checksum pinned ([guide](docs/user-guide/external-secrets.md)).
- **SSH security keys (FIDO2)**: a new credential kind for `sk-ssh-ed25519` and
  `sk-ecdsa-sha2-nistp256` keys, signed through your ssh-agent. Mooring shows "Touch your
  security key" with a countdown and never falls back to a password. Existing SSH key
  credentials that hold a security key are converted after unlock; SSH certificates in the
  agent now work for every key type ([ADR-0024](docs/adr/0024-fido2-ssh-keys.md),
  [guide](docs/user-guide/security-keys-and-smart-cards.md)).
- **Smart cards (PIV) for SSH**: a "Smart card / PIV" credential kind. Mooring asks for the PIN
  when you connect, hands it to ssh-agent once to load the card for 60 minutes, and never
  stores it ([ADR-0027](docs/adr/0027-rd-gateway-and-smart-card.md)).
- **RD Gateway** for RDP: Mooring's own MS-TSGU WebSocket transport, NTLM with channel binding
  (works with gateways that require Extended Protection), Basic only when you allow it, a
  separate certificate trust store with a hard stop on change, and "only when the computer is
  unreachable" mode. An RD Gateway also works behind a jump host chain
  ([guide](docs/user-guide/rd-gateway.md)).
- **winget manifests** for `yyasar21.Mooring` are generated and validated for every stable
  release; submission to `winget-pkgs` starts once Windows builds are Authenticode-signed.
- **Signing hooks** for notarization (`notarytool`) and Authenticode (Azure Trusted Signing),
  in their own protected release jobs. They stay switched off until certificates exist.
- **Mooring Dev and Move to Applications**
  ([ADR-0028](docs/adr/0028-build-identity-and-macos-install-hygiene.md)): every build that is
  not an official release is called "Mooring Dev", with its own identifier, data folder,
  keychain items and a DEV icon, and it never updates itself. A release started
  from the disk image or Downloads on macOS offers to move itself into Applications and ejects
  the disk image afterwards. The DMG has a drag-to-Applications layout.
- **Audit log filters**: filter by text, event type, connection and time, and open any entry in
  a side panel with local and UTC time, resolved names and the previous hash.
- Settings → SSH card; Settings → Known certificates lists RD Gateway pins; the import summary
  reports trust lines that were added or kept.

### Changed

- **New interface ("Harbor").** A calm, corporate look replaces the sci-fi "bridge console":
  IBM Plex Sans in sentence case, neutral light and dark surfaces, one blue accent, status
  shown with a colour and a label, and every text pair checked for WCAG AA contrast in both
  themes. A navigation rail (Hosts, Credentials, Audit, Settings; `mod 1`–`4`), a session
  header with breadcrumb, status and Disconnect, inspector tabs (Properties, Network, History),
  a "ready to connect" page, sortable data tables, a credentials list with a detail page and
  an editor sheet, a connection dialog with section navigation and inline validation, Settings
  with section navigation and search, and a command palette with recent connections, actions
  and settings pages. Chakra Petch is no longer shipped.
- **Kubernetes** tabs, `exec` shells and log streams now call the backend with its actual
  command names and arguments, so the cluster browser works in installed builds; jump-host
  prompts are answered in the cluster tab. The pod list refreshes every 15 seconds and on
  Refresh (there is no live watch).
- The credential model has 20 kinds (was 17): `ssh_sk_key`, `bitwarden_access_token` and
  `smart_card` are new. A security key pasted into an "SSH key" credential is refused with a
  pointer to the new kind.
- The `keyring` crate and its D-Bus dependencies are removed; a legacy keyring unlock wrap
  from 0.1.x is dropped on the next password unlock (audited).
- Release builds no longer carry platform signing secrets in the build job.

### Fixed

- A web window whose tab was closed while it was still opening stayed open without a tab.
- An unknown web-window event no longer closes the tab.

### Security

- Security review 9 ([docs/security/a5-review-9.md](docs/security/a5-review-9.md)): pass with
  conditions; the findings below are fixed. RD Gateway NTLM is bound to the gateway's TLS
  certificate (M-19, RFC 5929 `tls-server-end-point`); the web-via SOCKS proxy refuses targets
  outside the start host and allowed origins (L-48) and WebView2 keeps WebRTC on the proxy
  (L-47); smart-card keys are added to ssh-agent with a one-hour lifetime (L-49); the `bws`
  checksum pin persists across restarts and a changed binary is refused until you test the
  source again (L-50); backup files are written to a fresh, private temporary file (L-51); an
  import never adds trust for a host this device already pins (L-52); backup passwords never
  enter React state (L-53); the update manifest download is capped (L-40); the winget token is
  only available to the protected release job (L-54); plus N-72..N-75 and N-77.
- Threat model extended for biometric unlock (T-BIO), jump-host operators (T8), CLI-based
  secret sources (R-SEC-CLI) and RD Gateway. 66 fuzz targets (12 new: security-key and agent
  parsers, backup documents, dynamic-secret, 1Password and Bitwarden responses, RD Gateway
  packets and HTTP heads).

## [0.1.2] - 2026-11-07

### Fixed

- SSH (and Kubernetes `exec`) tabs opened a blank window in installed and portable builds on
  macOS and Windows: xterm.js 6 assigns `toString` on a plain object at module load, which throws
  under Tauri's `freezePrototype`. A build-time transform rewrites that assignment
  (`apps/desktop/vite-plugins/frozenPrototype.ts`, counted so an xterm upgrade fails the build instead),
  every session view now sits in an error boundary so one failing tab can never blank the window,
  and the Playwright flows run with a frozen `Object.prototype` like the app.

## [0.1.1] - 2026-11-07

### Added

- Portable builds for Windows (`Mooring_<v>_x64_portable.zip`) and macOS
  (`Mooring_<v>_universal_portable.zip`): a `portable` marker next to the app keeps every data
  file in `Mooring Data/` beside it; no installer, no admin, no fallback to the per-user folders
  when the directory is unwritable; updater reports `update.manual_only`
  ([ADR-0021](docs/adr/0021-portable-mode.md)).

### Changed

- Updater: `update.manual_only` now carries the reason from the backend (package manager,
  Homebrew or portable build) and the UI shows that text.

### Security

- Security review 8 ([docs/security/a4-1-review-8.md](docs/security/a4-1-review-8.md)):
  APPROVE WITH NITS. Fixed before the tag: M-18 (macOS App Translocation refused with
  `portable.translocated`), L-44 (`$APPIMAGE` honoured only on Linux and only for a real
  AppImage), L-45 (FAT/exFAT without POSIX modes is `portable.acl_unavailable`, not a refusal),
  L-46 (portable README claims), N-65/N-66/N-68/N-70. Threat model gains T-PORT-1..6.

## [0.1.0] - 2026-11-07

First release: Phase A of the roadmap (A1 connection manager, A2 graphical protocols and web
sessions, A3 infrastructure integrations, A4 release engineering). The A1 and early A2 entries
are under [0.1.0-rc.1] below; the sections here are per phase.

### Phase A4 — release engineering (importers, network tools, updater, pipeline)

#### Added

- **Importers**: Royal TS, Remote Desktop Manager, Termius (CSV/JSON), mRemoteNG, PuTTY and
  OpenSSH `~/.ssh/config` into a dry-run plan you review before anything is written; plaintext
  secrets only with an explicit opt-in, passwords that the source stores reversibly encrypted are
  never imported ([ADR-0019](docs/adr/0019-importers-and-onboarding.md)).
- **Directory import over LDAPS**: read-only search of computer objects (Active Directory or
  OpenLDAP) into folders mirroring the OU tree, with Mooring's own bounded LDAP v3 reader,
  certificate pinning and a native sign-in confirmation per directory host.
- **Network tools** in the inspector: TCP port check, ping, traceroute and read-only WireGuard
  status, with the OS tools run from fixed paths and no shell
  ([ADR-0020](docs/adr/0020-network-tools.md)).
- **In-app updates**: on-demand (background check is opt-in), packages signed with the project
  key and verified before install, never auto-installed, never elevated; package-manager and
  Homebrew installs are told to update there ([ADR-0018](docs/adr/0018-release-v0-1-0.md)).
- First-run onboarding card, Settings → Import / Updates / About, a new app icon, and the
  landing site refreshed to the shipped feature set.
- Release pipeline: Sigstore-signed `SHA256SUMS`, SLSA provenance, CycloneDX SBOMs, a
  reproducible-build check for the Rust crates, and a separate updater-signing job that runs in
  a protected GitHub environment.

#### Changed

- Syslog mirror structured-data element is now `[mooring@67553 …]`: 67553 is the Private
  Enterprise Number IANA assigned to the Mooring Project on 2026-11-06. Collectors that
  matched the interim RFC 5612 documentation number `32473` must update their rules.

#### Security

- Security review 7 ([docs/security/a4-review-7.md](docs/security/a4-review-7.md)): APPROVE
  WITH NITS after two fix rounds. The updater signing key never enters a build job (M-17);
  update offers below the last verified version are refused (L-39); update downloads are pinned
  to the project's release URL and capped (L-40); key files are imported only from the user's own
  `~/.ssh/config` (L-41); the first LDAPS sign-in to a host needs a native confirmation (L-43).
- `ldap3`'s BER decoder crashes on hostile input, so it is not in the product; the LDAP reader
  is Mooring's own and fuzzed. 18 more fuzz targets (importers, LDAP, network tools, RDP
  reactivation, VNC cut text, framebuffer ops); first green nightly fuzz run.

### Phase A3 — Kubernetes, vSphere, external secrets, vault sync (2026-11-05)

#### Added

- **Kubernetes sessions**: a read-only cluster browser from a kubeconfig or token credential
  (contexts, namespaces, pods with live watch, RBAC self-review), `exec` shells from an
  allow-list, log streaming with caps, pod port-forward — a closed route list guarantees
  Mooring never mutates the cluster ([ADR-0014](docs/adr/0014-kubernetes-sessions.md)).
- **vSphere inventory sync**: import datacenters, clusters, hosts and VMs into a read-only
  synced folder with scheduled refresh, VM power state and opt-in power actions behind a native
  confirmation, vSphere Client window and opt-in VMRC hand-off
  ([ADR-0015](docs/adr/0015-vsphere-integration.md)).
- **External secret sources**: HashiCorp Vault / OpenBao KV v2 with token, AppRole or OIDC
  sign-in (isolated sign-in window), `external_ref` credentials resolved at connect time,
  short-lived tokens renewed in memory and revoked on lock, root tokens refused
  ([ADR-0016](docs/adr/0016-external-secrets.md)).
- **Vault sync**: client-side encrypted MSY1 blobs to S3-compatible storage with conditional
  writes, three-way merge, fork and rollback hard stops, a join flow for new devices, and a
  global sync alarm banner ([ADR-0017](docs/adr/0017-vault-sync-and-signin.md)).
- New credential kinds `vault_approle` and `s3_access_key`; mock kube/vCenter/Vault/S3 test
  servers with a request recorder; 17 more fuzz targets; 11 more E2E flows.

#### Security

- Security review 6 ([docs/security/a3-review-6.md](docs/security/a3-review-6.md)):
  APPROVE WITH NITS after two fix rounds. Native confirmations are now `Cancel / <action> /
  Not now`: Return, Escape and the close box all refuse on every OS (M-16, and B-6 — the
  dialog plugin rewrites a cancelled dialog into the label of its cancel slot), answers are
  mapped by label only, one dialog at a time with a cool-down after a cancel; synced trust
  stores that disagree on a host fail closed until one pin is removed (L-35); a lock epoch drops tokens from
  sign-ins that straddled a lock (L-34); the join header is staged and renamed (L-37); web and
  OIDC windows get per-connection profiles on Windows (L-29, L-33); refused navigations are
  rate-limited in the audit log (N-43); `wry` is pinned by a test (N-46). Review-5 items
  L-29, L-30 and N-30..N-38 closed.

### Phase A2 — RDP, VNC, isolated web sessions (2026-11-04)

#### Added

- **RDP sessions** on IronRDP: NLA/CredSSP with domain or plain credentials, TLS through
  Mooring's own rustls verifier with certificate trust-on-first-use (hard stop on a changed
  certificate), dynamic resolution, text clipboard both ways under a per-connection policy,
  reconnect with backoff ([ADR-0011](docs/adr/0011-rdp-session.md)).
- **VNC sessions** with an own RFB 3.8 client: VeNCrypt (X509) with the same trust store,
  VNC auth, Raw/CopyRect/ZRLE/Tight (no JPEG), view-only, `prefer_tls`/`require_tls`
  ([ADR-0012](docs/adr/0012-vnc-session.md)).
- **Frame path**: Rust owns the framebuffer and streams dirty rectangles as binary messages
  with credit-based back-pressure; the UI renders with WebGL2.
- **Isolated web sessions**: one window per web connection with an empty capability, origin
  allow-list, ephemeral storage by default, downloads and permission prompts denied; **detach
  any session tab** into its own window with a six-command capability
  ([ADR-0013](docs/adr/0013-web-sessions.md)).
- Per-protocol connection options, a certificate trust dialog, a known-certificates manager,
  screenshot to clipboard (cleared on lock), in-process RDP/RFB test servers and nine more
  fuzz targets.

#### Security

- Security review 5 ([docs/security/a2-review-5.md](docs/security/a2-review-5.md)): a
  server-chosen desktop size was allocated before validation (B-5, fixed), VNC could be
  downgraded to plaintext for CA-issued hosts (M-13, fixed), reassembly caps (M-14),
  VNC zlib now decompresses in pure Rust (M-15). `tauri` is pinned to the reviewed release.

- **Port forwarding in the app**: local, remote and dynamic (SOCKS5) forwards per SSH session
  from a Forwards panel; non-loopback binds require an explicit confirmation and are audited
  ([ADR-0010](docs/adr/0010-a1-exit-ipc.md)).
- **SFTP browser**: two-pane file browser with navigate, new folder, rename and delete, streaming
  uploads and downloads with progress and cancel. Local folders and files are chosen through the
  native OS dialog opened by the Rust core — no local path ever crosses the WebView boundary.
  Uploads go through a temporary part file so a cancelled transfer never truncates the original;
  downloads refuse to overwrite without confirmation.
- **Auto-lock** is live: idle timeout (1 min–24 h or never), lock on sleep, on screen lock and
  when the window stays hidden for 60 s; externally exposed forwards are closed on every lock;
  sessions and loopback forwards survive a lock and reappear after unlock.
- **Syslog mirror** of the audit log (RFC 5424 over UDP, TCP or TLS with the system trust store),
  with chain hash in structured data, redirect audited on both collectors, startup entry and
  hourly heartbeat so collectors can alert on silence; "Send test entry" in Settings.
- Fuzz targets (`known_hosts`, kubeconfig, vault header, age import, SOCKS5) with a nightly
  job and a stable-toolchain corpus replay in `cargo test`; Playwright UI flows in CI.

#### Fixed

- Kubeconfig credentials: case variants of the `users` / `clusters` / `contexts` sections and
  mixed-case duplicate keys are now rejected (QA-F2).
- `known_hosts` files with multiple trailing carriage returns are rewritten byte-identically.

#### Security

- Security review 4 ([docs/security/a1-review-4.md](docs/security/a1-review-4.md)): the first
  SFTP design let the WebView name a local directory; it was replaced before release by a
  Rust-side picker with single-use pick tokens. The WebView capability remains `core:default`.

## [0.1.0-rc.1] - 2026-11-04

Work towards v0.1.0: Phase A0 (foundation) and Phase A1 (vault, connection tree, SSH).
Details per team role are in [docs/handoff/](docs/handoff/index.md).

### Added

- **Vault** (`mooring-vault`): Argon2id key derivation with XChaCha20-Poly1305 key wrapping
  and per-field sealing bound to record and field name; authenticated header with a KDF floor
  and ceiling; Argon2id cost calibrated to the host (64 MiB–1 GiB, about 500 ms); create,
  unlock, lock and change master password; header v2 with `vault_id`; durable header writes
  with fsync and a backup copy ([ADR-0002](docs/adr/0002-vault-cryptography.md),
  [ADR-0006](docs/adr/0006-vault-lifecycle.md)).
- Vault-side keyring wrap for a future "unlock with Touch ID / Windows Hello" option (not
  exposed in the app yet).
- `age`-compatible vault export and import in the library, with committed test vectors that
  CI verifies with the reference `age` CLI.
- Auto-lock policy (idle, screen lock, sleep, window hidden) as a tested, pure component.
- **Store** (`mooring-store`): SQLite database with folders, connections, tags and
  credentials (password, SSH key with passphrase, certificate); sealed secret columns;
  credential inheritance down the folder tree with per-connection override; FTS5 full-text
  search with query sanitising; migrations; secure delete; private file permissions
  ([ADR-0005](docs/adr/0005-storage.md)).
- **Audit log** (`mooring-audit`): SHA-256 hash-chained JSONL log with verification and
  secret redaction; events for vault, credential use, sessions and host-key decisions.
- **SSH** (`mooring-proto-ssh`, russh with the `ring` backend): PTY shell with resize,
  keepalive and back-pressure; password, public key, keyboard-interactive and ssh-agent
  authentication; host-key TOFU with OpenSSH `known_hosts` compatibility (hashed entries,
  serialised writes) and a hard stop on mismatch; strict algorithm allow-list
  ([ADR-0007](docs/adr/0007-ssh-trust-and-algorithms.md)).
- SSH local, remote and dynamic (SOCKS5) port forwarding with loopback-only binds by
  default, and an SFTP client with confined local paths and bounded transfers (library level;
  the app does not expose them yet).
- **Desktop app** (Tauri 2): 30 IPC commands for vault, tree, credentials, sessions and audit
  ([ADR-0008](docs/adr/0008-a1-ipc-contract.md)); copy-password with a 30-second clipboard
  clear, history exclusion, clear on lock and exit, and an audit entry; navigation guard for
  the main window.
- **UI** (React 19): three-pane layout, connection tree with keyboard navigation and
  drag-and-drop, command palette, tabs, inspector with a read-only credential reference,
  terminal (xterm.js with WebGL), host-key and keyboard-interactive prompts, audit log viewer
  with chain status, telemetry strip, dark and light themes, "bridge console" visual design.
- Typed credential model design with 15 kinds and a protocol compatibility matrix
  ([ADR-0009](docs/adr/0009-credential-model.md)); implementation pending.
- Quality gates: `make check`, CI on macOS, Windows and Linux, security workflow
  (cargo-deny, cargo-audit, pnpm audit, gitleaks, Semgrep, `forbid(unsafe_code)` check),
  test-vector workflow, lefthook pre-commit hooks.
- Tests: about 290 Rust tests (unit, property-based, in-process SSH server, end-to-end IPC
  flow, roughly 3 000 hostile IPC inputs) and 46 UI tests.
- Documentation: threat model, two security reviews, nine ADRs, user and developer guides.

### Changed

- Product renamed from Nexus Remote to Mooring.
- `age` is built from a pinned commit of the official repository until `age` 0.13 is on
  crates.io (accepted risk R-AGE-PIN).

### Security

- Names, hosts, tags and usernames refuse bidirectional-override and invisible format
  characters.
- Server-opened SSH channels (session, x11, agent, streamlocal, direct-tcpip) are rejected.
- Terminal hyperlinks (OSC 8) cannot open windows or navigate the app.
- SFTP local paths reject Windows alternate data streams and reserved device names.
- Host-key mismatch audit entries record both the expected and the presented fingerprint.

[Unreleased]: https://github.com/yyasar21/Mooring/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/yyasar21/Mooring/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/yyasar21/Mooring/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/yyasar21/Mooring/compare/v0.1.0-rc.1...v0.1.0
[0.1.0-rc.1]: https://github.com/yyasar21/Mooring/releases/tag/v0.1.0-rc.1
