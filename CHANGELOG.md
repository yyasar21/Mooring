# Changelog

All notable changes to Mooring are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until v1.0 a
minor version may contain breaking changes; they are called out under **Changed**.

## [Unreleased]

### Added

- Portable builds for Windows (`Mooring_<v>_x64_portable.zip`) and macOS
  (`Mooring_<v>_universal_portable.zip`): a `portable` marker next to the app keeps every data
  file in `Mooring Data/` beside it; no installer, no admin, no fallback to the per-user folders
  when the directory is unwritable; updater reports `update.manual_only`
  ([ADR-0021](docs/adr/0021-portable-mode.md)).

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
  ([ADR-0015](docs/adr/0015-vsphere-sync.md)).
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

[Unreleased]: https://github.com/yyasar21/Mooring/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yyasar21/Mooring/compare/v0.1.0-rc.1...v0.1.0
[0.1.0-rc.1]: https://github.com/yyasar21/Mooring/releases/tag/v0.1.0-rc.1
