# Changelog

All notable changes to Mooring are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until v1.0 a
minor version may contain breaking changes; they are called out under **Changed**.

## [Unreleased]

### Added

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

### Security

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

### Fixed

- Kubeconfig credentials: case variants of the `users` / `clusters` / `contexts` sections and
  mixed-case duplicate keys are now rejected (QA-F2).
- `known_hosts` files with multiple trailing carriage returns are rewritten byte-identically.

### Security

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

[Unreleased]: https://github.com/yyasar21/Mooring/compare/v0.1.0-rc.1...HEAD
[0.1.0-rc.1]: https://github.com/yyasar21/Mooring/compare/v0.1.0...v0.1.0-rc.1
