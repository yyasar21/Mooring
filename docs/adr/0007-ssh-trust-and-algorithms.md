# ADR-0007: SSH client — trust, authentication, algorithms

Status: Accepted · 2026-11-03 (Phase A1, item 3)

## Context
`mooring-proto-ssh` must give a Royal-TS-class terminal (shell, resize, streaming), SFTP and
port forwarding on top of ADR-0004, against servers the user does not control (home lab now,
customer estates later). Host-key handling and algorithm choice are the security core.

## Decision

### Library
- `russh` with `default-features = false, features = ["ring", "rsa", "flate2"]` — `ring` is on
  the crypto allow-list (ADR-0001); `aws-lc-rs` is not used. `russh-sftp` for SFTP. No other
  SSH crates.

### Host-key trust (TOFU + known_hosts)
- Trust store: `$APP_DATA/known_hosts` in OpenSSH `known_hosts` format (plain and `|1|`
  hashed entries are both read; new entries are written hashed). The parser treats the file as
  untrusted input: line length cap 8 KiB, 10 000 lines, base64 decoded with caps, unknown key
  types ignored, malformed lines skipped with a `tracing::warn!`; property tests feed random
  bytes.
- Decision table on `check_server_key(host, port, key)`:
  - key matches a stored entry → accept silently.
  - host unknown → emit `SessionEvent::Prompt { id, message: "<host>:<port> <key type> SHA256:<fp>  — trust this host?", secret: false }`; the UI answers via `SessionInput::Answer { id, text: "yes" | "no" }`; `yes` stores the key and proceeds, anything else aborts with `Closed { reason: "host key not trusted" }`. Audit `trust.host_key.added` with host, type, fingerprint.
  - host known, key differs → **hard stop**, no prompt: `Closed { reason: "HOST KEY CHANGED for <host>: expected <fp-old>, got <fp-new>" }` and audit `trust.host_key.mismatch`. Removal is an explicit UI action (A1 item 4) that audits `trust.host_key.removed`.
- `SessionEvent::Prompt` gains `purpose: PromptPurpose { HostKeyTrust, KeyboardInteractive, Other }`
  so the UI picks the dialog by a typed field, never by matching server-controlled text (L-2).
- `SessionEvent::Connected.peer_identity` carries `"<key type> SHA256:<fingerprint>"`.

### Authentication (in order, first success wins; the user may restrict)
1. `publickey` with the vault key (`ConnectSecret::PrivateKey` → `russh::keys::PrivateKey`,
   passphrase decrypt in memory, zeroized after).
2. `ssh-agent` (`SSH_AUTH_SOCK` on unix, Pageant/OpenSSH agent named pipe on Windows) when
   `ConnectParams.secret` is `None` or the key fails — opt-in flag `allow_agent` (default
   true).
3. `password` (`ConnectSecret::Password`).
4. `keyboard-interactive`: each server prompt becomes a `SessionEvent::Prompt` (`secret` =
   server's echo flag inverted) answered through `SessionInput::Answer`; the vault password is
   auto-filled for the first prompt when the prompt text matches `/password/i` and a password
   secret exists.
- `mooring_core::session::SessionInput` gains `Answer { id: u32, text: SecretString }` with a
  hand-written `Debug` (redacted) and a custom `Deserialize` only (never serialised back to
  the UI).
- Secret material is dropped right after the auth round; failed auth yields a generic
  `Closed { reason: "authentication failed" }` (no method detail in the UI, detail in tracing at
  `debug` without the secret).

### Algorithms (defaults; a per-connection "legacy" toggle in A2 may relax, audited)
- kex: `curve25519-sha256`, `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256/384/521`,
  `diffie-hellman-group16-sha512`, `diffie-hellman-group14-sha256` (post-quantum hybrids when
  russh exposes them). Never: `diffie-hellman-group1-sha1`, `*-sha1`.
- host keys: `ssh-ed25519`, `ecdsa-sha2-nistp*`, `rsa-sha2-512`, `rsa-sha2-256`. Never: `ssh-rsa` (SHA-1), `ssh-dss`.
- ciphers: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr`, `aes128-ctr`. Never: CBC, 3DES, arcfour.
- macs: `hmac-sha2-512-etm`, `hmac-sha2-256-etm`, `hmac-sha2-512`, `hmac-sha2-256`. Never: `hmac-sha1*`, `hmac-md5*`.
- The negotiated set is logged at `info` and exposed in a `SessionEvent::Connected`
  follow-up `Bytes` line only in verbose mode; not shown to the user by default.

### Channels and flow
- One `russh` client connection per `SshSession`; shell = one `session` channel with PTY
  (`xterm-256color`, size from `ConnectParams.size`, `Resize` → `window_change`). Output is
  forwarded as `SessionEvent::Bytes` in ≤ 64 KiB chunks; a bounded `tokio::mpsc` (256)
  applies back-pressure. Keepalive `ServerAliveInterval` 30 s, 3 misses → `Closed`.
- Port forwarding: `SshSession::forward_local(bind, target, exposure)`, `forward_remote`,
  `forward_dynamic(bind, exposure)` (SOCKS5, no auth, CONNECT only). `Exposure { Loopback,
  External }` applies to all three kinds; `Loopback` is the default and a non-loopback bind
  with `Loopback` is refused; `External` is audited (security review 2, M-2). Each returns a
  `ForwardId` and audits `session.forward.open/close`.
- SFTP: `SshSession::sftp()` opens one `russh-sftp` session on demand; `list`, `stat`, `mkdir`,
  `rename`, `remove`, `download(remote, local, progress)`, `upload` with a progress callback
  (`bytes_done, bytes_total`) and path normalisation that rejects `..` escapes for the local
  side. Transfers stream in 256 KiB blocks; no whole-file buffering.

### Tests
- In-process `russh` server (the crate's server half) in `tests/` provides: password,
  publickey and keyboard-interactive auth, a shell that echoes, host-key TOFU / mismatch
  scenarios, forwarding and SFTP round trips — no network beyond loopback, no lab.
- `known_hosts` parser: unit + proptest (random bytes never panic; round trip of written
  hashed entries). A `cargo fuzz` target `known_hosts_parse` is added when nightly is
  available (QA).
- `MOORING_LAB=1` integration test against `xinfra01.homelab.xyz`: connect, `uname -a`, close —
  read-only, skipped by default.

## Alternatives considered
- `libssh2` / `openssh` subprocess: C dependency or shelling out, no in-process TOFU control.
  Rejected.
- `thrussh` (predecessor): unmaintained. Rejected.
- Accepting changed host keys with a prompt: the mismatch case is exactly the MITM signal;
  OpenSSH's hard stop is the right model. Rejected.

## Security consequences
Hostile server bytes are parsed by `russh` (audited, `forbid(unsafe)` where possible) and by
our `known_hosts` parser only. Legacy algorithms are off by default and any relaxation is
per-connection and audited (A2). Secrets live for the auth round only.
