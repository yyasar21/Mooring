# SSH

Mooring's SSH client is built on [russh](https://github.com/Eugeny/russh) with the `ring`
crypto backend. The specification is [ADR-0007](../adr/0007-ssh-trust-and-algorithms.md).

## Terminal

- xterm-compatible terminal (`xterm-256color`) rendered with WebGL, with a DOM fallback.
- The remote terminal size follows the window.
- Keepalive every 30 seconds; after three missed replies the session is reported as lost.
- Clicking hyperlinks printed by the server (OSC 8) does nothing on purpose: a server cannot
  make Mooring open a web page or navigate the app.
- Several sessions run side by side in tabs; `mod Shift D` detaches a tab into its own window.
- The session header shows the folder, the host, a status pill with the time connected, the
  **Terminal / Forwards / Files** switch (Forwards shows the number of open forwards) and
  **Disconnect**, which closes the session but keeps the tab for **Reconnect**.

## Host-key verification (TOFU)

SSH servers prove their identity with a host key. Mooring follows the *trust on first use*
model of OpenSSH, with a strict rule for changes:

| Situation | What Mooring does |
| --- | --- |
| Key matches a trusted entry | Connects silently. |
| Host never seen before | Shows **Verify host identity** with the key type and `SHA256:` fingerprint. **Trust and connect** stores the key; **Reject and disconnect** aborts. Both are audited. |
| Host known, **key changed** | **Hard stop.** The session closes with `HOST KEY CHANGED`, showing the expected and presented fingerprints. There is no "connect anyway". Audited as `changed`. |

How to check a fingerprint: ask the server owner, or on the server run

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

A changed key can mean the server was reinstalled — or that someone is intercepting the
connection. Confirm with the server owner before removing the old entry.

**Trusted keys** live in `known_hosts` inside Mooring's application data directory, in
OpenSSH format, so you can pre-seed it from your existing `~/.ssh/known_hosts` while Mooring
is closed. New entries are written hashed (`|1|…`). Host certificates (`@cert-authority`) are
not supported yet and are refused; `@revoked` entries stop the connection. Removing a stored
host key from inside the app is planned.

If the `known_hosts` file cannot be written, an accepted key is trusted for the current session
only and the audit entry says `accepted_session_only`.

## Authentication

Mooring tries methods in this order and stops at the first success:

1. **Public key** from the vault (OpenSSH private key; the passphrase is decrypted in memory
   and wiped after use).
2. **ssh-agent**, when no vault key applies or the key is refused: `SSH_AUTH_SOCK` on macOS and
   Linux, the OpenSSH agent pipe or Pageant on Windows.
3. **Password** from the vault.
4. **Keyboard-interactive**: each server prompt appears as a dialog; the vault password is
   filled in automatically for a first prompt that asks for a password.

Failures are reported as `authentication failed` without detail, so a hostile server cannot
learn which method or secret was rejected.

Notes:

- When the agent is used, the server sees the agent's public keys, as with OpenSSH.
- **Agent forwarding is never requested**, and channels the server tries to open towards
  Mooring (X11, agent, sessions, forwarded sockets) are refused.
- Ed25519 keys are recommended. RSA keys work with `rsa-sha2-256/512` signatures.
- FIDO2 security keys (`sk-*`) and PIV smart cards sign through ssh-agent with their own
  credential kinds; see [Security keys and smart cards](security-keys-and-smart-cards.md).
- SSH certificates: an SSH key credential can carry an OpenSSH certificate, certificates held by
  your agent are used for every key type, and a Vault SSH CA can sign your key at connect time
  (see [External secrets](external-secrets.md#dynamic-vault-engines)).
- To reach a host through a bastion, see [Jump hosts](jump-hosts.md).

## Algorithms

Only these algorithms are offered. Older servers that need SHA-1 or CBC will fail to
negotiate; a per-connection, audited legacy option is planned for Phase A2.

| Category | Allowed |
| --- | --- |
| Key exchange | `mlkem768x25519-sha256`, `curve25519-sha256` (+ `@libssh.org`), `ecdh-sha2-nistp256/384/521`, `diffie-hellman-group16-sha512`, `diffie-hellman-group14-sha256`; strict KEX (Terrapin mitigation) |
| Host keys | `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `rsa-sha2-512`, `rsa-sha2-256` |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr`, `aes128-ctr` |
| MACs | `hmac-sha2-512-etm`, `hmac-sha2-256-etm`, `hmac-sha2-512`, `hmac-sha2-256` |
| Never | `ssh-rsa` (SHA-1), `ssh-dss`, `diffie-hellman-group1-sha1`, any `*-sha1` KEX, CBC, 3DES, arcfour, `hmac-sha1*`, `hmac-md5*`, compression |

## Port forwarding

Open the **Forwards** view of an SSH session and choose **New forward**.

| Kind | Equivalent | Notes |
| --- | --- | --- |
| Local | `ssh -L` | Listen on your machine, connect to a target via the server. |
| Remote | `ssh -R` | Listen on the server, connect back to a target on your side. |
| Dynamic | `ssh -D` | SOCKS5 proxy (no auth, CONNECT only) on your machine. |

Safety defaults:

- Listeners bind to **loopback only** (`127.0.0.1`, `::1`, `localhost`). Exposing a forward on
  your network (or a remote forward on the server's network) needs an explicit "external"
  choice, which is audited.
- At most 64 forwards per session and 128 connections per forward.
- All forwards close when the session closes; open and close are audited.
- While a dynamic forward is open, any program on your machine can use the SOCKS port to
  reach what the server can reach — close it when you are done.

## SFTP

Open the **Files** view of an SSH session. The remote listing is a sortable table; local files
are always picked in the system dialog, never by the interface.

- Browse, create folders, rename and delete (directories only when empty; never recursive).
- Upload and download with progress, streamed in blocks — large files are never loaded into
  memory in full.
- Downloads are written to a temporary file and only appear under their final name when
  complete.
- Downloads can only be written inside the folder you choose: `..`, absolute paths,
  symbolic-link escapes, Windows alternate data streams (`file:stream`) and reserved device
  names (`CON`, `NUL`, `COM1`…) are refused.
- Listings are capped at 10 000 entries; server error text is not shown verbatim.
- Not yet: preserving timestamps and permissions, recursive transfers, resume.
