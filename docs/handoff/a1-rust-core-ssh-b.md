# A1 · rust-core · SSH port forwarding and SFTP (item 3, part b)

Branch `worktree-agent-a33d74c4ad1887614`, on top of `85a9f05`. Not merged.
Inputs: ADR-0004, ADR-0007 §Channels and flow, `docs/handoff/a1-rust-core-ssh.md`.
Scope: `crates/mooring-proto-ssh/**` only. No manifest, lockfile or `src-tauri` change;
`russh-sftp 3.0.1` was already declared. Linux host.

## Done

| Commit | What |
| --- | --- |
| `ffa7077` | **feat(ssh): forwarding** — modules `forward` (registry + API), `forward_io` (accept loops, splice, forwarded-tcpip routing), `socks` (SOCKS5 parser/handshake). `ClientHandler::server_channel_open_forwarded_tcpip`; `TrustEvent::ForwardOpened/ForwardClosed`. |
| `a4b032e` | **test(ssh): forwarding** — test server gains `direct-tcpip`, `tcpip-forward`/`cancel-tcpip-forward`; 8 scenarios in `tests/forward.rs`. |
| `4e6d0bb` | **feat(ssh): SFTP** — modules `sftp` (client, list/stat/mkdir/rename/remove), `sftp_transfer` (download/upload), `local_path` (`LocalPath`). |
| `6973cec` | **test(ssh): SFTP** — `russh_sftp::server` over a tempdir (`tests/common/sftp_server.rs`); 7 scenarios in `tests/sftp.rs`. |

### Forwarding API (`SshSession`)
- `forward_local(bind: SocketAddr, target: (String, u16)) -> Result<ForwardId>`
- `forward_remote(remote_bind: (String, u16), target: SocketAddr) -> Result<ForwardId>`
- `forward_dynamic(bind: SocketAddr, allow_external: bool) -> Result<ForwardId>` — the
  `allow_external` flag is a parameter, not an option struct; non-loopback binds without it
  return `Invalid { field: "bind" }`.
- `forward_close(id)`, `forwards() -> Vec<ForwardInfo { id, kind, bind, port, target }>`.
  `port` is the port actually bound (local port 0 or server-allocated port 0 are resolved).
- All `async`, all `&self`, all refuse with `Protocol "not connected"` before `Connected`
  and `Closed` after close.
- Bounds: 64 forwards/session, 128 concurrent connections/forward (excess connections are
  dropped / channels rejected with `ResourceShortage`), 32 KiB copy buffer per direction.
  SOCKS handshake has a 10 s timeout; remote-forward target connect 10 s.
- Audit: `session.forward.open` / `session.forward.close` with `id`, `kind`
  (`local|remote|dynamic`), `bind`, `target` (`socks5` for dynamic). Per-connection events
  are not audited (only `debug!`).
- Lifecycle: `Shared::release_channels()` runs in `begin_close` (user close / drop) and in
  the driver after the session ends (remote exit, connection loss). It stops listeners,
  cancels every live spliced connection (watch channel) and audits each close.
  `forward_close` on a remote forward also sends `cancel-tcpip-forward`.
- Incoming `forwarded-tcpip` channels are matched by (address, port), falling back to port
  when unique (servers may rewrite the address); unknown ones are rejected.

### SFTP API
- `SshSession::sftp() -> Result<SftpClient>`: opens once (15 s timeout), reuses; clients
  obtained earlier fail after the session closes.
- `SftpClient::list(path) -> Listing { entries: Vec<Entry>, truncated }`,
  `stat(path) -> Entry`, `mkdir`, `rename(from, to)`, `remove(path)` (lstat first: rmdir for
  directories, which the server refuses when non-empty; never recursive).
- `Entry { name, kind: File|Dir|Symlink|Other, size, mtime, mode }` (`mode & 0o7777`).
- `download(remote, &LocalPath, progress) -> u64`, `upload(&LocalPath, remote, progress) -> u64`.
  `progress(bytes_done, bytes_total)` is called with `(0, total)` first, then after every
  256 KiB block. Each block = up to 8 pipelined 32 KiB requests; memory is one block.
  Downloads land in a `NamedTempFile` next to the target and are `persist`ed only on success.
- `LocalPath::new(base, relative)` — the caller names the base directory (e.g. the user's
  chosen download folder). Rejects `..`, absolute/prefix components, empty paths, > 4 KiB;
  at use time rejects symlink escapes (canonicalised parent/file must stay under the
  canonical base), symlink or directory targets, and non-regular sources. `Debug` and all
  errors omit both the base and the relative path.
- Hostile server: remote paths ≤ 4 KiB, no NUL; listing ≤ 10 000 entries; names that are
  empty, `.`, `..`, contain `/` or NUL, or exceed 1 KiB are dropped; a read reply larger
  than requested is an error; server error text is never surfaced (status → `NotFound` /
  `Protocol` / `Transport`).

## Left open

- **Fuzz targets** (QA, nightly): `socks::parse_request(&[u8])` is a pure entry point
  (proptested here). russh-sftp's packet decoding is upstream code.
- **No per-connection audit** for forwards; only open/close of the forward itself.
- **`forward_remote` bind address**: any `validate_host` string is accepted and passed to
  the server (e.g. `0.0.0.0` exposes the port on the server side, subject to sshd
  `GatewayPorts`). No client-side policy yet — see Decision 2.
- **Dynamic forward targets are unrestricted**: SOCKS clients may CONNECT to any host the
  server can reach, including the server's own loopback. That is what `ssh -D` does.
- Download does not preserve remote mtime/mode; upload does not set remote mode.
- Recursive transfers, resume, and cancellation of an in-flight transfer (other than
  dropping the future, which is safe: temp file is removed) are not implemented.
- Windows: `LocalPath` symlink tests are `cfg(unix)`; junction escapes on Windows rely on
  `canonicalize` and were not exercised here.
- Disk: the shared `/` volume hit 100 % at the start of this task; builds were done with
  `CARGO_TARGET_DIR=/home/claude/nexus/target` (identical `Cargo.lock`), the worktree's own
  `target/` was removed. Old scratchpad build dirs (`deptest`, `probe`, `kemcheck`,
  `kscheck`, ~2.5 GB) could not be cleaned by this agent.

## Decision needed

1. **API shape for `forward_dynamic`**: the task text had `forward_dynamic(bind)` plus an
   `allow_external: true` escape hatch; I made it a second bool parameter. Alternative: an
   `ForwardOptions` struct. src-tauri/IPC (ADR-0008) needs to pick one.
2. **Remote-forward bind policy**: should Mooring refuse non-loopback `remote_bind` hosts
   unless the user opts in (mirroring the dynamic rule)? Currently allowed.
3. **russh-sftp limitations accepted** (security-reviewer):
   - The high-level `SftpSession` has no listing cap (`read_dir` collects everything) and
     its `File` reader buffers; I used `RawSftpSession` directly to enforce caps.
   - `RawSftpSession::read` returns whatever length the server sent; we reject replies
     longer than requested, but the upstream decoder still allocates up to its packet cap
     (`max_packet_len` 256 KiB) per reply before we see it.
   - Per-request timeout is upstream's 10 s default; a stalled server stalls a transfer for
     10 s per request, not forever.
   - `russh-sftp` logs through `log`, not `tracing`; it logs server error strings at `warn`
     in its server side only (test code here), not in the client paths used.

## Test evidence

```
cargo fmt --all --check                                          OK
cargo clippy -p mooring-proto-ssh --all-targets -- -D warnings   OK
cargo test -p mooring-proto-ssh
  unit (src)        43 passed  (+19: socks 6 incl. 2 proptests, forward 3, forward_io 1,
                                local_path 5, sftp 4)
  tests/auth.rs      9 passed
  tests/forward.rs   8 passed  (local echo incl. 300 KB + audit + close, target validation,
                                remote forward w/ allocated port + cancel, SOCKS5 v4/domain/
                                unreachable, non-loopback bind refused/allowed, close with
                                session incl. live connection, close on remote exit,
                                refused before Connected)
  tests/sftp.rs      7 passed  (mkdir/list/stat + 640 KiB up/down with per-block progress +
                                empty files, rename/remove, ../absolute/symlink escapes,
                                path cap/NUL/missing file leaves nothing, 10 001-entry
                                listing truncated, closes with session, refused subsystem)
  tests/shell.rs     8 passed
  tests/trust.rs     5 passed
  tests/lab.rs       1 ignored
5 consecutive full runs: all green, < 4 s per binary after the build.
```
