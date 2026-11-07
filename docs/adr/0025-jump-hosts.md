# ADR-0025: Jump hosts and bastions (`via` chains)

Status: Accepted 2026-11-07 (owner decisions: 31 depth 3; 32 explicit per connection (folder inheritance later); 33 one chain per session; 34 web-via SOCKS ships with refusal on macOS < 14) · 2026-11-07 (Phase A5 / v0.2.0; amends ADR-0004, ADR-0005 schema, ADR-0007,
ADR-0009 §1 ("jump hosts are another connection"), ADR-0011, ADR-0012, ADR-0013, ADR-0014)

## Context
Every protocol crate opens its own `TcpStream` today: `SshSession::connect` (then
`russh::client::connect_stream`-compatible driver), `mooring-proto-rdp::connect::tcp_connect`
(`RdpStream = TlsStream<TcpStream>`), `mooring-proto-vnc::connect`, and `mooring-http`'s
connector (`connect.rs`, kube/vSphere/Vault/S3). SSH already has `direct-tcpip` channels
(`forward_io::open_direct`, `Handle::channel_open_direct_tcpip`) and `russh::Channel::into_stream`
gives an `AsyncRead + AsyncWrite` over a channel. ADR-0009 reserved `connection.via_connection_id`
(single hop). The owner's estates reach targets through one to three bastions; OpenSSH users
expect `ProxyJump` semantics (no local port, no second listener).

## Decision

### 1. Model (`mooring-core`, migration `0010_connection_via.sql`)
- `connection_via(connection_id FK CASCADE, position INTEGER 0..2, hop_connection_id FK→connection
  ON DELETE RESTRICT, PK(connection_id, position))`. The chain is **explicit on the leaf**
  (`via: [hop1, hop2, hop3]` = first hop is reached directly, the target through the last);
  a hop's own `via` is **ignored** (explicit > implicit, no recursion), which makes cycles
  impossible to *follow*; validation still refuses: the leaf in its own chain, duplicate hops,
  a hop that is not `Protocol::Ssh`, depth > 3 (`connection.via_invalid`). Deleting a hop that
  others use → `connection.in_use_as_hop` (RESTRICT, surfaced with the list).
- `Connection` gains `via: Vec<ConnectionId>`; `ConnectionDto.via: string[]`; create/update
  accept it. Inherited folder defaults: **not in 0.2.0** (owner decision 32).
- Each hop uses its **own** credential resolution (ADR-0009 §3: own/inherited/`prompt`/
  `external_ref`), its own `known_hosts` trust (TOFU/mismatch per hop), its own legacy-algorithm
  options and keepalive. Nothing about the leaf changes a hop's settings.

### 2. Transport (`mooring-proto-ssh::hops`, rust-core)
```rust
pub struct Hop { pub params: ConnectParams, pub options: SshOptions, pub index: u8 }
pub enum HopStream { Tcp(TcpStream), Channel(ChannelStream<Msg>) }   // AsyncRead + AsyncWrite
pub struct HopChain { hops: Vec<HopHandle> }                           // kept alive by the session
impl HopChain {
    /// Opens hop 0 over TCP, hops 1.. over `direct-tcpip` of the previous one, then one more
    /// `direct-tcpip` to `target`; emits `Prompt`/`Connected` events tagged with `hop`.
    pub async fn open(hops: Vec<Hop>, target: (&str, u16), events: &EventSink)
        -> Result<(HopChain, HopStream), HopError>;
    pub async fn close(self);                                          // reverse order
}
```
- `russh::client::connect_stream(config, HopStream, handler)` replaces the TCP-only entry in
  `SshSession` (the driver's `stream` field becomes `HopStream`); RDP's `RdpStream` becomes
  `TlsStream<HopStream>`, VNC's connect takes `HopStream`, and `mooring-http`'s connector gains
  a `Connector::via(HopChain)` that hands `HopStream` to hyper instead of a `TcpStream`
  (Kubernetes API, kube exec/port-forward/logs, vSphere, Vault, S3 — any connection whose
  `via` is set). SFTP and SSH port forwards ride the leaf session as today (a forward's
  `direct-tcpip` is opened on the leaf, so "local forward through a bastion to a third host"
  works unchanged).
- **No local listener** for SSH, SFTP, RDP, VNC, Kubernetes, vSphere: bytes stay inside the
  process. Keepalive runs per hop; a hop closing closes everything above it with
  `Closed { code: hop_lost, hop }`; reconnect (ADR-0011) rebuilds the whole chain.
- `SessionEvent::Prompt`, `Connected` and the new `HopStatus { hop, state: connecting |
  authenticating | up | failed, peer_identity }` carry `hop: Option<u8>` (`None` = target).
  Prompts are answered through the same `SessionInput::Answer { id }` (ids are unique per
  session), so the UI's host-key and keyboard-interactive dialogs work per hop without new
  IPC; the dialog title names the hop.
- Limits: ≤ 3 hops, each hop's connect timeout as configured, total chain deadline 90 s, one
  chain per session (no multiplexing / ControlMaster in 0.2.0: simpler lifecycle, each session
  re-authenticates; owner decision 33).

### 3. Web sessions through a chain (ADR-0013) — partial
A WebView cannot consume an in-process stream. For `Protocol::Web` with `via`, Rust opens a
**dynamic (SOCKS5) forward** on the last hop bound to `127.0.0.1:0` with `Exposure::Loopback`
(ADR-0007/ADR-0010; audited `session.forward.open { reason: web_via }`), and the web window is
built with `WebviewWindowBuilder::proxy_url("socks5://127.0.0.1:<port>")` (Tauri 2.12.5:
WebView2 and WebKitGTK; **macOS needs the `macos-proxy` feature and macOS 14+**, enabled in
0.2.0 with a fallback refusal `web.via_unsupported` on older macOS). The page keeps its real
host name, so TLS validation is unchanged. The listener dies with the window (and on lock, as
every forward with `Exposure::External` — this one is loopback and survives, like other
loopback forwards). This is the one place a loopback port exists; it is bound to a random
port, accepts no auth (SOCKS5 "no auth"), and T2 can reach it while the window is open —
recorded as **R-WEB-VIA** (same class as every local forward, R-SFTP-LOCAL neighbourhood).

### 4. IPC and audit
`connection_create/update` + `via`; `session_open` unchanged (the chain is resolved in
`connect_plan` from the leaf's `via`); new passive `session_hops({ sessionId }) -> HopStatus[]`
for re-adoption after unlock. Audit per hop: `session.hop.open { session, hop, connection,
peer_identity, auth_method }`, `session.hop.close { hop, code }`, trust events as today with
`hop`. Error codes: `connection.via_invalid`, `connection.in_use_as_hop`, `session.hop_failed`,
`session.hop_lost`, `web.via_unsupported`.

## Alternatives considered
- **Local port-forward per hop** (`ssh -L` chain, each hop a loopback listener): T2 can connect
  to every intermediate port while the session is open; ports leak into the audit as exposure;
  reconnect must rebind. Rejected except where unavoidable (§3).
- **`ProxyCommand`-style `ssh -W` subprocess**: process spawning with the user's `ssh` config,
  no in-app TOFU, no per-hop prompts. Rejected (ADR-0007).
- **Recursive `via` (hop's own chain applies)**: matches OpenSSH `ProxyJump` nesting but makes
  the effective path invisible in the UI and needs cycle detection at every edit. Rejected for
  the explicit list; the inspector shows the full path instead.
- **Multiplexed shared hop sessions**: fewer logins, but a lock or failure on one hop affects
  unrelated sessions and the audit loses one-session-one-chain. Deferred (decision 33).

## Security consequences
- T3: each hop is authenticated and host-key-pinned independently; a changed key on any hop is
  the same hard stop as today. A bastion operator (new attacker row **T8**: a compromised hop)
  sees cleartext of the *next* hop's TCP only where the next protocol is itself unencrypted —
  SSH/RDP(TLS)/VNC(VeNCrypt)/HTTPS are end-to-end through the tunnel; plain VNC
  (R-VNC-PLAIN) is exposed to the hop as it is to any network path, and the UI warns when a
  plain protocol crosses a hop.
- T2: no listener except §3 (loopback, random port, lives with the window).
- T4: the hop's SSH server is a hostile-input source as today (russh parsers, `known_hosts`);
  `direct-tcpip` refusals and channel EOF are mapped to `hop_failed`/`hop_lost`, never a panic
  (`panic = "unwind"` per session task, ADR-0011 decision 1).
- T5: can set `via` on a connection it can edit, which only routes through hosts the user
  already trusts; cannot create forwards beyond the web SOCKS one tied to a window.
- Credentials of every hop are resolved from the vault per connect and dropped after each
  hop's auth round (ADR-0004); a chain holds at most one secret in memory at a time.
- No new crate: `russh` already provides `connect_stream`, `channel_open_direct_tcpip`,
  `into_stream`; Tauri's `proxy_url` is in the pinned version (`macos-proxy` feature flag only).

## UI
Connection form: "Connect via" picker (ordered list of SSH connections, ≤ 3, drag to reorder,
search; hops with their own `via` show an "ignored" hint); inspector shows the path
`laptop → bastion-a → bastion-b → target`. Session header: one chip per hop with state
(connecting / up / failed) and the peer fingerprint on hover; trust and keyboard-interactive
dialogs are titled "Hop 1 of 3 — bastion-a". Web sessions show "via bastion (SOCKS)".

## Test plan
- Unit: `via` validation table (self, duplicate, non-SSH hop, depth 4, RESTRICT delete),
  `HopChain` ordering and reverse close, event tagging, deadline.
- Integration (`mooring-proto-ssh` in-process russh server as hop + a second instance as
  target): SSH through 1/2/3 hops, hop TOFU prompt then mismatch hard stop, hop loss →
  `hop_lost`, SFTP and a local forward over the chain; RDP (acceptor-based server) and VNC
  (RFB test server) through one hop; kube mock through one hop; web SOCKS forward bound to
  loopback only.
- E2E: picker, path in inspector, hop chips, per-hop dialogs with the mock transport.
- Fuzz: no new parser (channel stream is russh's); `via` DTO validation is covered by unit.
- Manual gate: the owner's lab bastion (`MOORING_LAB_JUMP_HOST`, `#[ignore]`, read-only).

## Owner decisions needed
31. Depth limit 3 (recommended) — or 2.
32. Folder-level default `via` inheritance (like `default_credential_id`): 0.2.0 or later.
    Default: later; explicit per connection now.
33. Shared/multiplexed hop sessions: later (default) — each session opens its own chain.
34. Web sessions via SOCKS proxy on all three OSes with `macos-proxy` (macOS 14+ only) — ship
    with the refusal on older macOS (default), or hold web-via for a later release.
