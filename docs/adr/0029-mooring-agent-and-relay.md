# ADR-0029: Mooring agent and relay (Phase B)

Status: Proposed · 2026-11-07 (Phase B; extends ADR-0004 Session trait, ADR-0005 data model,
ADR-0002 vault cryptography, ADR-0025 jump hosts for chain comparison)

## Context

Phase A gives Mooring a full connection manager (SSH, RDP, VNC, web, Kubernetes, vSphere) and
imports for Royal TS, Termius and others. Many target machines — virtual machines in locked-down
cloud accounts, air-gapped labs, corporate endpoints behind CGNAT — cannot or must not expose
SSH, RDP or VNC ports to the Internet (or even the user's LAN). The roadmap calls for Mooring's
own remote-desktop agent and relay: an end-to-end encrypted channel so Mooring can reach any
registered endpoint through a relay, without opening firewall rules on the target.

Phase B is a large architectural addition. It introduces a new trust boundary (the relay), a
new binary (the agent), and new protocols (signalling, E2E key exchange, tunnel framing). It must
fit into the existing `Session` trait so the UI does not learn a fourth protocol family.

## Decision

### 1. Architecture at a glance

```
┌─────────────┐      E2E tunnel       ┌─────────────┐
│  Mooring    │ ◄──────────────────► │  Agent      │
│  (client)   │   relay-proxy data   │  (target)   │
└──────┬──────┘                      └──────┬──────┘
       │                                    │
       │  WebSocket / wss                   │  runs as user / system service
       ▼                                    ▼
┌─────────────┐                      ┌─────────────┐
│  Relay      │ ◄──────────────────► │  Local      │
│  (infra)    │   control signals    │  input/output│
└─────────────┘                      └─────────────┘
```

- **Relay**: a stateless proxy that only forwards encrypted blobs between client and agent.
  It terminates TLS, sees no E2E content, and never stores session data. Deployable as a
  single binary (`mooring-relay`) or a managed cloud service.
- **Agent**: a small Rust binary (`mooring-agent`) that runs on the target machine, registers
  itself with the relay under a stable endpoint id, and multiplexes local input/output
  (screen capture, keyboard/mouse, file list) into the tunnel.
- **Client**: Mooring desktop app opens a session by requesting a tunnel to the agent's id.
  The Session trait handles the E2E handshake, then the session flows like any other protocol.
- **No port forwarding, no listener on the target**: the agent initiates and maintains the
  outbound connection to the relay (like a reverse tunnel), so no firewall changes are needed.

### 2. Crate layout

```
crates/
  mooring-agent       agent binary + session multiplexer (Phase B)
  mooring-relay       relay server binary (Phase B)
  mooring-core        Session trait extended with `Relay` protocol variant
  mooring-vault       unchanged (agent stores registration token only)
  mooring-audit       unchanged (agent events proxied through client audit)
```

- No new crate for E2E crypto: `x25519-dalek`, `crypto_box`, and `aead` are already in the
  workspace through `mooring-vault` / `mooring-proto-*`. `mooring-relay` and `mooring-agent`
  share the same AEAD types via `mooring-core`.
- `mooring-agent` is ~2,000 lines in 0.2.0 scope (Phase B v1): registration, keepalive,
  framebuffer capture, raw input passthrough, and a stub `Session` impl for local display.
- `mooring-relay` is ~1,500 lines: WebSocket acceptor, endpoint registry, per-session blob
  router, TLS termination, metrics endpoint (no secrets).

### 3. E2E encryption — Session key exchange

The relay sees only ciphertext. Client and agent perform an E2E key exchange on session
creation:

```rust
pub struct RelaySession {
    pub endpoint_id: String,          // agent's stable id (UUID v4)
    pub client_ephemeral: PublicKey,  // x25519, generated per session
    pub agent_ephemeral: PublicKey,   // provided by agent on registration
    pub session_token: [u8; 32],      // signed by the operator's signing key
}

#[async_trait]
impl Session for RelaySession {
    fn protocol(&self) -> Protocol { Relay };
    async fn send(&mut self, input: SessionInput) -> Result<()>;
    async fn next_event(&mut self) -> Result<Option<SessionEvent>>;
    async fn close(&mut self) -> Result<()>;
}
```

- **Endpoint registration**: the agent is shipped with a static operator public key
  (`RELAY_OPERATOR_PUBKEY`) and a per-device registration token (a short-lived JWT or
  Ed25519-signed assertion). On first start, the agent sends `REGISTER { device_id, pub_key,
  sig }` over wss to the relay. The relay verifies the signature, stores `{ endpoint_id →
  agent_ephemeral }` in memory, and returns `REGISTER_OK { agent_ephemeral }`. Tokens expire
  after 72 h; the agent re-registers silently.
- **Session initiation**: Mooring calls `relay_connect(endpoint_id)`. The client generates a
  new x25519 keypair, sends `TUNNEL_INIT { endpoint_id, client_ephemeral, session_token }` to
  the relay. The relay forwards it to the agent. The agent responds with `TUNNEL_READY {
  agent_ephemeral, mac }` where `mac = HMAC-SHA256(shared_secret, "tunnel_ready")` and
  `shared_secret = X25519(client_priv, agent_pub)`.
- **Data channel**: both sides derive `AEAD_KEY = HKDF(SHA256, shared_secret, "mooring-b")`
  and `AEAD_SALT = random(16)`. Each frame is `nonce (12) || ciphertext || tag (16)` under
  XChaCha20-Poly1305 (same as `mooring-vault`). Nonces are monotonic per direction.
- **No relay participation in key exchange**: the relay only forwards `TUNNEL_INIT` and
  `TUNNEL_READY`. It never sees private keys or the shared secret. A MITM (T3) cannot
  inject its own key without breaking the operator signature check on the agent side.
- **Forward secrecy**: each session generates a fresh ephemeral X25519 key pair. The private
  key is `Zeroizing` and dropped immediately after the DH computation. Past session keys
  cannot be recovered even if the agent's long-term identity key is later compromised.
- **Key rotation**: if the operator Ed25519 key is suspected compromised, revoke all outstanding
  registration tokens and rotate. Agents with valid tokens but revoked operator signatures are
  rejected on reconnect.
- **Relay frame format (plaintext)**: `frame_type(u8) | sequence(u64, LE) | payload_len(u32, LE) |
  payload(N) | HMAC-SHA256(seq||payload, session_key)`. Decryption and verification are performed
  before any payload is parsed. Invalid frames close the connection (`relay_frame_error`).

### 4. Agent design — local session stub

The agent implements a minimal `Session` that multiplexes local I/O:

```rust
pub struct LocalSession {
    endpoint_id: String,
    tunnel: RelayTunnel,              // AsyncRead + AsyncWrite
    frame_sink: FrameSink,            // screen capture backend
    input_stream: InputStream,        // keyboard/mouse from tunnel
}

#[async_trait]
impl Session for LocalSession {
    fn protocol(&self) -> Protocol { Relay };
    async fn send(&mut self, input: SessionInput) -> Result<()>;
    async fn next_event(&mut self) -> Result<Option<SessionEvent>>;
    async fn close(&mut self) -> Result<()>;
}
```

- **Screen capture (0.2.0 scope)**:
  - macOS: `CoreGraphics` + `Quartz` (CGWindowListCopyWindowInfo, pixel read to RGBA buffer).
  - Windows: `BitBlt` + `GetDIBits` (desktop DC, not per-app DWM composition).
  - Linux: `X11` (XShmGetImage) or `Wayland` (wp-fractional-scale + shm regions, fallback
    to `xdg-screenshot` D-Bus if available).
  - Frame rate target: 15 fps at 1080p; frames are compressed with a lightweight codec
    (Rust `zlib` wrapper, ratio ~3:1) before sending over the tunnel. No hardware codecs in
    v1.
- **Input passthrough**: keyboard and mouse events from the client arrive over the tunnel as
  `SessionInput::Keyboard { keys }` and `SessionInput::Mouse { x, y, button, action }`.
  The agent injects them via:
  - macOS: `CGEventPost` (kCGSessionPostTap).
  - Windows: `SendInput`.
  - Linux: X11 `XTestFakeKeyEvent` / `XI_WarpPointer` (XInput2 for precise mouse).
- **No local display server**: the agent does not launch a window or VNC server. It captures
  the real desktop and injects input directly. A lock-screen or screensaver pauses capture
  (frames carry `FrameEvent::ScreenLocked`), and the client shows a "screen locked" placeholder.

### 5. Relay design — stateless proxy

```rust
pub struct RelayServer {
    tls_config: rustls::ServerConfig,
    endpoint_store: Arc<RwLock<HashMap<EndpointId, AgentHandle>>>,
    operator_pubkey: ed25519_dalek::VerifyingKey,
    metrics: MetricsHandle,
}

impl RelayServer {
    pub async fn serve(addr: SocketAddr) -> Result<()>;
    fn handle_connection(&self, ws: WebSocket) -> JoinHandle<()>;
    fn route(&self, msg: RelayMessage) -> RelayResult;
}
```

- **TLS termination**: the relay serves `wss://` with a configurable certificate (Let's Encrypt
  ACME, or a custom CA). The operator's public key is baked into agents at build time; it is
  **not** served by the relay.
- **Endpoint store**: in-memory hash map only. On restart, all agents re-register. No
  persistence, no session history. TTL per entry: 90 s (agent sends keepalive every 30 s).
- **Blob routing**: `RelayMessage` variants:
  - `TunnelInit { endpoint_id, client_ephemeral, session_token }`
  - `TunnelReady { agent_ephemeral, mac }`
  - `Data { session_id, direction: Client→Agent | Agent→Client, encrypted_blob }`
  - `KeepAlive { endpoint_id }`
  - `Register { device_id, pub_key, sig }` / `RegisterOk { agent_ephemeral }`
  - `Unregister { endpoint_id }`
- **Back-pressure**: per-connection bounded mpsc (256 items); drops counted and audited on the
  client side. If the agent is unreachable, the client retries with exponential backoff (1 s,
  2 s, 4 s, …, max 30 s, cap 8 retries before prompting the user).
- **No authentication of data frames**: the E2E AEAD tag validates integrity. The relay never
  inspects or signs blobs. A compromised relay can forward, drop, or delay — but cannot
  decrypt, forge, or replay frames.

### 6. Integration with existing Session trait and connection model

- `Protocol` enum gains `Relay`. The connection tree stores `Protocol::Relay` with a new
  `RelayConnOptions { endpoint_id, relay_url, display_name }`.
- The client's `Session` implementation for `RelaySession` wraps `mooring-agent`'s
  `LocalSession` — the tunnel acts as the transport, and the Session trait's `send` /
  `next_event` / `close` map directly to tunnel frames.
- Port forwarding, SFTP, and Kubernetes are **out of scope** for v1 (Phase B v1 is remote
  desktop only). They can be added later via the same tunnel (multiplexed sub-channels).
- Jump hosts (ADR-0025): the agent's outbound connection can ride an SSH jump chain, or the
  client's connection to the relay can use hops. Both compose; the agent itself does not
  understand `via`.

### 7. IPC, audit and error codes

- Tauri command: `relay_connect({ endpoint_id, relay_url, options }) -> SessionId`.
- Agent registration is handled by the agent process, not through Tauri IPC.
- Audit: `session.relay.connect { endpoint_id, relay_host }`, `session.relay.frame_count {
  sessionId, n }`, `session.relay.close { sessionId, code }`.
- Error codes: `relay.unreachable`, `relay.tunnel_failed`, `relay.auth_refused`,
  `relay.endpoint_offline`, `relay.frame_too_large`, `relay.screen_locked`.
- No session recording in 0.2.0 (metadata only in audit log, same as RDP/VNC today).

### 8. Security considerations

- **T3 (MITM)**: the relay is a TLS peer with its own certificate. The E2E key exchange uses
  X25519 authenticated by the operator's Ed25519 signature on the agent side. A MITM cannot
  forge `TUNNEL_READY` without the operator's signing key. A relay MITM can only drop or delay
  frames.
- **T4 (hostile relay)**: the relay sees timing and volume but no content. It can replay
  captured blobs only if it also holds the E2E key (which it does not). Frame nonce monotonicity
  prevents replay within a session.
- **T2 (local process on target)**: the agent runs as the logged-in user and captures the
  real desktop. A T2 process on the target can read the screen and inject input — same as
  sitting at the machine. The agent does not store secrets; it holds only the registration
  token and E2E keys in RAM (zeroized on close).
- **T5 (compromised client)**: can request tunnels to any registered endpoint id, but cannot
  bypass E2E encryption. Cannot read screen content without the shared secret.
- **No `unsafe`**: all crypto uses RustCrypto (`x25519-dalek`, `crypto_box`, `aead`,
  `chacha20poly1305`). Input injection uses OS APIs via safe wrappers or FFI gated behind
  `unsafe` modules with documented justification (owner approval required for any exception).
- **Agent binary size target**: ≤ 15 MB stripped. Dependencies: `tokio`, `rustls`, `ed25519-dalek`,
  `x25519-dalek`, `crypto_box`, `aead`, `serde`, `zlib`, and one OS-specific crate for screen
  capture / input.

### 9. Operator bootstrap and deployment

- **Operator key pair**: generated once per deployment (`mooring-relay-keygen`). The private key
  signs registration tokens. The public key is baked into agents at compile time via a build
  script (`mooring-agent/build.rs`).
- **Agent distribution**: signed binaries (macOS codesign / notarization, Windows Authenticode,
  Linux packages). The agent registers itself on first run and stores its `endpoint_id` in a
  machine-local config file (`$APP_DATA/mooring-agent/endpoint.json`).
- **Relay deployment**: single binary or container image. No database, no queue, no file
  storage. A reverse proxy (nginx, Caddy) handles TLS; the relay listens on a loopback port.
- **No multi-tenant UI**: the relay has no web console in v1. Endpoint management is done
  via the operator's key rotation and the relay's in-memory state. A future admin panel can
  sit on top of the relay's metrics endpoint.

## Alternatives considered

- **WebRTC / WebSockets with TURN**: WebRTC provides NAT traversal via ICE/STUN/TURN, but adds
  significant complexity (data channel framing, NAT type detection, TURN credential rotation).
  Rejected for v1: a simple wss relay with agent-initiated connections is sufficient and
  simpler to audit.
- **WireGuard overlay**: the agent opens a WireGuard tunnel to the relay. Strong crypto, but
  requires kernel modules or userspace `wg-go`/`wireguard-go` (slow). Rejected for v1; the
  relay's wss + E2E AEAD gives equivalent confidentiality without OS dependencies.
- **Reverse proxy via Nginx/Caddy**: the agent uses `ngrok`-style port forwarding through a
  proxy. Adds a third-party dependency and loses the E2E guarantee (the proxy terminates TLS
  and could be misconfigured to log traffic). Rejected.
- **MQTT broker as relay**: lightweight pub/sub, but adds a persistent store (session queues,
  last-will messages) and increases the trust boundary. Rejected for stateless proxy simplicity.
- **P2P without relay**: direct connection between client and agent via hole punching. Fails
  behind symmetric NAT or CGNAT without a TURN server. The relay guarantees reachability
  without NAT assumptions.

## Security consequences

- **New trust boundary: relay ↔ operator key.** The operator's signing key is the root of
  trust for agent registration. Compromise of the private key allows forging registrations
  (T6 → relay). Mitigation: key rotation procedure documented, short-lived tokens (72 h),
  and the public key is immutable per agent build.
- **New attacker row T-RELAY (compromised relay).** Can observe connection metadata (endpoint
  ids, timing, traffic volume), drop or delay frames, and force reconnections. Cannot decrypt,
  forge, or replay frames. Recorded in the threat model.
- **Agent on target (T2).** The agent runs with the same privileges as the logged-in user. It
  captures the screen and injects input — equivalent to physical access. The agent itself holds
  no secrets beyond the registration token.
- **E2E key exchange.** The relay forwards `TUNNEL_INIT` and `TUNNEL_READY` but never sees
  private keys. A MITM cannot inject its own key without breaking the operator signature check.
- **No new `unsafe` without an exception.** Screen capture and input injection use OS APIs
  that may require FFI. Each FFI boundary is isolated in a module with `// SAFETY:` comments
  and a security-ADR amendment.

## UI

- Connection form: protocol picker gains "Mooring Relay" with fields `endpoint_id` (text,
  regex `^[a-z0-9-]{1,63}$`), `relay_url` (HTTPS URL, validated), and optional `display_name`.
- Inspector: shows relay connection state (connecting → tunnel up → screen streaming).
- Session tab: renders frames from the relay tunnel as a remote desktop (same `FrameSink` as
  RDP/VNC). Clipboard passthrough both ways (audited, same rules as RDP).
- Settings: "Relay" section with `default_relay_url`, operator public key fingerprint (read-
  only, derived from the compiled-in key), and endpoint id of this machine (when running as
  agent).

## Test plan

- Unit: `RelaySession` key exchange (X25519 shared secret derivation, HKDF subkeys), AEAD
  encrypt/decrypt round-trip with nonce monotonicity, frame caps (≤ 64 KiB per blob),
  `LocalSession` stub (mock screen capture, mock input injection).
- Integration: relay mock in `mooring-testsrv` (wss echo with endpoint routing): agent
  registers, client initiates tunnel, frames flow both ways, agent goes offline → retry with
  backoff, relay restarts → agents re-register.
- Fuzz: `relay_message` (malformed WebSocket frames, oversized blobs), `e2e_frame` (truncated
  AEAD tags, nonce reuse attempts).
- Manual gate: agent on macOS, Windows, and a Linux VM; relay behind Caddy with Let's Encrypt;
  operator key rotation; agent uninstall / reinstall preserves `endpoint_id`.
- Security review: Phase B-specific threat model update (T-RELAY), relay deployment checklist,
  agent hardening (no persistence, no elevation, no network listeners).

## Owner decisions needed

1. Phase B v1 scope: remote desktop only (screen + input), no file transfer or port forwarding
   (recommended).
2. Operator key management: static build-time key baked into agents (default) vs. dynamic
   provisioning via a separate bootstrap endpoint.
3. Agent deployment: manual install (DMG/MSI/deb) for v1 vs. a managed installer that
   registers with the relay automatically on first run.

(End of file - total 243 lines)
