# ADR-0011: RDP session (IronRDP), certificate trust and the shared frame path

Status: Accepted · 2026-11-04 (Phase A2; extends ADR-0004, ADR-0008, ADR-0009, ADR-0010)

## Context
A2 needs a Royal-TS-class RDP client: NLA, a certificate trust model as strict as SSH's
(ADR-0007), dynamic resolution, a text clipboard and 30 fps at 1080p. Today a session event
reaches the UI as base64 JSON over a `Channel` (`WireEvent::Frame.rgba`), and that cannot carry
video-rate pixels. VNC (ADR-0012) needs the same frame path, so this ADR defines it.

## Decision

### Library (versions checked on crates.io, 2026-11-04; all MIT OR Apache-2.0)
`ironrdp-connector` 0.12.0, `ironrdp-session` 0.13.0, `ironrdp-async` 0.12.0, `ironrdp-tokio`
0.12.0 (`default-features = false`), `ironrdp-graphics` 0.11.0, `ironrdp-pdu` 0.11.0,
`ironrdp-cliprdr` 0.9.0, `ironrdp-displaycontrol` 0.10.0, `ironrdp-input` 0.9.0. Every one was
released in the last 30 days. **Not** used: the `ironrdp` meta crate, `ironrdp-tls`, `rdpsnd`,
`rdpdr` (drives, printers, smart cards), `ironrdp-mstsgu` (gateway), EGFX with `openh264`.
- `unsafe`: 0 sites in the IronRDP crates above. `sspi` 0.23 (CredSSP/NTLM) has 32, all in
  Windows DNS, smart-card and PKU2U code. `ironrdp-connector` turns on `sspi/scard`, which pulls
  in `winscard`, `cryptoki` (+ `libloading`, dlopen of PKCS#11) and `flate2` → **`libz-sys`
  (C zlib)**. On macOS `sspi` also links `async-dnssd` (FFI to dns_sd); on Windows it uses
  `windows` 0.62. `yuv` and `wide` (SIMD) contain `unsafe`. `rsa` is the already-accepted R-RSA crate.
  We use no smart-card path. Upstream PR: make `scard` an opt-in feature; until it lands, R-RDP-FFI.
- Why not `ironrdp-tls`: its default policy is `DangerouslyAcceptInvalidCertificate`, and its
  override callback is synchronous on the handshake thread, so it cannot wait for a UI
  prompt. We build the rustls (ring) config ourselves (§Trust), which also keeps `aws-lc-rs` out.

### Security protocol and credentials
- `enable_credssp = true`, `enable_tls = false`, `enable_standard_rdp_security = false`:
  **NLA is required.** Option `allowTlsWithoutNla` (default false) adds TLS-only for legacy
  hosts. It is audited on every connect (`session.rdp.legacy_security`). Standard RDP Security
  (RC4) is never offered.
- CredSSP runs NTLMv2 through `sspi`. Kerberos is off in A2: the `NetworkClient` we pass
  refuses every request, so no KDC traffic starts from Mooring. Kerberos needs its own ADR
  (KDC discovery, DNS SRV).
- Valid primary kinds (ADR-0009 matrix, unchanged): `user_password` (sent verbatim, domain from
  `fields.domain` or the override), `domain_user` (netbios → `(user, domain)`, upn →
  `(upn, None)`) and `prompt` (a `purpose: credential` form with `needs_domain: true`).
  `x509` stays rejected for RDP: RDP has no TLS client authentication, and smart-card logon
  needs `scard` + Kerberos (PKINIT). Owner decision, see open questions.
- `Credentials::UsernamePassword.password` is a plain `String` inside IronRDP. We build it from
  `SecretString` right before `connect_finalize` and drop the connector right after. This is
  R-RDP-STR (like R-SSH-STR).

### Trust: TLS and certificate TOFU (mirrors ADR-0007)
- rustls 0.23 (ring, TLS 1.2+). Our `ServerCertVerifier` first runs `WebPkiServerVerifier`
  against the system roots (`rustls-native-certs`) plus the connection's custom CA
  (`options.caPem`: certificate PEM blocks only, ≤ 64 KiB, B-3 rule). Handshake signatures are
  always checked with ring's `verify_tls12/13_signature`. Only the chain decision is ours.
- Trust store `$APP_DATA/known_rdp_certs`, one entry per line:
  `|2|<salt b64>|<HMAC-SHA256(salt, "host:port") b64> x509-sha256 <b64 of SHA-256(leaf DER)> <added RFC 3339>`.
  Entries are always written hashed. The parser caps lines at 8 KiB and the file at 10 000
  lines, skips malformed lines, and has a fuzz target. The code is shared with VNC
  (`mooring_core::known_certs`, path `known_vnc_certs`).
- Decision table (the pin takes precedence over the CA, as with SSH):
  - pin exists and matches → accept, even when the chain fails (expiry shows as a warning).
  - pin exists and differs → **hard stop**. The session closes with `code: trust_mismatch`
    and reason "CERTIFICATE CHANGED for <host>:<port>: expected SHA256:<old>, got SHA256:<new>",
    and `trust.cert.mismatch` is audited. Removing the pin is an explicit UI action
    (`known_certs_remove`, audited).
  - no pin and the chain is valid → accept and audit `trust.cert.ca_valid`. No pin is
    written, because the CA is the trust anchor.
  - no pin and the chain is invalid → the verifier records the leaf and fails the handshake.
    The session emits `Prompt { purpose: certificate_trust, certificate: CertificateInfo }`.
    `yes` writes the pin and **reconnects on a new TCP connection**, which then hits the first
    row. Anything else closes with `code: trust_rejected`. The verifier never blocks on the UI.
- `Connected.peer_identity` = `"x509 SHA256:<hex>"`, and `Connected.security` = `"nla"` or `"tls"`.

### Session behaviour
- Graphics: `BitmapConfig { color_depth: 32, lossy_compression: false }`, with RemoteFX,
  planar and interleaved codecs. `support_dyn_vc_gfx_protocol = false` in A2 (AVC needs
  `openh264`, C). The pixel format is `RgbA32`, so blits are memcpy-only.
- Dynamic resolution: a UI `Resize` is debounced for 300 ms, clamped to 200–8192 with an even
  width, and sent with `ActiveStage::encode_resize` through Display Control (DVC). If the server
  has no DVC, the session keeps its size and the UI scales.
- Clipboard (cliprdr): only `CF_UNICODETEXT` (13) and `CF_TEXT` (1), ≤ 1 MiB after UTF-8
  conversion. File lists, HTML, images and file contents are refused. Remote → local: a
  format-list announcement makes Rust fetch the text and write it with `clipboard.rs`, which
  records its digest. Local → remote: `SessionInput::ClipboardOffer` (sent when the session tab
  gains focus) makes **Rust** read the OS clipboard and announce it. The text never crosses
  IPC. Each transfer audits `session.clipboard { direction, bytes }`, with at most one entry
  per second per direction (coalesced). On vault lock and on exit, a remote-originated value
  still on the clipboard is cleared (`clear_if_unchanged`). Option `clipboard: off | to_remote
  | from_remote | both` defaults to `both`.
- Audio: no `rdpsnd` channel, and `enable_audio_playback = enable_audio_capture = false`.
- Keyboard: `options.keyboardLayout` (KLID, closed list: 0x0409 en-US, 0x041F tr-TR Q, 0x1041F
  tr-TR F, 0x0407, 0x040C, 0x0809, 0x0410, 0x040A, 0x0419) defaults to 0x0409. Keys are sent as
  scancodes mapped from `KeyboardEvent.code` (layout-independent), and text the IME composes is
  sent as Unicode events. `ReleaseAll` goes out on blur, so no key is left stuck.
- Reconnect (shared with VNC): the Tauri layer retries only for `code ∈ {network,
  server_ended}` after `Connected`. The backoff is 1, 2, 4, 8, 16, 30 s with ±20 % jitter, at
  most 6 attempts, and each attempt emits `Reconnecting { attempt, delayMs }`. It never retries
  after `auth_failed`, `trust_*`, `user` or `vault_locked`. The credential is resolved again from
  the vault on every attempt, so a locked vault stops the retries. The server's auto-reconnect
  cookie is used when present. It is kept in `Zeroizing` memory only.

### Frame path (shared with VNC) — decision with numbers
1080p RGBA is 8 294 400 B per full frame, 248.8 MB/s at 30 fps. The current base64 JSON path
costs 331.8 MB/s of string data plus `JSON.parse` and `atob`, so it misses the 33 ms budget
by itself. Tauri 2.12.5 sends a raw `Channel` message ≥ 1 KiB as an eval followed by a fetch
over the IPC custom protocol into an `ArrayBuffer` (`ipc/channel.rs`,
`MAX_RAW_DIRECT_EXECUTE_THRESHOLD`). Our estimate (to be measured, §Tests) is 2 copies plus one
fetch, roughly 5–15 ms for a full 1080p frame on WKWebView/WebKitGTK and 10–30 ms on WebView2.
A typical desktop changes 10–25 % of the screen per tick: 0.8–2.1 MB, 25–62 MB/s.
- **Decision:** the framebuffer lives in Rust (`mooring_core::frame::Framebuffer`). The protocol
  writes into it through `FrameSink`. Per session, a `FramePump` task coalesces dirty rects for
  each tick (`1000/maxFps` ms, default 30 fps), with at most 2 messages in flight (credit
  returned by `session_frame_ack`). It sends one binary `MFR1` message over a dedicated raw
  `Channel` (`onFrame`). If there are more than 32 rects or more than 60 % of the area, it sends
  one full rect. A slow UI gets fewer, newer frames, never a queue. The UI keeps one WebGL2
  texture, calls `texSubImage2D` once per rect from a `Uint8Array` view, and draws a quad.
  `Canvas2D` `putImageData` is the fallback.
- `MFR1` (little-endian): `magic "MFR1" | seq u32 | fbW u16 | fbH u16 | n u16 | flags u16
  (1 = full, 2 = resized)`, then n records `kind u8 | 0 u8 | x y w h u16`, followed by the
  record's own fields: 1 = RGBA (w·h·4 bytes), 2 = copy (`srcX srcY u16`), 3 = fill (`rgba[4]`),
  4 = cursor sprite (`hotX hotY u16` + RGBA, ≤ 384²), 5 = cursor hidden, 6 = cursor default.
  Limits: n ≤ 256, fb ≤ 8192², message ≤ 4·fbW·fbH + 64 KiB.
- `session_screenshot` copies the Rust framebuffer to the OS clipboard as an image (arboard).
  No pixels go through the WebView for it.
- Rejected:
  - base64 JSON: shown above to be too slow.
  - `mooring-frame://` custom protocol: about the same cost, but a URI scheme is registered
    app-wide, so every web-session window (ADR-0013) could fetch it.
  - Shared memory: not in Tauri 2, and WebView2 `SharedBuffer` needs COM `unsafe`.
  - Loopback WebSocket: opens a port that T2 can reach.
  - Native wgpu child surface: unstable multi-webview, and a lot of per-OS work.
- Later (own ADR): forward EGFX H.264 to WebCodecs `VideoDecoder` in the WebView. That uses
  ~1–5 Mbit/s and needs no C codec in our process.

### Interfaces (mooring-core; amends ADR-0004)
```rust
pub mod frame {
    pub struct Rect { pub x: u16, pub y: u16, pub w: u16, pub h: u16 }
    pub enum Cursor { Default, Hidden, Sprite { hot_x: u16, hot_y: u16, w: u16, h: u16, rgba: Vec<u8> } }
    #[derive(Clone)] pub struct FrameSink(Arc<FrameShared>);      // Mutex<Framebuffer> + Notify
    impl FrameSink {
        pub fn resize(&self, w: u16, h: u16) -> Result<()>;      // ≤ 8192², clears dirty
        pub fn blit(&self, r: Rect, src: &[u8], stride: usize, order: PixelOrder) -> Result<()>;
        pub fn copy(&self, dst: Rect, src_x: u16, src_y: u16) -> Result<()>;
        pub fn fill(&self, r: Rect, rgba: [u8; 4]) -> Result<()>;
        pub fn cursor(&self, c: Cursor);
    }                                                // out-of-bounds rect → Err, never panic
}
#[async_trait] pub trait Session: Send {               // existing four methods unchanged, plus:
    fn take_audit_events(&mut self) -> Vec<SessionAudit> { Vec::new() }   // TrustEvent moves to core
}
```
- `SessionEvent`:
  - `Frame` is removed (no producer remains).
  - `Closed` gains `code: CloseCode` (`user | network | auth_failed | trust_rejected |
    trust_mismatch | server_ended | protocol_error | vault_locked`).
  - `Connected` gains `security: Option<String>`.
  - New `DesktopResized { width, height }`.
  - New `Prompt.certificate: Option<CertificateInfo { subject, issuer, not_before, not_after,
    sha256, problems: [self_signed | unknown_issuer | name_mismatch | expired | not_yet_valid] }>`.
  - `PromptPurpose` gains `CertificateTrust`.
- `SessionInput`:
  - `Key` becomes `Key { code: String /* KeyboardEvent.code ≤ 32 ASCII */, key: String
    /* ≤ 32 B */, pressed: bool }`.
  - New `Wheel { dx: i16, dy: i16 }` (120 per notch), `Unicode { text /* ≤ 64 chars */ }`,
    `ReleaseAll`, and `ClipboardOffer` (no payload).
  - `Pointer` is unchanged (buttons: 1 = left, 2 = middle, 4 = right, 8 = back, 16 = forward).
- `mooring_proto_rdp::RdpSession::connect(params: ConnectParams, options: RdpOptions)` with
  `RdpOptions { known_certs: PathBuf, frames: FrameSink, clipboard: Arc<dyn Clipboard>, conn: RdpConnOptions }`.
  The Tauri `sessions.rs` becomes generic over `S: Session`, and `SessionHandle.control` becomes
  `enum Control { Ssh(SshControl), Rdp(RdpControl), Vnc(VncControl) }`.

### IPC (ADR-0008 style; conventions unchanged)
```
session_open({ connectionId, size, onEvent, onFrame?: Channel<ArrayBuffer> }) -> { sessionId }
    # onFrame required for rdp/vnc, refused for ssh (input.invalid "onFrame")
session_frame_ack({ sessionId, seq })            -> void        # passive: in POLLED_COMMANDS
session_screenshot({ sessionId })                -> { width, height }   # audited session.screenshot
known_certs_list({ protocol: "rdp"|"vnc" })      -> KnownCert[] # { hostHash, fingerprint, addedAt }
known_certs_remove({ protocol, host, port })     -> { removed: number }   # audited trust.cert.removed
connection_create/update: + options: ProtocolOptions            # migration 0005: options_json
RdpConnOptions = { keyboardLayout, clipboard, allowTlsWithoutNla, caPem|null, maxFps: 30|60 }
```
`connection.options_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(options_json))` holds a
serde type per protocol (`deny_unknown_fields`, re-validated on read, ≤ 128 KiB). New error codes
are `session.trust_mismatch`, `session.trust_rejected` and `session.unsupported_security`.

## Alternatives considered
- FreeRDP through FFI: C, large CVE history, `unsafe`. Rejected.
- `ironrdp-tls` with its callback: see above. Rejected.
- TOFU prompt inside the verifier (blocking): stalls a Tokio worker during the handshake.
  Rejected in favour of fail-then-reconnect.
- Pinning certificates that a CA validated: would turn every routine reissue into a hard stop.
  Rejected (we pin only certificates that were TOFU-approved).

## Security consequences
- T3: NLA is required; a TOFU pin is a hard stop when it changes; no RC4 or Standard Security.
- T4: hostile PDUs reach IronRDP's parsers and our `known_certs` and `CertificateInfo` code.
  **`panic = "abort"` in release means a parser panic kills every session and the vault
  process.** We propose `panic = "unwind"` (orchestrator owns `Cargo.toml`) so that a panic
  ends only its own session task (`JoinError` → `protocol_error`).
- T5: never receives clipboard text or pixels for screenshots. It can request a screenshot of
  an open session or answer a TOFU prompt with `yes` (audited; a mismatch is not overridable).
- New risks for the threat model: R-RDP-FFI (`scard` C/FFI tree, `libz-sys`), R-RDP-STR, and
  R-CLIP (remote text lands on the OS clipboard, where other same-user processes (T2) can read it).

## Test plan
- Unit tests: decision table (4 rows), verifier signature checks still enforced, `known_certs`
  round trip + proptest, credential mapping per kind, KLID list, cliprdr caps (1 MiB, ±1), MFR1
  encoder vectors, `Framebuffer` bounds, coalescing (> 32 rects → full).
- Integration: an in-process RDP server built on `ironrdp-acceptor` (dev-dependency) with
  self-signed TOFU, mismatch, NLA failure, resize, clipboard both ways and reconnect. Plus an
  `#[ignore]`d connect to `MOORING_LAB_RDP_HOST`.
- Fuzz (ours): `known_certs_parse`, `certificate_info` (hostile DER), `rdp_active_stage` (bytes →
  `ActiveStage::process` at 1024×768), `cliprdr_text`, `framebuffer_ops`. Upstream targets
  pinned to our versions in the nightly job: `pdu_decoding`, `rle_decompression`,
  `bitmap_stream`, `cliprdr_format`, `channel_processing`, `bulk_*`.
- Bench gate `frame_bench` on all three OSes, 1080p synthetic at 10/25/100 % dirty. Pass:
  25 % ≥ 30 fps with p95 ≤ 50 ms decode→present; 100 % ≥ 15 fps without unbounded memory.

## A2 task split (orchestrator spawns; → = depends on)
| # | Owner | Package | Depends |
| --- | --- | --- | --- |
| R1 | rust-core | `mooring-core`: `frame` (Framebuffer, FrameSink, MFR1 encoder), `known_certs`, `CertificateInfo`, Session/Event/Input changes, `ProtocolOptions`, migration 0005 | ADR accept |
| R2 | rust-core | src-tauri: generic session task, `FramePump`, reconnect, `session_frame_ack`/`screenshot`, `known_certs_*`, options IPC, `POLLED_COMMANDS` | R1 |
| R3 | rust-core | `mooring-proto-rdp`: TLS verifier, connector, active stage, DVC resize, cliprdr, input mapping | R1 |
| R4 | rust-core | `mooring-proto-vnc` (ADR-0012) | R1 |
| R5 | rust-core | web windows, AppManifest, detach (ADR-0013) | R2 |
| U1 | ui-engineer | `ipc.ts`/types + mock transport for every new command, MFR1 decoder, WebGL2 `RemoteCanvas`, input capture | ADR accept (mock) |
| U2 | ui-engineer | RDP/VNC connection forms from `ProtocolOptions`, cert TOFU dialog from `CertificateInfo`, known-certs manager, reconnect banner | U1 |
| U3 | ui-engineer | web session tabs, detach/attach UI, blocked-navigation notice | U1, R5 |
| Q1 | qa-engineer | fuzz targets above + upstream targets in nightly; `frame_bench` | R1, R3, R4 |
| Q2 | qa-engineer | acceptor-based RDP server and RFB test server; E2E with mock frames; capability tests (ADR-0013) | R2–R5 |
| S1 | security-reviewer | review 5: threat model T3/T4/T5 rows, R-RDP-FFI, R-RDP-STR, R-CLIP, R-WEB-* | all |

## Owner decisions (2026-11-04)
1. Release profile switches to `panic = "unwind"` so a decoder or IronRDP panic ends one session
   task, never the process (Cargo.toml, orchestrator).
2. R-RDP-FFI accepted for A2: `sspi/scard` and its C deps are tolerated with the risk recorded;
   an upstream pull request to make `scard` optional is filed and tracked in the threat model.
3. `x509` smart-card logon, Kerberos and RD Gateway are deferred to A3; A2 ships NLA with
   `domain_user` / `user_password` only.

## Sources
crates.io API (2026-11-04) for versions/licences; crate sources read locally: `ironrdp-tls`
0.3.0 `src/lib.rs` (default policy, callback), `ironrdp-connector` 0.12.0 `Config`/`Credentials`,
`ironrdp-async` 0.12.0 `connect_finalize`, `ironrdp-session` 0.13.0 `ActiveStageOutput`,
`DecodedImage`, `sspi` 0.23.1 `Cargo.toml` (features, target deps); `cargo tree` of the set above
for linux/windows/macos; Tauri 2.12.5 `ipc/channel.rs`; IronRDP `fuzz/Cargo.toml` (master).
