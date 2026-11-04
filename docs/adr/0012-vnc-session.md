# ADR-0012: VNC session — own RFB 3.8 client, VeNCrypt and certificate TOFU

Status: Proposed · 2026-11-04 (Phase A2; builds on ADR-0011's frame path, trust store and reconnect)

## Context
`mooring-proto-vnc` is a stub. A2 needs an RFB 3.8 client (RFC 6143) for TigerVNC, x11vnc,
libvncserver, QEMU/KVM and Proxmox consoles. It must support Tight/ZRLE/Raw, VeNCrypt TLS,
password and no-auth logins, and a view-only mode. Every server byte is hostile (T4), and the
RFB security handshake can be downgraded by a MITM (T3).

## Decision

### Client: implement RFB 3.8 in `mooring-proto-vnc` on `tokio` (no VNC crate)
`vnc-rs` 0.6.0 (MIT OR Apache-2.0, released 2026-09-21, one maintainer, ~5.5 k lines, no
`unsafe`) was evaluated and is not used:
- `SecurityType::VeNCrypt` exists only as an enum value; the VeNCrypt handshake is not
  implemented, and it cannot be added from outside because it runs mid-handshake.
- It ships a hand-written DES (`client/security/des.rs`) instead of RustCrypto `des`. That is
  our "never roll your own crypto" rule.
- Tight JPEG rectangles are passed out undecoded, and every rect goes through a callback as an
  owned `Vec`, so we would need an adapter anyway to write into `FrameSink`.
Our client is about 2.5 k lines, kept in modules under 500 lines: `handshake`, `security`,
`vencrypt`, `messages`, `decode/{raw,copyrect,zrle,tight}`, `input`, `session`. It needs no new
dependency except `des` 0.9 (RustCrypto, MIT OR Apache-2.0, already in the lockfile through
russh), `flate2` 1.1 with the `miniz_oxide` Rust backend (already in the tree) and the rustls
stack from ADR-0011. All four rules are met: licence ✓, maintenance ✓ (all released in the last 12 months),
no `unsafe` ✓, already allowed ✓.

### Handshake and security types
- Only `RFB 003.008` is accepted: 3.3 and 3.7 are refused with `session.unsupported_security`
  (3.3 lets the server pick the type). The server name is capped at 4 KiB and sanitised (L-2),
  and the reason string at 4 KiB.
- Supported security types, in preference order:
  1. **VeNCrypt (19)** v0.2, subtypes `X509None` (260), `X509Vnc` (261) and `X509Plain`
     (262) only. The TLS* subtypes (257–259) need anonymous DH, which rustls does not support,
     so they are refused. `Plain` (256) without TLS would send the password in clear: refused.
  2. **VNC Authentication (2)**: DES of the 16-byte challenge using the `vnc_password` secret
     (≤ 8 B, ADR-0009 §5), with bit-reversed key bytes per RFB. The key is held in `Zeroizing`.
  3. **None (1)**: only when the connection's credential is `none`.
- Credentials (ADR-0009 matrix):
  - `vnc_password` → type 2 or `X509Vnc`.
  - `vnc_user_password` → `X509Plain` only (the username and password travel inside TLS).
  - `prompt` → a `purpose: credential` form.
  - No credential → None, `X509None`.
  Apple Remote Desktop (30), RA2 (5/6), Tight (16) and SASL are not offered in A2.
- `options.security` is `require_tls | prefer_tls | allow_plaintext`, default
  **`prefer_tls`**. A plaintext session shows a permanent "unencrypted" badge
  (`Connected.security = "none"` or `"vnc-auth"`) and audits `session.vnc.plaintext`.
  **Downgrade guard (HSTS-like):** once `known_vnc_certs` holds a pin for `host:port`, that
  connection behaves as `require_tls`. A MITM that strips VeNCrypt from the type list then
  causes a hard stop (`code: trust_mismatch`, "TLS EXPECTED for <host>:<port>").

### Trust (same as ADR-0011)
VeNCrypt X509 uses the ADR-0011 verifier (system roots + `options.caPem`), store
`$APP_DATA/known_vnc_certs` (same `known_certs` format and parser) and the same four-row
decision table. TOFU fails the handshake, prompts with `CertificateInfo`, and reconnects after
`yes`. A changed pin is a hard stop. Most VNC servers use self-signed certificates, so the
common first-connect case is the TOFU prompt.

### Encodings, pixel format, frames
- `SetPixelFormat`: 32 bpp, depth 24, true colour, little-endian, red/green/blue shifts 0/8/16.
  The bytes are then RGBX and are written as RGBA (alpha forced to 255) with no conversion
  loop.
- `SetEncodings` order: CopyRect (1), ZRLE (16), Tight (7), Raw (0), plus pseudo-encodings
  DesktopSize (-223), ExtendedDesktopSize (-308), LastRect (-224), Cursor (-239) and QEMU
  Extended Key Event (-258). Hextile and RRE are not advertised.
- **Tight without JPEG:** we send no JPEG quality pseudo-encoding (-32..-23), so servers use
  zlib basic, palette or gradient instead. JPEG decoding (`zune-jpeg` 0.5.15, MIT OR
  Apache-2.0 OR Zlib, SIMD `unsafe`) is an owner/security decision for later. A server that
  sends JPEG anyway gets `protocol_error`.
- Decoder caps (checked before allocating):
  - Framebuffer ≤ 8192 × 8192.
  - Every rect must lie within the framebuffer; rects per update ≤ 65 535 (LastRect ends early).
  - ZRLE and Tight zlib output ≤ 64 MiB per rect, using streaming inflate with a hard output
    limit (zlib bombs). The 4 persistent Tight zlib streams and the 1 ZRLE stream are reset on
    reconnect.
  - Tight palette ≤ 256 entries; cursor ≤ 384 × 384.
  - `ServerCutText` ≤ 1 MiB.
- All output goes through ADR-0011's `FrameSink` (`blit`/`copy`/`fill`/`cursor`) and so through
  the same `FramePump` → `MFR1` → WebGL2 path, credit flow control and `session_screenshot`.
  `FramebufferUpdateRequest` is incremental and is sent only when the pump has returned a
  credit, which back-pressures the server too.
- Resize: with ExtendedDesktopSize the client sends `SetDesktopSize` (debounced 300 ms), and
  the server's answer emits `DesktopResized`. Otherwise the UI scales.

### Input, view-only, clipboard
- Keys: when the server confirms QEMU Extended Key Event, keys go as `code` → XT scancode, which
  does not depend on the keyboard layout (QEMU/Proxmox). Otherwise as keysyms from
  `KeyboardEvent.key` (Latin-1 direct, Unicode via `0x0100_0000 + cp`, named keys from a fixed
  table). `ReleaseAll` goes out on blur.
- Pointer: `PointerEvent` with buttons 1/2/4 and the wheel as buttons 8/16 (one press and
  release per notch).
- **View-only** (`options.viewOnly`, plus a per-session toggle): Rust drops `Key`, `Pointer`,
  `Wheel`, `Unicode` and `ClipboardOffer` before they reach the socket, so the UI flag is
  advisory and Rust enforces it. `ClientInit.shared = options.shared` (default true).
- Clipboard: same policy, option and audit as ADR-0011. `ClientCutText`/`ServerCutText` are
  Latin-1 only: text is converted to UTF-8 on receipt, and on send, characters that cannot be
  encoded are refused rather than replaced. Extended Clipboard (UTF-8) is not used in A2.

### Interfaces
```rust
pub struct VncOptions {                 // mooring_proto_vnc::VncSession::connect(params, options)
    pub known_certs: PathBuf, pub frames: FrameSink, pub clipboard: Arc<dyn Clipboard>,
    pub conn: VncConnOptions,
}
pub struct VncControl { /* set_view_only(bool) */ }
```
`SessionInput` gains nothing beyond ADR-0011. `Closed.code`, `Prompt.certificate` and
`DesktopResized` are reused.

### IPC (ADR-0008 style)
```
VncConnOptions = { security: "require_tls"|"prefer_tls"|"allow_plaintext", viewOnly: bool,
                   shared: bool, clipboard: "off"|"to_remote"|"from_remote"|"both",
                   caPem: string|null, maxFps: 30|60 }        # in connection.options (migration 0005)
session_set_view_only({ sessionId, viewOnly })   -> void      # vnc only; audited session.view_only
known_certs_list / known_certs_remove({ protocol: "vnc", ... })   # from ADR-0011
```
Every other session command (`session_open` with `onFrame`, `session_send`,
`session_frame_ack`, `session_screenshot`, `session_close`) is unchanged from ADR-0011.

## Alternatives considered
- `vnc-rs` with a fork for VeNCrypt and RustCrypto DES: we would own a fork of 5.5 k lines and
  still adapt its event model. Not much less work than our own client, and an upstream we do
  not control. Rejected.
- libvncclient through FFI: C, `unsafe`, its own TLS (GnuTLS/OpenSSL). Rejected (ADR-0001).
- Accepting RFB 3.3 and 3.7 for old servers: 3.3 lets the server dictate the security type,
  which weakens the downgrade guard. Rejected for A2; it could come later behind
  `allow_plaintext`.
- Default `require_tls`: the safest choice, but most stock QEMU, ESXi-era and x11vnc setups
  have no TLS, so it would fail for most users. Flagged as an owner decision.

## Security consequences
- T3: VNC without TLS is readable and modifiable on the wire, and the type-2 DES response can be
  cracked offline. The badge, the audit entry and the HSTS-like pin guard limit the damage;
  `require_tls` removes it.
- T4: every decoder is ours. It has caps before allocation, no `unsafe` and streaming inflate
  with output limits, and a fuzz target covers each one. Under `panic = "unwind"` (proposed in
  ADR-0011) a decoder panic ends only that session.
- T5: view-only is enforced in Rust. Clipboard text and screenshots never cross IPC.
- R-VNC-PLAIN (new, accepted per connection by the user): `allow_plaintext` and `prefer_tls`
  without a pin.

## Test plan
- Unit tests:
  - Version-string parsing (only 3.8).
  - Security-type selection matrix (type list × policy × pin present).
  - VNC auth DES vector (a challenge/response captured from a TigerVNC handshake, bit-reversal).
  - VeNCrypt subtype negotiation.
  - Pixel-format bytes; keysym table; QEMU scancode table.
  - Cut-text Latin-1 round trip and refusal.
- Integration: an in-process RFB test server in `crates/mooring-proto-vnc/tests/` covering
  None, VncAuth and VeNCrypt X509Vnc with a self-signed cert (TOFU, mismatch, stripped
  VeNCrypt after pin → hard stop), each encoding, resize, view-only drop and clipboard. Plus an
  `#[ignore]`d connect to `MOORING_LAB_VNC_HOST`.
- Fuzz: `rfb_handshake` (version, security list, reason, ServerInit), `rfb_server_message`
  (dispatch over all message types), `zrle_decode`, `tight_decode` (all filters and control
  bytes, persistent streams), `raw_copyrect_bounds`, `vencrypt_negotiation`, `cut_text`, and
  `known_certs_parse` (shared). Each target asserts no panic, output ≤ the caps, and
  `FrameSink` bounds respected.
- Bench: VNC joins `frame_bench` (ADR-0011) with ZRLE at 10/25/100 % dirty.

## Sources
RFC 6143 (RFB 3.8); VeNCrypt subtypes per the RFB community spec (rfbproto, "VeNCrypt"); QEMU
Extended Key Event per rfbproto; `vnc-rs` 0.6.0 source read locally (`client/auth.rs`,
`client/security/des.rs`, `codec/tight.rs`, `limits.rs`); crates.io API 2026-11-04 for `des`,
`flate2`, `miniz_oxide`, `zune-jpeg`, `vnc-rs`.
