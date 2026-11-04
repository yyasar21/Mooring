# A2 — rust-core R4: VNC session (ADR-0012)

Branch: worktree `agent-a44bf3cad7ac1a1bd` (`worktree-agent-a44bf3cad7ac1a1bd`), from `a2` @ 817a349.
Not merged. Only `crates/mooring-proto-vnc` changed (plus `Cargo.lock`, see Dependencies).

## Done
- Own RFB 3.8 client in `mooring-proto-vnc`. Every module is under 500 lines:
  - `wire`: the `Parsed::{Need, Done}` incremental parser contract.
  - `handshake`: version, security list, reason, `SecurityResult`, `ServerInit`, pixel format.
  - `security`: selection matrix and VNC-auth DES with RustCrypto `des` (bit-reversed key, zeroized).
  - `vencrypt`: 0.2 negotiation, X509 subtypes only.
  - `tls`: rustls/ring `TofuVerifier`, the ADR-0011 decision table, x509-parser → `CertificateInfo`.
  - `messages`: server message headers, rectangle framing with bounds, client encoders.
  - `decode/{mod,zrle,tight}`: Raw, CopyRect, ZRLE, Tight basic, Cursor, DesktopSize/ExtendedDesktopSize, LastRect, QEMU ext key.
  - `input` + `scancode`: keysyms, the QEMU qnum table, the wheel accumulator.
  - `conn`, `connect` (handshake and retries), `reader` (receive task), `driver` (control loop), `shared`, `session`.
- Security policy:
  - `prefer_tls` (default), `require_tls` and `allow_plaintext`.
  - A pin in `known_vnc_certs` makes the connection behave as `require_tls`. If the server offers no VeNCrypt, or VeNCrypt without an X509 subtype, the session hard-stops with `trust_mismatch` ("TLS EXPECTED for host:port") and audits `trust.cert.mismatch` with `presented = none`.
  - TOFU: an unknown certificate raises a `Prompt { purpose: certificate_trust, certificate }`. `yes` writes the pin (`add_and_save`, `stored` in the audit entry) and reconnects on a new TCP connection. Any other answer gives `trust_rejected`. A changed pin is a hard stop.
  - Encodings: Tight JPEG is refused with `protocol_error`, and no JPEG quality pseudo-encoding is advertised.
- Caps:
  - Framebuffer ≤ 8192², and every pixel rect must lie inside it.
  - zlib output ≤ 64 MiB per rect, via streaming inflate with a hard limit. Tight output must match the exact expected size.
  - ZRLE compressed size ≤ 64 MiB.
  - Tight palette ≤ 256, cursor ≤ 384².
  - Cut text ≤ 1 MiB. Anything larger is streamed to `/dev/null`, so the session stays up.
  - Reason and name ≤ 4 KiB, sanitised.
  - The receive buffer is capped at max(4·fb, 64 MiB) + 64 KiB.
  - No `unsafe`, and no panics on hostile input (proptests).
- Session behaviour:
  - Update requests: at most 1 `FramebufferUpdateRequest` outstanding, paced to `maxFps`. After a resize the next request is non-incremental.
  - View-only is enforced in `VncSession::send` when the input arrives, so a later toggle never releases queued input. `ReleaseAll` always passes. The driver re-checks it. Dropped inputs are counted (`VncControl::dropped_inputs`) and logged at debug level.
  - Clipboard: `ClipboardPolicy`, Latin-1 conversion in both directions. Text that is not Latin-1 is refused on send, not replaced. `session.clipboard` entries are coalesced to at most one per second per direction and flushed at close.
  - Pointer coordinates are clamped to the framebuffer. Wheel: DOM sign, buttons 4/5 and 6/7, fractional deltas accumulate, at most 10 notches per event.
  - Keys: release sends the keysym of the press, tracked per `code`. QEMU Extended Key Event (qnum scancodes) is used once the server confirms it.
  - Resize: `Resize` → `SetDesktopSize`, debounced 300 ms, only once the server has shown ExtendedDesktopSize.

## Public API (for R2)
```rust
VncSession::connect(params: ConnectParams, options: VncOptions, sink: FrameSink, audit: AuditLog)
    -> Result<VncSession, MooringError>          // validates host/port/options/credential, spawns the driver
VncOptions { known_certs: PathBuf, clipboard: Arc<dyn Clipboard>, conn: VncConnOptions,
             connect_timeout: Duration /*15 s*/, handshake_timeout: Duration /*30 s, per attempt*/ }
VncOptions::new(known_certs, conn)               // NoClipboard default
pub trait Clipboard: Send + Sync + Debug { fn read_text(&self) -> Option<String>; fn write_text(&self, &str) -> bool; }
AuditLog (Clone, Default): push / take — the same log `Session::take_audit_events` drains
VncSession::control() -> VncControl { set_view_only(bool), view_only(), dropped_inputs() }
impl Session for VncSession   // Prompt* → Connected{security} → DesktopResized (initial size, then on change)* → Closed{code}
```
- `Connected.security` is `vencrypt-x509`, `vnc-auth` or `none`. `peer_identity` is `x509 SHA256:<hex>` only with TLS.
- The audit log can contain: `AuthSucceeded{VncAuth|VncPlain|None}`, `AuthFailed`, `VncPlaintext{none|vnc-auth}`, `CertAdded/CertRejected/CertMismatch/CertCaValid`, `Clipboard`.
- `CloseCode` mapping: network → `network`; protocol, decoder or policy refusal → `protocol_error`; bad credential → `auth_failed`; pin → `trust_mismatch`; TOFU no → `trust_rejected`; server refusal reason → `server_ended`; close → `user`.
- Credential mapping:
  - `Password` with no username → VNC auth or `X509Vnc`.
  - `Password` + username, or `DomainPassword` → `X509Plain` only.
  - `None` → None or `X509None`.
  - `Prompt` → a `credential` form before TCP. A non-empty username means X509Plain. Cancelling closes with `user`.
  - Other kinds → `Invalid` at connect.

Fuzz entry points (pure over `&[u8]`, for Q):
- `handshake::{parse_version, parse_security_types, parse_reason, parse_security_result, parse_server_init}`
- `vencrypt::{parse_version, parse_version_ack, parse_subtypes, parse_subtype_ack, select_subtype}`
- `parse_server_message`
- `parse_rect` + `Decoders::decode` (`raw_copyrect_bounds`)
- `decode_zrle(&mut Decompress, data, w, h)`
- `decode_tight(&mut TightStreams, data, w, h)` + `decode::tight::frame_len`
- `decode_cursor`
- `messages::{latin1_to_string, string_to_latin1}` (`cut_text`)
- `tls::certificate_info` (leaf DER)

## Decisions taken where the brief and the ADR differ
1. **Versions:** only 3.8 is accepted (ADR-0012), and so is a newer 3.x, which gets a 3.8 answer. The brief's "3.3/3.7 negotiation" was not implemented, because 3.3 lets the server pick the security type (downgrade).
2. **VeNCrypt subtypes:** X509None/X509Vnc/X509Plain only (ADR). The brief's TLSNone/TLSVnc need anonymous DH, which rustls does not support. When VeNCrypt offers only anonymous or plain subtypes and TLS is not required (no pin, not `require_tls`), the client **reconnects once without VeNCrypt** (QEMU/x11vnc anon-TLS setups). That attempt is plaintext, audited `session.vnc.plaintext` and badged.
3. **Pixel format:** `PixelOrder::Rgbx` (ADR shifts 0/8/16 LE). A CPIXEL/TPIXEL is 3 bytes, R, G, B.
4. **Clipboard:** the coordinator's U1 note asks for remote cut text as "ClipboardText events". `SessionEvent` has no such variant (core, R1), and ADR-0011/0012 say clipboard text never crosses IPC. So remote text goes to `Clipboard::write_text` (Rust-side OS clipboard). If the UI really needs an event, R1/the architect must add the variant; the driver hook is `ReaderEvent::CutText`.
5. **Bell:** logged only. No `SessionEvent` variant exists.
6. **`ContinuousUpdates`:** not enabled (optional in the brief). A server message of type 150 is a protocol error, since we never ask for it.
7. **View-only "audit the attempt":** there is no `SessionAudit` variant for dropped input, so drops are counted and logged at debug level. The toggle itself is audited by R2's `session_set_view_only`.
8. **`Clipboard` trait:** defined in this crate, because no core trait exists. R3 (RDP) likely needs the same one, so it is a candidate to move to `mooring-core`.
9. **X.509 parsing for `CertificateInfo`:** uses `x509-parser` 0.18 (already in the lockfile through rcgen, `forbid(unsafe)`). R1 left this choice open for R3; align with R3's choice at merge.
10. **Self-signed flag:** true when the issuer DN equals the subject DN (`CertProblem::SelfSigned` doc). Name mismatch is computed separately with `rustls::client::verify_server_name`, so it shows even when the first chain error is something else.

## Dependencies (crate `Cargo.toml` only)
- `tokio-rustls` 0.26.6: MIT/Apache-2.0/ISC, rustls project, no unsafe, features `ring`+`tls12`. **New to the lockfile** and its only new package.
- Already in the lockfile:
  - `des` 0.9 (RustCrypto, MIT OR Apache-2.0).
  - `flate2` 1.1 with `rust_backend` (miniz_oxide, MIT OR Apache-2.0).
  - `x509-parser` 0.18 (MIT OR Apache-2.0).
  - Workspace `rustls`, `rustls-native-certs`, `secrecy`, `zeroize`, `time`.
  - Dev: `rcgen`, `tempfile`, `proptest`.
- `Cargo.lock` gained only the `tokio-rustls` package and the edges of `mooring-proto-vnc` (orchestrator owns the lockfile).

## Left open
- `crates/mooring-testsrv` did not exist in this worktree. `src/testsrv.rs` is a minimal in-test RFB server, with `TODO(merge)` to switch to QA's server.
- Fuzz targets (`fuzz/`, QA) and the `#[ignore]`d `MOORING_LAB_VNC_HOST` test (QA).
- VNC in `frame_bench` (Q1).
- The R2 Tauri wiring: `Control::Vnc(VncControl)`, the `Clipboard` adapter over `clipboard.rs`, `session_set_view_only`.
- Not advertised in A2: Hextile/RRE, Extended Clipboard, Apple/RA2/Tight-security auth.

## Decision needed
- Architect/owner:
  - Is the one-shot plaintext fallback after an anonymous-only VeNCrypt list acceptable under `prefer_tls`? It is never taken with a pin or `require_tls`.
  - Does the U1 "ClipboardText event" contract override ADR-0012 §Clipboard?
- Security reviewer: approve `tokio-rustls`, and `x509-parser` as a runtime dependency.

## Test evidence
- `cargo fmt --all` clean.
- `cargo clippy -p mooring-proto-vnc --all-targets -- -D warnings` clean (only the pre-existing `unknown lint clippy::unused_async_trait_impl` toolchain note).
- `cargo test -p mooring-proto-vnc`: **64 passed**, 0 failed, stable over 4 runs. The tests cover:
  - Parsers:
    - version matrix (3.3/3.7/4.x refused, 3.889 → 3.8);
    - security list, refusal and reason caps;
    - `SecurityResult`;
    - `ServerInit` caps;
    - pixel-format bytes.
  - Security and auth:
    - selection matrix over type list × policy × pin, including the downgrade guard and the anonymous-TLS fallback;
    - DES known-answer (FIPS vector through the bit reversal), plus two VNC-auth vectors cross-checked with `openssl enc -des-ecb`;
    - VeNCrypt negotiation and the subtype matrix;
    - the TOFU decision table through the real rustls verifier with rcgen certs: prompt, pinned with an invalid chain, pin mismatch with a valid CA, CA valid, name mismatch.
  - Decoders:
    - ZRLE raw/solid/packed palette/plain RLE/palette RLE/persistent stream;
    - nine hostile tiles, a zlib bomb and corrupt zlib;
    - Tight fill/JPEG refusal/copy/palette (1-bit and 8-bit)/gradient/stream reset;
    - wrong size and bomb cases;
    - cursor mask and hot-spot clamp;
    - DesktopSize, ExtendedDesktopSize incl. refusal, and bounds.
  - Proptests (no panic, output within bounds) for ZRLE, Tight and rect framing + decode.
  - Input and clipboard: keysym table, release-matches-press, tracker bound, wheel accumulation, Latin-1 round trip and refusal.
  - Loopback end-to-end against `testsrv`:
    - None auth with Raw, Tight, ZRLE, QEMU ext key, Bell and cut text, then input and clipboard offer;
    - VNC auth good, bad and missing password;
    - `require_tls` against a plaintext server;
    - VeNCrypt TOFU yes → reconnect → pin, then stripped VeNCrypt after the pin, then a changed cert;
    - TOFU no;
    - anonymous-TLS fallback;
    - pinned X509Plain with a username;
    - view-only drops (incl. the toggle race);
    - hostile updates → `protocol_error`;
    - DesktopSize → sink, event and a full request;
    - bad connect input.
