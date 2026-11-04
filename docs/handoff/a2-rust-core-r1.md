# A2 — rust-core R1: core types for RDP/VNC (ADR-0011, ADR-0012, ADR-0013)

Branch: worktree `agent-a0957c7e18b3564a1`, from `main` @ 5f4f393. Not merged.

## Done
- `mooring_core::frame` (ADR-0011 §Frame path):
  - `Framebuffer`: RGBA, ≤ 8192², resize clears to opaque black and makes the next update
    full + resized; bounds-checked `blit` (pixel orders `Rgba/Bgra/Rgbx/Bgrx` → RGBA, `x` →
    alpha 255), overlap-safe `copy`, `fill`, `set_cursor`, `mark_dirty`, `invalidate`,
    `take_update`, `read_rect`. Dirty rects stay pairwise disjoint (overlaps merge into the
    bounding box); > 32 rects or > 60 % area → one full rect. Out of bounds → `Err`, never panic.
  - `FrameSink` = `Arc<{Mutex<Framebuffer>, Notify}>` with exactly the ADR methods plus pump
    helpers (`changed`, `take_frame`, `snapshot`, `size`, `invalidate`).
  - `mfr1`: byte-exact ADR layout; `Mfr1Writer` (all 6 record kinds), `encode_update`,
    hostile-input `decode_mfr1(&[u8])` (never panics, allocation bounded by input), and
    `Mfr1Frame::apply(&mut Vec<u8>)` (what the UI texture does; used for round-trip proofs).
  - `FrameCredits` (2 in flight, cumulative ack, forged/stale acks create no credit, seq
    wraps and skips 0) and `FrameStats`.
- `mooring_core::known_certs`: `KnownCerts` (parse/load/check/add/remove/list/save, locked
  `add_and_save` / `remove_and_save`), `CertProtocol::{Rdp,Vnc}.file_name()`, the pure
  decision table `decide(CertTrust, chain_valid) -> CertVerdict`, `CertificateInfo`
  (+ `fingerprint`, `hex`, `display_fingerprint`, `peer_identity`), `KnownCert` for IPC.
- `mooring_core::session` per ADR-0011 (see API below); `mooring_core::audit::SessionAudit`
  (former SSH `TrustEvent`, now shared) with `trust.cert.{added,rejected,mismatch,ca_valid}`,
  `session.rdp.legacy_security`, `session.vnc.plaintext`, `session.clipboard`.
- `mooring_core::options`: `ProtocolOptions` + `RdpConnOptions`, `VncConnOptions`,
  `WebConnOptions`, `ClipboardPolicy`, `MaxFps`, `VncSecurity`.
- `mooring-store` migration 0005: `connection.options_json TEXT NOT NULL DEFAULT '{}'`,
  CHECK json object ≤ 128 KiB; `Store::connection_options` / `set_connection_options`;
  `update_connection` resets options to `{}` when the protocol changes. `LATEST = 5`.
- `mooring-proto-ssh` adapted (behaviour unchanged): `TrustEvent` is a re-export of
  `SessionAudit`; every close path carries a `CloseCode`; new graphical inputs are refused.

## Decisions taken where the ADR was ambiguous (documented in doc comments)
1. **known_certs line format follows ADR-0011 exactly** (`|2|salt|HMAC-SHA256 x509-sha256
   <b64 sha256> <RFC 3339>`), not the brief's `<host>:<port> <proto> SHA256:<fp>` form: the
   protocol is implied by the file (`known_rdp_certs` / `known_vnc_certs`). Entries are
   always written hashed (32-byte salt, padded standard base64). Plain `host:port` /
   `[v6]:port` is accepted on read only. `host:port` always includes the port.
2. Fingerprint display is `SHA256:<64 lowercase hex>` (ADR: `peer_identity = "x509
   SHA256:<hex>"`), unlike SSH/credential fingerprints (base64). `CertificateInfo.sha256` is
   the bare hex.
3. `CertificateInfo` adds `san: Vec<String>` (brief); "self-signed flag" is
   `problems ∋ self_signed` + `is_self_signed()`. Times serialise RFC 3339; fields snake_case
   like the rest of `SessionEvent`. DER → fields parsing is **not** in R1 (needs a new X.509
   dependency, see Decision needed); the constructor takes parsed fields + DER and sanitises.
4. MFR1 size cap: `4·fbW·fbH + 64 KiB` **plus one maximal cursor record** (4·384² + 14 B);
   otherwise a valid sprite on a small framebuffer is unencodable. Kinds 5/6 must have an
   all-zero rect, kind 4 has x = y = 0, reserved byte must be 0, unknown flags refused,
   trailing bytes refused.
5. The R1 encoder emits only RGBA records (+ cursor). `copy`/`fill` on the sink are sent as
   pixels; kinds 2/3 exist in writer and decoder for a later optimisation.
6. `FrameSink::cursor` with an invalid sprite (ADR signature returns `()`) stores
   `Cursor::Default` and warns.
7. `ProtocolOptions` is untagged: the connection's protocol selects the struct
   (`from_value(protocol, json)` / `from_json`). `{}` = owner defaults for RDP/VNC; protocols
   without options accept only `{}`; **web requires `url`**, so `{}` does not validate for web.
   `maxFps` is the JSON number 30|60, `keyboardLayout` a JSON number (KLID). Serde errors are
   rewritten so no UI/DB value is echoed.
8. Options are not a field of `Connection` (keeps every A1 caller compiling); IPC handlers
   combine `get_connection` + `connection_options`.
9. `DesktopResized { width, height }` uses `u32` like `Size`.
10. `Reconnecting { attempt, delayMs }` is **not** a `SessionEvent` (the ADR lists it under the
    Tauri reconnect loop): R2 adds it to `WireEvent`.
11. `SessionInput::Key/Unicode` content is redacted in `Debug` (keystrokes may be passwords).
    `SessionInput::validate()`: `code` 1–32 ASCII alphanumerics, `key` ≤ 32 B no control
    chars, `Unicode.text` 1–64 chars no control chars.
12. New `AuthMethod` variants: `Nla`, `RdpTls`, `VncAuth`, `VncPlain`, `None`.
13. Added `rand_core`, `tempfile`, `tracing` to `mooring-core` (all existing workspace deps,
    already in the lockfile; `Cargo.lock` only gained the three dependency edges).

## Left open
- **src-tauri does not compile against this branch** until R2 adapts it: `WireEvent::Frame`
  (removed `SessionEvent::Frame`), `SessionEvent::Closed { reason }` / `Connected { .. }`
  patterns (new fields), `WireInput::Key { scancode }` → `{ code, key }` + new inputs, and
  `audit_trust` (match `SessionAudit` — the new variants need arms). Merge R1 together with R2,
  or the orchestrator applies those mechanical fixes.
- Fuzz targets (`known_certs_parse` → `KnownCerts::parse_bytes`, `mfr1_decode` /
  `framebuffer_ops` → `frame::decode_mfr1` + `Framebuffer` ops) are Q1; the properties
  exist as proptests.
- Legacy web connections (protocol `web`, `{}` options) fail `connection_options` until a URL
  is set (R5/U3 decide: prompt, or derive `https://<host>:<port>`).
- `frame_bench` (Q1).

## Decision needed
- X.509 DER parsing for `CertificateInfo` (subject, issuer, validity, SAN): `x509-parser`
  0.18 is already in the lockfile (via rcgen, dev only) vs RustCrypto `x509-cert`. Needs
  security-reviewer approval; R3 owns it.
- Architect: confirm the MFR1 cursor allowance (decision 4) and the hex fingerprint form.

## Test evidence
`cargo fmt --all --check` clean; `cargo clippy -p mooring-core -p mooring-store
-p mooring-proto-ssh --all-targets -- -D warnings` clean (only the pre-existing
`unknown lint clippy::unused_async_trait_impl` toolchain note); also clippy for the RDP/VNC
stubs. `cargo test -p mooring-core -p mooring-store -p mooring-proto-ssh`: all green —
mooring-core 112 unit + 5 corpus; mooring-store 25 unit + 50 integration; mooring-proto-ssh
61 unit + 53 integration (1 lab test ignored). New tests include: MFR1 byte vector, 18
hostile-message cases, encode→decode proptest, hostile-bytes and mutated-message proptests,
mirror-equals-framebuffer proptest (coalescing never loses pixels, rects disjoint, ≤ 32),
known_certs decision table (4 rows), round trip/caps/malformed/proptests, 0600 save,
options defaults/wire/closed lists/caPem/web URL rules, migration v4 → v5, CHECK constraint,
re-validation on read, protocol-change reset, CloseCode wire + retry rule, certificate prompt
wire shape, input validation and redaction.

## Public API for R2–R4 and the UI
```rust
// mooring_core::frame
pub struct Rect { pub x: u16, pub y: u16, pub w: u16, pub h: u16 }      // new, fits, overlaps, union, area
pub enum PixelOrder { Rgba, Bgra, Rgbx, Bgrx }
pub enum Cursor { Default, Hidden, Sprite { hot_x, hot_y, w, h, rgba: Vec<u8> } }  // is_valid()
pub const MAX_DIM: u16 = 8192; MAX_CURSOR: u16 = 384; COALESCE_MAX_RECTS = 32; FULL_AREA_PERCENT = 60;
#[derive(Clone, Default)] pub struct FrameSink;  // new()
  resize(w,h)->Result<()>; blit(r, src, stride, PixelOrder)->Result<()>; copy(dst, sx, sy)->Result<()>;
  fill(r, [u8;4])->Result<()>; cursor(Cursor); invalidate(); size()->(u16,u16);
  async changed(); take_frame(seq: u32)->Option<Vec<u8>> /* MFR1 */; snapshot()->(u16,u16,Vec<u8>)
pub struct Framebuffer; pub struct FrameUpdate { full, resized, rects: Vec<Rect>, cursor: Option<Cursor> }
pub struct FrameCredits;  // default()/new(max); reserve()->Option<u32>; cancel(seq); ack(seq)->bool; in_flight(); reset()
pub struct FrameStats { frames, full_frames, rects, bytes, max_message, throttled }  // record_sent, record_throttled
pub fn decode_mfr1(&[u8]) -> Result<Mfr1Frame, Mfr1Error>;  pub fn encode_update(seq, &Framebuffer, &FrameUpdate) -> Vec<u8>
pub struct Mfr1Frame { seq, width, height, flags, records: Vec<Mfr1Record> }  // is_full, is_resized, apply(&mut Vec<u8>)
pub enum Mfr1Record { Rgba{rect,data}, Copy{rect,src_x,src_y}, Fill{rect,rgba}, Cursor(Cursor) }
mfr1::{Mfr1Writer, MAGIC, HEADER_LEN=16, RECORD_HEADER_LEN=10, MAX_RECORDS=256, FLAG_FULL=1, FLAG_RESIZED=2, max_message_len}

// mooring_core::known_certs
pub enum CertProtocol { Rdp, Vnc }                    // file_name(): "known_rdp_certs" | "known_vnc_certs"
pub struct KnownCerts;  parse_bytes(&[u8]); load(&Path); check(host, port, &[u8;32]) -> CertTrust;
  has_pin(host, port); add(host, port, &[u8;32], OffsetDateTime); remove(host, port)->usize;
  list()->Vec<KnownCert>; save(&Path); add_and_save(..); remove_and_save(path, host, port)->usize
pub enum CertTrust { Trusted, Unknown, Mismatch { expected: [u8;32] } }
pub enum CertVerdict { AcceptPinned { chain_valid }, AcceptCa, Mismatch { expected }, Prompt }
pub const fn decide(CertTrust, chain_valid: bool) -> CertVerdict
pub struct KnownCert { host_hash, fingerprint /* SHA256:<hex> */, added_at }   // camelCase JSON
pub struct CertificateInfo { subject, issuer, not_before, not_after, sha256 /* hex */, san, problems }
  // CertificateInfo::new(der, subject, issuer, not_before, not_after, &san, problems)
pub enum CertProblem { SelfSigned, UnknownIssuer, NameMismatch, Expired, NotYetValid }
pub fn fingerprint(der)->[u8;32]; display_fingerprint(&[u8;32]); peer_identity(&[u8;32]) /* "x509 SHA256:<hex>" */
pub fn host_key(host, port) -> String; KnownCertsError { Io, Truncated }

// mooring_core::session
SessionEvent::{Connected{protocol, peer_identity, security}, Bytes{data}, DesktopResized{width,height},
  Prompt{id, message, secret, purpose, account, certificate: Option<CertificateInfo>}, Closed{reason, code: CloseCode}}
pub enum CloseCode { User, Network, AuthFailed, TrustRejected, TrustMismatch, ServerEnded, ProtocolError, VaultLocked } // is_retryable()
PromptPurpose::{HostKeyTrust, CertificateTrust, KeyboardInteractive, Credential, Other}
SessionInput::{Bytes, Resize, Pointer{x,y,buttons}, Key{code,key,pressed}, Wheel{dx:i16,dy:i16}, Unicode{text},
  ReleaseAll, ClipboardOffer, Answer, CredentialAnswer}   // validate(); wire tag "kind", snake_case
trait Session { ..; fn take_audit_events(&mut self) -> Vec<SessionAudit> { Vec::new() } }

// mooring_core::audit
pub enum SessionAudit { HostKey*, AuthSucceeded{method}, AuthFailed, Forward*, BecomeFailed,
  CertAdded{host,port,fingerprint,stored}, CertRejected{host,port,fingerprint},
  CertMismatch{host,port,expected,presented}, CertCaValid{host,port,fingerprint},
  RdpLegacySecurity, VncPlaintext{security}, Clipboard{direction, bytes} }   // action()
pub enum AuthMethod { PublicKey, Agent, Password, KeyboardInteractive, Nla, RdpTls, VncAuth, VncPlain, None }
pub enum ClipboardDirection { ToRemote, FromRemote }

// mooring_core::options
pub enum ProtocolOptions { Rdp(RdpConnOptions), Vnc(VncConnOptions), Web(WebConnOptions), None(NoOptions) }
  // default_for(Protocol); from_value(Protocol, Value); from_json(Protocol, &str); to_json(); fits(Protocol); validate()
RdpConnOptions { keyboard_layout: u32, clipboard, allow_tls_without_nla, ca_pem: Option<String>, max_fps }
VncConnOptions { security: VncSecurity /* prefer_tls */, view_only, shared /* true */, clipboard, ca_pem, max_fps }
WebConnOptions { url, allowed_origins, persistent /* false */, allow_http }   // origin()
ClipboardPolicy { Off, ToRemote, FromRemote, Both }; MaxFps { Thirty, Sixty } // interval()
KEYBOARD_LAYOUTS, DEFAULT_KEYBOARD_LAYOUT = 0x0409, MAX_OPTIONS_JSON = 128 KiB, MAX_ALLOWED_ORIGINS = 16

// mooring_store
Store::connection_options(ConnectionId) -> Result<ProtocolOptions>
Store::set_connection_options(ConnectionId, &ProtocolOptions) -> Result<ProtocolOptions>
```
UI wire notes: `SessionEvent`/`SessionInput` stay snake_case (`desktop_resized`,
`release_all`, `clipboard_offer`, `certificate_trust`, `not_before`); options and `KnownCert`
are camelCase. MFR1 decoding in TypeScript must mirror `decode_mfr1` (same refusals).
