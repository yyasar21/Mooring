# A2 — rust-core R3: `mooring-proto-rdp` (ADR-0011)

Branch: worktree `agent-aa58800f0beafa723`, from `a2` @ 817a349. Not merged.

## Constructor API for R2
```rust
use mooring_proto_rdp::{AuditSink, LocalClipboard, RdpOptions, RdpSession};

let options = RdpOptions::new(app_data.join(CertProtocol::Rdp.file_name()), rdp_conn_options)
    .with_clipboard(Arc::new(TauriClipboard { .. }));       // Arc<dyn LocalClipboard>
// optional: options.connect_timeout (15 s), .handshake_timeout (30 s), .keepalive (Some(30 s)), .client_name
let audit = AuditSink::new();                                 // Clone; same buffer as take_audit_events
let mut s = RdpSession::connect(params, options, frame_sink.clone(), audit.clone()).await?;
// then the usual Session loop: next_event / send / close / take_audit_events
```
- `connect(params: ConnectParams, options: RdpOptions, sink: FrameSink, audit: AuditSink)
  -> Result<RdpSession, MooringError>` returns at once; `Err` only for input errors (port 0,
  `become` set, host not a TLS server name, `RdpConnOptions::validate` failure, credential kind
  not `Password` / `DomainPassword` / `Prompt`). Everything on the wire arrives as events.
- Event order: `Prompt{credential}`? → `Prompt{certificate_trust}`* → `Connected{protocol: rdp,
  peer_identity: "x509 SHA256:<hex>", security: "nla"|"tls"}` → `DesktopResized{w,h}` (first one
  right after `Connected`, then on every server-side size change) → `Closed{reason, code}`.
- `trait LocalClipboard: Send + Sync + Debug { fn read_text(&self) -> Option<String>; fn
  write_text(&self, text: &str); }` — R2 implements it over `clipboard.rs` (arboard, digest for
  `clear_if_unchanged`). Called from `spawn_blocking`. `None` disables cliprdr entirely.
- `send`: `Answer` / `CredentialAnswer` go to the open prompt (wrong id or shape → `Invalid`);
  `Bytes` → `Invalid`; graphical inputs before `Connected` are dropped (`Ok`), after it they are
  queued (bounded 256). Every input is `validate()`d.
- `Resize` is debounced 300 ms, clamped 200–8192 / even width, sent through Display Control;
  without DVC the session keeps its size (UI scales). The new size arrives as `DesktopResized`
  after the server's Deactivation–Reactivation.

## Done
- Deps (ADR versions): `ironrdp-{connector 0.12, session 0.13, tokio 0.12 (no default features),
  graphics 0.11, pdu 0.11, cliprdr 0.9, displaycontrol 0.10, input 0.9}` + `ironrdp-{dvc 0.10,
  svc 0.10, core 0.3}` (already pulled in by ironrdp-session; needed for `DrdynvcClient`,
  `StaticChannelSet`, `WriteBuf`). `rustls`/`rustls-native-certs` (workspace), `tokio-rustls 0.26`
  (ring, tls12, no aws-lc), `x509-parser 0.18` (default features off, already in the lock via
  rcgen), `socket2 0.6` (TCP keepalive, already in the lock via tokio), workspace `secrecy`,
  `zeroize`, `time`; dev: `rcgen`, `tempfile`, `proptest`. **Not** used: `ironrdp` meta,
  `ironrdp-tls`, rdpsnd, rdpdr, mstsgu, EGFX/openh264, arboard.
- TLS upgrade hook: `ironrdp_tokio::connect_begin` → `Framed::into_inner` → our
  `tokio_rustls::TlsConnector` with `TofuVerifier` → `mark_as_upgraded` → `connect_finalize`
  with the leaf's `subjectPublicKey` (same bytes `ironrdp-tls` extracts) for the CredSSP binding.
- `TofuVerifier` (src/tls.rs): webpki chain check against OS roots + `caPem` (once-per-process
  root load), `KnownCerts::check` + `decide`, records a `Decision` and fails the handshake for
  `Prompt` / `Mismatch` (never blocks on the UI). TLS 1.2+1.3, ring, no resumption, handshake
  signatures always verified with ring's `verify_tls12/13_signature`.
- Driver: unknown + invalid chain → `Prompt{certificate_trust, certificate: CertificateInfo}`;
  `yes` → `KnownCerts::add_and_save` (+ in-memory session pin if the file cannot be written,
  `CertAdded{stored}`) → new TCP connection; else `CertRejected` + `trust_rejected`. Pin differs →
  `CertMismatch` + `trust_mismatch` with "CERTIFICATE CHANGED for host:port: expected
  SHA256:<old>, got SHA256:<new>". No pin + valid chain → `CertCaValid`, nothing written.
- NLA required: `enable_credssp`, `enable_tls = allowTlsWithoutNla`, Standard RDP Security never.
  If the server selects TLS-only without the option → `protocol_error`; with it →
  `RdpLegacySecurity` audit, `security: "tls"`, `autologon` only in that mode. Kerberos off
  (`kerberos_config: None` → NTLM; the `NetworkClient` refuses every request).
  `AuthSucceeded{Nla|RdpTls}` / `AuthFailed`.
- Credentials: `Password` → username verbatim, no domain; `DomainPassword` → `(user, domain)` or
  UPN; `Prompt` → `credential` form with `needs_domain: true` before connecting
  (`DOMAIN\user` split, empty answer = cancel → `user`). Password stays `SecretString`, copied
  into the connector right before CredSSP; the IronRDP `ConnectionActivationFactory` (which
  clones the config incl. password) is **replaced** by one built from the password-free config,
  so no copy lives for the session.
- Active stage (src/active.rs): `ActiveStage::process` → `GraphicsUpdate` blits (RgbA32 →
  `PixelOrder::Rgbx`, clipped), pointer default/hidden/sprite (≤ 384², non-premultiplied),
  bitmap-recovery redraw, Deactivation–Reactivation (new `DecodedImage`, `sink.resize`,
  `DesktopResized`), `Terminate` → `server_ended` (or `user` when we closed), redirection →
  `protocol_error`. Graceful close: `graceful_shutdown` + up to 2 s for the server disconnect.
- Input: W3C `code` → set-1 scancode table (146 codes + 5 legacy aliases; US + ISO 102nd key
  `IntlBackslash`, `IntlRo`, `IntlYen`, Lang/Kana, numpad, media); KLID from options goes to the
  server. Pointer (buttons 1/2/4/8/16, clamped), wheel per U1 contract (DOM sign: `dy > 0` =
  down → negative RDP rotation; split into ≤ 120-unit events, no clamping loss), `Unicode` as
  Unicode key press/release (surrogate pairs), `ReleaseAll` via `ironrdp_input::Database`.
- cliprdr text only (src/clipboard.rs, src/active_clip.rs): requests only CF_UNICODETEXT/CF_TEXT,
  1 MiB after UTF-8 (raw ≤ 4 MiB+2), no file-clip capability, bounded backend queue (64), at
  most 8 pending pastes; `ClipboardPolicy` per direction; `ClipboardOffer` reads the OS
  clipboard in Rust and announces it; remote copies are fetched proactively and written through
  `LocalClipboard`; `session.clipboard{direction, bytes}` coalesced ≤ 1/s/direction, flushed on
  close. Offered text held in `Zeroizing`.
- Errors → `Closed{reason, code}` with fixed strings (src/errors.rs): CredSSP/AccessDenied →
  `auth_failed`, negotiation failure → `protocol_error` + IronRDP's static text, I/O →
  `network`/`server_ended`, everything else `protocol_error`. Handshake timeout 30 s → `network`.
  TCP keepalive 30 s idle / 10 s interval (socket2).
- Fuzz entry points (`mooring_proto_rdp::fuzz`, all panic-free, proptest-covered):
  `certificate_info(&[u8])`, `cliprdr_text(&[u8])` (byte 0 = format), `active_stage(&[u8])`
  (byte 0 = fast-path/X.224, 1024×768, outputs → `FrameSink`), `input_sequence(&[u8])`.

## Left open
- **Loopback acceptor test**: `mooring-testsrv` was not in this worktree. `tests/lab.rs` has
  `todo_loopback_connect_and_frame_against_mooring_testsrv` (`#[ignore]`, empty) to replace at
  merge with NLA → Connected → DesktopResized → blit, resize, clipboard both ways, mismatch.
  The in-crate fake server (X.224 confirm + real TLS) already covers the whole TOFU flow.
- Auto-reconnect cookie (`ActiveStageOutput::AutoReconnectCookie`) is ignored: a reconnect is a
  new `RdpSession` (R2 loop), and handing the cookie across needs an API; propose
  `RdpOptions.auto_reconnect: Option<Zeroizing<..>>` + an accessor if wanted.
- Fast-path input is always used (every Windows server since 2003 advertises it); the
  `input_flags` slow-path fallback is not implemented.
- `ClipboardText` event: the coordinator's U1 note mentions remote copies "arriving as
  ClipboardText events"; no such `SessionEvent` exists in mooring-core and ADR-0011 says the
  text never crosses IPC. R3 follows the ADR (Rust writes via `LocalClipboard`); if the UI
  wants a notification, R2 can emit one from its `LocalClipboard::write_text` (no text).
- Wheel "accumulate fractional": the wire type is `i16` in 120ths, so nothing fractional
  arrives; deltas are forwarded unchanged (split at ±120).
- Files ≤ 479 lines (active.rs largest).

## Decision needed
- **deny.toml**: none needed — `cargo deny check licenses bans sources advisories` passes on
  this branch unchanged. Note: `Cargo.lock` gained `aws-lc-rs`/`aws-lc-sys` entries only as
  edges of `rustls`/`rustls-webpki` (enabled by `sspi`'s weak `rustls?/aws-lc-rs` feature
  mapping); they are **not** in any build graph (`cargo tree --all-features --target all -i
  aws-lc-rs` is empty, nothing compiled). Orchestrator may add `aws-lc-sys` to `bans.deny` to
  make that a gate. `Cargo.lock` is in this commit (orchestrator owns lockfiles: please accept or
  regenerate).
- **R-RDP-FFI** (accepted by owner) — exact C/unsafe tree via `sspi/scard`:
  ```
  libz-sys v1.1.31 ← flate2 v1.1.10 ← winscard v0.4.0 ← sspi v0.23.0 ← ironrdp-connector v0.12.0
  cryptoki v0.12.1 (+ cryptoki-sys v0.5.0, libloading v0.8.9: dlopen PKCS#11) ← sspi v0.23.0
  winscard v0.4.0 ← sspi v0.23.0
  async-dnssd v0.5.1 (macOS dns_sd FFI) ← sspi v0.23.0
  ```
  (all ← `ironrdp-connector` ← `mooring-proto-rdp`). None of those code paths is reached: no
  smart-card credentials are ever built, Kerberos/DNS is off.
- **R-RDP-STR**: IronRDP holds the password as `String` in the connector and CredSSP state
  until `connect_finalize` returns (then dropped, not zeroized). Mitigated by replacing the
  activation factory (above). Upstream ask: `Credentials` over `Zeroizing<String>`.
- security-reviewer: `x509-parser` chosen over `x509-cert` (already in the lock, nom-based, no
  `unsafe` in default features, gives RFC 4514 names and SAN directly); `tokio-rustls` and
  `socket2` are new direct edges of existing lock entries.
- Ownership: `crates/mooring-proto-rdp/tests/lab.rs` is QA's path per CLAUDE.md; written here
  because the R3 brief asked for the ignored lab test and the merge TODO.

## Test evidence
`cargo fmt --all` clean; `cargo clippy -p mooring-proto-rdp --all-targets -- -D warnings` clean
(only the pre-existing `unknown lint clippy::unused_async_trait_impl` toolchain note);
`cargo test -p mooring-proto-rdp`: **51 unit tests pass**, 2 integration tests ignored
(`lab_rdp_connects_and_draws` needs `MOORING_LAB_RDP_HOST/_USER/_PASSWORD`; the testsrv TODO),
1 ignored doc example. Coverage includes:
- verifier decision table: unknown self-signed → `Prompt` + `UnknownIssuer`; pinned → accept
  without chain; changed → `Mismatch{expected}`; CA-valid (caPem) → `AcceptCa`; pin wins over CA;
  CA leaf for another name → `Prompt` + `NameMismatch`;
- real loopback TLS: pinned handshake succeeds; **pinned certificate served with a different key
  fails** (signature check survives the pin); unknown certificate fails;
- session against a fake X.224+TLS server: TOFU prompt → `yes` → pin written + reconnect +
  `trust.cert.added`; `no` → `trust_rejected` + `trust.cert.rejected`; pre-pinned other cert →
  `trust_mismatch` with the ADR reason, no prompt; TLS-only server refused without the option;
  refused TCP → `network`; credential prompt first + cancel → `user`; close during a prompt is
  fast and final; input validation;
- `CertificateInfo` from DER (self-signed, expired, not-yet-valid, name mismatch, IP SAN,
  trailing bytes/garbage/oversize refused); scancode table (uniqueness, all letters/digits/F1–24,
  ISO keys, aliases); input mapping (repeat filter, button diff, clamp, wheel sign/split,
  surrogates, ReleaseAll); cliprdr decode/encode and the exact 1 MiB cap (±1), format choice,
  policy matrix, audit coalescing, bounded queue; credential mapping per kind; error mapping;
  prompt broker; fuzz entry points (proptest, 256 cases × 4 targets).
