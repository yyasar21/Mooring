# A2 — rust-core R2: Tauri session task, frame pump, reconnect, RDP/VNC IPC (ADR-0011)

Branch: worktree `agent-ab88765b21817dfce`, from `a2` @ 817a349 (R1). Not merged.

## Done
- **R1 adaptation:** `src-tauri` compiles against the new `SessionEvent` / `SessionInput` /
  `CloseCode` / `SessionAudit`. `audit_trust` became `session_audit::audit_session(audit,
  connection, protocol, events)`; every `SessionAudit` variant has an arm (the `cert_*`,
  `rdp`, `vnc` and clipboard arms are new).
- **Generic task** (`session_task::drive<S: Session + ?Sized>`): SSH runs it once
  (`run_ssh`), graphical sessions once per connection (`graphical_task`). It forwards every
  event except `Closed`; the caller emits `Closed` or reconnects.
- **`FramePump`** (`frame_pump.rs`): waits on `FrameSink::changed()`, sends at most one MFR1
  message per tick (`1000/maxFps` ms; 33 ms by default), keeps 2 in flight (`FrameCredits`)
  and sends raw bytes as `InvokeResponseBody::Raw` over the `onFrame` channel (Tauri 2.12.5:
  ≥ 1 KiB goes eval + fetch into an `ArrayBuffer`; `Channel<Vec<u8>>` would serialise to a
  JSON number array, so it is not used). The bytes are R1's `take_frame`, so the U1 strictness
  rules (flags, reserved byte, trailing bytes) hold by construction.
- **Reconnect** (`reconnect.rs`): 1, 2, 4, 8, 16, 30 × unit (1 s) ± 20 % jitter (`OsRng`), at
  most 6 attempts, only for `network | server_ended`, only after a `Connected` on this session,
  never after a user close. The attempt counter resets after a successful `Connected`. Each
  attempt calls `connect_plan::plan` again (credential from the vault), so a locked vault ends
  the session with `code: vault_locked`. A failed attempt maps its `IpcError` to a close code
  (`close_code_of`). The same `FrameSink` survives reconnects.
- **Certificate prompt:** the task watches for `Prompt { purpose: certificate_trust,
  certificate }`. The answer to that prompt id never reaches the session. `yes` (trimmed, any
  case) → `KnownCerts::add_and_save` → audit `cert_decision accepted` → close → new connect.
  If the pin cannot be written → `accepted_session_only` and the next connect gets
  `trusted_once: Some(sha256)`. Anything else → `cert_decision rejected`, `Closed { code:
  trust_rejected }`. While the prompt is open, a `Closed` or stream end from the session is
  swallowed. A mismatch is the protocol's `Closed { trust_mismatch }` + `SessionAudit::
  CertMismatch`; it is never retried.
- **View-only:** pointer, key, wheel, unicode and clipboard_offer are dropped (`Ok`) while on;
  `release_all` always passes. Initialised from VNC `viewOnly`; `session_set_view_only` toggles it.
- **Inputs:** `pointer` (x, y < 8192, buttons ⊆ 0b11111), `key`, `wheel` (DOM sign, unchanged),
  `unicode`, `release_all`, `clipboard_offer`, all through `SessionInput::validate()`. rdp/vnc
  sizes (open and `resize`) must be 200..=8192 with an even width (refused, not clamped). The
  last `resize` size is used on reconnect.
- **Clipboard:** `Clipboard` gains `text()` (for `ClipboardOffer`) and `set_image()`. Sessions get
  a `RemoteClipboard` that records the digest of what the remote wrote; `vault_lock` and exit
  clear it if it is unchanged (`AppState::remote_clipboard`).
- **AppState:** `vault` / `store` are now `Arc<Mutex<…>>`, and `Ready` (`state.ready()`) is the
  `'static` handle the reconnect loop re-plans with. `Settings` gains `graphical: Arc<dyn
  SessionFactory>` and `reconnect_unit`.
- **Audit (mooring-audit):** `cert_decision`, `cert_removed`, `session_weak_security`,
  `session_clipboard`, `session_screenshot` (wire names = snake_case event names; the ADR
  action names `trust.cert.*` / `session.screenshot` map to them). Syslog: rejected, changed,
  removed and weak security are warnings.
- `ipc-passive.json` gains `session_frame_ack` and `web_list` (R5 command, passive per
  ADR-0013). `ipc-codes.json` gains `ipc.forbidden`, `protocol.unavailable`,
  `session.trust_mismatch`, `session.trust_rejected`, `session.unsupported_security`.

## IPC for the UI (exact JSON)
```
session_open({ connectionId, size: {width, height}, onEvent: Channel, onFrame?: Channel })
  -> { sessionId }
  # rdp/vnc: onFrame required (else input.invalid "onFrame"), size 200..=8192, even width
  # ssh: onFrame refused (input.invalid); size 1..=16384
  # caller window must be "main", else ipc.forbidden
  # stubs (until R3/R4 merge): protocol.unavailable
onFrame message: raw MFR1 bytes (ArrayBuffer), one message = one frame
session_frame_ack({ sessionId, seq })            -> null   # passive; forged/stale seq ignored
session_attach({ sessionId })                    -> { protocol: "rdp"|"vnc",
                                                      state: "connecting"|"connected"|"reconnecting",
                                                      size: { width, height } }
  # drops in-flight credits, next message is full (flags & 1)
session_screenshot({ sessionId })                -> { width, height }
  # session.not_connected before the first frame; clipboard.unavailable (see Decision 1)
session_set_view_only({ sessionId, viewOnly })   -> null
known_certs_list({ protocol: "rdp"|"vnc" })      -> [{ hostHash: "|2|…", fingerprint: "SHA256:<hex>", addedAt }]
known_certs_remove({ protocol, host, port })     -> { removed: number }   # audited cert_removed
connection_options_get({ connectionId })         -> RdpConnOptions | VncConnOptions | WebConnOptions | {}
connection_options_set({ connectionId, options }) -> stored options (defaults filled in)
  # input.invalid for unknown fields, wrong protocol, maxFps ∉ {30,60}, > 128 KiB
session_list() rows: state may now also be "reconnecting"
# graphical-session and known_certs/options commands need an unlocked vault (vault.locked)
# frame_ack/attach/screenshot/view_only on an ssh session: input.invalid "sessionId"

Events (onEvent, snake_case):
{"kind":"connected","protocol":"rdp","peer_identity":"x509 SHA256:<hex>","security":"nla"}
{"kind":"desktop_resized","width":1280,"height":800}
{"kind":"prompt","id":7,"message":"…","secret":false,"purpose":"certificate_trust","account":null,
 "certificate":{"subject","issuer","not_before","not_after","sha256","san":[],"problems":["self_signed"]}}
{"kind":"reconnecting","attempt":1,"delay_ms":1043}
{"kind":"closed","reason":"…","code":"network|user|auth_failed|trust_rejected|trust_mismatch|server_ended|protocol_error|vault_locked"}
Certificate answer: session_send({ sessionId, input: {"kind":"answer","id":7,"text":"yes"|"no"} })
Inputs: {"kind":"pointer","x","y","buttons"} {"kind":"key","code","key","pressed"}
 {"kind":"wheel","dx","dy"} {"kind":"unicode","text"} {"kind":"release_all"} {"kind":"clipboard_offer"}
 {"kind":"resize","size":{"width","height"}}
```

## Factory hook for R3/R4 (merge)
`src-tauri/src/session_factory.rs`, `impl SessionFactory for BuiltinFactory`:
```rust
Protocol::Rdp => Err(unavailable("RDP")),   // MERGE R3
Protocol::Vnc => Err(unavailable("VNC")),   // MERGE R4
```
becomes, for example:
```rust
Protocol::Rdp => {
    let ProtocolOptions::Rdp(conn) = req.options else { return Err(IpcError::invalid("options", "not rdp")) };
    let opts = mooring_proto_rdp::RdpOptions { known_certs: req.known_certs, frames: req.frames,
        clipboard: /* adapter over req.clipboard */, conn /* + req.trusted_once */ };
    let s = mooring_proto_rdp::RdpSession::connect(req.params, opts).await.map_err(IpcError::from)?;
    Ok(Box::new(s) as Box<dyn Session>)
}
```
plus the `mooring-proto-rdp` / `-vnc` dependencies in `src-tauri/Cargo.toml` (orchestrator).
`GraphicalConnect` = `{ protocol, params: ConnectParams (size in pixels), options:
ProtocolOptions, known_certs: PathBuf, frames: FrameSink, clipboard: Arc<dyn
crate::clipboard::Clipboard>, trusted_once: Option<[u8; 32]> }`. The future resolves when TCP is
up; handshake, TLS trust and auth go on in `next_event`.

Contract R3/R4 must follow:
1. Unknown certificate: emit `Prompt { purpose: CertificateTrust, certificate: Some(info) }` and
   then wait or end the stream. **Do not write the pin or audit the answer**: the Tauri layer
   does both and reconnects. Accept `trusted_once` as if pinned for that one connect.
2. Pin mismatch: `SessionAudit::CertMismatch` + `Closed { code: TrustMismatch }`. CA-valid →
   `CertCaValid`. Legacy/plaintext → `RdpLegacySecurity` / `VncPlaintext` on every connect.
3. Close codes decide retries: only `Network` / `ServerEnded` are retried. Connect errors
   that should not be retried return `IpcError` codes `session.trust_mismatch`,
   `session.trust_rejected`, `session.unsupported_security` or `credential.*`
   (`graphical_task::close_code_of`).
4. Clipboard: read with `Clipboard::text()`, write with `set()` (tracked for lock clearing).
   Coalesce `SessionAudit::Clipboard` to ≤ 1 per second per direction in the protocol crate.
5. Wheel arrives in the DOM sign (positive `dy` = down); convert in the protocol crate.
   `Resize` arrives already validated (200..=8192, even width); debounce in the protocol crate.
6. A panicking protocol task: no `JoinError` mapping yet (the session runs inside the task
   future, not a separate task); with `panic = "unwind"` a panic ends the session task without
   `Closed`. Spawn decoders on their own task if that matters.

## Decisions taken
1. `Reconnecting` is `{ attempt, delay_ms }` (snake_case like every event field; ADR says
   `delayMs`, the U1 decoder reads `delay_ms` and tolerates camelCase). The R2 brief said
   `nextInMs`; I followed the ADR + U1 contract instead.
2. Retries need a `Connected` earlier in the same session (not necessarily on the dropped
   connection); the counter resets after each `Connected`.
3. Cert prompt answer `yes` is case-insensitive and trimmed, as for SSH TOFU.
4. Commands for graphical sessions refuse `""` / > 64-char ids (`input.invalid`); unknown →
   `session.not_found`.
5. `session_open` checks `webview.label() == "main"` (`ipc.forbidden`) ahead of ADR-0013.

## Left open
- **`session_screenshot` returns `clipboard.unavailable` in the real app**: arboard is built with
  `default-features = false`; images need `features = ["image-data"]`, which adds the `image`
  crate (PNG on Linux) and `objc2-core-graphics` / `windows-sys` GDI. The whole flow is there
  (`Clipboard::set_image`, audited) and tested with `MemoryClipboard`.
- `connection_options_set` is not audited (e.g. `allowTlsWithoutNla` turned on); the connect
  itself audits `session_weak_security`. Security-reviewer call.
- `connection_create/update` do not take `options` yet (ADR IPC line); the UI uses
  `connection_options_set` after create. Can be folded in if U2 wants one call.
- `window_detach` is still `ipc.unknown` (R5). `session_attach` keeps the same channels.
- No coalescing of high-rate `pointer` inputs in Rust (U1 note); each is one `session_send`.

## Decision needed
1. Orchestrator + security-reviewer: enable `arboard/image-data` (new transitive `image` crate)
   for `session_screenshot`, or change the ADR to "save as PNG file" via the Rust dialog.

## Test evidence
`cargo fmt --all`, `cargo clippy -p mooring-app --all-targets -- -D warnings` clean.
`cargo test -p mooring-app`: lib 151 passed, 1 ignored (`frame_bench`); e2e_flow 13 passed.
`cargo test -p mooring-audit`: green. New tests: pump ordering / 2 credits / forged and stale
acks / coalescing to the newest pixels / tick cadence / UI gone; ack is passive (+ golden);
reconnect schedule, jitter bounds, cap, retry rule; end-to-end with a scripted session:
frames + ack + attach + screenshot, network drop → reconnect with the last size → auth
failure stops, no retry before `Connected`, 6 failed attempts then `closed`, vault lock
stops retries, certificate yes (pin written, reconnect) / no (`trust_rejected`) / unwritable
store (`trusted_once`) / mismatch (hard stop, audited); view-only drops input but not
`release_all`, wheel sign unchanged; hostile inputs (key code/key/unicode caps, control
characters, pointer range and bits, odd/small desktop sizes, unknown session ids, frames on
SSH, missing `onFrame`); known_certs list/remove + audit + hostile host/port + locked vault;
options round trip, refusals without echo, 128 KiB cap, per-protocol rules; stub factory.
`frame_bench` (`cargo test -p mooring-app --release --lib -- --ignored frame_bench
--nocapture`, Linux container, 2 Tokio workers, 1080p, 25 % dirty per 16 ms source tick,
consumer decodes + applies + acks): **29.1 fps, p95 change→applied 19.6 ms**, 146 messages in
5 s (1 full), 587 MB, 0 throttled. The ceiling is the 33 ms tick (30.3 fps). The first run
gave 25.6 fps because the tick was measured after encoding; it now starts before
`take_frame`. This measures the Rust side only (encode + channel + decode); the WebView
fetch/`texSubImage2D` part of the ADR gate needs Q1 on real WebViews.
