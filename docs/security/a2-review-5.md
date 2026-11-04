# A2 security review 5 — RDP, VNC, frame path, certificate TOFU (ADR-0011, ADR-0012)

Reviewer: security-reviewer · 2026-11-04 · Range `git diff main...a2` (`5f4f393..f85a319`,
270 files). Focus: `crates/mooring-core/src/{frame,known_certs,options,audit,clipboard}`,
`crates/mooring-proto-rdp`, `crates/mooring-proto-vnc`, `src-tauri/src/{session_factory,
sessions,session_task,graphical_task,frame_pump,clipboard}.rs`, `src-tauri/src/commands/**`,
`fuzz/`, `apps/desktop/src/{lib/frame,components/remote,lib/ipc.mock.remote.ts}`.
`crates/mooring-testsrv` was read as test scope only.

Inputs:
- [ADR-0011](../adr/0011-rdp-session.md), [ADR-0012](../adr/0012-vnc-session.md) and
  [ADR-0013](../adr/0013-web-sessions.md), including the owner decisions 1–7.
- Handoffs `a2-rust-core-r1..r4.md`, `a2-ui-u1.md`, `a2-qa.md` and `a2-integration.md`.
- [Review 4](a1-review-4.md) and the [threat model](threat-model.md).

Evidence gathered here (Linux x86_64, `CARGO_INCREMENTAL=0`, shared
`CARGO_TARGET_DIR=/home/claude/nexus/target`):
- `cargo test -p mooring-proto-rdp -p mooring-proto-vnc -p mooring-core` is green (log at the
  end).
- `cargo deny check`: advisories, bans, licenses and sources are all ok.
- `cargo tree` on the app for `image`, `pxfm`, `moxcms`, `flate2`, `libz-sys`, `x509-parser`
  and the R-RDP-FFI crates.
- The sources of `ironrdp-{connector 0.12.0, session 0.13.0, svc 0.10.0, dvc 0.10.0,
  graphics 0.11}`, `sspi` 0.23.0, `flate2` 1.1.10, `winscard` 0.4.0 and `arboard` 3.7.0 were
  read from the cargo registry.
- **Not run:** `cargo audit` (the advisory DB could not be fetched here), `cargo geiger`,
  `gitleaks`, `semgrep`, `pnpm audit`, cargo-fuzz (no nightly toolchain), the `mooring-app`
  suite and the macOS and Windows builds.

## Verdict: `BLOCKER`

There is one blocker, **B-5**. A hostile RDP server, or a MITM the user trusted at the TOFU
prompt, picks the desktop size. `mooring-proto-rdp` then allocates
`width × height × 4` bytes through `DecodedImage::new` **before** anything checks the size
against the 8192² limit. With 65535 × 65535 that is a 17 GiB zeroed allocation. On Linux and
Windows the allocation fails, and allocation failure **aborts the process even under
`panic = "unwind"`**. One server can therefore kill every session and the unlocked vault
process. That defeats owner decision 1 (one session task fails, never the process). It is the
same class as B2 (KDF ceiling), and the fix is about four lines.

The trust design itself holds:
- The RDP and VNC verifiers check the pin before the CA, check the name through webpki for the
  CA path, and always verify the handshake signatures. The loopback test proves that a pin does
  not bypass the signature check.
- The Tauri `Gate` is the **only** writer of pins and the only auditor of answers: no
  `add_and_save` is left in either protocol crate.
- `trusted_once` lives for exactly one connect.
- NLA is required and Kerberos is unreachable.
- Passwords stay `SecretString` up to IronRDP's own `String` (R-RDP-STR).
- `Key`, `Unicode` and `Answer` are redacted in every `Debug`.
- Clipboard and screenshot data never cross IPC.
- MFR1 is strict on both sides.
- CSP and capabilities are byte-identical.
- `aws-lc-*` is banned and not built.

There are three Medium findings:
- **M-13:** the VNC downgrade guard does not cover CA-validated servers.
- **M-14:** IronRDP reassembles virtual-channel and fast-path fragments without any cap.
- **M-15:** feature unification makes the app inflate hostile VNC zlib streams with **C zlib**,
  so the R-RDP-FFI tree *is* executed.

None of the three stops the merge, but all three land before the A2 tag.

## Findings

Numbering continues from review 4 (last used: B-4, M-12, L-19, N-22).

| ID | Sev | Where | Finding | Exact fix |
| --- | --- | --- | --- | --- |
| **B-5** | **Blocker** | `crates/mooring-proto-rdp/src/active.rs:137`, `:156` (`Active::new`), `:168-172` (`resized`); size source `ironrdp-connector` 0.12.0 `connection_activation.rs:303-310` (server Bitmap capability, unchecked); `ironrdp-session` 0.13.0 `image.rs:146-151` (`vec![0; w·h·4]`) | `result.desktop_size` (initial activation) and the `desktop_size` of every Deactivation–Reactivation come from the server's Demand Active and are not bounded by IronRDP. `DecodedImage::new(RgbA32, w, h)` runs first, and only then does `sink.resize` refuse sizes over 8192². At 65535² that is 17.2 GiB. On Linux (heuristic overcommit) and Windows (commit charge) the allocation fails, and `handle_alloc_error` **aborts the process**. `panic = "unwind"` does not help. Under 8192 the same path allocates 256 MiB per image, which is intended. The `rdp_fastpath` fuzz target uses a fixed 1024 × 768 image, so it cannot reach this. | **rust-core.** In `Active::new` and `resized`, validate first: `if size.width == 0 \|\| size.height == 0 \|\| size.width > MAX_DIM \|\| size.height > MAX_DIM { return Err(end(CloseCode::ProtocolError, "the server desktop size is not supported")) }`. `Active::new` therefore returns `Result`. Call `sink.resize` **before** `DecodedImage::new`. Tests: a unit test of the size guard (0, 8193 and 65535 refused; 8192 accepted), and a `mooring-testsrv` RDP knob `--desktop 65535x65535` → `Closed { protocol_error }` without a large allocation (assert the process RSS stays under 512 MiB, or run the test under `ulimit -v`). **QA:** an `rdp_reactivation` fuzz entry that feeds a server Demand Active to the reactivation sequence |
| **M-13** | Medium | `crates/mooring-proto-vnc/src/security.rs:106-135` (`tls_required` = pin or `require_tls`); `connect.rs:104-106`, `:238-245` (`CaValid` writes nothing); `known_certs::decide` (`AcceptCa`: no pin, by ADR-0011 design) | The HSTS-like guard of ADR-0012 depends on a **pin**. A VNC server whose certificate validates against the system roots or `caPem` is never pinned, so with the default `prefer_tls` a MITM that strips VeNCrypt from the type list gets a silent plaintext session. The client then sends the type-2 DES response (8-byte password, offline-crackable), or falls back to None. This hits exactly the users who did the right thing and deployed a CA-issued certificate. The badge and `session.vnc.plaintext` appear only after the password response has been sent. | **rust-core.** Record that TLS was seen. On every successful VeNCrypt X509 connect, `known_vnc_certs` gets a host-only marker line `\|2\|<salt>\|<hmac> tls-required - <RFC 3339>`, written by the Tauri layer (the single writer, which keeps the R2 contract), for example from a new `SessionAudit::TlsSeen` that the Gate turns into `KnownCerts::mark_tls`. `SecPolicy.pinned` becomes "pin **or** marker". The marker carries no fingerprint, so a CA reissue never trips it. `known_certs_remove` deletes the marker too. Tests: a CA-valid connect → marker written → stripped VeNCrypt → `trust_mismatch` "TLS EXPECTED", with no DES response sent (the testsrv records whether one arrived) |
| **M-14** | Medium | `ironrdp-svc` 0.10.0 `lib.rs:373-445` (`dechunkify`: `chunked_pdu.extend_from_slice` up to the declared `u32` length); `ironrdp-dvc` 0.10.0 `complete_data.rs:32-41` (`DataFirst.length`); `ironrdp-session` 0.13.0 `fast_path.rs:964-1010` (`Fragmentation::Next` appends without a limit); our caps apply only afterwards (`crates/mooring-proto-rdp/src/clipboard.rs`, 1 MiB / 4 MiB raw) | A hostile server can stream fragments into memory with no limit: static channels (`drdynvc` is always joined, and `cliprdr` is joined unless the policy is off), DVC `DataFirst` and fast-path updates. Each reassembly is bounded only by a server-declared `u32` (4 GiB), or not at all for fast-path. Memory grows until allocation fails, and that again **aborts the process**. It costs the server bandwidth, not cleverness. Our cliprdr cap is correct but sits behind the reassembly. Also, `ironrdp-graphics` RLE accepts 8192 × 8192 per bitmap, so a few bytes of PDU cost a 192 MiB zeroed allocation (bounded, but a 10⁷× amplification). | **rust-core.** 1. Upstream: a `max_reassembly` limit in `ironrdp-svc` (`dechunkify`), in `ironrdp-dvc` `CompleteData`, and the negotiated `MultifragMaxRequestSize` in the fast-path assembler. File it with the `scard` PR (R-RDP-FFI). 2. Until it is released, the active stage tracks the reassembly itself. Before `ActiveStage::process`, decode the X.224 → MCS `SendDataIndication` → `ChannelPduHeader`, refuse `length > 8 MiB` on `FLAG_FIRST` for any channel, and count the bytes since `FLAG_FIRST`. For fast-path, count `First`/`Next` bytes per update code and refuse more than 8 MiB. Either refusal is `protocol_error`. 3. QA: a testsrv knob `--svc-flood` (FLAG_FIRST with a declared 4 GiB, then 32 MiB of chunks) → `protocol_error`, with RSS bounded. Gate: before the A2 tag |
| **M-15** | Medium | `crates/mooring-proto-vnc/Cargo.toml:29` (`flate2` `rust_backend`); `winscard` 0.4.0 `Cargo.toml:114-117` (`flate2` `features = ["zlib"]`, non-wasm); `flate2` 1.1.10 `src/ffi/mod.rs:63-77` (`any_c_zlib` wins over `miniz_oxide`); used by `crates/mooring-proto-vnc/src/decode/mod.rs:193` (`inflate`) | In the app build, the R-RDP-FFI tree turns on `flate2/zlib`, and flate2 then selects **C zlib (`libz-sys`) for every user in the build**. VNC's ZRLE and Tight streams, which are hostile T4 bytes after any security type (including None and VNC auth, so also a T3 under `prefer_tls`), are therefore inflated in C. `libz-sys` links the system `libz` on Linux and macOS when pkg-config finds it, and builds a bundled copy otherwise. That contradicts ADR-0012 ("`flate2` with the `miniz_oxide` Rust backend") and the R-RDP-FFI acceptance, which was granted because "none of those code paths is reached". A `cargo test -p mooring-proto-vnc` run on its own uses miniz_oxide, so the tests do not exercise what ships. **Ruling:** not acceptable as is. Feature flags cannot "force" `rust_backend`, because features are additive. | **rust-core.** Make VNC independent of flate2's backend choice. Depend on `miniz_oxide` (0.8, already in the tree, `forbid(unsafe)`) directly, and implement `inflate` with `miniz_oxide::inflate::stream::{InflateState, inflate}` (persistent state per stream, `MZFlush::Sync`, the same output cap). Drop `flate2` from `mooring-proto-vnc`. Test: the existing ZRLE/Tight/bomb vectors pass unchanged, plus a `cargo tree -p mooring-app -i flate2` CI check that `mooring-proto-vnc` is not among its dependents. Upstream `scard`-optional (owner decision 2) then removes `libz-sys` from the app entirely |
| L-20 | Low | `crates/mooring-proto-vnc/src/connect.rs:60-66` | An unreadable `known_vnc_certs` (permissions, an I/O error) is **treated as empty**. Every pin, and with it the downgrade guard, is ignored: a pinned host gets a TOFU prompt instead of a hard stop, and `prefer_tls` may fall back to plaintext. RDP fails closed in the same case (`mooring-proto-rdp/src/connect.rs:158-180`). | Fail closed as RDP does: `Closed { protocol_error, "the certificate trust store could not be read" }`. Test with a directory in place of the file |
| L-21 | Low | `crates/mooring-proto-rdp/src/session.rs:166-181`, `crates/mooring-proto-vnc/src/session.rs` (`next_event`: `let _ = task.await`); `src-tauri/src/session_task.rs:149-156` | A panic in a driver task (IronRDP or our decoder) is isolated, because the work runs in its own `tokio::spawn` and the poisoned `FrameSink` mutex is recovered. But the dropped sender surfaces as `Ok(None)`, which becomes `ServerEnded`, which is **retryable**. A deterministic panic is therefore replayed for six attempts. It is not audited or logged as a panic either. ADR-0011 asked for `JoinError` → `protocol_error`. | In both `next_event`s, when the channel closes without `Closed`, inspect `task.await`. On `Err(e) if e.is_panic()`, emit `Closed { protocol_error, "internal error in the RDP/VNC decoder" }` and `tracing::error!` (no payload). Test: a factory whose session's driver panics → one `closed { protocol_error }`, no `reconnecting` |
| L-22 | Low | `src-tauri/src/commands/conn_options.rs:98-113` | `connection_options_set` is not audited (R2 left this to us). **Ruling: it must be.** Several options weaken trust silently and persistently: `caPem` (a T5-supplied CA makes its MITM certificate `AcceptCa`, with no prompt and no `cert_decision`), `allowTlsWithoutNla`, `security: allow_plaintext`, the `clipboard` policy, `viewOnly`, and the web `url`/`allowedOrigins`/`allowHttp`/`persistent` (ADR-0013 owner decision 7 already says "audited when enabled"). The per-connect `session_weak_security` / `cert_ca_valid` entries do not show *who changed what, when*. | New `AuditEvent::ConnectionOptionsChanged { connection, protocol, changed: Vec<&'static str> }` (field **names** only, plus `caPem` as the SHA-256 fingerprints of its certificates). Syslog severity is warning when a change weakens security (`caPem` added or changed, `allowTlsWithoutNla` → true, `security` → `allow_plaintext`, `allowHttp` → true, `persistent` → true). Test: each weakening field → one entry with the right `changed` list; an unchanged re-save → no entry |
| L-23 | Low | `src-tauri/src/clipboard.rs:52-62` (`clear_image_if_unchanged`), `:227-236` (`current_image` → `arboard::get_image`); `arboard` 3.7.0 `platform/osx.rs:237` (TIFF), `linux/x11.rs:1052` (PNG), `linux/wayland.rs:196` (guessed format), `windows.rs:38-40` (PNG/BMP) | On every lock after a screenshot, Mooring **decodes whatever image is on the OS clipboard**, which any same-user process (T2) can set: PNG on Linux and Windows, BMP on Windows, TIFF on macOS. The `tiff` crate pulls in `zune-jpeg` for JPEG-in-TIFF, the SIMD-`unsafe` decoder that owner decision 5 kept out of VNC. `image` 0.25 also runs `moxcms` (ICC profiles; 356 `unsafe` sites) and `pxfm` (225, SIMD math). A memory-safety bug in that stack becomes code execution **inside the process that holds the DEK**, which is more than a T2 otherwise gets on macOS under the hardened runtime. | **Ruling on `image` / `moxcms` / `pxfm`: accepted for encoding our own RGBA only** (PNG on Linux, through arboard). Never decode foreign clipboard data. Replace `current_image` in the lock path: clear when `current()` (text) is `None` and `screenshot_clipboard` is `Some`. That accepts clearing an image the user copied after the screenshot, which is the fail-safe direction. Remove `current_image` from the trait. Test: the lock path never calls `get_image` (a `MemoryClipboard` counter). Revisit (A3) whether `arboard` can be replaced by the `png` crate + a native set per OS |
| L-24 | Low | `src-tauri/src/lib.rs:185` (`EnvFilter::try_from_env("MOORING_LOG")`); `ironrdp-connector` 0.12.0 `src/credssp.rs:184`, `:191`, `:228` (`debug!(message = ?ts_request…)`) | With `MOORING_LOG=debug`, which users are asked for when they report bugs, IronRDP logs every CredSSP `TsRequest`, including the NTLM AUTHENTICATE message. That is the NetNTLMv2 response, offline-crackable material for the user's domain password, written to stderr and to any log file. | Always append `ironrdp_connector::credssp=info,sspi=info` (and `ironrdp_connector::connection=info`) **after** the user's `MOORING_LOG` directives, so a broader `debug` cannot lower them. Document this in the logging section of the user guide. Test: an `EnvFilter` built from `"debug"` reports `ironrdp_connector::credssp` as disabled at debug |
| L-25 | Low | `crates/mooring-proto-rdp/src/active_clip.rs:150-165` (proactive fetch → `write_text`); `crates/mooring-proto-vnc/src/driver.rs:208-210`; `src-tauri/src/state.rs:290-296` | R-CLIP, made concrete. 1. Remote → local is proactive and also runs **while the vault is locked** and the tab is in the background. The lock clears the last remote value once, and the server can write again right after (pastejacking into a local terminal behind a locked UI). 2. `ClipboardOffer` pushes **whatever** is on the OS clipboard, including a vault secret placed there by `credential_copy`. The `session_clipboard { to_remote, bytes }` entry does not say that it was a vault secret, and a T5 can trigger the offer on any open session. | 1. Suppress remote → local writes while the vault is locked: `SessionClipboard::write_text` returns `false` when `!ready.unlocked()`. Count the drops in the session audit. 2. When the offered text's digest equals `pending_clipboard` (a Mooring-copied secret), add `credential_sent_to_remote { credential, connection }` to the audit (warning). Tests for both |
| L-26 | Low | `src-tauri/src/commands/session_graphics.rs:34-48`, `:69-94` | `session_screenshot` and `session_set_view_only` work **while the vault is locked**. R2's handoff says graphical-session commands need an unlocked vault, but only `session_open` and the store-backed commands check. A screenshot taken behind the lock screen re-populates the clipboard right after the lock cleared it. The view-only toggle is **not audited**, although ADR-0012 §IPC says `audited session.view_only`. | `screenshot` and `set_view_only` call `state.with_ready(\|_, _\| Ok(()))?` first. `frame_ack` and `attach` stay lock-agnostic (the UI acks frames while locked and re-attaches after unlock). New `AuditEvent::SessionViewOnly { connection, view_only }`. Tests: locked → `vault.locked` for both; toggle → one audit entry |
| L-27 | Low | `crates/mooring-proto-vnc/src/security.rs:141-142` | `_ if has(SEC_NONE) => Ok(SecChoice::None)` also applies when the connection has a `vnc_password`. A MITM that offers only None (type 1) gets a silent, unauthenticated session to *its own* desktop, for example a fake login screen. ADR-0012: "None (1): only when the connection's credential is `none`". | Match `CredKind::None if has(SEC_NONE)` only. A password credential with only None offered → `Unsupported("the server offers no authentication although a password is configured")`. Extend the selection-matrix test |
| L-28 | Low | `fuzz/fuzz_targets/`, `.github/workflows/fuzz-nightly.yml:34-49` vs ADR-0011/0012 §Test plan | These fuzz targets are owed: `rfb_handshake` (version, security list, reason, `ServerInit`) and `vencrypt_negotiation`, which are **pre-TLS and reachable by a T3**; `cut_text` (Latin-1); `framebuffer_ops`; the RDP reactivation path (B-5); and the pinned upstream IronRDP targets (`pdu_decoding`, `rle_decompression`, `bitmap_stream`, `cliprdr_format`, `channel_processing`). The entry points exist (R4 handoff), only the targets are missing. Nightly has never run on a nightly toolchain (integration handoff). | **qa-engineer.** Add the targets and seeds, plus `-malloc_limit_mb=1024` for the RDP and VNC targets (it catches B-5/M-14-class allocations below the RSS limit). The first green nightly run is the evidence. Before the A2 tag |
| N-23 | Nit | `crates/mooring-proto-rdp/src/tls_tests.rs:156-163`; `crates/mooring-proto-vnc/src/tls_tests.rs` | The RDP "pin does not bypass the signature check" test asserts only `!err.is_empty()`. It is sound (it differs from the passing test only in the key), but it would also pass on an unrelated failure. VNC has no such test. | Assert that the error is a signature failure (`InvalidCertificate(BadSignature)` / "invalid peer signature"), and add the same loopback test to VNC |
| N-24 | Nit | `crates/mooring-proto-rdp/src/tls.rs:88-105` | `chain_problems` reports only the first webpki error. An unknown-issuer certificate for the wrong name shows `unknown_issuer` only. VNC computes `name_mismatch` separately (R4 decision 10). | Use the VNC approach in RDP too (`verify_server_name` on the leaf) |
| N-25 | Nit | `crates/mooring-proto-rdp/src/connect.rs:252-253` | Pinned certificate + bad handshake signature (an active attacker who holds the certificate but not the key) → `CloseCode::Network`, which is retried 6 times. | Map it to `TrustMismatch` (or `ProtocolError`), never retried, and audit it as `CertMismatch` with `presented = "signature"` |
| N-26 | Nit | `src-tauri/src/commands/sessions.rs:258-260` | Only `session_open` checks `webview.label() == "main"`. The A2 commands that a remote window must never reach (`session_send`, `session_screenshot`, `known_certs_remove`, `connection_options_set`, `session_attach`) do not. No remote window exists yet (R5), so the capability is the real control. | R5 condition: the remote-window capability grants **no** app command (Tauri `remote` ACL test), and a shared `require_main(&webview)` guard covers every session, trust and options command |
| N-27 | Nit | `src-tauri/src/commands/known_certs.rs:34-53` | `known_certs_remove` + an IPC `yes` lets a T5 replace a pin and **override a `trust_mismatch`**. Both steps are audited (`cert_removed`, `cert_decision`). SSH has no remove command, so this is new, but it is the same class as N-17. | Accepted for A2 under R-T5-TOFU. A3: confirm the removal in a Rust-opened native message dialog that names the host |
| N-28 | Nit | `src-tauri/src/commands/sessions.rs:97-110`; `crates/mooring-proto-vnc/src/reader.rs:40`; `apps/desktop/src/lib/ipc.ts:10`, `:211` | (a) `MAX_SESSIONS` is checked before the graphical `await`, so concurrent opens can exceed it. (b) The worst-case memory of one hostile 8192² session is about 1 GiB (256 MiB framebuffer + up to 256 MiB receive buffer + an MFR1 message + the RDP `DecodedImage`). (c) `MockTransport` (synthetic frames, fake TOFU) ships in the production bundle; it is selected at runtime only outside Tauri. | (a) Re-check under the registry lock in `register`. (b) Documented here; no change. (c) Import the mock behind `import.meta.env.DEV` (dynamic import) so that production tree-shakes it |
| N-29 | Nit | `crates/mooring-proto-vnc/Cargo.toml:31` vs `crates/mooring-proto-rdp/Cargo.toml:43`; `crates/mooring-proto-vnc/src/security.rs:166-177` | `x509-parser` has `default-features = false` in RDP and the defaults in VNC. The DES key schedule (`Des`) and the 16-byte response are not zeroized. | Align on `default-features = false`. Enable `des/zeroize` (RustCrypto `ZeroizeOnDrop`) |

### Closure of carried-forward items touched by this range
| ID | Status | Evidence |
| --- | --- | --- |
| M-8 (polled commands) | **holds** | `session_frame_ack` and `web_list` are in `PASSIVE_COMMANDS` (`src-tauri/src/autolock.rs:58-61`) and `ipc-passive.json`. Acks cannot keep the vault open. `session_attach` and `session_screenshot` are user-initiated and correctly count as activity |
| N-14 (error codes) | **holds** | `ipc-codes.json` gained `ipc.forbidden`, `protocol.unavailable`, `session.trust_*` and `session.unsupported_security` |
| L-2 (trust dialog by purpose) | **partly closed** | The certificate dialog is chosen by `purpose: certificate_trust` (`PromptModal`), never by message text. SSH host-key prompts are unchanged |
| R-SSH-STR | unchanged | R-RDP-STR added (below) |
| A1 "A2: RDP certificate pinning UX" | **done (U1 minimal)** | The full TOFU dialog and the known-certs manager are U2 |

## Rulings on open decisions

### Trust
1. **Pin before CA, name check, signatures: approved.** `decide` gives `Trusted` → accept,
   whatever the chain; `Mismatch` → hard stop, whatever the chain; CA-valid → accept, no pin.
   The CA path uses `WebPkiServerVerifier`, so names are checked. RDP and VNC verify the
   TLS 1.2/1.3 signatures through ring. The RDP loopback test (`tls_tests.rs:156`) shows a
   pinned certificate without its key failing (see N-23). Resumption is disabled, so every
   connect runs the verifier.
2. **Single writer: confirmed.** A grep finds no `add_and_save`, `save(` or
   `CertAdded`/`CertRejected` in either protocol crate. The `Gate` intercepts the answer to
   the open certificate prompt id before it can reach the session
   (`graphical_task.rs:196-202`), writes the pin (`:169`) and audits `cert_decision` exactly
   once. The E2E test checks one pin and one audit entry per connect.
3. **`trusted_once`: approved.** It is set only when the pin cannot be written, used for the
   single reconnect right after the answer (`graphical_task.rs:293`), and added in memory only
   when no other pin exists for `host:port`, so it can never override a mismatch. Later
   reconnects pass `None` and prompt again, which fails safe.
4. **`known_certs` format and parser: approved.** HMAC-SHA256 with a random 32-byte salt per
   entry; 8 KiB per line and 10 000 lines; the file is read with `take(cap)`; a store over the
   caps refuses to save; written atomically through `NamedTempFile` (0600); a per-path mutex
   for read-modify-write; a fuzz target with its stable replay. The host key is lowercased with
   bracketed IPv6. See L-20 (VNC fails open on I/O errors) and M-13 (no TLS marker).
5. **VeNCrypt anonymous-TLS fallback under `prefer_tls` (R4 decision): approved.** It is never
   taken with a pin or with `require_tls`. A MITM could strip VeNCrypt anyway, so the fallback
   adds no attacker power. It is audited (`session.vnc.plaintext`) and badged.
   **Is the badge sufficient?** For a first connect without a pin it is, with the residual
   recorded under R-VNC-PLAIN, because the DES response has already been sent when the badge
   shows. For a host seen with TLS before it is **not**: that is M-13. U2 must also show
   "may fall back to unencrypted" in the connection form while `prefer_tls` is selected.
6. **VNC view-only as a Tauri-only switch (integration decision 2): approved.** Enforcement in
   one place, in Rust before the session, is what ADR-0012 asks for. `release_all` always
   passes. `VncControl` may stay unused. See L-26 for the missing audit.

### Credentials in flight
7. **R-RDP-STR: accepted** (like R-SSH-STR). The password becomes a plain `String` in
   `Credentials::UsernamePassword` only right before `connect_finalize`
   (`connect.rs:325-328`), and the connector is consumed by it. `sspi` holds it as its own
   zeroizing `Secret<String>`. The activation factory is rebuilt from the password-free config
   (`connect.rs:345-349`), and `creds` is dropped after NLA (`driver.rs:111`). IronRDP's
   `Credentials` derives a plaintext `Debug`, but neither IronRDP nor our code formats `Config`
   or `Credentials` (grepped). Conditions: no other plain-`String` secret API, upstream
   `Zeroizing` ask, and L-24.
8. **CredSSP/NTLM without Kerberos: approved.** `kerberos_config: None` gives NTLM, and
   `NoNetwork` refuses every network request. `sspi`'s `network_client`, `dns_resolver` and
   `tsssp` features are off, so `rustls`, `reqwest` and `hickory` are not compiled into sspi.
9. **VNC DES: approved.** RustCrypto `des`; the key is bit-reversed in `Zeroizing`; passwords
   over 8 bytes are refused, not truncated; the `X509Plain` message is `Zeroizing` and is sent
   only after the TLS upgrade. A FIPS vector and two `openssl` cross-checks exist. See N-29.
10. **Redaction: approved.** `SessionInput::Key`/`Unicode`/`Answer`/`CredentialAnswer` and
    `WireInput` are redacted in `Debug`. The only `?input` log line (VNC view-only drop) goes
    through that `Debug`. `Creds`, `Credential` and the verifiers print no secret. Every `tracing` call this range
    adds with a `%`/`?` argument was grepped (19 lines). Each `%e` is an error `Display`
    without a value, and each `?` is a close code, a discriminant or the redacted input.
    `Invalid` errors name the field only (tested with a typed-secret probe).

### Hostile input
11. **MFR1: approved.** Byte-exact on both sides. Unknown flags, a reserved byte that is not 0,
    rects outside the framebuffer, trailing bytes, kind-5/6 fields and cursors over 384² are
    all refused. The TS decoder bounds the loop by `n ≤ 256` and checks every length before it
    reads. Rust has proptests and a fuzz target with an `apply` oracle.
12. **Framebuffer bounds: approved.** `Rect::fits` works in `u32`, `blit` checks
    `stride·(h−1)+row` with `checked_*`, and `copy` checks both rects.
13. **ZRLE/Tight 64 MiB zlib cap: approved, not too generous.** The cap is an outer bound
    only. Tight inflates to its **exact** expected size, and ZRLE to `inflate_bound(w, h)`
    (≤ 64 MiB at 8192²). The dominant memory term is the 8192² framebuffer and the receive
    buffer (N-28 b), not the inflater. Rule: keep 64 MiB, and keep the exact-size limits as the
    real control.
14. **Cut text (1 MiB, the rest drained) and cliprdr (1 MiB after UTF-8, 4 MiB raw, 8 pending
    pastes, 64 queued): approved**, behind M-14 for IronRDP's reassembly.
15. **DesktopSize: VNC approved** (`parse_server_init` caps at 8192 before any allocation;
    ExtendedDesktopSize screens ≤ 16). **RDP: B-5.**
16. **Panic surface: isolated, not reported.** Each driver runs in its own task, and
    `FrameSink` recovers from poison. The mapping and audit are missing (L-21). Allocation
    failure is **not** a panic and is not isolated: B-5 and M-14.
17. **Fuzz coverage:** nine new targets, and every one asserts more than "no panic". Owed:
    L-28.

### IPC
18. **Input validation: approved.** `decode_input` → `SessionInput::validate` (key code 1–32
    ASCII alphanumerics, key ≤ 32 B, Unicode 1–64 chars, no controls); pointer < 8192 with
    known button bits; desktop 200–8192 with an even width; `deny_unknown_fields`.
19. **Credits and back-pressure: approved.** Acks are cumulative; forged and stale acks create
    no credit; at most 2 messages in flight; `attach` resets the credits and forces one full
    frame. Unbounded acks cost one mutex each and are passive. Size is not taken from the UI
    for allocation (the server's size is, see B-5).
20. **Screenshot and clipboard clear on lock: approved, with L-23 and L-26.** The remote text
    digest and the screenshot size are cleared on every lock path (`state.rs:290-296`, called
    from `vault::lock`).
21. **`connection_options_set` not audited: must be audited (L-22).**
22. **Options validation: approved.** `caPem` holds certificate blocks only (the B-3 rule
    through `fingerprint::x509_pem`); the closed KLID list; `maxFps ∈ {30, 60}`; a 128 KiB cap
    before parsing; serde errors without values; web `url` `https://` only (`http://` only with
    `allowHttp`), no userinfo, exact origins only, ≤ 16. RDP/VNC ports come from the existing
    connection validator.

### Clipboard
23. **Text only, both ways: confirmed.** RDP requests and announces only `CF_UNICODETEXT`/
    `CF_TEXT` and has no file-clip capability. VNC is Latin-1 `ServerCutText`/`ClientCutText`
    only, and text that cannot be encoded is refused, not replaced. The policy is enforced in
    the protocol crates, in Rust, from the stored options. The UI button is advisory.
24. **`image` crate tree (`image` 0.25.10, `moxcms` 0.8.1, `pxfm` 0.1.30, `tiff` on macOS, BMP
    on Windows): accepted for encoding our own RGBA only, on condition of L-23** (no decode of
    foreign clipboard content). Encoding only ever sees our framebuffer bytes. The
    "PNG with the `png` crate only" alternative is not reachable through arboard's API; it is
    an A3 candidate (own per-OS set with `png` 0.18, which is `forbid(unsafe)`).

### Dependencies
| Crate | Version | License | Reached from | Ruling |
| --- | --- | --- | --- | --- |
| `ironrdp-{connector, session, tokio (no default), graphics, pdu, cliprdr, displaycontrol, input, dvc, svc, core}` | 0.12 / 0.13 / 0.12 / 0.11 / 0.11 / 0.9 / 0.10 / 0.9 / 0.10 / 0.10 / 0.3 | MIT OR Apache-2.0 | mooring-proto-rdp → app | **Approved.** No `ironrdp` meta crate, no `ironrdp-tls`, rdpsnd, rdpdr, mstsgu or EGFX. M-14 upstream |
| `sspi` + R-RDP-FFI (`winscard` 0.4.0, `cryptoki` 0.12.1 + `libloading` 0.8.9, `async-dnssd` 0.5.1 macOS, `libz-sys` 1.1.31) | 0.23.0 | MIT OR Apache-2.0 (libz: Zlib) | ironrdp-connector | **Owner-accepted (decision 2). Not executed:** `winscard`, `cryptoki`/`libloading` (smart-card credentials are never built: `creds.rs` maps only password kinds) and `async-dnssd` (Kerberos/KDC discovery off). **Executed: `libz-sys`, through flate2 unification (M-15).** |
| `tokio-rustls` (`ring`, `tls12`, `logging`) | 0.26.6 | MIT/Apache-2.0/ISC | rdp, vnc | **Approved.** rustls project, no `unsafe` |
| `x509-parser` (+ `asn1-rs` 0.7, `der-parser` 10) | 0.18.1 | MIT OR Apache-2.0 | rdp, vnc (now runtime) | **Approved.** `forbid(unsafe_code)` in all three (rusticata, maintained); parses only the TLS leaf after rustls has accepted the DER. Features: N-29 |
| `socket2` | 0.6 | MIT OR Apache-2.0 | rdp | Approved (already in the tree via tokio) |
| `des` | 0.9 | MIT OR Apache-2.0 | vnc | Approved (RustCrypto) |
| `flate2` (`rust_backend`) | 1.1.10 | MIT OR Apache-2.0 | vnc | **Superseded by M-15:** replace it with `miniz_oxide` directly |
| `arboard` `image-data` (+ `image` 0.25.10, `moxcms` 0.8.1, `pxfm` 0.1.30; macOS `tiff` 0.11.3, `weezl`, `fax`, `half`, `zune-jpeg`, `zune-core`; `byteorder-lite`, `quick-error`, `crunchy`) | 3.7.0 | MIT OR Apache-2.0, BSD-3-Clause OR Apache-2.0, MIT, Zlib | app | **Approved for encoding only, condition L-23** |
| `mooring-testsrv` tree (`ironrdp-acceptor` 0.12, `rcgen`, …) | — | MIT OR Apache-2.0 | dev only | **Approved.** A dev-dependency of the app, not in a release build |
| `aws-lc-rs` / `aws-lc-sys` | — | — | Cargo.lock edges only | **Banned** in `deny.toml`; `cargo deny check` bans ok. `sspi`'s default `aws-lc-rs` feature is the weak `rustls?/aws-lc-rs`, and sspi's `rustls` dependency is not enabled, so nothing is built |

### UI
25. **WebGL canvas input capture: nothing new beyond T5.** Keys go through a hidden textarea
    and become `key`/`unicode` IPC calls. A T5 could read them, as it can read xterm input
    today. There is no `console.*`, no storage, no `innerHTML` and no paste handler in
    `components/remote`. The clipboard never touches the WebView.
26. **MFR1 strictness: approved** (ruling 11); undecodable messages are still acked.
27. **Mock-only paths:** selected only when `__TAURI_INTERNALS__` is absent; shipped in the
    bundle (N-28 c).

## Conditions for merge
1. **B-5 fixed with its tests.** Re-review only that diff.
2. M-13, M-14 (at least the interim guard) and M-15 before the A2 tag.
3. L-20..L-28 before the A2 tag (L-28: one green nightly run). Nits as scheduled.
4. `security.yml` green (cargo-deny, cargo-audit, gitleaks, semgrep), and `mooring-app` built
   and tested on macOS, Windows and Linux. None of these was run here, except `cargo deny`.

## Test evidence
```
Linux x86_64, 2026-11-04, CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/home/claude/nexus/target
git log --oneline -1                     f85a319 docs(handoff): a2 wave-2 integration notes and test evidence
cargo test -p mooring-proto-rdp -p mooring-proto-vnc -p mooring-core       EXIT 0
  mooring-core       lib 114 passed; fuzz_corpus 9 passed
  mooring-proto-rdp  lib 52 passed; fuzz_corpus 5; loopback 7; lab 1 ignored
  mooring-proto-vnc  lib 68 passed; fuzz_corpus 4
cargo deny check                          advisories ok, bans ok, licenses ok, sources ok
cargo tree -p mooring-app -i libz-sys     <- flate2 <- winscard <- sspi <- ironrdp-connector (normal)
cargo tree -p mooring-app -e features -i flate2   features: zlib, any_c_zlib, rust_backend (C wins)
cargo tree -p mooring-app -i pxfm         <- moxcms <- image <- arboard (image-data)
grep add_and_save|CertAdded|CertRejected crates/mooring-proto-{rdp,vnc}/src (non-test)   none
grep DecodedImage::new crates/mooring-proto-rdp/src/active.rs   :156, :169 (before any size check)
CSP (tauri.conf.json) and capabilities/   unchanged in the range
```
Not run: cargo-audit (advisory DB fetch failed), cargo-geiger, gitleaks, semgrep, pnpm audit,
cargo-fuzz, the `mooring-app` suite, vitest/E2E, and the macOS and Windows builds.
