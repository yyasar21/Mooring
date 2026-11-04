# A2 — rust-core: wave-2 integration (R1–R4 + Q2 + U1)

Branch `a2`, from 8504553 (R2 merge). Single writer, no worktree. Seven commits:

| Commit | What |
| --- | --- |
| `b4f3425` refactor(core) | One `Clipboard` trait and `AuditBuffer` in core; no pin writes in the protocol crates; `trusted_once` |
| `09a75d2` feat(app) | `BuiltinFactory` builds the real `RdpSession` / `VncSession` |
| `1bf001a` test(rdp,vnc,app) | Loopback tests against `mooring-testsrv`, plus the A2 `e2e_flow` |
| `94e0bc9` test(fuzz) | Real A2 fuzz targets, stable corpus replay, nightly matrix |
| `755e076` feat(app) | `session_screenshot` puts the image on the OS clipboard (arboard `image-data`); cleared on lock |
| `c6ecde3` build(deny) | `aws-lc-rs` and `aws-lc-sys` banned |
| `ccc524c` test(app) | Syslog heartbeat test made deterministic |

## Done

### 1. Shared clipboard trait and audit buffer
- `mooring_core::clipboard::{Clipboard, NoClipboard}` holds `read_text() -> Option<String>` and `write_text(&str) -> bool`. `mooring_proto_rdp::LocalClipboard` and `mooring_proto_vnc::{Clipboard, NoClipboard}` are re-exports of it. RDP ignores the `bool`.
- `mooring_core::AuditBuffer` is shared, capped at `MAX_AUDIT = 4096` and drained with `take()`. `mooring_proto_rdp::AuditSink` and `mooring_proto_vnc::AuditLog` are type aliases of it. The two old types had the same shape; R3's version had no cap. The constructors did not change.
- **R2 trust contract:** both protocol crates used to write `known_*_certs` and audit `CertAdded` / `CertRejected` themselves. That code is removed. The Tauri layer (`graphical_task::Gate`) is now the only place that writes pins and audits `cert_decision`.
  - In the app, the prompt answer never reaches the session anyway.
  - When a crate is used on its own and receives `yes`, it trusts the leaf in memory for its reconnect only.
  - The `CertMismatch` and `CertCaValid` audits stay in the crates.
  - `RdpOptions.trusted_once` and `VncOptions.trusted_once` (`Option<[u8; 32]>`) work as an in-memory pin.

### 2. Factory
- `src-tauri/Cargo.toml` now depends on `mooring-proto-rdp` and `mooring-proto-vnc`.
- `connect_rdp` / `connect_vnc` pass the `known_certs` path, the `RdpConnOptions` / `VncConnOptions`, the `FrameSink`, `SessionClipboard` (an adapter over the tracked `RemoteClipboard`, so a lock still clears remote text) and `trusted_once`.
- The `protocol.unavailable` arms are gone. A `ProtocolOptions` that does not match the protocol returns `input.invalid`.
- **VNC view-only:** the factory passes `VncConnOptions.view_only = false`. View-only is enforced once, in the Tauri gate, which starts from the stored option and is toggled by `session_set_view_only`. If the crate kept its own switch, started from the stored option, IPC could never turn it off: input would stay dropped after the user toggled view-only off.

### 3. Loopback tests
- **VNC:** `src/testsrv.rs` is deleted. `src/session_tests.rs` (12 tests) now runs against `mooring_testsrv::rfb`. It covers:
  - every encoder path, with the `FrameSink` pixel-equal to the server framebuffer;
  - cut text in both directions, QEMU extended keys and pointer clamping;
  - the TOFU flows, strip-after-pin, a changed certificate and `trusted_once`;
  - the anonymous-TLS fallback and the hostile knobs;
  - resize in both directions, X509Plain, VNC auth, and `require_tls`.
- **RDP:** `tests/loopback.rs` (7 tests) runs against `mooring_testsrv::rdp`. It covers:
  - NLA with TOFU `yes`, and a check that the crate wrote no pin;
  - bitmap updates (raw and planar) reaching the `FrameSink`;
  - key, pointer and unicode echo counters;
  - cliprdr text in both directions and the Display Control layout;
  - TOFU `no`, a changed certificate and a wrong password;
  - TLS-only: refused without the option, audited `RdpLegacySecurity` with it;
  - out-of-bounds tiles.

  The ignored placeholder in `tests/lab.rs` is removed.
- **`src-tauri/tests/e2e_flow/graphical.rs`:** RDP and VNC go through the IPC command functions with the real factory. Each test:
  - opens the session and answers the certificate prompt `yes`;
  - checks that the Tauri layer wrote the pin once and `cert_decision` was audited once;
  - receives a full MFR1 frame and acks it;
  - sends a key and a pointer event (both reach the server), resizes (the server records the layout or `SetDesktopSize`) and closes with `user`.

### 4. Fuzz
- The `r1` / `r3` / `r4` gates are removed. These four targets now fuzz real code:
  - `mfr1_decode`: record caps, determinism and `apply`.
  - `known_certs_parse`
  - `rfb_server_msg`: the new `mooring_proto_vnc::fuzz::server_messages`, which uses the reader's framing and `Decoders` and writes into a `FrameSink`.
  - `rdp_fastpath`: `mooring_proto_rdp::fuzz::active_stage`.
- New targets: `rdp_certificate_info`, `rdp_cliprdr_text`, `rdp_input`, `vnc_zrle` and `vnc_tight`. Each has seeds and an empty `regressions/` directory.
- Stable replay runs in `crates/{mooring-core,mooring-proto-rdp,mooring-proto-vnc}/tests/fuzz_corpus.rs`, including checks that the key seeds still reach the accepting paths.
- `fuzz-nightly.yml`: the five new targets are in the matrix, and the "Stub notice" warning step is removed. The "A2 targets" section of `docs/qa/fuzzing.md` is rewritten.
- `fuzz/Cargo.lock` gained 136 packages, all at root-lockfile versions. None were removed or re-versioned.

### 5. Screenshot
- arboard is built with `image-data`. `SystemClipboard::set_image` checks the size, then sets the image with clipboard history excluded, as it already does for text.
- `AppState::screenshot_clipboard` remembers the image size. `vault_lock` and exit clear the clipboard if it still holds an image of that size and no text.

### 6. Lockfile and deny
- `cargo metadata --locked` passes.
- `cargo deny check` passes: advisories, bans, licenses and sources are all ok. The only warnings are for duplicate versions.
- `aws-lc-rs` and `aws-lc-sys` are added to `[bans].deny`. `cargo tree --workspace --all-features --target all -e all -i aws-lc-sys` (and the same for `-rs`) prints nothing.

### 7. Flaky test
`heartbeats_are_written_only_while_the_mirror_runs` now stops after exactly two heartbeats, signalled from the callback, instead of counting inside a wall-clock window.

## Left open
- **RDP TLS-only servers that drop the connection.** QA's acceptor closes TCP instead of sending `RDP_NEG_FAILURE` when the client offers only NLA. The client then ends with `network`, which is retryable, so the Tauri loop would try 6 times. A Windows host sends `RDP_NEG_FAILURE` and gets `protocol_error`. The test accepts both codes.
- **Fuzz targets were not built with nightly.** `fuzz/` passes `cargo check --bins` on stable. No nightly toolchain or cargo-fuzz build was available here, so the first nightly run is the proof.
- **Screenshot clear compares the size only.** The OS may convert the pixels (BMP, TIFF or PNG), so the bytes are not compared. If the user copies another image of exactly the same size before locking, that image is cleared too. `SystemClipboard::set_image` and `current_image` were not exercised against a real display. CI and this container have no X or Wayland server; the flow is tested with `MemoryClipboard`.
- **`VncControl` is unused by the app** (see factory, view-only). `dropped_inputs` therefore counts nothing in the app, and the Tauri gate does not count drops.
- **Commit boundary.** Commit 1 holds both the trait unification and the crate-side trust de-duplication: the two touch the same option structs. Commit 2 holds the factory wiring.
- **Ownership.** Some files changed here are QA-owned: `crates/*/tests/{loopback,fuzz_corpus}.rs`, `fuzz/**`, `fuzz-nightly.yml` and `docs/qa/fuzzing.md`. The brief asked for these changes, so QA should re-review them.
- `protocol.unavailable` stays in `ipc-codes.json` and `close_code_of`, but no code path produces it any more.
- These items from R2/R3/R4 are still open:
  - the RDP auto-reconnect cookie;
  - the slow-path input fallback;
  - `connection_options_set` is not audited;
  - pointer coalescing.

## Decision needed
1. **security-reviewer: new runtime dependencies in the app build.**
   - `image` 0.25.10 (MIT OR Apache-2.0).
   - `moxcms` 0.8.1 and `pxfm` 0.1.30 (BSD-3-Clause OR Apache-2.0). `pxfm` uses `unsafe` for SIMD math.
   - macOS only: `tiff` 0.11.3 (MIT), with `weezl`, `fax`, `half`, `zune-jpeg` and `zune-core`.
   - Also `byteorder-lite`, `quick-error` and `crunchy`.
   - Platform crates: `objc2-core-graphics` on macOS; `windows-sys` `Win32_Graphics_Gdi` on Windows.
   - From the protocol crates, now in the app: `tokio-rustls` 0.26 (ring), `x509-parser` 0.18 as a runtime dependency, the IronRDP set, and the R-RDP-FFI tree (`libz-sys` via `sspi/scard` → `winscard` → `flate2`, `cryptoki` / `libloading`, `async-dnssd`).
   - Note: with feature unification, `flate2` in the app build links C zlib through `libz-sys`.
2. **Architect:** should VNC view-only stay a Tauri-only switch? The alternative is to share one `Arc<AtomicBool>` between the gate and `VncControl` through `GraphicalConnect`.

## Test evidence
- `cargo fmt --all --check`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean. The only output is the existing `unknown lint clippy::unused_async_trait_impl` toolchain note.
- `cargo test --workspace`: **770 passed, 0 failed, 6 ignored**, identical on 3 runs. Per binary:

  | Crate | Results |
  | --- | --- |
  | mooring-app | lib 154 (+1 ignored `frame_bench`), e2e_flow 15 (2 new) |
  | mooring-core | 114, fuzz_corpus 9 |
  | mooring-proto-rdp | lib 52, loopback 7, fuzz_corpus 5 (lab and doc test ignored) |
  | mooring-proto-vnc | lib 68, fuzz_corpus 4 |
  | mooring-proto-ssh | 61 + 59 integration |
  | mooring-testsrv | 53 |
  | mooring-store | 25 + 50 |
  | mooring-vault | 52 + 18 (2 ignored) |
  | mooring-audit | 30 |

- The RDP loopback tests passed 3 times in a row, and the VNC lib tests 3 times in a row. The heartbeat test passed 3 times on its own and in all 3 workspace runs.
- `pnpm install --frozen-lockfile`, `pnpm lint`, `pnpm typecheck` and `pnpm build`: green.
- `pnpm test`: **33 files, 242 passed, 0 skipped.**
- `NODE_PATH=/opt/node-tools/node_modules node --test --test-concurrency=1 apps/desktop/e2e/flows.e2e.mjs`: **5 passed, 0 failed.**
- `cargo metadata --locked`: ok. `cargo deny check`: ok.
- `cd fuzz && cargo check --bins`: ok on stable.

## Fix round 6 (rust-core, review 5)

Branch `worktree-agent-abad2b984b727cb76`, base `a2` @ c5565c6, `a2` (U2, R5, U3) merged in
at the end (conflicts were additive; `AuditEvent` moved to `mooring-audit/src/event.rs` to keep
`chain.rs` under 500 lines). One commit per finding, Claude-Session trailer, no
Co-Authored-By.

### Done

| ID | Status | What |
| --- | --- | --- |
| B-5 | fixed | `active::check_desktop` (1..=8192 per side) before `Connected` and in `Active::new` / `resized`; `sink.resize` before `DecodedImage::new`. Tests: guard unit test, testsrv `advertised_desktop` 65535² → `protocol_error` before `Connected`, peak RSS < 512 MiB |
| M-13 | fixed | `known_vnc_certs` marker `\|2\|salt\|hmac tls-required - <RFC 3339>` (`KnownCerts::mark_tls`, `tls_expected`; removed by `known_certs_remove`). The Gate writes it on `Connected { security: vencrypt-x509 }` (single writer). `SecPolicy.pinned` = pin or marker. Test: CA-issued cert → marker → stripped VeNCrypt → `trust_mismatch`, `expected tls-required`, no security type chosen (no DES) |
| M-14 | fixed (interim) | `mooring-proto-rdp/src/reassembly.rs` before `ActiveStage::process`: SVC `FLAG_FIRST` declaring > 8 MiB or > 8 MiB of chunks, drdynvc `DataFirst(Compressed)` > 8 MiB (IronRDP's `CompleteData` refuses blocks past the declared total), fast-path fragment runs > 8 MiB → `protocol_error`. Testsrv knob `svc_flood`; fuzz target `rdp_reassembly` |
| M-15 | fixed | VNC inflates with `miniz_oxide` 0.9 directly (`decode::ZStream`); `flate2` is a dev-dependency only. `cargo tree -p mooring-app -e features -i libz-sys` has no path from `mooring-proto-vnc` |
| L-20 | fixed | unreadable `known_vnc_certs` → `protocol_error` "the certificate trust store could not be read" before any byte (as RDP); audited by `session_closed` |
| L-21 | fixed | `mooring_core::driver_task::next_driver_event`: a driver that ends without `Closed` (panic) → `Closed { protocol_error, "internal error in the RDP/VNC decoder" }`, not retried, `tracing::error!` without payload. Before, a panic left `next_event` hanging (the session holds an event sender) |
| L-22 | fixed | `connection_options_changed { connection, protocol, changed, ca_pem, weakened }`: field names only, SHA-256 of each new `caPem` certificate, `weakened` → syslog warning; unchanged re-save → no entry |
| L-23 | fixed | lock clears the screenshot when the clipboard holds no text, without reading the image; `current_image` removed from the trait |
| L-24 | fixed | `log_filter`: user directives for `ironrdp_connector::credssp`, `ironrdp_connector::connection`, `sspi` are dropped and `=info` appended (separate block in `lib.rs`). User guide note still owed (docs) |
| L-25 | fixed | `RemoteGuard` on the session clipboard: remote writes refused while locked (`session_clipboard_blocked`, once per locked period), no offer while locked, `session_clipboard_offer { bytes }` per offer, `credential_sent_to_remote { credential }` (warning) when the offer is the `credential_copy_*` secret |
| L-26 | fixed | `session_screenshot` / `session_set_view_only` → `vault.locked` first; `session_view_only { view_only }` audited |
| L-27 | fixed | password credential + None-only offer → `unsupported_security` unless VNC option `allowNoAuth` (default false); taking it is audited `session_weak_security` `none_with_password` |
| L-28 | partial | new targets `rfb_handshake`, `vencrypt_negotiation`, `rdp_reassembly` with seeds and stable replay; nightly matrix + `-malloc_limit_mb=1024` for `rdp_/rfb_/vnc_/vencrypt_` targets. **Open (QA):** `cut_text`, `framebuffer_ops`, `rdp_reactivation`, the pinned upstream IronRDP targets, first green nightly run |
| N-23 | fixed | RDP test asserts a signature failure (not unknown issuer); same loopback test added to VNC |
| N-24 | fixed | RDP verifier adds `NameMismatch` via `verify_server_name` next to webpki's first error |
| N-25 | fixed | pinned cert + `BadSignature` → `trust_mismatch`, audited mismatch `presented = signature` |
| N-26 | open | `require_main` for session/trust/options commands: R5 owns the guard (merged `guard/`); not touched here |
| N-27 | accepted | A3 item, no change |
| N-28 | partial | (a) cap re-checked under the registry lock; (b) no change; (c) UI mock import → ui-engineer |
| N-29 | fixed | `des/zeroize`, `vnc_auth_response` → `Zeroizing<[u8; 16]>`, VNC `x509-parser` `default-features = false` |

Coordinator additions:
- **U2 `once`**: a `certificate_trust` answer `yes` pins, `once` trusts for the next connect
  only (`trusted_once`, no pin, audited `cert_decision` with decision `trusted_once`),
  anything else rejects.
- **U2 named pins**: `known_certs_list` entries gain optional `host` / `port` when a pin
  matches one of the user's own connections of that protocol (Rust-side join; default ports
  3389 / 5900). Hash-only otherwise. The UI may drop its local HMAC.
- **U3**: `session_attach` ignores `onFrame` for SSH; a detached view re-attaching to its own
  session sends `detached` to its previous channel only.

New IPC-visible shapes for ui-engineer: VNC option `allowNoAuth` (bool, default false);
`KnownCert.host?` / `port?`; audit events `connection_options_changed`, `session_view_only`,
`session_clipboard_offer`, `session_clipboard_blocked`, `credential_sent_to_remote`. No new
`IpcError` codes (`ipc-codes.json` unchanged).

Testsrv knobs for QA: RDP `advertised_desktop` (`--desktop WxH`), `svc_flood`
(`--svc-flood`); `TestCert::generate_ca_issued(names) -> (leaf, ca_pem)`. QA-owned files
touched minimally: `crates/mooring-proto-vnc/tests/fuzz_corpus.rs` (ZStream, new replays),
`crates/mooring-proto-rdp/tests/fuzz_corpus.rs`, `fuzz/**`, `fuzz-nightly.yml`.

Upstream issue text (M-14, file with the `scard` PR, R-RDP-FFI):
> ironrdp-svc `dechunkify`, ironrdp-dvc `CompleteData` and the ironrdp-session fast-path
> assembler grow their buffers up to a server-declared `u32` (or, for fast-path, without
> any limit) before any consumer sees the data. A hostile server can stream fragments until
> allocation fails, which aborts the client process. Please add a configurable
> `max_reassembly` to `StaticVirtualChannel` / `dechunkify`, to `CompleteData`
> (`DataFirst.length`), and bound the fast-path assembler by the negotiated
> `MultifragMaxRequestSize`, returning an error instead of growing.

### Left open
- L-28 remainder (above), N-26 (R5 guard), N-28 (c) (UI).
- `russh` still links C zlib through flate2 unification for SSH compression (same class as
  M-15, SSH side): security-reviewer to rule.
- The B-5 abort is not observable on this host (heuristic overcommit let the 17 GiB
  `calloc` succeed); the test discriminates by `Connected` ordering and peak RSS instead.

### Decision needed
- Disk: the 3.8 GB free on this host could not hold a fresh per-worktree target; the round
  built in the shared `/home/claude/nexus/target` (and deleted its stale test executables
  older than 30 min, ~12 GB, which cargo relinks on demand).

### Test evidence
```
Linux x86_64, CARGO_INCREMENTAL=0, CARGO_TARGET_DIR=/home/claude/nexus/target, after the a2 merge
cargo fmt --all --check                                         ok
cargo clippy --workspace --all-targets -- -D warnings            ok
cargo test --workspace                                           842 passed, 0 failed, 6 ignored
  mooring-app lib 201 (+1 ignored), e2e_flow 15 · mooring-core 119, fuzz_corpus 9
  mooring-proto-rdp lib 62, loopback 7, fuzz_corpus 6 · mooring-proto-vnc lib 74, fuzz_corpus 7
  mooring-audit 30 · mooring-testsrv 9 + 44 · ssh, store, vault unchanged
cargo check --manifest-path fuzz/Cargo.toml (3 new bins)         ok
cargo tree -p mooring-app -e features -i libz-sys | grep mooring-proto-vnc   (none)
```
