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
