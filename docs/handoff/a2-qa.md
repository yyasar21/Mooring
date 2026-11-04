# A2 — qa-engineer (Q2: test infrastructure)

Scope: ADR-0011 §Test plan + task row Q2, ADR-0012 §Test plan, ADR-0013 §Test plan
(capability tests: see Left open). Test infrastructure only. No product client code: rust-core
builds the clients in parallel. Worktree branch from main @ 5f4f393, not merged.

## Done

- **New dev-only crate `crates/mooring-testsrv`** (`publish = false`). It is added to the workspace
  `members` (the one approved root `Cargo.toml` edit), not to `default-members`, so
  `cargo test --workspace` (CI) runs it and a bare `cargo test` does not. Usage, flags and the
  coverage tables are in [docs/qa/test-servers.md](../qa/test-servers.md).
- **`mooring_testsrv::rfb`**: an in-process RFB 3.8 server.
  - Security: None, VNC auth (RustCrypto `des`; vector checked against `openssl enc -des-ecb`),
    and VeNCrypt 0.2 with every subtype (X509*/TLS* over a rustls ring server with an rcgen
    cert, Plain).
  - Encodings: Raw, CopyRect, ZRLE (all five tile sub-encodings), Tight basic (fill / copy /
    palette / gradient, persistent zlib streams). Pseudo-encodings: DesktopSize,
    ExtendedDesktopSize (incl. the SetDesktopSize answer), LastRect, QEMU Extended Key.
  - Input counters, cut text both ways.
  - Knobs: version override, TLS strip after pin, slow-loris, oversized rect, zlib / cut-text
    length lies, missing rects, forced encoding, Tight JPEG control, forced auth failure, huge
    name.
- **`mooring_testsrv::rdp`**: an RDP server on `ironrdp-acceptor` 0.12 (the ADR-0011 generation).
  - Security: TLS-only or NLA (CredSSP/NTLM, no network client).
  - Graphics: fast-path bitmap updates, raw 32 bpp or planar.
  - Channels: fast/slow-path input recording, `cliprdr` text both ways, `drdynvc` + Display
    Control layout recording.
  - Shutdown recording, plus two knobs: out-of-bounds tile and drop after accept.
- **Self-tests**: 53 in total (9 unit, 33 RFB, 11 RDP).
  - RFB is checked through a minimal verification client in `tests/common/` that decodes every
    encoder path and asserts which sub-encodings it saw.
  - RDP is checked with `ironrdp-connector` / `ironrdp-async` / `ironrdp-session` as the client.
  - `mooring-proto-rdp` and `mooring-proto-vnc` are untouched.
- **Binaries** `rfb-testsrv` and `rdp-testsrv` for manual testing with the app. Every knob is
  a flag, unknown flags are an error, and the certificate SHA-256 is printed.
- **Fuzz scaffolding**: `mfr1_decode`, `known_certs_parse`, `rfb_server_msg`, `rdp_fastpath`.
  - Each is in `fuzz/Cargo.toml`, has seeds and empty regression dirs, and is in the
    `fuzz-nightly.yml` matrix.
  - R1's `decode_mfr1` / `known_certs::parse_bytes` and the R3/R4 decoders do not exist on main
    yet, so each entry is gated behind a fuzz-crate feature (`r1` / `r3` / `r4`). Without the
    feature it is a compiling no-op with a `PENDING` marker, and the nightly job prints a
    warning for it. [docs/qa/fuzzing.md](../qa/fuzzing.md), "A2 targets", says how to activate
    each one.

## Left open

- **The four new fuzz targets fuzz nothing until their gates are on.** The `r1` branches name
  the functions from the brief and have never been compiled: check them against R1's real
  signatures, add the stable replay in `crates/mooring-core/tests/fuzz_corpus.rs`, then delete
  the gates. The other ADR fuzz targets (`certificate_info`, `cliprdr_text`, `framebuffer_ops`,
  the RFB decoders, upstream IronRDP) are Q1.
- **ADR-0013 capability snapshot tests and the E2E with mock frames** (rest of the Q2 row) are
  not in this change. Both depend on R2/R5/U1 artefacts that do not exist yet (`web.json`,
  `detached.json`, the `AppManifest`, the MFR1 channel). The test servers are ready for those E2E
  runs.
- **RDP server limits** (full table in test-servers.md):
  - Not supported: Kerberos, smart card, RemoteFX / NSCodec / EGFX, interleaved RLE, pointer
    PDUs, a server-side resize (Deactivation–Reactivation), the auto-reconnect cookie, CF_TEXT.
  - Fast-path fragmentation is implemented but never triggered (each tile is under 16 KiB).
  - The R3 reconnect and trust-mismatch tests are possible: restart the server, or pass another
    `TestCert`.
- **RFB server limits**: colour-map formats, Hextile/RRE, the Cursor pseudo-encoding and real
  Tight JPEG are not served. The TLS* subtypes run an ordinary certificate handshake (rustls has
  no anonymous DH), so they are only useful for refusal tests.
- The nightly workflow change has not run on GitHub. It was YAML-parsed only, because
  `actionlint` is not available here. `gitleaks` and lefthook are not installed in this
  environment, so the pre-commit hooks did not run. Their fmt and clippy parts were run by hand
  for this crate only (disk limit). The workspace-wide clippy and test have not been run.

## Decision needed

1. **security-reviewer**: review the new direct dependencies of `mooring-testsrv` (dev-only):
   - `tokio-rustls` 0.26 (ring + tls12, no aws-lc-rs).
   - `des` 0.9 and `flate2` 1.1 (rust_backend).
   - `ironrdp-{acceptor,connector,async,tokio,pdu,core,svc,cliprdr,dvc,displaycontrol,graphics}`
     at the ADR-0011 versions, and `ironrdp-session` 0.13 (dev).

   All are MIT OR Apache-2.0. Building the crate activates `sspi/scard` → `winscard` → `flate2`
   → **`libz-sys` (C zlib)**, which is the accepted R-RDP-FFI tree. With feature unification, a
   `cargo test --workspace` build therefore links C zlib for every crate that uses `flate2` in
   that build. Release builds of `mooring-app` do not include this crate. R3 brings in the same
   tree anyway. `aws-lc-rs` / `aws-lc-sys` now appear in `Cargo.lock` (the lockfile does not
   depend on features) but are not built: `cargo tree -p mooring-testsrv -i aws-lc-rs` is empty.
2. **orchestrator**: `Cargo.lock` changed with the new crate (79 packages added, none removed or
   re-versioned; checked by diffing name/version sets).
3. **rust-core (R3/R4)**: to use the servers, add
   `mooring-testsrv = { path = "../mooring-testsrv" }` under `[dev-dependencies]`. The RDP
   CredSSP public key for `connect_finalize` is the SPKI `subjectPublicKey` bytes
   (`TestCert::public_key_raw`). The product client must extract those bytes from the peer
   certificate itself.

## Test evidence

```
cargo fmt --all                                                    # clean
cargo clippy -p mooring-testsrv --all-targets -- -D warnings      # clean (Rust 1.97)
cargo test -p mooring-testsrv                                      # 9 + 11 + 13 + 7 + 13 = 53 passed
  rdp.rs 11 · rfb_encodings.rs 13 · rfb_handshake.rs 7 · rfb_knobs.rs 13 · lib 9
  (after the pump fix below: rdp.rs ×6 and rfb_* ×4 repeat runs, all green)
cd fuzz && cargo check --bins                                      # 9 targets build on stable
rfb-testsrv / rdp-testsrv --port 0                                 # start, print addr + SHA256
rfb-testsrv --bogus 1                                              # exit 1, "unknown flag --bogus"
```

One flaky run was found and fixed in the harness, not the server. The RDP test client blocked in
`read_pdu` while it waited for server-side state that needed no further PDU. Waits on server
state now use a bounded `pump(ms)`.
