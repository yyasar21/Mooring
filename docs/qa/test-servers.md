# Test servers (`mooring-testsrv`)

`crates/mooring-testsrv` holds two loopback servers for the A2 protocol clients (ADR-0011,
ADR-0012). It is dev-only: `publish = false`, never a normal dependency of a product crate.
Product crates use it as a `[dev-dependencies]` entry in their integration tests. Both servers bind
`127.0.0.1` only and generate a fresh self-signed certificate (rcgen, ECDSA P-256) on every
start, unless the caller passes one in.

## Running them by hand (manual testing with the app)

```sh
cargo run -p mooring-testsrv --bin rfb-testsrv -- --port 0 --animate
cargo run -p mooring-testsrv --bin rdp-testsrv -- --port 0 --animate
```

Each server prints its address and the certificate's SHA-256. The certificate fingerprint is
what the TOFU dialog should show. `--port 0` picks a free port, and the defaults are 5900 and
3389. `--animate` moves a coloured square every 100 ms, so incremental updates are visible.
Stop a server with Ctrl-C. An unknown flag is an error. In the app, point a VNC or RDP
connection at `127.0.0.1:<port>`. The default test credentials are user `alice` and password
`testpass`. These are throwaway test values: never use real credentials here.

Restarting a server generates a new certificate. That is the easy way to see the
"CERTIFICATE CHANGED" hard stop after a pin: connect, trust the certificate, restart the server
on the same `--port`, and connect again.

### `rfb-testsrv` flags

| Flag | Default | Effect |
| --- | --- | --- |
| `--port N` | 5900 | `0` = ephemeral |
| `--width N` / `--height N` | 1024 / 768 | framebuffer size |
| `--name S` | `mooring-testsrv` | ServerInit name |
| `--security LIST` | `x509vnc,x509none,vnc,none` | comma list in offer order: `none`, `vnc`, and VeNCrypt subtypes `x509none`, `x509vnc`, `x509plain`, `tlsnone`, `tlsvnc`, `tlsplain`, `plain` (all subtypes go into one type-19 entry, offered first) |
| `--user S` / `--password S` | `alice` / `testpass` | VNC auth uses the password (first 8 bytes); Plain subtypes use both |
| `--zrle auto\|raw\|plain-rle` | `auto` | ZRLE tile sub-encodings |
| `--tight auto\|copy\|palette\|gradient` | `auto` | Tight basic filter |
| `--no-client-resize` | off | refuse SetDesktopSize (EDS status 1) |
| `--animate` | off | moving square |

Hostile knobs (each one is also a field of `rfb::Knobs`):

| Flag | Effect |
| --- | --- |
| `--version "RFB 003.003"` | send this 11-byte version (plus `\n`) instead of 3.8 |
| `--strip-tls-after N` | drop VeNCrypt from the security list from connection N on (0-based): the "TLS stripped after pin" MITM |
| `--slow-loris-ms N` | delay before every handshake byte |
| `--oversized-rect N` | every update also carries a raw rect that extends N px past the framebuffer |
| `--lie-zlib-length N` | ZRLE / Tight zlib length field says N (the real data follows) |
| `--lie-cut-text-length N` | ServerCutText length field says N |
| `--missing-rects N` | FramebufferUpdate announces N more rects than it sends |
| `--last-rect` | announce 0xFFFF rects and end the update with LastRect |
| `--force-encoding N` | send every rect as encoding N (e.g. 16) whatever the client asked for |
| `--tight-jpeg` | Tight rects use the JPEG control byte 0x90 with garbage data (ADR-0012: must give `protocol_error`) |
| `--fail-auth "reason"` | SecurityResult fails with this reason even after a correct password |
| `--huge-name N` | ServerInit name of N bytes (the client caps it at 4 KiB) |

### `rdp-testsrv` flags

| Flag | Default | Effect |
| --- | --- | --- |
| `--port N` | 3389 | `0` = ephemeral |
| `--width N` / `--height N` | 1024 / 768 | desktop size |
| `--security nla\|tls` | `nla` | NLA (`HYBRID \| HYBRID_EX`, CredSSP/NTLM) or TLS only (`PROTOCOL_SSL`, Client Info credentials) |
| `--user S` / `--password S` / `--domain S` | `alice` / `testpass` / none | accepted account |
| `--bitmap raw\|planar` | `raw` | uncompressed 32 bpp or RDP 6.0 planar |
| `--no-clipboard` / `--no-display-control` | on | drop the `cliprdr` / `drdynvc` channel |
| `--clipboard-text S` | none | announce S on the clipboard 1 s after start (the client then fetches it) |
| `--out-of-bounds N` | off | every update carries a tile N px past the desktop |
| `--drop-after-accept` | off | close right after the connection sequence |
| `--animate` | off | moving square |

## Using them from integration tests

```rust
// [dev-dependencies] mooring-testsrv = { path = "../mooring-testsrv" }
let srv = mooring_testsrv::rfb::start(RfbConfig { security: vec![SecurityOffer::VncAuth],
    password: Some("pw".into()), ..RfbConfig::default() }, 0).await?;   // needs a Tokio runtime
srv.fill(Rect::new(0, 0, 10, 10), [255, 0, 0, 255]);   // dirty rect → next incremental update
assert_eq!(srv.stats().pointer_events, 1);

let rdp = mooring_testsrv::rdp::start(RdpConfig::default(), 0)?;     // own thread, any runtime
let pin = rdp.cert().sha256_hex();            // the x509-sha256 pin the client should write
```

`stats()` returns snapshots: what the client chose, every input event, the cut text and
clipboard text it sent, and errors that ended a connection. `set_knobs` / `set_security` (RFB)
apply to the next connection. The servers' own self-tests (`cargo test -p mooring-testsrv`) use
small verification clients in `crates/mooring-testsrv/tests/common/`. These clients are not the
product clients, and their decoders are not the product decoders.

## What the RFB server exercises

- Handshake: RFB 3.8 only (the version knob lets the client's refusal of 3.3 / 3.7 be tested;
  the server itself always expects a 3.8 reply). The client's choice must be in the list.
- Security: None (1), VNC Authentication (2, RustCrypto DES, fixed challenge available for
  vectors), VeNCrypt 0.2 (19) with Plain, TLSNone/Vnc/Plain, X509None/Vnc/Plain, and inner
  VNC / Plain authentication. SecurityResult failures carry a reason.
- Encodings: Raw, CopyRect, ZRLE (solid, packed palette 2–16, palette RLE 17–127, plain RLE,
  raw tiles; CPIXEL rules for 32 / 16 / 8 bpp true colour, both byte orders), Tight basic (fill,
  copy, palette with 1-bit and 8-bit indices, gradient; persistent zlib streams 0–2; compact
  lengths). Pseudo: DesktopSize, ExtendedDesktopSize (initial, server resize, SetDesktopSize
  answer with status 0 / 1), LastRect, QEMU Extended Key Event (confirmation + event receipt).
- Client messages: SetPixelFormat (true colour 8 / 16 / 32 bpp), SetEncodings, incremental and
  full FramebufferUpdateRequest, KeyEvent, PointerEvent, ClientCutText (≤ 1 MiB, larger ends
  the connection), SetDesktopSize, QEMU key event.

**Not exercised:** colour-map pixel formats and SetColourMapEntries, Hextile / RRE / Zlib /
ZlibHex, the Cursor pseudo-encoding (-239), real Tight JPEG, Bell, Extended Clipboard, the
Apple / RA2 / Tight / SASL security types, Continuous Updates, Fence, xvp, multi-screen
ExtendedDesktopSize. The TLS* subtypes are specified as anonymous-DH TLS, which rustls does not
implement, so the server answers them with a certificate handshake. They are useful only to
check that the client *refuses* them (ADR-0012).

## What the RDP server exercises (and what it cannot)

The RDP server is built on `ironrdp-acceptor` 0.12 with `ironrdp-pdu` 0.11, `ironrdp-svc`
0.10, `ironrdp-cliprdr` 0.9, `ironrdp-dvc` / `ironrdp-displaycontrol` 0.10 and
`ironrdp-graphics` 0.11: the same IronRDP generation as ADR-0011. It does not use
`ironrdp-server` 0.13, which depends on the older acceptor 0.10 / pdu 0.9 and pulls `reqwest`
in through `ironrdp-tokio`.

The client side of each feature is checked in `crates/mooring-testsrv/tests/rdp.rs` with
`ironrdp-connector` 0.12, `ironrdp-async` 0.12 and `ironrdp-session` 0.13.

| Area | Exercised | Not exercised |
| --- | --- | --- |
| Negotiation | X.224 with `PROTOCOL_SSL` or `HYBRID \| HYBRID_EX`; a client whose protocols do not match is refused | Standard RDP Security (RC4): the acceptor is never configured for it, so "never offered" can only be checked from the client's request |
| TLS | rustls (ring) server, self-signed cert: first-connect TOFU, pin, mismatch after a restart or with another `TestCert` | CA-valid chains (no CA-issued test cert; a test can pass its own `TestCert` but rcgen certs are self-signed) |
| NLA | CredSSP with NTLMv2 through `sspi`, HYBRID_EX early user authorization result, wrong password → refusal (`credssp:` error), `DOMAIN\user` accounts | Kerberos (the server's `NetworkClient` refuses every request, matching ADR-0011's NTLM-only A2), smart card / PKINIT, Restricted Admin, Remote Credential Guard |
| TLS-only | Client Info credentials compared by the acceptor; a wrong password does not reach the active stage | the graphical logon screen (there is none) |
| Graphics | fast-path Bitmap Update, 32 bpp uncompressed (BGRX, bottom-up) and RDP 6.0 planar with RLE, 64 × 32 tiles; initial full screen, incremental updates after `fill` / `blit` | interleaved RLE (< 32 bpp), RemoteFX, NSCodec, surface commands, EGFX / H.264, bulk compression, pointer / cursor PDUs, fast-path fragmentation (implemented, but each tile is under the 16 374-byte limit so it never splits), Refresh Rect / Suppress Output (ignored) |
| Resize | Display Control DVC opens; `encode_resize` reaches the server and the monitor layout is recorded (`stats.layouts`) | the server never resizes: no Deactivation–Reactivation, so a `DesktopResized` event after a server-side resize cannot be produced |
| Input | fast-path scancode (extended, release), Unicode, mouse, sync; slow-path input PDUs | relative mouse, `ainput`, QoE |
| Clipboard | `cliprdr` server role: server → client (Format List with CF_UNICODETEXT, client fetches the text) and client → server (server fetches and records it), UTF-16 both ways | CF_TEXT (not announced; a CF_TEXT data request gets no answer at all, so a client must time it out), file lists, images, HTML, locks, size caps (the server sends whatever the test sets) |
| Session | graceful Shutdown Request, disconnect, reconnect on a new TCP connection | the auto-reconnect cookie (no Save Session Info PDU), server redirection, licensing beyond the acceptor's default, audio, `rdpdr`, multitransport |
| Hostile | out-of-bounds bitmap tile, dropped connection after accept | malformed PDUs: use the fuzz targets (docs/qa/fuzzing.md) |

The IronRDP futures are `!Send`, so `rdp::start` runs the server on its own thread with a
current-thread runtime. The handle can be used from any runtime or from synchronous code.
Building the server compiles `sspi` with the `scard` feature, and through it `winscard` →
`flate2` → `libz-sys` (C zlib). This is the R-RDP-FFI tree that ADR-0011 owner decision 2
accepted, and it comes in with `ironrdp-connector` whichever crate depends on it.
