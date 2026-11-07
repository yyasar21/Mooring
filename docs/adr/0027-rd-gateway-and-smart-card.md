# ADR-0027: RD Gateway (MS-TSGU over WebSocket) and smart card / PIV

Status: Proposed · 2026-11-07 (Phase A5 / v0.2.0; amends ADR-0011 decision 3, ADR-0009 §2 footnote
⁴ and role `gateway`; builds on ADR-0007, ADR-0013 B-6, ADR-0024, ADR-0025 `HopStream`)

## Context
ADR-0011 deferred RD Gateway, smart-card logon and Kerberos; ADR-0009 already has the
`gateway` credential role (`R(gw)` for `user_password`/`domain_user`/`prompt`) and the
`x509 → rdp` footnote "Smart-card RDP is planned for later". Our RDP connector is TCP → our
rustls (ring) verifier → CredSSP/NTLM through `sspi` with a `NoNetwork` client (no KDC traffic).
Upstream status (sources read 2026-11-07): **`ironrdp-mstsgu` 0.1.0** (MIT OR Apache-2.0,
2026-10-27, 0 `unsafe` in `src/`) implements MS-TSGU over WebSocket with a legacy
RPC-over-HTTP fallback and HTTP Negotiate/NTLM/Basic auth, exposing `GwClient: AsyncRead +
AsyncWrite`. But its `rustls` feature is `ironrdp-tls/rustls` = **`aws-lc-rs`** (banned,
ADR-0011) plus `tokio-tungstenite/rustls-tls-native-roots` (same), its certificate callback is
`Fn(&[u8], &str, &str) -> bool` (sync), it enables `sspi/network_client` (**`reqwest`** KDC
client, `resolve_with_default_network_client()` in `http_auth.rs`), and 0.1.0 is two weeks old.
`ironrdp-rdcleanpath` is Devolutions Gateway's own path, not RDG. `ironrdp-rdpdr` 0.9.0
(0 `unsafe`) has `DeviceType::Smartcard` and `RdpdrBackend::handle_scard_call`; the PC/SC
side is the caller's. `pcsc` 2.9.0 (MIT) was last released **2024-12-14** (older than 12
months) with 39 `unsafe` FFI sites to `winscard.dll`/`pcsc-lite`. `cryptoki` 0.12.1 is in the
tree through `sspi` (dlopen PKCS#11, FFI). `winscard` 0.4.0 (in tree, 0 `unsafe`) is an
*emulated* PIV card over a supplied key, not a reader.

## Decision

### 1. RD Gateway — own WebSocket transport, 0.2.0 scope (`mooring-proto-rdp::gateway`)
- Transport `RdgStream` over the **`RDG_OUT_DATA` WebSocket** (`wss://<gw>/remoteDesktopGateway/`,
  Server 2016+): our `tokio-rustls` (ring) with the ADR-0011 verifier and a new pin store
  `known_rdg_certs` (TOFU/mismatch rules identical; fail-then-reconnect), HTTP upgrade and
  framing with `tokio-tungstenite` 0.30 `handshake` feature (**already in the tree**, `mooring-http`
  / kube) via `client_async` over our TLS stream, then the MS-TSGU §2.2.10 PDUs:
  `HANDSHAKE_REQUEST/RESPONSE`, `TUNNEL_CREATE` (no PAA cookie), `TUNNEL_AUTHORIZE`
  (`client_name` = hostname sanitised ≤ 32), `CHANNEL_CREATE` (target host:port), then
  `DATA` packets carrying the RDP stream; `KEEPALIVE` every 15 min; `REAUTH` handled by
  reconnecting the tunnel. Encoders/decoders are ours (≤ 600 lines, every length field capped,
  fuzz target `rdg_pdu`), with `ironrdp-mstsgu`'s `proto.rs` as the reference while reading
  the spec.
- HTTP authentication at the upgrade: **NTLM** through the `sspi::Ntlm` we already link
  (no `network_client` feature, so no KDC traffic — ADR-0011 stays true), and **Basic** only
  over TLS when the gateway refuses NTLM (`allowBasicGateway` option, audited). Kerberos,
  PKINIT smart-card gateway auth and `HTTP_EXTENDED_AUTH_SC`: **not in 0.2.0**.
- `RdgStream` plugs into `RdpStream = TlsStream<HopStream>` (ADR-0025) as a third variant
  `HopStream::Gateway(RdgStream)`; RDP over RDG over an SSH jump chain composes (the gateway
  TCP is the chain's `direct-tcpip` target).
- Legacy **RPC-over-HTTP** (`RPC_IN_DATA`/`RPC_OUT_DATA`, Server 2008 R2–2012) and the UDP
  side channel: out of scope; refusal `rdp.gateway_unsupported` with the gateway's reason.
  Marked **stretch** only if the owner has such a gateway.
- Options (`RdpConnOptions.gateway`): `{ host, port: 443, usage: always | if_unreachable
  (probe 3 s, audited) , allowBasicGateway, caPem }`; credential from role `gateway` or
  "same as sign-in" (ADR-0009 §3 null + flag). `Connected.security` gains `"nla+rdg"`.
- Adopting `ironrdp-mstsgu` instead is the first alternative: it needs upstream (a) a
  `rustls-ring` feature in `ironrdp-mstsgu` and `ironrdp-tls`, (b) an injectable
  `NetworkClient` for `http_auth`; rust-core files both issues/PRs at the start of A5; if both
  land before the 0.2.0 code freeze, the own transport is replaced (owner decision 39).

### 2. Smart card — credential kind and PIN handling (0.2.0), readers (stretch)
- Kind **`smart_card`** (20th kind): fields `username?`, `domain?`, `reader_hint?`,
  `cert_fingerprint` (derived from the chosen certificate, plaintext), `pkcs11_module?`
  (one of a fixed list: OpenSC `opensc-pkcs11.{so,dylib,dll}`, YubiKey `libykcs11`, Windows
  `msclmd` is not PKCS#11 → `cryptoapi`); secrets: none (**the PIN is never stored**; it is
  asked per use with a native Rust dialog, ADR-0013 B-6 three-slot rules, `Zeroizing`).
- **SSH with a PIV key — 0.2.0 via the agent** (ADR-0024 §2): the user loads the PKCS#11
  provider into `ssh-agent` (`ssh-add -s <module>`); Mooring pins the fingerprint and shows
  the touch/PIN banner. Direct `cryptoki` use (dlopen of a vendor `.so`, FFI, PIN over the
  module) is **stretch** and needs an `unsafe`/C exception ruling (R-RDP-FFI class) — not
  proposed for 0.2.0.
- **RDP smart-card logon — stretch**: needs (i) `rdpdr` with a PC/SC backend (`pcsc`: FFI +
  maintenance exception) for redirection, and (ii) Kerberos **PKINIT** in CredSSP (`sspi/scard`
  + KDC traffic), which ADR-0011 deferred with Kerberos itself. Both are out of 0.2.0; the
  matrix keeps `x509/smart_card → rdp —` with the footnote updated to "needs Kerberos PKINIT
  (planned)". What *is* done in 0.2.0: the kind, the PIN dialog, the schema and the matrix
  rows, so a later Kerberos ADR adds only the transport pieces.
- Emulated card (`winscard` crate, in tree): lets an `x509` credential log on as a smart
  card without hardware — also PKINIT-bound; evaluated with the Kerberos ADR, not here.

### 3. IPC, audit, codes
`RdpConnOptions.gateway` through `connection_create/update`; `known_certs_list/remove` accept
`protocol: "rdg"`; `credential_kinds()` serves `smart_card`. Audit `session.rdp.gateway { host,
auth: ntlm|basic, tunnel_id }`, `trust.cert.*` with `protocol: rdg`, `session.rdp.gateway_basic`
(warning), `credential.pin_prompted { id }` (never the PIN). Codes: `rdp.gateway_auth_failed`,
`rdp.gateway_unsupported`, `rdp.gateway_channel_refused`, `session.trust_*` (reused),
`credential.pin_cancelled`.

## Alternatives considered
- `ironrdp-mstsgu` as published: banned `aws-lc-rs` through two features, KDC traffic through
  `reqwest`, sync callback; see §1 — first choice once upstream exposes ring and no-network.
- A git-source `[patch]` of IronRDP with the two changes: `deny.toml` allows exactly one git
  source (age, R-AGE-PIN); a second needs an owner ruling and widens supply-chain exposure.
  Rejected unless the owner prefers it over our ~600 lines.
- FreeRDP's gateway code via FFI: C, rejected (ADR-0011).
- Smart card now via `pcsc` + `cryptoki` with exceptions: two FFI/C trees and a stale crate for
  a feature that still cannot log on to RDP without PKINIT. Rejected for 0.2.0.

## Security consequences
- T3: the gateway is a TLS peer with its own pin store; NTLM over TLS only; Basic is opt-in and
  audited (credentials in a header — only ever inside TLS). The gateway sees the RDP stream's
  TLS, not its contents (NLA/TLS is end-to-end to the target as today).
- T4: new parsers (`rdg_pdu`, HTTP upgrade response, WebSocket framing from `tungstenite`)
  take hostile bytes — caps, fuzz, `panic = "unwind"` per session.
- T5: cannot see the PIN or gateway credentials; can open sessions the user could.
- Smart-card PIN: Rust-side dialog, `Zeroizing`, used once per operation; a cancelled dialog
  closes with `credential.pin_cancelled`. No PIN caching (owner decision 40).
- No new crate for 0.2.0 scope. Stretch items each carry an explicit exception ruling.

## UI
RDP connection form: "RD Gateway" section (host, port, usage, credential picker with "same as
sign-in", Basic toggle with warning, CA); session header chip "via RDG <host>"; trust dialog
titled "RD Gateway certificate"; kind picker entry "Smart card / PIV" with the fixed module list
and "PIN asked at connect" note; SSH form hint for `ssh-add -s`.

## Test plan
- Unit: PDU encode/decode vectors per MS-TSGU type, length caps, `TUNNEL_RESPONSE` error codes
  → messages, NTLM challenge/response state machine with a scripted gateway, Basic refusal
  without the option, `known_rdg_certs` rows, kind schema snapshot.
- Integration: an RDG mock in `mooring-testsrv` (TLS + WebSocket + MS-TSGU PDUs) in front of the
  acceptor-based RDP server: NTLM success, 401 loop limit, TOFU → reconnect, mismatch hard stop,
  channel refused, keepalive, tunnel drop → `server_ended`; RDG over one SSH hop (ADR-0025).
- Fuzz: `rdg_pdu`, `rdg_http_response`.
- Manual gate: the owner's lab RD Gateway (`MOORING_LAB_RDG_HOST`, `#[ignore]`); YubiKey PIV
  via `ssh-add -s` on the three OSes.

## Owner decisions needed
39. RD Gateway: own WebSocket transport (recommended) vs waiting for upstream `ironrdp-mstsgu`
    ring/no-KDC changes vs a second git-source exception.
40. Smart card in 0.2.0 = kind + PIN dialog + SSH PIV via agent only (recommended); RDP
    smart-card logon and direct PKCS#11 wait for the Kerberos ADR with explicit FFI rulings.
41. Legacy RPC-over-HTTP gateways: unsupported in 0.2.0 (recommended) unless the lab has one.
