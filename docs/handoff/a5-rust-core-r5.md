# A5 W3 — rust-core R5: RD Gateway (MS-TSGU over WebSocket) + `smart_card` kind (ADR-0027)

Branch `worktree-agent-a6d15374d56333135`, worktree
`/home/claude/nexus/.claude/worktrees/agent-a6d15374d56333135`. ADR-0027 is still *Proposed*;
I applied the owner defaults from the decision table:
- **39**: our own MS-TSGU WebSocket transport. `ironrdp-mstsgu` is not used.
- **40**: smart card in 0.2.0 = the kind, the PIN prompt, and SSH PIV through the agent only.
  RDP smart-card logon is refused.
- **41**: legacy RPC-over-HTTP gateways are unsupported.

**No new crate, no manifest or lockfile change.** See "Manifest" below for `tokio-tungstenite`.

## Done

### Core (`mooring-core`)
- **`smart_card`**: the 20th kind, last in `CredentialKind::ALL`, after `bitwarden_access_token`.
  It is in `credential/card_fields.rs`.
  - Fields: `username?` (hint), `domain?`, `reader_hint?`, `public_key?` (the card key's OpenSSH
    line, from `ssh-keygen -D <module>`), `pkcs11_module?` (`opensc|ykcs11|cryptoapi`, a closed
    enum), and a derived `fingerprint`.
  - **No secret field.** The PIN is never stored.
  - `sk-*` lines are refused with `credential.use_sk_kind`.
- Matrix: SSH primary only. RDP primary and gateway are refused with the footnote "Smart-card
  logon over RDP needs Kerberos PKINIT (planned)." The `x509 → rdp` footnote now says the same.
- `CertProtocol::Rdg` → `known_rdg_certs` (`tls_always`, no connection protocol).
- `RdpConnOptions.gateway: RdGatewayOptions { host, port = 443, usage: always | if_unreachable,
  allowBasicGateway = false, caPem }`.
  - It is validated: host shape, port, CA PEM, `deny_unknown_fields`.
  - It is skipped on the wire when `null`, so existing rows stay `{}`-compatible.
- Sessions:
  - New prompt purposes: `PromptPurpose::GatewayCertificateTrust`, `SmartCardPin`.
  - New event: `SessionEvent::GatewayStatus { host, state: HopState, peer_identity? }`.
  - New close codes: `CloseCode::GatewayAuth | GatewayRefused | GatewayUnsupported` (none are
    retryable).
  - New secret: `ConnectSecret::SmartCard(PivLogin { public_key, fingerprint, module,
    reader_hint })`.
- Audit:
  - `SessionAudit::Gateway { host, auth, outcome, tunnel_id }` (`session.rdp.gateway`).
  - `GatewayBasic { host }` (`session.rdp.gateway_basic`, a warning).
  - `PinPrompted { fingerprint, outcome }` (`credential.pin_prompted`). It never holds the PIN.

### Store (`mooring-store`)
- Migration **`0011_smart_card.sql`** (`LATEST = 11`). It is the FK-off `credential` rebuild,
  with `smart_card` added to the kind CHECK.

### RDP (`mooring-proto-rdp::gateway`, our own transport)
- `pdu.rs`: MS-TSGU §2.2.10 encoders and a bounded decoder.
  - Handled: HANDSHAKE, TUNNEL_CREATE/RESPONSE, TUNNEL_AUTH/RESPONSE, CHANNEL_CREATE/RESPONSE,
    DATA, KEEPALIVE, SERVICE_MESSAGE, REAUTH, CLOSE_CHANNEL(_RESPONSE).
  - The header length is capped at 72 KiB before anything is buffered. Every inner length is
    checked against the packet, and trailing bytes are refused.
  - `client_name` is sanitised to `[A-Za-z0-9_-]`, at most 32 characters.
  - We send caps `IDLE_TIMEOUT` only: no SOH/NAP, PAA, UDP, consent or in-band reauth.
- `http.rs`: our upgrade request (`GET /remoteDesktopGateway/`, `RDG-Connection-Id`, …) and a
  bounded response-head parser.
  - Limits: 16 KiB head, 64 headers, 64 KiB drained body. Chunked bodies are refused.
  - `WWW-Authenticate` challenge parsing.
  - Strict RFC 4648 base64.
- `ws.rs`: RFC 6455 client framing.
  - Our frames are masked. The gateway's frames must be unmasked, with no RSV bits, ≤ 128 KiB.
  - Control frames must be ≤ 125 bytes and final. Text frames are refused.
  - Fragmented binary is streamed straight into the packet parser.
- `ntlm.rs`: HTTP NTLM (NEGOTIATE → CHALLENGE → AUTHENTICATE). It uses the `sspi::Ntlm` that
  IronRDP already links, through the `ironrdp_connector::sspi` re-export. There is no
  `network_client`, so there is no KDC traffic.
- `open.rs`, one open:
  1. TCP to the gateway goes through the connection's dialer, so **RD Gateway behind an SSH
     jump chain composes**.
  2. TLS with the ADR-0011 `TofuVerifier` over `known_rdg_certs`:
     - unknown certificate → `gateway_certificate_trust` prompt, then reconnect;
     - **changed pin → `trust_mismatch` hard stop, before any HTTP byte** ("RD GATEWAY
       CERTIFICATE CHANGED …");
     - conflict → `trust_conflict`.
  3. HTTP auth:
     - NTLM first.
     - Basic only with `allowBasicGateway`. It is audited, and a `Connection: close` leads to
       one reconnect.
     - A Negotiate-only gateway → `gateway_auth`.
     - 401 after the last leg → `gateway_auth`.
     - 400/404/405/501 → `gateway_unsupported` (RPC-over-HTTP-only gateways).
     - Any other status → `gateway_refused`.
  4. Tunnel. Non-zero HRESULTs → `gateway_refused`, with the hex code in the reason. Another
     MS-TSGU version → `gateway_unsupported`. A packet out of order → `protocol_error`.
  5. A relay task joins an in-process duplex (what the connector reads) to DATA packets.
     - KEEPALIVE every 15 min.
     - The gateway's CLOSE_CHANNEL is answered.
     - REAUTH or a dropped tunnel → EOF → the session's normal end, and the app reconnects the
       whole tunnel.
  - `usage: if_unreachable`: a 3 s direct probe first, audited `outcome: direct`.
- Integration:
  - `Target.gateway`; `Attempt::NeedsGatewayTrust`.
  - The driver's trust rounds went from 2 to 3 (gateway + server).
  - `Connected.security` = `nla+rdg` / `tls+rdg`.
  - `RdpOptions.gateway: Option<GatewayConfig { known_certs, credential: Arc<GatewayCredential
    { SameAsSignIn | Account } >, trusted_once }>`. With it absent, the defaults are
    `known_rdg_certs` next to `known_certs` and the sign-in credential.
- Fuzz entries for qa:
  - **`mooring_proto_rdp::gateway::fuzz_rdg_pdu`** (`rdg_pdu`): packets and WebSocket frames,
    both roles.
  - **`mooring_proto_rdp::gateway::fuzz_rdg_http_response`** (`rdg_http_response`): head, body
    length, challenges, base64.

### SSH (`mooring-proto-ssh::piv_auth`)
- `smart_card` round. It is the only method tried; there is never a password fallback.
  1. Agent identity pinned by blob, with the same matching as R4 (`sk_agent::find`).
  2. When the agent lacks the key and a module is set:
     - The **PIN is asked** through the prompt channel: `purpose: smart_card_pin`, secret,
       `Zeroizing` frame.
     - It is handed to the agent as **`SSH_AGENTC_ADD_SMARTCARD_KEY`**, the same mechanism as
       `ssh-add -s`. No FFI, no `cryptoki`.
     - The identities are listed again.
  3. Sign with `rsa-sha2-256/512` flags for RSA keys. The signature is **verified against the
     pinned key before it is sent**.
- The module path comes from a fixed per-OS list (`piv_module_candidates`) and is never taken
  from input. `SshOptions.pkcs11_module_path` is a test override.
- Failure reasons:
  - `not_in_agent`: "load the card with `ssh-add -s …`"
  - `card_refused`: wrong PIN, card or module
  - `pin_cancelled`: close code `user`
  - `no_agent`, `bad_key`, `bad_signature`, `refused`
- Audit: `session.auth_sk` with `backend: "piv"`, plus `credential.pin_prompted`.
- `agent_holds_key(line, path)` is used by the app pre-flight.

### App (`src-tauri`)
- **The existing "RD Gateway credential" field** (`gatewayCredentialId`, role `gateway`) was
  stored but never read. `connect_plan::gateway_of` now resolves it:
  - `user_password` / `domain_user` → `GatewayCredential::Account`;
  - empty → `SameAsSignIn` (after a `prompt` form too);
  - any other kind → `rdp.gateway_auth`.
  - The gateway credential is added to `credential_used`.
- `GraphicalConnect.gateway`, `Launcher.known_rdg_certs`, `Launched.gateway`, and `TrustOnce {
  target, gateway }`. A "once" for the gateway survives a following target prompt.
- **Gate**: `gateway_certificate_trust` answers are handled like the RDP ones:
  - `yes` pins `known_rdg_certs` at the gateway's `host:port`;
  - `once` → `trusted_once` for the gateway;
  - anything else → `trust_rejected`.
  - It is audited as `cert_decision` with `protocol: "rdg"`.
- Plan / pre-flight:
  - `smart_card` → `ConnectSecret::SmartCard`. With no public key → `ssh.piv_key_not_in_agent`.
  - Pre-flight: a key that is not in the agent, with no installed module → **`ssh.piv_key_not_in_agent`**
    before any network I/O.
  - RDP with a `smart_card` primary → `rdp.smart_card_unsupported` (defence behind the matrix).
- `WireEvent::GatewayStatus`.
- `close_code_of` maps `rdp.gateway_*`.
- Audit rows `session.rdp.gateway`, `session.rdp.gateway_basic`, `credential.pin_prompted`
  (`mooring-audit`).
- `sessions.rs` tests moved to `sessions_tests.rs`, so the file stays under 500 lines.
- `kinds.snapshot.json`: the `smart_card` row was appended. `ipc-codes.json` was blessed with +5
  codes: `rdp.gateway_auth`, `rdp.gateway_refused`, `rdp.gateway_unsupported`,
  `rdp.smart_card_unsupported`, `ssh.piv_key_not_in_agent`.

## UI contract (U5)
- **RDP form, "RD Gateway" section** → `options.gateway = { host, port (443), usage: "always" |
  "if_unreachable", allowBasicGateway, caPem | null }`. Send `null`, or leave the field out, for
  no gateway.
  - Credential picker: the existing `gatewayCredentialId`. Empty means "Same as sign-in". Only
    `user_password` / `domain_user` are valid there; `credential_kinds()` already lists `rdp`
    role `gateway` for them.
  - Basic toggle copy: "Sends the password in an HTTP header (inside TLS). Audited."
- **Session channel**:
  - `{ kind: "gateway_status", host: "gw01:443", state: connecting|authenticating|up|failed,
    peer_identity? }` comes before the target's `connected`.
  - Header chip "via RD Gateway gw01" while `up`.
  - `connected.security` is `"nla+rdg"`.
- **Trust dialog**: `prompt.purpose === "gateway_certificate_trust"` (with `certificate`). Title
  it "RD Gateway certificate". Answers are `yes` / `once` / anything else, as for
  `certificate_trust`.
- **`closed.code`**:
  - `gateway_auth`: "The RD Gateway refused the credentials" (the reason may name
    `allowBasicGateway` or Kerberos).
  - `gateway_refused`: the reason carries the hex HRESULT.
  - `gateway_unsupported`: "No RD Gateway WebSocket endpoint (RPC over HTTP gateways are not
    supported)".
  - `trust_mismatch`: the reason starts "RD GATEWAY CERTIFICATE CHANGED".
- `known_certs_list/remove({ protocol: "rdg" })` works (`CertProtocol` serde). Hosts show hashed
  only (see Left open).
- **Kind picker**: "Smart card / PIV" (`smart_card`, group "Smart card").
  - Form fields: `username`, `domain`, `reader_hint`, `public_key` (multiline), and
    `pkcs11_module` (enum `opensc|ykcs11|cryptoapi`).
  - Show the derived `fingerprint` read-only.
  - Note "PIN asked at connect, never stored".
  - SSH hint: "Load the card into ssh-agent with `ssh-add -s <module>`, or choose the module so
    Mooring asks the PIN."
- **PIN dialog**: `prompt.purpose === "smart_card_pin"`, `secret: true`. Answer with
  `session_send { kind: "answer", id, text }`. An empty answer cancels, giving `closed.code:
  user` with "smart card PIN cancelled".
- Error copy:
  - `ssh.piv_key_not_in_agent`: show the message plus the `ssh-add -s` help.
  - `rdp.smart_card_unsupported`: "Smart-card logon over RDP needs Kerberos PKINIT (planned)."
  - A matrix refusal of `smart_card` on RDP arrives as `credential.incompatible` with the same
    sentence.
- `ipc.kinds.ts` must gain the `smart_card` row, or the snapshot vitest fails.

## Left open
- **`tokio-tungstenite` was not added** (not workspace-declared); the RFC 6455 framing is ours.
  Follow-up: `sha1 = { workspace = true }` was added to `mooring-proto-rdp` and the
  `Sec-WebSocket-Accept` value is now verified exactly (`base64(SHA-1(key ‖ GUID))`); a wrong
  or missing value → `protocol_error` before any MS-TSGU byte (mock modes `BadAccept`,
  `NoAccept`).
- The RDG TLS uses `mooring-proto-rdp`'s own ADR-0011 verifier, not `mooring-http`'s.
  - Reason: NTLM needs a raw keep-alive connection, and the crate has no `mooring-http`
    dependency.
  - The semantics are the same as for RDP pins: TOFU, mismatch hard stop, conflict.
- `HopStream::Gateway` was not added as a variant. `HopStream` lives in `mooring-proto-ssh`, and
  RDP consumes `Dialer` / `Erased` (R1). The gateway is opened *inside* the RDP connect, through
  the connection's dialer, and hands back an `Erased` stream. RDG over a jump chain therefore
  works without new plumbing. It is not covered by an integration test through a real hop;
  qa can add one (the `ViaSession` + mock gateway).
- A `prompt` kind as the *gateway* credential is refused (`rdp.gateway_auth`): there is no
  second sign-in form. Use "same as sign-in".
- `known_certs_list({protocol:"rdg"})` does not join gateway host names from connection options
  yet. Pins are listed hashed.
- Upstream issues for `ironrdp-mstsgu` (a ring feature, an injectable `NetworkClient`) were
  **not filed**. That needs a human GitHub account.
- No app-level e2e through the mock gateway. The mock lives in
  `crates/mooring-proto-rdp/tests/rdg_mock/`; qa can lift it into `mooring-testsrv`.
- No keepalive test (15 min timer) and no service-message display.
- Lab gate `MOORING_LAB_RDG_HOST` was not run. YubiKey PIV through `ssh-add -s` was not tested
  on the three OSes.
- The Windows OpenSSH agent may not support `ADD_SMARTCARD_KEY`; it then answers FAILURE, which
  we report as `card_refused`. `cryptoapi` has no module path, so the key must already be in the
  agent.

## Decision needed
- Code names: ADR-0027 §3 now lists the implemented `rdp.gateway_auth` / `rdp.gateway_refused`
  / `rdp.gateway_unsupported` (follow-up commit). `credential.pin_cancelled` is a close (`user` plus a reason), not an IPC
  code.
- WebSocket: our framing vs `tokio-tungstenite` (the Accept value is verified now).
- ADR-0027 → *Accepted* with 39/40/41 as applied. The SSH PIN goes to the agent
  (`ADD_SMARTCARD_KEY`), not to a native dialog → `cryptoki`; this deviates from §2 "asked per
  use with a native Rust dialog" (it uses the session prompt channel instead).
- Migration number 0011 (the latest was 0010).

## Manifest
- Follow-up: `mooring-proto-rdp` gained `sha1 = { workspace = true }` (RFC 6455
  Sec-WebSocket-Accept check; RustCrypto, already in the lockfile). Nothing else.

## Test evidence
```
cargo fmt --all --check                                   clean
cargo clippy --workspace --all-targets -- -D warnings     clean
MOORING_BLESS=1 cargo test -p mooring-app golden          6/6, ipc-codes.json +5
```
New tests:
- `mooring-proto-rdp --test gateway` **6/6**: the mock RD Gateway (TLS + sspi NTLM server +
  WebSocket + MS-TSGU) in front of QA's IronRDP acceptor.
  - NTLM + gateway TOFU yes → reconnect → RDP `nla+rdg` + `DesktopResized`. Statuses come as
    connecting, connecting, authenticating, up. 2 HTTP requests; channel to the target; audit
    `ntlm/ok/tunnel 7`.
  - Wrong password → `gateway_auth`; no CHANNEL_CREATE is ever sent.
  - Basic-only: refused without the option (the reason names `allowBasicGateway`); with it
    → connected, plus a `GatewayBasic` row.
  - 404 → `gateway_unsupported`; channel HRESULT → `gateway_refused` (`0x800759DD` in the
    reason).
  - Oversized packet header → `protocol_error`; DATA before HANDSHAKE_RESPONSE →
    `protocol_error`.
  - Changed gateway cert → `trust_mismatch` with 0 HTTP requests, plus CertMismatch and
    `trust` rows.
  - Rejected TOFU → `trust_rejected`.
- `mooring-proto-rdp` unit: `gateway_tests` (layouts, hostile packets, proptest DATA round-trip,
  proptest fuzz entries never panic, seeds), `http` 4, `ws` 2.
- `mooring-proto-ssh --test smart_card` **4/4** (Unix fake PIV agent):
  - key in the agent → no PIN;
  - PIN → `ADD_SMARTCARD_KEY(provider, pin)` → signs, the PIN absent from the audit;
  - wrong PIN → `card_refused`; empty PIN → `user`; no module → `ssh-add -s` reason and no
    prompt;
  - `agent_holds_key`.
- `piv_auth` unit 2.
- `mooring-core`: `card_fields` 2, gateway options 1, options wire round-trip, PromptPurpose
  and gateway wire shapes, `Rdg` store name, the matrix row and PKINIT footnote, a per-kind
  sample.
- `mooring-audit`: 3 new wire rows.
- `mooring-app`:
  - gateway `yes` pins `known_rdg_certs` (the RDP store is untouched, audit `protocol: rdg`);
  - gateway `once` plus target `once` are both kept;
  - the role credential reaches the protocol;
  - `close_code_of` gateway rows;
  - `gateway_status` wire;
  - `smart_card` plan + pre-flight.
- Full gate (`cargo test -p mooring-proto-rdp -p mooring-core -p mooring-store -p mooring-http -p
  mooring-app -p mooring-proto-ssh -p mooring-audit -p mooring-proto-kube`): **1212 passed, 0 failed, 4 ignored**
  (lab/manual) — app 508, proto-rdp 97, core 213, store 109, http 42, proto-ssh 156, audit 41,
  proto-kube 46. Run per package because the shared volume hit ENOSPC on the combined run; the
  cleanup rule (incremental + test executables > 60 min) was applied twice.
- `cargo deny --offline check`: advisories ok, bans ok, licenses ok, sources ok (one
  pre-existing "unmatched license allowance" note).
- Store test `migration_ten_is_latest_and_accepts_the_kind` became `migration_ten_accepts_the_kind`
  (≥ 10), plus `migration_eleven_is_latest_and_accepts_smart_card`; app
  `every_kind_can_be_created_from_its_schema` gained the `smart_card` case.
