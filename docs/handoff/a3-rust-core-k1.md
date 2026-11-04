# A3 — rust-core K1: `mooring-http` and the new `CertProtocol` stores (ADR-0014 §1)

Branch: worktree `agent-a0fecab667ee63678`, from `a3` @ aa629eb. Not merged.
**New crate + new dependencies: security review required before merge.**

## Done
- **`crates/mooring-http`** (workspace member and default member). hyper 1.12 + hyper-util
  0.1.21 legacy pool, HTTP/1.1 only (ALPN `http/1.1`), connector = `TcpStream` +
  `tokio-rustls` 0.26 (ring) with our verifier. No `hyper-rustls`, no proxy support, no
  environment variables read.
- **Verifier** (`verify.rs`, mirrors `mooring-proto-rdp/src/tls.rs`): chain via
  `WebPkiServerVerifier` (system roots + `extra_ca_pem`), host-name check, then the ADR-0011
  table (pin before CA). Handshake signatures are always checked with ring (test:
  `a_pin_does_not_bypass_the_handshake_signature`). Session resumption is off, so every
  connection runs the verifier. **Anchored mode** (`ca_exclusive`, ADR-0014 §3): only
  `extra_ca_pem`, no system roots, no pins, no TOFU; a failure is `TrustRejected`.
- **Non-blocking TOFU**: unknown + invalid chain fails the handshake with
  `HttpError::TrustPrompt(Box<TrustDecision>)` before any request byte is sent. The caller
  prompts and either builds a client with `trusted_once = Some(fp)` (no pin written) or lets the
  Gate write the pin. Each new connection reloads `known_*_certs`, so the **same** client works
  after the pin is written. An unreadable store fails closed (`HttpError::TrustStore`).
  `trusted_once` never overrides an existing pin (mismatch stays a hard stop).
- **`TrustDecision`** `{ protocol, host, port, fingerprint, trust: CertTrust, verdict:
  TrustVerdict, info: CertificateInfo }`: in `Trust*` errors, on every response
  (`RawResponse::trust`, `Response::extensions()`), on `WsStream::trust()`, and on the optional
  `trust_events` channel (`try_send`, never blocks). `verdict = CaValid` is the cue for the Gate
  to write a "TLS seen" marker.
- **Caps**: `Content-Length` above the cap fails before reading (also malformed / conflicting
  lengths); frames are counted before they are copied into a `Zeroizing<Vec<u8>>` that grows by
  frame size, never by a declared length; JSON is decoded only from the capped buffer and the
  error carries line/column only. hyper's header buffer is capped (64 KiB, 128 headers).
- **Policy**: token bucket per client (default 10 rps, burst 10), 4 concurrent requests,
  connect 10 s / request 30 s per phase, retries only for GET/HEAD/OPTIONS/PUT/DELETE on connect
  failure, timeout, 429, 502–504 (default 3 attempts, full jitter 200 ms·2ⁿ capped at 2 s,
  `Retry-After` seconds honoured up to the cap); POST and websockets are never retried.
  Redirects are refused; `RedirectPolicy::SameOrigin { max }` follows GET/HEAD only to the base
  origin.
- **Plaintext**: `http://` is refused unless `allow_plaintext` **and** the host is a loopback IP
  literal, and even then refused when the store has a pin or a `tls-required` marker for it.
- **Redaction**: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`,
  `X-Vault-Token`, `vmware-api-session-id`, `X-Amz-Security-Token`, `X-Api-Key` and any
  `*-token` / `*-secret` header are marked sensitive and print `<redacted>` in every `Debug` of
  ours. `tracing` gets method and status only (no path, query, headers or body).
- **`mooring-core::known_certs::CertProtocol`** moved to `known_certs/protocol.rs` (mod.rs was
  at 493 lines) and gained `Kube`, `Vsphere`, `Vault`, `Sync` (`known_kube_certs`,
  `known_vsphere_certs`, `known_vault_certs`, `known_sync_certs`), plus `ALL`, `name()`,
  `connection_protocol()` and `tls_always()`. The `tls-required` marker format is unchanged.
- **src-tauri** `commands/known_certs.rs`: the two exhaustive matches now use `name()` /
  `connection_protocol()`. IPC `known_certs_list/remove` therefore also accept `kube`,
  `vsphere`, `vault`, `sync` (Vault/Sync pins are listed without host names).

## Public API (for K3 / V1 / E1 / S1)
```rust
let mut cfg = HttpConfig::new(CertProtocol::Kube, "https://api.example.test:6443", known_path);
cfg.extra_ca_pem = Some(ca_pem); cfg.ca_exclusive = true;   // kubeconfig CA data (K2/K3)
cfg.tls_server_name = Some(name);                           // kubeconfig tls-server-name
cfg.client_identity = Some(ClientIdentity { cert_chain_der, key_der }); // mTLS
cfg.trusted_once = Some(fp); cfg.trust_events = Some(tx);   // prompt flow / audit feed
cfg.max_body = 16 << 20; cfg.rate = RateLimit { rps, burst }; cfg.redirects = RedirectPolicy::Refuse;
let c = HttpClient::new(cfg)?;                              // validates, no I/O

let h = Headers::new().bearer(&token)?.insert("vmware-api-session-id", &sid)?;
c.get_json::<T>("/api/v1/namespaces?limit=500", &h).await?;          // 2xx + JSON, ≤ max_body
c.post_json::<B, T>("/v1/auth/approle/login", &h, &body).await?;     // never retried; empty → null
c.delete("/api/session", &h).await?;                                 // -> StatusCode
c.request(Method::HEAD, path, &h, None, cap).await?;                 // RawResponse for any status
c.put_raw(key, &Headers::new().insert("If-None-Match", "*")?, bytes, None).await?; // 412 is Ok(raw)
let mut s = c.get_stream("/api/v1/namespaces/ns/pods/p/log?follow=true", &h, max_log).await?;
while let Some(chunk) = s.next_chunk().await? { /* ≤ 64 KiB */ } s.truncated();
let ws = c.websocket(path, &h, &["v5.channel.k8s.io", "v4.channel.k8s.io"], WsLimits::default()).await?;
ws.protocol(); ws.send_binary(b).await?; ws.recv().await; ws.into_inner(); // Stream + Sink<Message>
let svc = c.service(16 << 20)?;  // tower::Service<Request<B>> → Response<CappedBody>, for kube::Client::new
```
- Paths start with a single `/`, ≤ 8 KiB, ASCII without space/`#`/controls (percent-encode);
  they are appended to the base URL's path prefix. `HttpService` also accepts an absolute URI
  of the base origin; other authorities are refused. It keeps hyper's upgrade handle, so kube's
  `ws` exec/port-forward work; it does not retry and refuses redirects.
- Errors: `HttpError::code()` gives `http.*`; `status_class()` → `Unauthorized`, `Forbidden`,
  `NotFound`, `Conflict`, `PreconditionFailed`, `TooManyRequests`, `Server`, `Other`;
  `trust_decision()` for the prompt / mismatch / rejected cases. Non-2xx bodies are discarded
  by the JSON helpers; use `request()` to read an error document.
- Fuzz entries (`mooring_http::fuzz`): `fuzz_certificate_info`, `fuzz_response_headers`
  (`Content-Length`, `Retry-After`, `Location`), `fuzz_json_body`.

## Left open
- QA: cargo-fuzz targets for the three entries above (`fuzz/` is QA-owned).
- No HTTP/2 (kube works on 1.1; watches use one connection each). No proxy support at all;
  an opt-in proxy needs its own decision (CONNECT through our verifier).
- R-EXT-STR (ADR-0016): hyper and rustls buffer response bytes before we own them; our copies
  are `Zeroizing`, theirs are not. Same for the mTLS key inside rustls.
- `known_certs_list` names Kube/vSphere pins only for connections with a `port`; K4/V2 should
  pass the API-server `host:port` from connection options.
- `cargo tree … | grep -iE 'aws-lc|openssl|libz-sys|native-tls'` prints `openssl-probe`
  (pure Rust; locates the CA bundle for `rustls-native-certs`, same as `mooring-proto-rdp`).
  No `openssl-sys`, `aws-lc-*`, `libz-sys` or `native-tls`.

## Decision needed
- Plaintext is limited to loopback IP literals in the crate itself (stricter than an option).
  ADR-0016 wants exactly that; ADR-0017 (S3 on a LAN MinIO over http) would need an ADR change.

## Test evidence
`cargo fmt --all && cargo clippy -p mooring-http -p mooring-core --all-targets -- -D warnings`
clean; `cargo test -p mooring-http -p mooring-core`: core 120 + 9, http unit 10, `trust` 7
(prompt → trusted_once → pin on the same client, mismatch, CA-valid + event, name mismatch +
`tls_server_name`, anchored reject / ignore pins, unreadable store, bad handshake signature),
`policy` 10 (declared and chunked oversize, stream 64 KiB chunks + total cap/truncated, JSON
position-only, rate limit, retry bounds 3 / POST 1 / 429 recovery, redirect refuse /
same-origin / cross-origin, plaintext guard incl. marker, status mapping + 412 `put_raw`, tower
service), `redaction` 1 (tracing + `Debug`), `websocket` 4 (echo + v5/v4 negotiation, protocol
not offered, message cap, non-101). Proptests on all response parsers and fuzz entries.
