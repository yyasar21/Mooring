# Test servers (`mooring-testsrv`)

`crates/mooring-testsrv` holds two loopback servers for the A2 protocol clients (ADR-0011,
ADR-0012) and four mock API servers for the A3 clients (ADR-0014..0017; see
[A3 mock API servers](#a3-mock-api-servers) below). It is dev-only: `publish = false`, never a
normal dependency of a product crate. Product crates use it as a `[dev-dependencies]` entry in
their integration tests. Every server binds `127.0.0.1` only and generates a fresh self-signed
certificate (rcgen, ECDSA P-256) on every start, unless the caller passes one in.

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

## A3 mock API servers

Four HTTP/1.1-over-TLS mocks serve the A3 clients: `kube` (ADR-0014), `vcenter` (ADR-0015),
`vault` (ADR-0016) and `s3` (ADR-0017). They run in-process on hyper 1. They use the same loopback
and rcgen TLS setup as the RFB and RDP servers. Each needs a Tokio runtime
(`start(config, port).await`). The shared code is in `mooring_testsrv::http`.

### The request recorder (the "never mutates / never calls X" gate)

Every server has a `recorder()` that holds one `RecordedRequest` per request, with these fields:

- `method`, the raw `path` and the decoded `query`;
- `headers` with lowercase names. The values of `authorization`, `proxy-authorization`,
  `cookie`, `x-vault-token`, `vmware-api-session-id` and `x-amz-security-token` are replaced by
  `REDACTED`;
- `body_len` (the body itself is never kept), the response `status`, and `upgrade`;
- `violation`, set when the request hit the server's forbidden-call trap.

These query values are redacted too: `code`, `state`, `client_nonce`, `token`, and the
`X-Amz-Signature`, `X-Amz-Credential` and `X-Amz-Security-Token` parameters. The record is
written before the response goes out. A request the client gave up on (a timeout, or a
slow-loris knob) is still recorded.

```rust
let kube = mooring_testsrv::kube::start(KubeConfig::default(), 0).await?;
// ... drive the product client against kube.base_url() ...
kube.recorder().assert_no_violations();          // panics and lists the offending requests
assert_eq!(kube.recorder().count("POST", "/api/v1"), 0);
let lines = kube.recorder().lines();              // ["GET /version", "GET /api/v1/namespaces", ...]
```

The trap answers `500` with `{"mooringTestsrvViolation": "<reason>"}`. A client that ignores
the status code still cannot hide a violation, because the recorder has it.

### Transport knobs (all four servers)

`HttpKnobs` can be set in the config or later with `set_http_knobs`:

| Field | Flag | Effect |
| --- | --- | --- |
| `response_delay` | `--delay-ms N` | waits N ms after recording, before the response head (client timeouts) |
| `drip` | `--drip-ms N` | slow-loris response: a fixed body goes out one byte every N ms; the full `Content-Length` is announced first |
| `max_request_body` | `--max-body N` | a request body above N bytes gets `413` before the handler runs (default 16 MiB; 80 MiB for S3) |

### `kube`: mock Kubernetes API (`kube-testsrv`, default port 6443)

| Area | Behaviour |
| --- | --- |
| Allow-list (ADR-0014 §4) | `GET /version`, `/api`, `/apis`; `GET /api/v1/namespaces[/{ns}]`; `GET …/pods[/{pod}]` (also `watch=1`); `GET …/pods/{pod}/log`; `GET` with Upgrade on `…/exec` and `…/portforward`; `POST` SelfSubjectAccessReview, SelfSubjectRulesReview, SelfSubjectReview |
| Trap | everything else is a violation: Secrets, ConfigMaps, events and every other resource; any `PUT`, `PATCH` or `DELETE`; any `POST` except the reviews; exec over `POST` (SPDY); `dryRun` or `fieldManager`; names that are not RFC 1123 (`..`, `%2F`, uppercase) |
| Auth | `Authorization: Bearer test-token`, or the client certificate from `client_identity()` (issued by a fresh test CA; `client_cert_auth: false` turns it off). Discovery needs no auth. A wrong or missing credential gets a 401 `Status` |
| RBAC | `AccessRule { verbs, resources, namespaces }`. The default allows get, list and watch on namespaces, pods and pods/log, and create on pods/exec and pods/portforward. A denied request gets a 403 with the API server's wording. The review APIs answer from the same rules |
| Lists | `PodFixture` / `ContainerFixture` fixtures. `default_pods()` has `default/web-0` (two containers), `default/db-0` and `team-a/worker-1`; `many_pods(ns, n)` makes more for scale tests. Supports `labelSelector` equality terms and `limit` + `continue` (a bad token gets 410 `Expired`) |
| Watch | `watch=1` sends one `ADDED` per pod, then the events the test sends with `push_pod_event`, until `timeoutSeconds` (default 300) |
| Logs | `container` (required when the pod has two), `tailLines`, `limitBytes`, `timestamps` and `follow`. With `follow`, the backlog is sent first, then `follow_lines` lines every `follow_interval`; then the stream ends, as if the container exited. `ContainerFixture.log` sets exact lines, so a test can feed control characters and bidi overrides to the sanitiser |
| Exec | WebSocket subprotocols `v5.channel.k8s.io` and `v4.channel.k8s.io`; the `ws_protocols` knob limits them, to test the v5 → v4 fallback. Channels: 0 stdin, 1 stdout, 2 stderr, 3 status, 4 resize `{"Width","Height"}`, and on v5 also 255 close (`[255, 0]` closes stdin, which exits 0). The backend is an echo shell, described below the table. `exec_sessions()` records the container, argv, tty, protocol, every resize, the stdin byte count and the exit code |
| Port-forward | the **native WebSocket** variant (`v4.channel.k8s.io` or `portforward.k8s.io`), as kube-rs's `Portforwarder` and the kubelet's websocket handler speak it. For the i-th `ports=` entry, channel 2i carries data and channel 2i+1 errors; both start with the port as 2 little-endian bytes. Data is echoed back. KEP-4006 SPDY-over-WebSocket tunnelling (`SPDY/3.1+portforward.k8s.io`) is **not** implemented and gets 400. `port_forwards()` records the ports and the echoed bytes |
| WebSocket | RFC 6455 server side: client frames must be masked, fragments are reassembled, a ping gets a pong, and a message above `max_ws_message` (1 MiB) ends the session |
| Hostile knobs | `force_401`, `force_403`, `oversized_body` (list bodies padded with valid JSON), `huge_log` (N bytes, ignoring `limitBytes`), `portforward_error` (text on the error channel, then close), plus the transport knobs |

The exec echo shell behaves like this:

- it echoes stdin to stdout, and prints a `$ ` prompt when `tty=true`;
- `stty size` prints `<rows> <cols>` from the last resize;
- `stderr <text>` writes the text to channel 2 (non-tty only);
- `exit [N]` sends a `Success` or `NonZeroExitCode` status and closes.

Flags: `--token S`, `--no-client-cert`, `--pods N` (adds N pods to `default`), `--force-401`,
`--force-403`, `--oversized-body N`, `--huge-log N`, `--log-lines N`, `--ws-protocols a,b`,
`--portforward-error S`. The binary prints a ready-made kubeconfig with the server address, the
server certificate as `certificate-authority-data`, and the fake token.

**Not exercised:**

- watch bookmarks and `resourceVersion` semantics;
- `sinceSeconds` (accepted and ignored) and `previous` logs;
- protobuf, server-side apply, the SPDY transports and HTTP/2;
- aggregated discovery (`/apis` returns only the two groups the client calls);
- OIDC and exec credential plugins.

### `vcenter`: mock vSphere Automation REST (`vcenter-testsrv`, default port 8443)

| Area | Behaviour |
| --- | --- |
| Session | `POST /api/session` with Basic `alice@example.test:testpass` returns `201` and the session id as a JSON string in the **body**, as vCenter 7+ does. The client then sends `vmware-api-session-id`. `GET` and `DELETE /api/session` work too. `expire_sessions()` invalidates every session, for the 401 → re-login test. `login_count()` and `session_count()` report the sessions |
| Inventory | `GET /api/vcenter/datacenter`, `/cluster`, `/host` and `/vm` with the API's filters: `datacenters`, `clusters`, `hosts`, `vms`, `names`, `power_states`, `standalone` (repeated or comma lists). `InventorySpec` sets the shape (`one_host(n)`, `total_vms(5000)`). Every third VM is off and every fifth has no VMware Tools; IPs are in 198.51.100.0/24. `set_inventory` changes it between refreshes |
| Caps | the lists do not paginate (the real `/api` does not either). A result above `result_limit` (4 000) is refused with `400 UNABLE_TO_ALLOCATE_RESOURCE`, as vCenter does |
| VM | `GET /api/vcenter/vm/{vm}`, `…/power` and `…/guest/identity` (503 without Tools). `POST …/power?action=start\|stop\|reset\|suspend` and `…/guest/power?action=shutdown\|reboot\|standby` change the state. `power_actions()` records each one with its status; refusals are `ALREADY_IN_DESIRED_STATE`, `NOT_ALLOWED_IN_CURRENT_STATE` or `SERVICE_UNAVAILABLE` |
| Console | `POST …/console/tickets {"type":"VMRC"\|"WEBMKS"}` returns `vmrc://clone:cst-…@vcenter.example.test:443/?moid=vm-N` or `wss://<esx host>:443/ticket/<hex>`. `ticket_requests()` records the requests |
| Other | `GET /api/appliance/system/version`. Every other path or method is a violation (500) |
| Knobs | `rate_limit_per_sec` (429 with `Retry-After: 1` above N requests per second), `result_limit`, `tools_missing`, `tickets_unavailable` |

Flags: `--user`, `--password`, `--datacenters`, `--clusters`, `--hosts`, `--standalone`,
`--vms-per-host`, `--rate-limit N`, `--result-limit N`, `--tools-missing`, `--no-tickets`.

**Not exercised:** SOAP / `/sdk`, the deprecated `/rest` API (a violation), folders, resource
pools, vApps, tags, WebMKS traffic itself (only the ticket), and SAML / SSO token exchange.

### `vault`: mock Vault / OpenBao (`vault-testsrv`, default port 8200)

| Area | Behaviour |
| --- | --- |
| Tokens | three fixtures: `hvs.test-token` (`default`, `mooring-read`, 3600 s, renewable), `hvs.root-token` (`root`, no TTL) and `hvs.no-policy` (`default`, not renewable). `GET /v1/auth/token/lookup-self` reports a TTL that counts down in real time. `POST renew-self` gets 400 when the token is not renewable; `POST revoke-self` revokes it. An expired, revoked or unknown token gets 403. `token_events()` records lookup, renew, revoke and login events, with the accessor only |
| AppRole | `POST /v1/auth/approle/login {role_id: test-role-id, secret_id: test-secret-id}` returns a new `hvs.…` token with a 1200 s TTL |
| OIDC | `POST /v1/auth/oidc/oidc/auth_url {role: mooring, redirect_uri, client_nonce}` returns an `auth_url` on the fake IdP `https://idp.example.test/authorize`, with a fresh `state`. The redirect must be `http://localhost:8250/oidc/callback`. `idp_redirect(auth_url)` plays the IdP and the browser: it returns `<redirect_uri>?code=test-oidc-code&state=…`. `GET …/oidc/callback?code&state&client_nonce` checks all three. A state works only once |
| KV v2 | `GET /v1/<mount>/data/<path>[?version=N]` and `…/metadata/<path>`. `default_kv()` holds `secret/servers/web` (v1 and v2), `secret/servers/deleted` and `secret/servers/destroyed`. A deleted or destroyed version answers 404 with its metadata, as Vault does. `lease_duration` is 0, because KV v2 has no lease |
| Policy | a token can read `<mount>/<data\|metadata>/<path>` when one of its policies has a matching `read` prefix (`mooring-read` has `secret/data/` and `secret/metadata/`). `root` reads everything. Anything else gets 403 |
| Trap | these are violations: every write (`POST`, `PUT` or `DELETE` on data or metadata, `destroy`, `delete`, `undelete`), every `sys/*` path except `sys/health`, `auth/token/create`, and every other path |
| Knobs | `sealed` (503 everywhere, `sys/health` 503), `standby` (307 to `vault-active.example.test`, `sys/health` 429), `root_token` (`lookup-self` reports `root` for any token), `force_403`, `raw_kv_body` (an exact KV body, for duplicate keys and non-string values), `oversized_body`. `namespace` in the config makes `X-Vault-Namespace` required |

Flags: `--namespace S`, `--sealed`, `--standby`, `--root-token`.

**Not exercised:** dynamic secrets, leases on secrets, response wrapping, batch tokens, identity
entities, CIDR-bound tokens, a real IdP or JWT validation, the `LIST` method, and HTTP/2.

### `s3`: mock S3 bucket (`s3-testsrv`, default port 9000)

| Area | Behaviour |
| --- | --- |
| Addressing | one bucket (`mooring-sync`), path style `/<bucket>/<key>` or virtual-host `Host: <bucket>.…`. Any other bucket gets `NoSuchBucket` |
| SigV4 | every request is verified for the fake access key `AKIDMOORINGTEST0001`, secret `testsecretkey`, region `us-east-1`. Two forms are accepted. An `Authorization` header: `x-amz-content-sha256` must match the body unless it is `UNSIGNED-PAYLOAD`, and the clock skew must be within 15 minutes. A presigned query: `X-Amz-Expires`, signed header `host`, `UNSIGNED-PAYLOAD` (what `rusty-s3` produces). The two AWS documentation examples check the signer (`s3::sigv4` unit tests). `sigv4::sign_headers` and `sigv4::presign` sign test requests |
| SigV4 errors | `SignatureDoesNotMatch`, `InvalidAccessKeyId`, `AccessDenied` (missing or expired), `RequestTimeTooSkewed`, `XAmzContentSHA256Mismatch`, and `InvalidToken` when `session_token` is set |
| Objects | `PutObject` with `If-None-Match: *` (412 when the key exists) and `If-Match: <etag>` (412 on a mismatch, 404 when missing); `GetObject` and `HeadObject` (`If-None-Match` gives 304); `DeleteObject`; `HEAD /<bucket>`. ETags are quoted hex. Every version is kept (`versions(key)`). `put_object` writes out of band, for "another device pushed" |
| List | `ListObjectsV2` (`list-type=2`, `prefix`, `delimiter` → `CommonPrefixes`, `max-keys` ≤ 1000, `continuation-token`, `start-after`) |
| Trap | these are violations: multipart (`?uploads`, `?uploadId`), `?acl` and other sub-resources, `x-amz-copy-source`, any `POST` (including `?delete`), and bucket-level calls other than `ListObjectsV2` and `HEAD` |
| Knobs | `conditional_writes: false` makes the backend ignore `If-None-Match` and `If-Match`, so the setup probe must report `sync.unsupported_backend`. `rollback: N` makes GET, HEAD and List serve the version N steps back. `fork` makes GET, HEAD and List report a different ETag, so an `If-Match` with it fails. `max_object_size` gives `EntityTooLarge` |

Flags: `--access-key`, `--secret-key`, `--region`, `--bucket`, `--max-object N`, `--rollback N`,
`--fork`, `--no-conditional`.

**Not exercised:**

- chunked `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` signatures (accepted without checking the chunk
  signatures);
- multipart upload, the versioning APIs, object lock and SSE headers;
- `Range`, ListObjects v1, and virtual-host buckets with dots in the name.

### Self-tests

`cargo test -p mooring-testsrv` runs `tests/kube_api.rs`, `kube_ws.rs`, `vcenter.rs`, `vault.rs`
and `s3.rs`. They use a raw hyper 1 client and a small masked WebSocket client in
`tests/common/http_client.rs`. Neither is the product client: `mooring-http` does not exist
yet. Every knob has at least one assertion.
