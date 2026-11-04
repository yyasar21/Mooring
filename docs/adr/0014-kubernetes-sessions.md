# ADR-0014: Read-only Kubernetes sessions and the shared `mooring-http` client

Status: Accepted · 2026-11-04 (Phase A3; extends ADR-0004, ADR-0009, ADR-0010, ADR-0011)

## Context
A3 adds Kubernetes: contexts from a kubeconfig, namespaces, pods and containers, `exec` shells,
logs and port-forward. The roadmap says "read-only, never mutates the cluster", and CLAUDE.md
forbids mutations against lab clusters. `kubeconfig` and `kube_token` credentials exist
(ADR-0009); the kubeconfig parser refuses `exec`, `auth-provider`, `tokenFile` and file paths
and requires ASCII keys (review 4, M-12, closed). The threat model gates any Kubernetes consumer
on M-12 and an ASan fuzz run (R-YAML-DEQ). vSphere (ADR-0015), Vault (ADR-0016) and S3 sync
(ADR-0017) all need an HTTPS client too, so this ADR also defines that client once.

## Decision

### 1. `mooring-http` (new crate, shared by ADR-0014..0017)
- `hyper` 1.x + `hyper-util` 0.1.21 legacy client (both already in `Cargo.lock` via Tauri),
  connector = `tokio::net::TcpStream` + `tokio-rustls` 0.26 (in the lockfile) with **our**
  `ServerCertVerifier` from `mooring_core::known_certs` (pin before CA, ADR-0011 table,
  fail-then-reconnect TOFU). ring provider only; no `hyper-rustls`, no
  `rustls-platform-verifier`, no `reqwest` in our code.
- `HttpPolicy { connect_timeout: 10 s, request_timeout: 30 s, max_body: per call, redirects:
  refused, max_concurrent: 4, rate: 10 req/s per origin, user_agent: "Mooring/<ver>" }`.
- **Body caps are enforced while reading** (`http_body_util::Limited`), before any
  `serde_json` call, and `Content-Length` above the cap fails before the first allocation
  (review 5 class: allocation-before-check). Bodies that carry secrets are read into
  `Zeroizing<Vec<u8>>`.
- New `CertProtocol` values: `Kube`, `Vsphere`, `Vault`, `Sync` (files `known_kube_certs`, …).
  The Tauri `Gate` stays the single writer of pins (R2 contract).
- Never logs headers or bodies; `tracing` gets method, path template and status only.

### 2. Kubernetes library
`kube` 5.0.0 (Apache-2.0, released 2026-11-01, MSRV 1.95 = ours) with
`default-features = false, features = ["client", "ws"]`, and `k8s-openapi` 0.29.0 (Apache-2.0,
2026-10-28) with one `v1_*` feature: the **oldest** version 0.29 offers (we then never read a
field older clusters lack). Not enabled: `rustls-tls` (drags `rustls-platform-verifier`, OS FFI),
`openssl-tls`, `aws-lc-rs`, `oauth`, `oidc`, `proxy`, `gzip`, `runtime`, `derive`.
- `kube::Client::new(service, namespace)` takes any tower `Service`; we pass
  `mooring-http` wrapped in our layers (§4, §5). `kube::Config`, `Kubeconfig::read*`,
  `Config::infer`, `Client::try_default` and `TryFrom<Config|Kubeconfig>` are **never** called:
  they go into `clippy.toml` `disallowed-methods`, and a test greps for them.
- New in the lockfile: `kube-client`, `kube-core`, `k8s-openapi`, `tokio-tungstenite` 0.30,
  `tungstenite`, `tower-http` 0.7 (duplicate of 0.6.11), `hyper-timeout`, `jsonpath-rust`,
  `serde-saphyr` (kube's own YAML loader, compiled but unreachable). `unsafe`: hyper and
  tungstenite (masking) contain some; `cargo geiger` numbers go into the dependency PR.

### 3. Kubeconfig → connection
- One connection per context: `protocol: kubernetes`, credential `kubeconfig` (or `kube_token`).
  `KubeConnOptions { context|null, server|null, caPem|null, tlsServerName|null,
  namespace|null, maxLogBytes, allowedNamespaces: string[] }` (`deny_unknown_fields`).
  `server` and `caPem` are required for `kube_token` and refused for `kubeconfig`.
- `mooring_core::credential::kubeconfig::resolve(yaml, context) -> ResolvedContext` extends the
  existing parser (same event-level tree, same caps): `server` (https only), `ca_der`
  (`certificate-authority-data`, PEM certs only, ≤ 64 KiB), `tls_server_name`,
  `insecure_skip_tls_verify`, `namespace`, and exactly one of `token` / `client_cert_der +
  client_key_der` (`*-data` only) as `Zeroizing`. Refused at connect: `proxy-url`,
  `impersonate*`, `username`/`password` (basic auth was removed upstream), an `extensions` key
  is ignored. New `ConnectSecret::Kube { token | client_cert }` (redacted `Debug`).
- Trust: CA data present → the chain **must** validate against it (no TOFU, no system roots;
  a failure is `trust_rejected`: an explicit anchor that fails is a MITM or a misconfiguration).
  No CA data → system roots; an invalid chain → the ADR-0011 TOFU prompt with `known_kube_certs`.
  `insecure-skip-tls-verify: true` is treated as "no CA data", so it becomes a TOFU prompt and
  is never a silent skip. Token lifetime: when the token is a JWT, `exp` is read **unverified**
  for display only ("expires in 42 min"); an expired token fails with `auth_failed`. We do not
  refresh tokens (no exec/OIDC in A3).

### 4. Never-mutate enforcement (`ReadOnlyGuard`, a tower layer under `kube::Client`)
The guard matches `(method, path template)` **before** the request leaves the process; anything
else is refused locally with `kube.forbidden_request` and audited `kube.request_refused { method,
template }`. The allow-list (query parameters are re-checked: `dryRun`, `fieldManager` refused):
| Method | Path template | Purpose |
| --- | --- | --- |
| GET | `/version`, `/api`, `/apis` | discovery |
| GET | `/api/v1/namespaces`, `/api/v1/namespaces/{ns}` | namespace list / get |
| GET | `/api/v1/namespaces/{ns}/pods`, `…/pods/{pod}` (incl. `watch=1`) | pods |
| GET | `/api/v1/namespaces/{ns}/pods/{pod}/log` | logs (`pods/log` get) |
| GET+Upgrade | `/api/v1/namespaces/{ns}/pods/{pod}/exec` | `pods/exec` create (WebSocket) |
| GET+Upgrade | `/api/v1/namespaces/{ns}/pods/{pod}/portforward` | `pods/portforward` create |
| POST | `/apis/authorization.k8s.io/v1/selfsubjectaccessreviews`, `…/selfsubjectrulesreviews` | RBAC pre-flight |
| POST | `/apis/authentication.k8s.io/v1/selfsubjectreviews` | "who am I" |
Secrets, ConfigMaps, events and every other resource are not reachable in A3. `{ns}` and
`{pod}` must be RFC 1123 labels/subdomains (≤ 253). `exec` lets the user change the container's
filesystem, as SSH does; "never mutates" means no API object is created, changed or deleted.

### 5. RBAC pre-flight, browsing, exec, logs, port-forward
- `kube_open` runs `SelfSubjectReview` (identity) and five `SelfSubjectAccessReview`s per
  namespace on demand (`list namespaces`, `list pods`, `get pods/log`, `create pods/exec`,
  `create pods/portforward`) and returns booleans; the UI greys out what the token cannot do.
  If `list namespaces` is denied, the UI offers the context namespace plus `allowedNamespaces`.
- Lists use `limit=500` with `continue`, at most 10 pages; body cap 16 MiB; watches keep one
  stream per open namespace view and drop events above 50/s (the UI re-lists).
- **Exec is a `Session`** (`mooring-proto-kube::KubeExecSession`): `AttachParams { tty: true,
  stdin: true, stdout: true, stderr: false }` over WebSocket (`v5.channel.k8s.io`, falling back
  to v4). `Bytes` in/out ≤ 64 KiB, bounded mpsc 256 as in ADR-0007; `Resize` → kube's terminal
  size channel (debounced 100 ms). The status channel (3) maps to `Closed { code, reason }`
  (non-zero exit → `server_ended`). The argv is chosen in the UI from `["/bin/sh"]`,
  `["/bin/bash"]` or a custom argv (≤ 16 args, ≤ 1 KiB each, no shell interpolation by us).
  Reconnect: never automatic (a new shell is a new process).
- **Logs** are not a terminal: `log_stream` with `limitBytes` = `maxLogBytes` (default 8 MiB,
  max 64 MiB), `tailLines ≤ 10 000`, optional `follow`, `timestamps`, `sinceSeconds`. Rust
  replaces C0/C1 controls except `\t\n` and bidi overrides before the bytes leave, and stops
  at the cap with `truncated: true`. Per cluster at most 8 log streams.
- **Port-forward** reuses the ADR-0010 Forwards panel: the cluster handle is a session
  (`protocol: kubernetes`, no terminal) so `forward_open/close/list` work unchanged with a new
  `kind: "pod"` and `target: { namespace, pod, port }`. Loopback by default; `external` is
  confirmed and audited; forwards close on lock when external (ADR-0010 M-10) and with the
  cluster session. Each accepted local connection opens one stream on kube's `Portforwarder`.

### 6. IPC (ADR-0008 style; conventions unchanged)
```
kube_open({ connectionId })   -> { sessionId, identity: { user, groups[] }, server, contextNamespace|null }
kube_access({ sessionId, namespace }) -> { listPods, getLogs, exec, portForward, listNamespaces: bool }
kube_namespaces({ sessionId })         -> { items: string[], truncated }
kube_pods({ sessionId, namespace, labelSelector|null }) -> { items: PodSummary[], truncated }
kube_watch({ sessionId, namespace, onEvent: Channel<PodEvent> }) -> { watchId }   # kube_unwatch({ sessionId, watchId })
kube_logs({ sessionId, namespace, pod, container, follow, tailLines|null, sinceSeconds|null,
            timestamps, onChunk: Channel<LogChunk> }) -> { streamId }            # kube_logs_stop({ sessionId, streamId })
session_open({ connectionId, size, onEvent, kube: { parentSessionId, namespace, pod, container, argv[] } })
forward_open({ sessionId, kind: "pod", bind, target: { namespace, pod, port }, exposure })
PodSummary = { name, phase, node|null, createdAt, containers: [{ name, image, ready, restarts, ports: number[] }] }
LogChunk   = { kind: "data", data /* base64 */ } | { kind: "end", truncated, reason|null }
```
`session_close` on the cluster session closes its exec tabs, watches, log streams and forwards.
Error codes: `kube.forbidden_request`, `kube.rbac_denied`, `kube.not_found`, `kube.unsupported_auth`.
Audit: `kube.connected { connection, server, identity }`, `kube.exec.open/close { connection,
namespace, pod, container, argv0 }`, `kube.logs.open { …, follow }`, `kube.request_refused`,
`session.forward.*` (existing), `trust.cert.*` with protocol `kube`. `kube_pods`, `kube_access`
and `kube_namespaces` join `POLLED_COMMANDS`, so an auto-refreshing view never keeps the vault
unlocked (ADR-0010 M-8).

## Alternatives considered
- Shelling out to `kubectl`: inherits the user's kubeconfig with `exec` plugins, mutating
  verbs one typo away, and process spawning. Rejected.
- `kube` with its own config loader and `rustls-tls`: runs `exec` providers, reads files and
  uses the platform verifier (no TOFU, OS FFI). Rejected; we only borrow its client and
  WebSocket code.
- Hand-written client without `kube`: the exec/port-forward channel protocols are subtle;
  `kube` is maintained by the CNCF project. Rejected for A3 (revisit if the tree grows).
- RBAC as the only guard: RBAC is the server's policy and tokens are often over-privileged;
  the local allow-list is our promise. Both stay.

## Security consequences
- T3: TLS is ours (pin/CA/TOFU); an explicit kubeconfig CA is never overridable.
- T4: hostile API JSON is size-capped before parsing; exec/log bytes are caps + sanitised; the
  WebSocket framing is tungstenite's (fuzzed upstream, ours below).
- T5: a compromised UI can open shells and forwards the token allows (audited) but cannot send
  a mutating request: the guard sits in Rust under the client.
- New risks: R-KUBE-EXEC (an exec shell can change the container; it is user intent, audited),
  R-KUBE-TOKEN (static bearer tokens live in the vault and in memory for the session).

## Test plan
- Unit: guard matrix (every allowed row, PUT/PATCH/DELETE/POST elsewhere, `dryRun`, path
  traversal `..`, encoded `%2F`, uppercase method); `resolve` per field and refusal; CA/TOFU
  decision table; JWT `exp` peek; log sanitiser; argv caps.
- Integration: a hyper mock API server in `mooring-testsrv` speaks list/watch/log/exec v5 and
  port-forward and **records every request**; the whole UI flow runs and the recorded set must be
  a subset of the allow-list. `#[ignore]` lab test (`MOORING_LAB_KUBECONFIG`): list pods, exec
  `true`, read-only.
- Fuzz: `kubeconfig_resolve`, `kube_pod_list_json` (capped body → models), `kube_exec_frames`
  (channel demux + status JSON), `kube_log_sanitize`, `jwt_exp_peek`. ASan run of
  `kubeconfig_parse` first (R-YAML-DEQ gate).

## A3 task split (covers ADR-0014..0017; → = depends on)
| # | Owner | Package | Depends |
| --- | --- | --- | --- |
| K1 | rust-core | `mooring-http` (connector, verifier, caps, rate limit), `CertProtocol` additions | ADR accept, dep review |
| K2 | rust-core | `kubeconfig::resolve`, `KubeConnOptions`, `ConnectSecret::Kube` | ADR accept |
| K3 | rust-core | `mooring-proto-kube`: `ReadOnlyGuard`, client, exec `Session`, logs, port-forward | K1, K2 |
| K4 | rust-core | src-tauri: `kube_*` commands, cluster session, forward kind `pod`, audit | K3 |
| V1 | rust-core | `mooring-vsphere`: REST session, inventory models, power, tickets (ADR-0015) | K1 |
| V2 | rust-core | store migration 0006 (synced folders, `external_id`), sync diff, scheduler, IPC | V1 |
| E1 | rust-core | `mooring-secrets`: Vault KV v2, token/AppRole/OIDC, token cache (ADR-0016) | K1 |
| E2 | rust-core | src-tauri: `secret_source_*`, resolver in `connect_plan`, OIDC window | E1 |
| S1 | rust-core | `mooring-sync`: `MSY1` blob, S3 via `rusty-s3`, merge (ADR-0017) | K1 |
| U1 | ui-engineer | `ipc.ts` + mocks for every new command; cluster browser, exec tabs, logs viewer | ADR accept |
| U2 | ui-engineer | vSphere import wizard, synced-folder badges, power menu, console actions | U1 |
| U3 | ui-engineer | secret sources, `external_ref` form, sync settings + conflict view | U1 |
| Q1 | qa-engineer | mock API servers (kube, vCenter, Vault, S3) in `mooring-testsrv`; request-recording gate | K3, V1, E1, S1 |
| Q2 | qa-engineer | fuzz targets of ADR-0014..0017, ASan kubeconfig run, E2E with mocks | Q1 |
| R1 | security-reviewer | review 6: guard, power actions, token handling, sync format, threat model rows | all |

## Open questions for the owner
1. Which `k8s-openapi` floor: the oldest version 0.29 supports (proposed), or a fixed `v1_30`?
2. `kube_token` connections: should `server`/`caPem` live in options (proposed) or in a new
   `kube_cluster` credential field?
3. May `exec` offer a custom argv at all, or only `sh`/`bash`?
4. Should Secrets/ConfigMaps stay unreachable in A3 (proposed), even read-only?
5. Is `kubectl`-style `exec` plugin support wanted later (it needs its own ADR and allow-list)?

## Owner decisions (2026-11-04)
1. `k8s-openapi` floor: the oldest version `k8s-openapi` 0.29 supports; bump only with a review.
2. `server` / `caPem` for `kube_token` connections live in connection options.
3. `exec` offers a fixed command allow-list only (`/bin/sh`, `/bin/bash`, `/bin/ash`, `sh`, `bash`);
   no custom argv in A3.
4. Secrets and ConfigMaps stay unreachable in A3, even read-only.
5. `exec` credential plugins stay out; a later ADR may add an allow-listed plugin model.

## Sources
crates.io API (2026-11-04): `kube` 5.0.0, `k8s-openapi` 0.29.0; kube-rs `kube/Cargo.toml`,
`kube-client/Cargo.toml` and workspace `Cargo.toml` on `main` (features, hyper 1.9, tower 0.5,
tower-http 0.7, tokio-tungstenite 0.30, MSRV 1.95); docs.rs `kube_client::Client::new`/`connect`;
Kubernetes API reference for `SelfSubjectAccessReview`, `SelfSubjectReview`, pod `log` params.
