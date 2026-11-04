# A3 rust-core — K3: `mooring-proto-kube` (ADR-0014 §2, §4, §5)

Branch: worktree `agent-a0991b89be78edb35` from `a3` @ `24b2b88`. Not merged.
**New crate + new dependencies (kube 5.0, k8s-openapi 0.29): security review required.**

## Done
- **`crates/mooring-proto-kube`** (workspace member + default member). Stack for every
  request — JSON, log stream, WebSocket upgrade: `kube::Client::new(svc)` → `ReadOnlyGuard` →
  `BearerLayer` (sensitive `Authorization`) → `mooring_http::HttpService`. Two kube clients over
  the same `HttpClient`: JSON (16 MiB cap) and streams (cap `maxLogBytes + 1 MiB`, ≥ 16 MiB).
  We only use `kube::Client::send` + hyper's upgrade; bodies are read with our caps into
  `Zeroizing` buffers and decoded with position-free errors (kube's `request*` helpers log the
  body on decode failure, so they are not used). `kube::Config` is never constructed.
- **`clippy.toml`** (crate dir) `disallowed-methods`: `Config::{new, infer, incluster*,
  from_kubeconfig, from_custom_kubeconfig}`, `Kubeconfig::{read, read_from, from_yaml,
  from_env}`, `Client::try_default`; a test greps `src/` for the loaders.
  (`Client::try_from` is not a resolvable path for clippy; it needs a `Config`, which needs
  the disallowed `Config::new`.)
- **`ReadOnlyGuard`** (`guard.rs`, `query.rs`): exactly the ADR §4 table (incl.
  `GET /api/v1/namespaces/{ns}`, which the ADR lists and the brief did not). Read routes:
  GET/HEAD without upgrade; exec/portforward: GET **with** `Upgrade: websocket` +
  `Connection: upgrade`; the three reviews: POST only. Path: ASCII, no `%`, `;`, `\`, empty /
  `.` / `..` segment, no trailing `/`, no absolute URI; `{ns}`/`{container}` = `is_dns_label`,
  `{pod}` = `is_dns_subdomain`. Query: raw alphanumeric keys from a per-route list, each once;
  values strictly percent-decoded then checked (`limit` 1..=500, `continue`, `labelSelector`,
  `watch`, `resourceVersion`, `timeoutSeconds`, `tailLines` ≤ 10 000, `limitBytes` ≤
  `maxLogBytes`, `container`, `follow`, `timestamps`, `sinceSeconds`, `command` ∈ the five
  shells, `stdin/stdout/stderr/tty`, `ports` single 1..=65535); exec requires `command`,
  portforward requires `ports`. `Impersonate-*` headers refused. Refusal = `Refused { method,
  template, reason }` (no concrete path/query kept), error code **`kube.refused`**, audit
  `kube.request_refused { method, template }` (`template = "unlisted"` when no route matched).
- **`KubeClient::connect(&Resolved, &KubeConnOptions, template: HttpConfig)`**: `http_config`
  maps K2 → K1: CA data → `extra_ca_pem` + `ca_exclusive`; no CA or `insecure_skip` → system
  roots + TOFU (`HttpError::TrustPrompt` from the first request, `GET /version`); retry with
  `template.trusted_once` or after the Gate pinned. Token → bearer; client cert → mTLS identity
  (PEM blocks → DER, key in `Zeroizing`). Namespace: options, then context. Records
  `kube.connected { server, identity }`.
- **RBAC**: `preflight(ns) -> RbacSummary { canListPods, canGetLogs, canExec, canPortForward,
  canListNamespaces, identity|null, rules: [{verbs, apiGroups, resources}], rulesIncomplete }`
  (5 SSARs, SSR, trimmed SSRR ≤ 256 rules); denied/404 reviews count as "no". Also
  `whoami()`, `can(verb, resource, sub, ns)`, `rules(ns)`.
- **Browsing**: `namespaces() -> Listing<String>`, `pods(ns, labelSelector) ->
  Listing<PodSummary>`, `pod(ns, name)`; `limit=500` + `continue`, ≤ 10 pages, `truncated`.
  Only the DTO fields are deserialised (no env, annotations). `PodSummary { name, phase, node,
  createdAt, ageSeconds, restarts, containers: [{ name, image, ready, restarts, ports }] }`,
  every string through `clean()` (controls + bidi stripped, length cap).
- **Exec** (`exec.rs`, `frame.rs`): `client.exec(ExecTarget { namespace, pod, container,
  command: ExecCommand }, size) -> ExecSession: Session`. `v5.channel.k8s.io` preferred, v4
  fallback; own channel framing (0 stdin, 1/2 out, 3 status JSON, 4 resize, 255 close),
  `tty=true, stdin=true, stdout=true, stderr=false`. `Bytes` ≤ 64 KiB both ways, channels 256,
  resize debounced 100 ms. Events: `Connected { security: "<subprotocol>" }`, `Bytes`*,
  `Closed`: exit/success/failure → `server_ended` (reason has the status), socket loss →
  `network`, malformed frame → `protocol_error`, user → `user`. Audit `kube.exec.opened` /
  `kube.exec.closed { …, code }` (brief names; the ADR wrote `open/close`). Dropping the session
  still closes and audits (no abort).
- **Logs** (`logs.rs`): `client.logs(ns, pod, LogParams { container, follow, tailLines,
  sinceSeconds, timestamps }) -> LogStream`; `next() -> LogChunk::Data(bytes) |
  End { truncated, reason }`. Request carries `limitBytes = maxLogBytes`, `tailLines =
  min(param or logTailLines, 10 000)`; reader stops at the cap itself → `End { truncated: true,
  reason: "kube.stream_limit" }`. Sanitiser: CSI / OSC / DCS-SOS-PM-APC strings (7-bit and
  C1), C0/C1 controls except `\t\n`, DEL, bidi controls; streaming, line-buffered (16 KiB
  max line). ≤ 8 streams per cluster: the 9th is `KubeError::StreamLimit` (also
  **`kube.stream_limit`**). Audit `kube.logs.opened`.
- **Port-forward** (`portforward.rs`): `client.port_forward(&PodTarget) -> PortForwardStream`
  (`AsyncRead + AsyncWrite`, one `v4.channel.k8s.io` WebSocket per stream, port headers
  checked); `PodForward::open(&client, id, bind, target)` = loopback-only listener (non-loopback
  bind refused; A3 offers no external exposure), ≤ 128 connections, audit
  `session.forward.open/close` with `kind: "pod"`, target `ns/pod:port`. Respects
  `portForwardEnabled`. I did not reuse `mooring-proto-ssh`'s registry (it is bound to russh
  handles); K4 keeps the ids/registry for `forward_list`.
- **Audit**: `AuditSink` (bounded 1024, `dropped()` counter) in `KubeClient::audit()`;
  `KubeAudit::action()` gives the names. `ExecSession::take_audit_events()` is empty by design.
- **Errors**: `KubeError::code()`: `kube.refused`, `kube.rbac_denied` (403), `kube.not_found`,
  `kube.auth_failed` (401), `kube.unsupported_auth`, `kube.invalid`, `kube.status`,
  `kube.protocol`, `kube.stream_limit`, `kube.closed`, or the `http.*` code. `close_code()`
  maps to `CloseCode`; `From<KubeError> for MooringError`.
- **Fuzz entries** (`mooring_proto_kube::fuzz`): `fuzz_exec_frame`, `fuzz_portforward_frame`,
  `fuzz_log_line`, `fuzz_guard_path` (with oracles); all four also run under proptest.

## For K4 (src-tauri)
- `kube_open`: `resolve()` (kubeconfig) or build `Resolved` by hand for `kube_token` (server +
  CA from options, `KubeAuth::Token`), then `KubeClient::connect(&resolved, &opts, tpl)` with
  `tpl = HttpConfig::new(CertProtocol::Kube, "", known_kube_certs)` + `trusted_once` /
  `trust_events`. Map `Http(TrustPrompt)` to the ADR-0011 prompt.
- Drain `client.audit().take()` after every command and on close.
- Coordinator / U1 items not in K3: the cluster session needs an `onEvent` channel with a
  `closed` event; `session_list` rows need `kind: "cluster" | "exec"` (U1 assumed
  `kube: { parentSessionId|null }`); `kube_access`, `kube_namespaces`, `kube_pods` are passive
  (`POLLED_COMMANDS`, `ipc-passive.json`); `kube_access` returns the `RbacSummary` flags;
  `LogChunk.data` is base64 on the wire; `session_close` of the cluster must drop exec
  sessions, `LogStream`s and `PodForward`s (dropping is enough; each audits). Watches
  (`kube_watch`, 50 events/s drop) are **not** in K3: the guard allows `watch=1` on pods, the
  stream reader is `send(req, true)`; K4 or a K3 follow-up adds the line-JSON decoder.
- JWT `exp` peek (ADR §3) is still open (K2 left it for K3/K4; not done here).

## Mock server coverage
`crates/mooring-testsrv::kube` (Q1) was not in my worktree, so `src/mock.rs` is a minimal
in-test hyper mock over loopback plain HTTP (`allow_plaintext` + 127.0.0.1) — **TODO(merge)**:
switch to QA's server. It records every request; each loopback test asserts the recorded set
passes the guard and carried the bearer. Exercised: `/version`, namespaces with two pages
(continue token needing encoding), pods with selector, pod get + 404, 401, SSAR/SSR/SSRR,
logs (sanitised, cap → truncated, 8-stream limit), exec v5 (echo, debounced resize, exit 7 via
channel 3, user close), port-forward stream + loopback listener. **Not** exercised: TLS / CA
anchoring / TOFU against a mock (unit-tested as the `http_config` decision table; the TLS
paths themselves are K1's tests), mTLS client certs end-to-end, v4-only exec servers, watches,
real kubelet error-channel messages, oversized WebSocket messages, the 16 MiB JSON cap.

## Decision needed
- **Error code of the guard**: the coordinator and U1 use `kube.refused`; ADR-0014 §6 says
  `kube.forbidden_request`. I implemented `kube.refused` — the ADR should be amended (or I flip
  one string).
- `kube.stream_limit` is used for both the 8-stream cap (error, as U1 assumed) and the byte cap
  (`LogChunk.end.reason`, as the coordinator described).
- **New build-time C/asm**: `kube-client` → `jsonpath-rust` → `pest` → `pest_stack_guard` →
  `stacker`/`psm` (psm assembles a small stack-switching shim with `cc`; unsafe). Not in the
  ADR's dependency list. jsonpath is only reachable from kube's kubeconfig auth code we never
  call, but it is compiled. Needs the security reviewer's call (accept, or ask upstream to
  feature-gate jsonpath).

## Test evidence
`cargo fmt --all && cargo clippy -p mooring-proto-kube --all-targets -- -D warnings && cargo test
-p mooring-proto-kube`: green, 31 tests (guard matrix: 13 routes × 9 methods × upgrade flag,
24 unlisted resources, 20 traversal/encoding cases, 40 query cases, impersonation, websocket
detection, layer audit; 4 proptests; frame/status/resize/port-header units; sanitiser table +
split input; log path clamp; CA/TOFU table; 9 loopback tests above; source grep). `cargo tree -p
mooring-proto-kube | grep -iE 'aws-lc|openssl-sys|native-tls|reqwest'` is empty
(`openssl-probe` from K1 remains). `cargo deny check licenses bans`: ok.
