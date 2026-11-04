# A3 rust-core — K4: Kubernetes commands in src-tauri (ADR-0014 §5, §6)

Branch: worktree `agent-a99badec3a10f92ae` from `a3` @ `6bd87c9`. Not merged.
**Touches `permissions/mooring-main.toml` (9 new `allow-kube-*`, main only) and
`src-tauri/Cargo.toml` (path deps on the K1/K3 crates, no new third-party crate): security
review required.**

## Done
- **Cluster session** (`kube_sessions.rs`, `commands/kube_cluster.rs`): a registry entry with
  `Control::Kube(KubeRole::Cluster)`, protocol `kubernetes`, no terminal. Holds the
  `KubeClient` (token / client key in memory only), the RBAC cache, log streams, pod
  forwards and its exec children. `session_close`, the UI channel going away, or a vault
  lock tears it all down (logs aborted + audited, forwards dropped, shells closed, client
  dropped). Its task is the **only writer of `known_kube_certs`** (ADR-0011 Gate contract:
  `yes` pins, `once` = `trusted_once`, anything else rejects; ≤ 3 prompts per open).
- **Exec** = an ordinary terminal session (`Control::Kube(KubeRole::Exec { parent })`):
  `session_factory::kube_exec` boxes `ExecSession` as `Box<dyn Session>`, `run_exec` drives
  it with the SSH `session_task::drive`; `session_send` / `session_close` / detach as usual.
- **`connect_plan::kube`** (separate block): connection must be `kubernetes`; options;
  primary credential `kubeconfig` (secret `kubeconfig_yaml`, context = options → credential
  → `current-context`, `resolve()`) or `kube_token` (secret `token`, visible ASCII ≤ 16 KiB,
  `server` + `caPem` from options); **`check_credential(kind)`**; `tlsServerName` override;
  **JWT `exp` peek** (`commands/kube_jwt.rs`, unverified): expired → `kube.auth_failed` before
  any request, otherwise `tokenExpiresAt` in `connected`.
- **`check_credential` at save time** (`kube::save_check`) in `connection_create`,
  `connection_update` and `connection_options_set`: a stated conflict (`server`/`caPem` with
  `kubeconfig`, `context` with `kube_token`) is refused and the write rolled back; a
  `kube_token` connection without `server`/`caPem` *yet* is accepted (the form saves options
  after creating the connection) and refused at `kube_open` (`input.invalid`).
- **Lock** (`vault::lock` → `kube_sessions::close_all`): every cluster, exec shell, log stream
  and pod forward ends; `closed { code: "vault_locked" }` on the cluster and exec channels.
- **Audit** (new `mooring-audit` variants, snake_case like the rest): `kube_cluster_opened
  { connection, server, identity }`, `kube_cluster_closed { reason }`, `kube_exec_opened
  { namespace, pod, container, argv0 }`, `kube_exec_closed { …, code }`, `kube_logs_opened
  { stream, …, follow }`, `kube_logs_closed { stream, …, truncated, reason }`,
  `kube_forward_opened { id, bind, target, exposure }`, `kube_forward_closed`,
  `kube_request_refused { method, template }`; plus `credential_used`, `session_opened/closed`
  and `trust_cert` (protocol `kube`). The client's audit queue is drained after every command.
- Guard table + manifest + `ipc-manifest.json`, `ipc-passive.json` (`kube_access`,
  `kube_namespaces`, `kube_pods`), `ipc-codes.json` regenerated (`MOORING_BLESS=1`).

## IPC (exact)
```
kube_open({ connectionId, onEvent: Channel<ClusterEvent> }) -> { sessionId }
  ClusterEvent =
    { kind: "connected", server, identity: { user, groups[] } | null, contextNamespace: string|null,
      namespace, rbac: Access, allowedNamespaces: string[], execCommand, tokenExpiresAt: string|null }
  | { kind: "prompt", id, message, secret: false, purpose: "certificate_trust", account: null,
      certificate: CertificateInfo }            # answer: session_send({ sessionId, input:
                                                #   { kind: "answer", id, text: "yes"|"once"|"no" } })
  | { kind: "closed", reason, code }            # user | vault_locked | auth_failed | trust_rejected |
                                                # trust_mismatch | network | protocol_error | server_ended
kube_access({ sessionId, namespace }) -> Access                                   # passive, cached
  Access = { listPods, getLogs, exec, portForward, listNamespaces: bool }
kube_contexts({ credentialId }) -> { contexts: string[], selected: string|null }  # names only
kube_namespaces({ sessionId }) -> { items: string[], truncated }                   # passive
kube_pods({ sessionId, namespace, labelSelector?: string|null }) -> { items: PodSummary[], truncated }  # passive
kube_pod({ sessionId, namespace, pod }) -> PodSummary
  PodSummary = { name, phase, node|null, createdAt|null, ageSeconds|null, restarts,
                 containers: [{ name, image, ready, restarts, ports: number[] }] }
kube_exec_open({ sessionId, namespace, pod, container?: string|null, command?: string|null,
                 size: { width, height }, onEvent: Channel<WireEvent> }) -> { sessionId }
  # command ∈ "/bin/sh" "/bin/bash" "/bin/ash" "sh" "bash"; null = the connection's execCommand
kube_logs_open({ sessionId, namespace, pod, container?, follow?, tailLines?, sinceSeconds?,
                 timestamps?, onChunk: Channel<LogChunk> }) -> { streamId: "log-<n>" }
  LogChunk = { kind: "data", data /* base64 */ } | { kind: "end", truncated, reason: string|null }
  # reason "kube.stream_limit" when maxLogBytes stopped it, an error code on failure
kube_logs_close({ sessionId, streamId }) -> null
forward_open({ sessionId, kind: "pod", bind: { host, port }, target: { namespace, pod, port },
               exposure?: "loopback" }) -> PodForward
forward_list({ sessionId }) -> PodForward[]       forward_close({ sessionId, forwardId })
  PodForward = { id: "fwd-<n>", kind: "pod", bind: { host, port }, target: { namespace, pod, port },
                 exposure: "loopback", openedAt, connections }
session_list() rows: + kind?: "cluster" | "exec", parentSessionId?: string  (absent for other protocols)
```
New codes: `kube.refused`, `kube.rbac_denied`, `kube.not_found`, `kube.auth_failed`,
`kube.unsupported_auth`, `kube.stream_limit` (9th stream), `kube.status`, `kube.protocol`,
`kube.closed`, `kube.unreachable` (transport); trust failures use `session.trust_*`; argument
errors are `input.invalid`; a cluster not connected yet is `session.not_connected`.

## UI alignment list (U1 assumed → Rust)
1. `kube_open` returns `{ sessionId }` only; identity / server / namespace / RBAC arrive in the
   `connected` event (U1 assumption 5: yes, there is an `onEvent`, with `closed`).
2. `kube_logs` → **`kube_logs_open`**, `kube_logs_stop` → **`kube_logs_close`**; args flat as U1.
3. Exec: **`kube_exec_open({ sessionId, namespace, pod, container, command, size, onEvent })`**
   instead of `session_open({ kube: { parentSessionId, …, argv } })`; `command` is a string,
   not `argv[]`.
4. `session_list`: `kind` + `parentSessionId` instead of `kube: { parentSessionId }`.
5. `PodSummary.createdAt` may be `null`; extra `ageSeconds`, `restarts`.
6. `kube_watch` / `kube_unwatch` are **not** implemented (rely on the 15 s `kube_pods` poll).
7. Guard code is `kube.refused` (not `kube.forbidden_request`).
8. `kube_contexts` is new (names only); `KubeConnOptions` keeps K2's `portForwardEnabled`
   (U1 wrote `portForward`) and `logTailLines` 1..=100 000 (clamped to 10 000 per request).
9. Pod forwards: `exposure: "external"` is refused (`input.invalid`); U1's confirmation path
   is dead for `kind: "pod"` in A3.

## Left open
- Pod watch (`kube_watch`, 50 events/s drop) — needs a line-JSON decoder in K3.
- `kube_pods` does not take `continue`: K3 follows pages itself (≤ 10 × 500, `truncated`).
- `window_detach` of a cluster session is not refused (it has no UI events to route).
- `known_certs_list` cannot name kube pins (connections have no API `host:port` column).
- RDP/VNC-style `tls-required` marker for kube is not written (kube is always TLS).

## Decision needed
- Audit names are snake_case (`kube_exec_opened`) like every other entry; the brief wrote
  `kube.exec.opened`.
- Save-time leniency for an incomplete `kube_token` connection (above) vs refusing at create.

## Test evidence
`cargo fmt --all && cargo clippy -p mooring-app --all-targets -- -D warnings && cargo test -p
mooring-app`: green. Lib 214 passed (1 ignored, pre-existing), `e2e_flow` 16 passed;
`cargo test -p mooring-audit` 30 passed. All against QA's `mooring-testsrv::kube` over loopback TLS:
- `commands/kube_flow_tests.rs`: full flow (open → `connected` with RBAC → access / namespaces /
  pods / selector / pod / 404 → exec echo + `exit 3` → `server_ended` → `session_list` kinds →
  logs tail 3 → following log + 2nd shell + pod forward echo → **lock** ends cluster, shell, log
  stream and listener with `vault_locked`; all 8 audit names present, no token in the audit
  file); byte cap (`truncated: true, reason: kube.stream_limit`) + 8-stream limit + close
  twice; certificate prompt `no` / `once` / `yes` (pin written, next open silent) and a lock
  during an open prompt; RBAC denials (flags, `kube.rbac_denied` on namespaces / exec / logs,
  `allowedNamespaces`); hostile inputs (namespaces, pod, container, command, selector, tail,
  since, external / LAN bind, wrong kind, unknown target fields, port 0, unknown / long / exec
  session ids) refused **with zero requests recorded**; closing the cluster closes its shell.
- `commands/kube_tests.rs`: credential rules at save time and open (incl. update rollback,
  no credential, SSH connection, unknown context, `kube_contexts`); expired JWT refused with
  nothing sent; live JWT → `tokenExpiresAt`; wrong token → `closed auth_failed` (the mock,
  like real clusters, serves `/version` anonymously, so a 401 in the pre-flight now ends the
  session instead of showing "connected" with every flag false); guard matrix through
  `mooring_proto_kube::check` (Secrets, ConfigMaps, DELETE/POST/PATCH, `..`, `dryRun`);
  `kube_request_refused` mapping; error-code literals; event / chunk / access JSON shapes.
- `commands/kube_jwt.rs`: `exp` peek table. `tests/e2e_flow/kube.rs`: token + options →
  open → browse → exec (connection `execCommand`) → forward → lock → `vault.locked` → unlock →
  reopen. `recorder().assert_no_violations()` in every flow.
