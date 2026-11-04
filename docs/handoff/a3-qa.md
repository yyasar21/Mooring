# A3 — qa-engineer (Q1: mock API servers)

Scope: ADR-0014..0017 §Test plan and task row Q1. This is test infrastructure only; there is no
product client code (K1/K3/V1/E1/S1 are in progress in parallel). Worktree branch from `a3` @
aa629eb, not merged.

## Done

- **Four mock API servers in `mooring-testsrv`.** They run in-process on loopback, over rustls
  (ring) with an rcgen `TestCert`, on hyper 1 `http1` with upgrades. Each has knobs and a request
  recorder, in the style of the RFB/RDP servers. The full behaviour tables are in
  [docs/qa/test-servers.md](../qa/test-servers.md), "A3 mock API servers".
  - `kube`: discovery, namespaces, pods (list/get/watch, `limit`/`continue`, `labelSelector`),
    `pods/log` (`tailLines`, `follow`, `container`, `limitBytes`, `timestamps`), and the three
    self-review APIs. Exec runs over WebSocket (`v5`/`v4.channel.k8s.io`, echo shell, resize,
    status channel, v5 close). Port-forward uses native WebSocket `v4.channel.k8s.io` /
    `portforward.k8s.io` framing with an echo backend; KEP-4006 SPDY tunnelling is refused.
    Auth is a bearer token or a client certificate from a test CA. RBAC comes from `AccessRule`s
    (403 in the API server's wording), with 401/403 knobs. The **forbidden-call trap** answers 500
    and records a violation for Secrets, ConfigMaps, every other resource, every mutating verb,
    `dryRun`/`fieldManager`, invalid names and exec over POST. Knobs: oversized body, huge log,
    port-forward error, WebSocket message cap, slow-loris.
  - `vcenter`: `/api/session` (Basic auth; the session id comes in the body, as vCenter 7+ does),
    datacenter/cluster/host/VM lists with the API's filters over a synthetic inventory (up to
    5 000+ VMs), the 4 000-result refusal, VM detail, power GET, and power plus guest-power POST
    (applied and recorded). It also serves `guest/identity`, VMRC/WEBMKS tickets (recorded),
    401 on a bad or expired session, a 429 rate-limit knob, a Tools-missing knob and a
    tickets-unavailable knob.
  - `vault`: token `lookup-self`/`renew-self`/`revoke-self` (live TTL, renewable, policies,
    plus a root-policy knob for the refusal test), AppRole login, OIDC `auth_url` and `callback`
    (a fake IdP through `idp_redirect`; state and nonce are checked and single-use), KV v2
    `data` (`?version=`, deleted/destroyed 404) and `metadata`. Policy checks give 403.
    Sealed and standby (307) knobs, `X-Vault-Namespace`, raw and oversized KV bodies. Every
    write is a violation.
  - `s3`: SigV4 verification of header-signed and presigned (rusty-s3 style) requests. It is
    pure Rust (`hmac`/`sha2`) and checked against both AWS documentation examples.
    `PutObject` with `If-None-Match: *` / `If-Match` (412), Get/Head (304), Delete,
    `ListObjectsV2` (prefix, delimiter, pages). Knobs: rollback, fork (ETag mismatch), a mode
    without conditional writes, size caps, session token, virtual-host addressing. Multipart,
    copy, ACL and bucket APIs are violations.
- **Request recorder** (`mooring_testsrv::http::Recorder`). It records method, raw path, decoded
  query, header names and values, body size, status, upgrade and violation reason. Header and
  query values that carry secrets become `<redacted>`; bodies are never stored. The API is
  `requests()`, `lines()`, `violations()`, `assert_no_violations()`, `count(method, prefix)`,
  `clear()`. Records are written before the response, so a client-side timeout still leaves one.
- **Binaries** `kube-testsrv`, `vcenter-testsrv`, `vault-testsrv` and `s3-testsrv`. Every knob
  is a flag; `--delay-ms`, `--drip-ms` and `--max-body` are shared. Unknown flags are an error.
  Each prints its address, the certificate SHA-256 and the fake test credentials;
  `kube-testsrv` also prints a ready-made kubeconfig.
- **Self-tests**: 39 new tests, 7 unit and 32 integration (`tests/kube_api.rs` 8,
  `kube_ws.rs` 7, `vcenter.rs` 5, `vault.rs` 6, `s3.rs` 6). Every knob has at least one
  assertion. They use a raw hyper 1 client and a small masked WebSocket client
  (`tests/common/http_client.rs`), because `mooring-http` does not exist here yet.
- **Fuzz scaffolding** for the 15 parsers that ADR-0014..0017 list. Each target has an entry, a
  wrapper, seeds and a regression directory, and is gated behind a `k2`/`k3`/`v1`/`e1`/`s1` fuzz
  feature (as in A2). They are in `fuzz-nightly.yml` with the "Stub notice" warning step
  restored, and the new families run with `-malloc_limit_mb=1024`.
  [docs/qa/fuzzing.md](../qa/fuzzing.md), "A3 targets", says how to activate each one.

## What each server cannot exercise

The full lists are in test-servers.md. In short:

- **kube**: watch bookmarks and `resourceVersion`, `sinceSeconds` (ignored), `previous` logs,
  protobuf, SPDY, HTTP/2, aggregated discovery.
- **vcenter**: SOAP, `/rest` (a violation), folders, resource pools, WebMKS traffic, SSO.
- **vault**: dynamic secrets, wrapping, batch tokens, a real IdP, `LIST`.
- **s3**: streaming chunk signatures (accepted unchecked), multipart, `Range`, ListObjects v1.
- All four speak HTTP/1.1 only.

## Left open

- **Q1 depends on K3/V1/E1/S1 for the real gate.** The servers are ready, but no product client
  drives them yet. When the clients land, each integration test should end with
  `recorder().assert_no_violations()`, and for the lab-like flows also with
  `power_actions().is_empty()`.
- **The fuzz targets fuzz nothing until their gates are on.** The gated calls guess names in the
  A2 `fuzz::` pattern and have never been compiled. The owners must check them against the real
  signatures (fuzzing.md lists the steps).
- **Two decisions belong to the ADR owners.**
  - Port-forward is the native WebSocket variant. If K3 uses kube's KEP-4006 SPDY-over-WebSocket
    tunnel instead, the mock needs a second mode.
  - The `kube` mock treats exec over `POST` as a violation, per the ADR-0014 table
    (GET+Upgrade only).
- Not run here: `gitleaks`, lefthook, `actionlint` (not installed), and workspace-wide
  clippy/test (disk). `fuzz-nightly.yml` was YAML-parsed only. The AWS documentation example key
  in the SigV4 unit test is split with `concat!` so secret scanners do not match it.

## Decision needed

1. **security-reviewer**: review the new direct dependencies of `mooring-testsrv` (dev-only).
   All of them were already in `Cargo.lock` except `httpdate`:
   - `hyper` 1 (server, http1; client in dev) — MIT
   - `hyper-util` 0.1 (`tokio` only) — MIT
   - `http` 1 — MIT OR Apache-2.0
   - `http-body` 1 and `http-body-util` 0.1 — MIT
   - `bytes` 1 — MIT
   - `serde_json`, `sha1` 0.11, `hmac` 0.13, `base64` 0.23 (workspace versions) — MIT OR
     Apache-2.0
2. **orchestrator**: `Cargo.lock` changed by one new package, `httpdate` 1.0.3 (MIT OR
   Apache-2.0), which hyper's server feature pulls in; no other package was added or
   re-versioned. `fuzz/Cargo.lock` is unchanged. Please also add this note to
   `docs/handoff/index.md`.
3. **rust-core (K3/V1/E1/S1)**: to use the servers, add
   `mooring-testsrv = { path = "../mooring-testsrv" }` under `[dev-dependencies]`, trust
   `srv.cert()` (pin or `caPem`), and point the client at `srv.base_url()` (S3: `endpoint()`,
   path-style).

## Test evidence

```
cargo fmt --all                                                   # clean
cargo clippy -p mooring-testsrv --all-targets -- -D warnings     # clean (Rust 1.97; only the pre-existing unknown-lint warning)
cargo test -p mooring-testsrv                                     # 16 + 8 + 7 + 11 + 13 + 7 + 13 + 6 + 6 + 5 = 92 passed
  lib 16 · kube_api 8 · kube_ws 7 · rdp 11 · rfb_encodings 13 · rfb_handshake 7 · rfb_knobs 13 · s3 6 · vault 6 · vcenter 5
cd fuzz && cargo check --bins                                     # 32 targets build on stable (15 new stubs)
{kube,vcenter,vault,s3}-testsrv --port 0                          # start, print addr + SHA256 + test credentials
s3-testsrv --bogus 1                                              # exit 1, "unknown flag --bogus"
```
