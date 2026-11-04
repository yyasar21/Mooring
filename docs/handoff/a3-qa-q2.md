# A3 — qa-engineer (Q2: fuzz targets on, hostile-input suites, E2E for Kubernetes)

Scope: ADR-0014..0017 §Test plan, task Q2. Worktree branch `worktree-agent-a5f98317a85d0e192`
from `a3` @ `27433f2` (all A3 Rust work merged there). Five commits, not merged:

| Commit | What |
| --- | --- |
| `5b81819` | fuzz: 12 A3 targets wired to the real parsers, 5 new targets, seeds, stable replay in six crates |
| `60d3d86` | fuzz: clippy doc lints in the replay tests |
| `00a27b2` | hostile-input suites against the QA mock servers (+ `mooring-testsrv` dev-dependency) |
| `2dc2cc9` | E2E: Kubernetes cluster flows (`apps/desktop/e2e/kube.e2e.mjs`, `e2e.yml`, `make e2e`) |
| `d6184e6` | src-tauri tests end with `assert_no_violations()` / `power_actions().is_empty()` |

## PASS / FAIL per item

### 1. Fuzz targets — PASS (12 of 15 ungated; 3 stay gated with a named blocker)

Every target was checked against the real signatures. `fuzz/Cargo.toml` now depends on
`mooring-http`, `mooring-proto-kube`, `mooring-vsphere`, `mooring-secrets` and `mooring-sync`
(`fuzz/Cargo.lock` grew accordingly; it is the fuzz crate's own lockfile).

| Target | Status | Real entry |
| --- | --- | --- |
| `kubeconfig_resolve` | on | `mooring_core::credential::kubeconfig::resolve(&[u8], Option<&str>)` — oracle: `parse` accepted it, `https` server, cert-only CA ≤ 64 KiB or none, visible-ASCII token ≤ 16 KiB or cert pair, DNS-label namespace, the named context resolves equal |
| `external_ref_parse` | on | `mooring_core::credential::{fuzz_external_ref, parse_vault_reference}` — segment grammar oracle |
| `kube_exec_frames` | on | `mooring_proto_kube::{decode_exec, fuzz::fuzz_exec_frame}` — channel oracle, 64 KiB status cap, stdout/stderr borrow the payload |
| `kube_log_sanitize` | on | `mooring_proto_kube::{sanitize_line, fuzz::fuzz_log_line}` |
| `kube_portforward_frames` | **new** | `mooring_proto_kube::{PfDecoder, fuzz::fuzz_portforward_frame}` |
| `kube_guard_path` | **new** | `mooring_proto_kube::fuzz::fuzz_guard_path` (the read-only request guard) |
| `vsphere_inventory_json` | on | `mooring_vsphere::fuzz::fuzz_inventory_json` (`[selector, body]`; seeds rewritten with the selector byte) |
| `vsphere_session_token` | on | `mooring_vsphere::parse_session_token` + crate entry |
| `vsphere_ticket_url` | on | `mooring_vsphere::fuzz::fuzz_ticket_url` (`parse_vmrc_ticket`; the seed was JSON, the parser takes the raw URL) |
| `vault_kv_response` / `vault_login_response` | on | `mooring_secrets::fuzz::{fuzz_kv_response, fuzz_login_response}` |
| `oidc_callback_url` | on | `mooring_secrets::{parse_callback, fuzz::fuzz_oidc_callback_url}` — only the fixed redirect path is a callback |
| `sync_blob_parse` | on | `mooring_sync::{decode_msy1, fuzz::fuzz_msy1}` — size bounds, magic/version, `aad ‖ nonce ‖ ct` = input; the committed `blob-v1.hex` vector is a seed |
| `sync_snapshot_json` | on | `mooring_sync::fuzz::fuzz_snapshot_json` (seeds rewritten: `trust`, `vault_id`, `deny_unknown_fields`) |
| `http_certificate_info` / `http_response_headers` / `http_json_body` | **new** | `mooring_http::fuzz::*` (entries the crate exposed without a target) |
| `jwt_exp_peek` | **gated** (`k2`) | `peek_exp` lives in `src-tauri/src/commands/kube_jwt.rs` (mooring-app) — see Decision 1 |
| `kube_pod_list_json` | **gated** (`k3`) | `browse::PodIn` / `List<T>` are `pub(crate)`; no crate entry — see Decision 2 |
| `s3_error_xml` | **gated** (`s1`) | `mooring-sync` parses no XML at all (presigned PUT/GET/HEAD/DELETE, errors from status + `ETag`, no listing) — see Decision 3 |

Stable replay (`cargo test --test fuzz_corpus`): mooring-core 12 (+3), mooring-http 5,
mooring-proto-kube 7, mooring-secrets 4, mooring-sync 4, mooring-vsphere 5. Each replay also
pins that the accepting seeds keep being accepted and the refusing seeds are refused for their
own reason (so the fuzzer never loses the accepting branch). `fuzz-nightly.yml`: 37 targets, the
`-malloc_limit_mb=1024` family gains `http_*`; the "Stub notice" step stays because three
targets are still stubs. `docs/qa/fuzzing.md` "A3 targets" rewritten (table of real entries,
"Still gated" table, stable command line).

No private key is committed: the `http_certificate_info` seed is a throwaway self-signed EC
certificate for `k.example.test`, and the kubeconfig seeds use token auth only.

### 2. Hostile-input tests — PASS (38 tests, 1 `#[ignore]`d finding)

| File | Tests | Covers |
| --- | --- | --- |
| `crates/mooring-core/tests/hostile_kubeconfig.rs` | 8 | path keys in every spelling (relative, absolute, `..`, `~`, `/proc`, UNC, symlink-style), `exec` / `auth-provider` in ten shapes plus a merge-key alias, > 1 MiB, 5 000 contexts (capped, deterministic), 200-deep nesting, 5 000-entry mapping, bidi / zero-width / C0 / C1 / ESC / BOM in token, namespace, context and server, Kelvin / long-s keys, 64 KiB + 1 and 900 KiB base64, key PEM as CA, binary CA, CA + insecure-skip, basic / impersonation / unknown user fields, bad server URLs, duplicates. No error text carries a value. |
| `crates/mooring-sync/tests/hostile_blob.rs` | 7 | every truncation (format below `MIN_BLOB`, tampered above), `MAX_BLOB + 1`, appended byte, empty plaintext, every header byte (AAD), every nonce / ciphertext / tag byte, stripped and rotated tag, foreign vault, swapped header → `sync.tampered`; header rules are static reasons |
| `crates/mooring-vsphere/tests/hostile_vcenter.rs` | 7 | against `mooring-testsrv::vcenter`: 4 001-VM refusal (`vsphere.too_large`) and 4 000 accepted, own-cap refusal, full read is GETs only, Tools missing, 429 + `Retry-After`, expired session fails closed, slow-loris hits the body deadline; 8 MiB + 1, 100 000-deep array and 200 000 control chars via the in-crate mock. Every test ends with `assert_no_violations()` and `power_actions().is_empty()` |
| `crates/mooring-secrets/tests/hostile_vault.rs` | 6 | against `mooring-testsrv::vault`: 15 raw KV bodies (duplicate keys, non-string / nested / null values, NUL key, empty key, 65 fields, 129-byte key, 50 000-deep value, BOM, `errors` array) → shape; 1 MiB + 1 and 8 MiB padded → "too large", 900 KiB read; sealed / standby (307 not followed) / 403 / root token; hostile references never hit the wire. Every test ends with `assert_no_violations()` |
| `crates/mooring-sync/tests/hostile_s3.rs` | 5 | against `mooring-testsrv::s3`: real `SigV4` on every presigned request, wrong key → one 403 and no retry, object over `MAX_BLOB` → `sync.too_large` (cap exact), rollback and fork knobs through `head`/`get`/`put` (412, never an overwrite), the conditional-write probe refusal with no leftovers, XML error bodies never echoed. **`ListObjects` XML is not applicable**: the backend never lists |
| `crates/mooring-proto-kube/tests/hostile_kube.rs` | 5 + 1 ignored | against `mooring-testsrv::kube`: 16 MiB + 1 list body refused / 15 MiB parsed, 4 MiB log at a 64 KiB cap → `truncated` + `kube.stream_limit`, forced 401 / 403 codes, hostile namespaces and selectors never reach the wire, slow-loris (ignored, QA-Q2-1). Every test ends with `assert_no_violations()` |

To put these in `crates/*/tests/**`, `mooring-testsrv` was added under `[dev-dependencies]` of
`mooring-proto-kube`, `mooring-vsphere`, `mooring-secrets` and `mooring-sync` (Q1 decision 3,
which rust-core had not picked up). `Cargo.lock` gains only those four dev edges.

### 3. Integration tests end with `assert_no_violations()` — PASS

src-tauri (test files only): `vsphere_sync_tests.rs` (8 tests: `read_only(&vc)` =
`assert_no_violations` + `power_actions().is_empty()`; the power test asserts exactly one
approved action), `commands/sync_tests.rs` (4), `commands/secret_sources_tests.rs` (5),
`secrets_runtime_tests.rs` (4), `commands/kube_tests.rs` (2) and `kube_flow_tests.rs` (2; the
other three already had it). `crates/mooring-{vsphere,secrets,sync,proto-kube}` own tests use
their in-crate hyper mocks (no recorder); the new hostile files above are the recorder-backed
ones for those crates. `cargo test -p mooring-app --lib` for the touched modules: 37 passed.

### 4. E2E — PASS (6 flows)

`apps/desktop/e2e/kube.e2e.mjs` (Playwright + `node:test`, mock transport): open stage-cluster
(read-only banner, identity, contexts, RBAC card for `payments` and the denied `kube-system`
with disabled actions), pod search (name / node / image, empty result), exec into a container
opens a terminal tab that echoes, logs viewer (follow by default, search count = highlights,
only-matches, Stop ends the backend stream, Restart reopens it, closing the tab stops it), pod
port-forward from a port button (loopback `127.0.0.1` default, forward listed, exposure switch
sets `0.0.0.0`, the "Expose this forward?" dialog cancels and then confirms, audit `loopback`
then `external`), and no mutating action anywhere on the tab. Added to `e2e.yml` as its own
step and to `make e2e`. `tsc -p e2e/tsconfig.json` clean.

### 5. Checks — PASS

```
cargo fmt --all -- --check                                                   clean
cargo clippy -p mooring-core -p mooring-proto-kube -p mooring-vsphere \
  -p mooring-secrets -p mooring-sync -p mooring-http --tests -- -D warnings  clean (only the pre-existing unknown-lint warning)
cargo test -p <same six> --tests                                             core 150+12+8 · http 10+5+10+1+7+4 · kube 31+7+5(+1 ignored)
                                                                             · secrets 29+4+6 · sync 32+4+7+5 · vsphere 25+5+7+8+6+7 — all green
cargo test -p mooring-app --lib -- vsphere_sync::tests commands::sync::tests \
  commands::secret_sources::tests commands::kube::tests secrets_runtime::tests sync_runner
                                                                             37 passed
cd fuzz && cargo check --bins                                                37 targets build on stable
pnpm test (apps/desktop)                                                     49 files, 373 passed, 1 skipped
node --test apps/desktop/e2e/flows.e2e.mjs                                   5 passed
node --test apps/desktop/e2e/kube.e2e.mjs                                    6 passed
```

Not run: nightly libFuzzer (no nightly here; stable corpus replay covers the entries),
`gitleaks`, `actionlint` (workflows YAML-parsed only), workspace-wide clippy/test (disk).

## Left open

- The three gated fuzz targets (Decisions 1–3). Once rust-core exposes the entries, each is a
  five-line change in `fuzz/entries/*.rs` plus a replay test.
- `pnpm test` flaked once on `src/stores/sessions.remote.test.ts` ("VNC: view-only … reconnect
  cycle") while the src-tauri build was saturating the machine; 4 of 5 runs green, the file alone
  3/3. Pre-existing, not touched here; worth a look by U-owners if it recurs in CI.
- `vsphere_inventory_json` seeds were raw JSON arrays before; the entry reads the first byte as
  the model selector, so those seeds only ever exercised `DatacenterList` with a VM body. Fixed.
- The in-crate mocks of `mooring-{vsphere,secrets,sync,proto-kube}` still carry their
  `TODO(merge): switch to mooring-testsrv` notes; the dev-dependency is now there.
- ASan on `kubeconfig_parse` (ADR-0014 test plan, named as Q2 in fuzzing.md) is not run; the
  hostile kubeconfig cases are plain `cargo test`s instead. Memory-safety is `forbid(unsafe)` +
  the stable replay; a sanitizer run needs nightly and belongs in `fuzz-nightly.yml` if wanted.

## Decision needed

1. **rust-core (K2/K4)**: move `peek_exp` from `src-tauri/src/commands/kube_jwt.rs` into
   `mooring_core::credential::kubeconfig` (it has no Tauri dependency) so `jwt_exp_peek` can
   fuzz it; the gated entry already calls `mooring_core::credential::kubeconfig::peek_exp`.
2. **rust-core (K3)**: add `pub fn fuzz_pod_list_json(data: &[u8])` to
   `crates/mooring-proto-kube/src/fuzz.rs` (cap check, `serde_json::from_slice::<List<PodIn>>`,
   `PodIn::summary` with the string-bound asserts). The gated entry calls exactly that.
3. **architect / rust-core (S1)**: `s3_error_xml` has nothing to fuzz. Either drop the target
   from ADR-0017's list (the backend maps S3 errors from status + `ETag` and never lists) or
   keep it gated until a listing / error-body parser exists.
4. **rust-core (K3 / mooring-http), QA-Q2-1**: the kube tower path (`HttpService`) has a
   deadline on the response head only. A server dripping a 1.4 KB pod list at 50 ms/byte makes
   `pods()` succeed after ~70 s instead of failing; only the body cap bounds it. Log streams
   are legitimately unbounded, but buffered JSON calls (`get_json` / `post_json`) should carry a
   body deadline. Failing test: `crates/mooring-proto-kube/tests/hostile_kube.rs::slow_loris_times_out`,
   `#[ignore = "QA-Q2-1 …"]`. The vCenter and Vault clients use the buffered helpers and do time
   out (`hostile_vcenter.rs::slow_loris_hits_the_body_deadline`).
5. **orchestrator**: `Cargo.lock` changed by four dev-dependency edges (`mooring-testsrv` under
   `mooring-proto-kube`, `mooring-vsphere`, `mooring-secrets`, `mooring-sync`); no package added
   or re-versioned. `fuzz/Cargo.lock` (fuzz-crate owned) grew by the five product crates'
   trees. Please add this note to `docs/handoff/index.md`.
6. **security-reviewer**: no new dependency anywhere; the `mooring-testsrv` dev edges are
   workspace-internal.

## Test evidence

Counts are in §5. Product bugs found: one (QA-Q2-1, Decision 4). Everything else behaved as
the ADRs say: every cap fired with a static reason, no secret or server text in any error,
no violation recorded by any mock in any test, no power action ever sent without the native
confirmation.
