# A3 — rust-core F1: follow-ups before security review 6

Branch: worktree `agent-acaf062a650293479`, started from `a3` @ 729468c (U3), `a3` @ ea3d810
(Q2) merged in (`2a4f976`, clean). Not merged. No manifest or lockfile changed.

## Done
- **`credential.external_*` in `ipc-codes.json`** (`d3f61da`). The golden scanner reads only
  literal codes in `src-tauri/src`, so the codes `SecretsError::code()` produced never reached
  the manifest. `secrets_runtime::ipc_error` now spells the five codes out (mirroring the crate,
  with a `debug_assert_eq!` against `code()`), and
  `secrets_runtime::tests::every_secrets_error_code_is_in_the_golden_list` builds every
  `SecretsError` variant (including `Trust(TrustDecision)`) and checks that its code equals
  `code()` and is in the checked-in list. Golden re-blessed: `ipc-codes.json` gains
  `credential.external_{not_found,root_token,shape,unavailable}`; the manifest and passive
  lists are unchanged. Other crate-side families were already literal: `kube.*` via
  `kube_wire::kube_error`, `vsphere.*` via `vsphere_login::map_error`, `sync.*` via
  `sync::SYNC_CODES`, `source.*` via `connect_plan_external::source_error`;
  `KubeResolveError` via `connect_plan::kube_resolve_error`. Nothing else is produced from a
  crate's `code()`.
- **UI pending map** (`9db50cc`, orchestrator-approved edit of `PENDING_A3_CODES` only): the
  four `credential.external_*` entries are gone. The "A3 codes are Rust codes" test is still
  skipped for one entry, `kube.forbidden_request`: the UI's `errors.ts` and the pending map use
  the ADR-0014 §6 name while Rust emits `kube.refused` (ADR-0014 amendment, K3/K4 handoffs).
  That is a UI-owned rename (`errors.ts` + the map), not a Rust change.
- **Lock gate** (`48607d7`): `support::vault_gated_codes` grows from 22 to 44 commands —
  `secret_source_{list,get,create,update,delete,test}`, `credential_external_test`,
  `secret_source_oidc_begin`, `sync_{configure,status,now,resolve_fork,disable}`,
  `vault_join`, `vsphere_{test,sync_enable,sync_disable,refresh,status}`,
  `vsphere_vm_{power,action,identity}` — every one refuses with `vault.locked` before any
  I/O, with well-formed arguments. `secret_source_revoke` (only drops in-memory material) and
  `secret_source_oidc_status` (passive) are not gated by design and are left out.
- **QA-Q2-1 body deadline** (`3c9f258`): `HttpClient::buffered_service(cap)` is
  `service(cap)` plus `timeouts.request` on the whole response body (`CappedBody` carries an
  optional `tokio::time::Sleep`; a dripped body fails with `HttpError::Timeout`).
  `mooring-proto-kube` builds its `api` stack (lists, gets, reviews, `/version`) on it and
  the `stream` stack (watch, logs, exec/port-forward upgrades) on the plain service, so
  long-lived streams keep only their byte caps. `hostile_kube.rs::slow_loris_times_out` is no
  longer ignored and passes in ~1 s; `mooring-http/tests/policy.rs::
  buffered_service_puts_the_request_deadline_on_the_body` shows the buffered service timing
  out and the plain one reading the same drip to the end.
- **Fuzz entries unblocked** (`57b7ff1`): `peek_exp` moved from `src-tauri/src/commands/
  kube_jwt.rs` (deleted) to `mooring_core::credential::kubeconfig::peek_exp` (uses the
  crate's `data-encoding`, no new dependency; tests moved with it).
  `mooring_proto_kube::fuzz::fuzz_pod_list_json(&[u8])`: cap check at `MAX_JSON_BODY`, then
  `List<PodIn>` → `summary()` with the string-bound oracle (chars, since `clean` counts
  chars); unit test with bidi/ESC/negative/oversized inputs.

## Left open
- **`secret_source_trust({ id, fingerprint })`** — not added (over the one-hour budget). The
  pin path itself is short (`KnownCerts::add_and_save` into `known_vault_certs` + audit
  `cert_decision { protocol: "vault" }`, like the sync Gate), but the UI has nothing to pin:
  `secret_source_test` returns only `error` + `category: "tls"`, while the engine's
  `SecretsError::Trust(TrustDecision)` holds the host, port, fingerprint and
  `CertificateInfo`. A usable prompt needs `SourceTestDto` to grow a `trust: { host, port,
  fingerprint, info } | null` field (DTO contract U3 consumes), the command, a guard row,
  `permissions/mooring-main.toml`, golden re-bless and a `mooring-testsrv::vault`
  self-signed test. Proposal for the next round; security review should see the new DTO
  field. Until then `caPem` is the way out, as U3 documents.
- **QA-owned switches**: `fuzz/Cargo.toml` features `k2` / `k3` can now be turned on and the
  entries `fuzz/entries/{jwt_exp_peek,kube_pod_list_json}.rs` de-stubbed; replay tests for
  both belong in `crates/mooring-core/tests/fuzz_corpus.rs` and
  `crates/mooring-proto-kube/tests/fuzz_corpus.rs` (seeds already exist under
  `fuzz/corpus/`).
- **`kube.forbidden_request` → `kube.refused`** in `apps/desktop/src/stores/errors.ts` and
  the pending map (UI).
- Kube streams still have no idle deadline (by design per QA-Q2-1; `LogStream` has the byte
  cap and the UI closes it).

## Decision needed
- security-reviewer: `buffered_service` is the only behavioural change in a crate (a dripped
  kube list now fails with `http.timeout` / `kube.unreachable` after `timeouts.request`,
  30 s by default). Watch/log/exec paths are untouched.
- orchestrator: nothing in `Cargo.toml` / `Cargo.lock` changed.

## Test evidence
- `cargo fmt --all -- --check` clean.
- `cargo clippy -p mooring-app -p mooring-secrets -p mooring-http -p mooring-proto-kube
  -p mooring-core --all-targets -- -D warnings` clean (only the pre-existing unknown-lint
  warning).
- `cargo test -p mooring-app -p mooring-secrets -p mooring-http -p mooring-proto-kube
  -p mooring-core` green: mooring-app lib 251 passed (1 ignored, as before), e2e_flow 19;
  mooring-core 152 + fuzz_corpus 12 + hostile_kubeconfig 8; mooring-http fuzz_corpus 5 +
  policy 11 + redaction 1 + trust 7 + websocket 4; mooring-proto-kube 32 + fuzz_corpus 7 +
  hostile_kube 6 (0 ignored); mooring-secrets 29 + fuzz_corpus 4 + hostile_vault 6.
- `cd apps/desktop && pnpm test`: 57 files, 422 passed, 1 skipped (the `kube.forbidden_request`
  skip above).
