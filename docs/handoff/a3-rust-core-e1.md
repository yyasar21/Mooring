# A3 — rust-core E1: external secrets from Vault / OpenBao KV v2 (ADR-0016)

Branch: worktree `agent-a89c425670b5e3b25`, from `a3` @ 24b2b88. Not merged.
**New crate: security review required before merge** (no new third-party dependency; the
lockfile only gains `mooring-secrets` itself). `Cargo.toml` (orchestrator-owned) was touched
only to add the crate to `members` / `default-members`.

## Done
- **mooring-core**
  - Kinds 16/17: `vault_approle` (no fields; secrets `role_id`, `secret_id`, **both sealed**
    as ADR-0016 §1 says) and `s3_access_key` (fields `access_key_id`, `region?`; secrets
    `secret_access_key`, `session_token?`, ADR-0017 §4). New `SecretName`s `role_id`,
    `secret_id`, `secret_access_key`, `session_token`. Neither kind is valid for any protocol.
  - `KindSchema.consumers: [secret_source | sync]` (omitted on the wire when empty);
    `valid_for_consumer` / `check_consumer`. `api_token` and `vault_approle` serve
    `secret_source`, `s3_access_key` serves `sync`. Refusal text: "Vault AppRole is only for
    secret sources.".
  - `ExternalRefFields` gains `source: SecretSourceId?`, `version: u64?` (≥ 1),
    `field_map: {name: kvKey}?` (≤ 32, names of the target kind incl. `otp_seed`, keys
    ≤ 128 B visible text). On **input**, `provider: vault` requires `source` and the strict
    reference grammar; stored A1/A2 rows without a source keep reading. Schema rows `source`
    (enum, options from `secret_source_list`) and `version` were added to the form.
  - `credential::parse_vault_reference` → `VaultPath { mount, path }` (`<mount>/<path>`,
    first segment = mount, `[A-Za-z0-9._-]+`, no `.`/`..`/empty, ≤ 1 KiB, ≤ 64 segments, no
    normalisation). Fuzz entry `credential::fuzz_external_ref(&[u8])`.
  - `secret_source` module: `SecretSourceInput` (IPC shape, camelCase, deny unknown) →
    `validate()` → `ValidSource`; `SecretSource`, `SecretSourceAuth::{Token, AppRole{mount},
    Oidc{mount, role}}`, `SourceOptions { caPem, allowHttp, allowedOrigins }`,
    `OIDC_REDIRECT_URI = http://localhost:8250/oidc/callback`. Address: `https://` only
    (http only to `127.0.0.1` / `[::1]` with `allowHttp`), no userinfo/query/fragment/`%`,
    lower-cased host, ≤ 2048. Namespace / mount / role: `[A-Za-z0-9._-]` segments, ≤ 256.
    `allowedOrigins` only for OIDC, ≤ 16, `https://host[:port]`.
- **mooring-store**: migration **`0007_secret_sources.sql`** (fk-off rebuild of `credential`
  for the new kinds + table `secret_source`, no secret columns, CHECKs tie method ↔
  credential/role). `Store::{create,get,list,update,delete}_secret_source`,
  `external_refs_of`, `sources_using_credential`, `source_of`. The login credential must be
  `api_token` (token) / `vault_approle` (approle). Rows re-validate on read (`Corrupt`).
  `StoreError::InUse { kind, id }`: deleting a source named by an `external_ref`, or a
  credential a source logs in with, is refused. `update_secret_source` returns the changed
  field names for `secret.source_changed`.
- **crates/mooring-secrets** (new): `VaultClient`, `TokenCache`, `SecretsEngine`, resolve
  mapping, OIDC flow, audit hooks, fuzz entries. Nothing is ever written to disk.
- **src-tauri** (minimal): `StoreError::InUse` → `source.in_use` / `credential.in_use`;
  `kinds.snapshot.json` refreshed (two new rows, `consumers` on `api_token`, two new
  `external_ref` fields).

## API for E2 (src-tauri) and the UI
```rust
// once per process
let cache = Arc::new(TokenCache::new(Arc::new(SystemClock::default()), audit.clone()));
let renewer = cache.spawn_renewer(Duration::from_secs(15));
let mut cfg = ClientConfig::new(app_data.join(CertProtocol::Vault.file_name()));
cfg.trust_events = Some(tx);                       // optional audit feed
let engine = SecretsEngine::new(cache, audit, cfg); // audit: Arc<dyn SecretsAudit>

// connect_plan, CredentialFields::ExternalRef(f):
let source = store.source_of(&meta.fields)?.ok_or(..)?;          // source.not_found
let login = |s: &SecretSource| -> Result<LoginMaterial, SecretsError> {
    // open s.auth.credential_id(): api_token.token -> LoginMaterial::Token,
    // vault_approle.role_id/secret_id -> LoginMaterial::AppRole; locked vault ->
    // Err(SecretsError::Unavailable { category: Category::Locked, .. })
};
let r: ResolvedSecrets = engine.resolve(&source, cred_id, &f, &login).await?;
// r.kind, r.fields (validated CredentialFields of the target kind), r.secret(SecretName::Password),
// r.version, r.names(); build the ConnectSecret exactly as for a stored credential, then drop r.
// check_compatible() already follows target_kind.

engine.test_source(&source, &login).await   // -> SourceTest { method, ttl_seconds, renewable, policies_count }
engine.test_ref(&source, &f, &login).await  // -> RefTest { version, present, missing, extra } (names only)
engine.logout(source.id).await              // secret_source_logout
engine.cache().revoke_all().await           // vault lock and app exit (before zeroizing the vault)

// OIDC window (ADR-0016 §4)
let flow = engine.begin_oidc(&source).await?;     // flow.auth_url, flow.allowed_origins
// on_navigation(url): match flow.navigation(url) { Allow => load, Deny => refuse,
//   Callback { .. } => refuse, close window, engine.complete_oidc(&source, flow, url).await? }
```
- Errors: `SecretsError::code()` → `credential.external_unavailable` (+ `category()`:
  `network | tls | auth_failed | forbidden | not_found | shape | locked`),
  `credential.external_shape` (`Shape { missing, extra, invalid }`, names only),
  `credential.external_not_found`, `credential.external_root_token`, `input.invalid`.
  `trust_decision()` gives the certificate prompt (`Trust(Box<TrustDecision>)`).
- Audit (`SecretEvent`): `Login { source, method, ttl }`, `Renewed`, `Resolved { credential,
  source, reference, version, target_kind, fields }`, `Failed { source, category }`,
  `Revoked { source }`; `name()` gives the ADR event name. src-tauri adds the connection.
- Fuzz entries for QA: `mooring_core::credential::fuzz_external_ref`,
  `mooring_secrets::fuzz::{fuzz_kv_response, fuzz_login_response, fuzz_oidc_callback_url}`.
- UI: `credential_kinds()` now lists `vault_approle` / `s3_access_key` (empty `protocols`,
  `consumers`); `external_ref` sends `source` (id) and `version` as a **number**;
  `field_map` is an object (no form row yet). `apps/desktop/src/lib/ipc.kinds.ts` must be
  re-synced with `kinds.snapshot.json`.

## Behaviour notes
- Token cache: lifetime = reported TTL capped at 24 h; a token with no TTL is cached 15 min
  and then re-checked. Refresh when < 10 % or < 30 s remains: renew-self if renewable, else
  drop (revoke when ours); the next resolve logs in again. A cached token refused with
  401/403 is forgotten and **one** fresh login is tried; nothing else retries.
- Root refusal: `policies`, `token_policies` or `identity_policies` containing `root`.
- Extra KV keys (not names of the target kind after `field_map`) are **refused**, as the E1
  task asked; ADR-0016 is silent on this (see Decision needed).
- 503 (sealed / standby), 429 and 5xx → `unavailable/network`; GETs use mooring-http's
  retry policy (default 3 attempts), POSTs never retry.

## Left open
- QA: `mooring-testsrv::vault` was not in this worktree; tests use an in-crate hyper mock
  (`src/mock.rs`, `TODO(merge)`). cargo-fuzz targets for the four entries; lab test
  (`MOORING_LAB_VAULT_ADDR`, read-only `kv get`).
- E2: wiring above, IPC commands of ADR-0016 §7, the OIDC window, `secret.source_changed`
  warnings on `caPem` / `allowHttp`.
- Migration slot 6 is reserved for `0006_vsphere_sync.sql` (V2); `MIGRATIONS` jumps 5 → 7
  with a `TODO(merge)`. After the merge V2's script must stay version 6 (a dev database
  already at 7 would skip it; production has none).
- R-EXT-STR grows: the `X-Vault-Token` `HeaderValue`, the request `Bytes` and
  `serde_json`'s scratch buffer for escaped strings are not zeroized.
- The OIDC callback is a GET and goes through the client's retry policy; a retry after the
  server consumed the code just fails (`auth_failed`).

## Decision needed
1. Spec deviations from the task text, following the ADRs: `vault_approle.role_id` is
   sealed (ADR-0016 §1), `s3_access_key` has `session_token?` and no `endpoint` (ADR-0017
   §4; the endpoint lives in the sync config), error codes are ADR-0016's
   `credential.external_*` (not `secrets.*`), the table is `secret_source` (ADR naming), the
   OIDC redirect is the fixed constant (no per-source redirect), `field_map` is snake_case
   like every other `fields_json` key (ADR writes `fieldMap`).
2. Refuse or ignore extra KV keys? Implemented: refuse (`extra` listed in
   `external_ref_test`). Ignoring would let one KV secret serve several kinds.
3. Credential deletion while a source uses it: refused (`credential.in_use`); the FK is
   `ON DELETE RESTRICT` as a backstop.

## Test evidence
`cargo fmt --all && cargo clippy -p mooring-secrets -p mooring-core -p mooring-store
--all-targets -- -D warnings` clean; `cargo test -p mooring-secrets -p mooring-core -p
mooring-store` green: core 149 + 9, store 31 unit + integration suites, secrets 29.
Secrets tests (loopback mock): token login + KV latest / pinned version + cached reuse +
namespace header; root refusal (not cached), bad token, locked vault; 503 sealed and 429
standby with no fallback; AppRole bad/good login, renew at < 10 % with `FakeClock`, drop +
revoke when not renewable, expiry miss, `revoke_all` on lock (ours revoked, user token only
forgotten), background renewer; server-side revoked token replaced once; KV deleted /
destroyed / absent version → `not_found`; `field_map` + extra/missing; hostile bodies
(> 1 MiB, number, array, duplicate key, wrong types, garbage, bad lookup) → `shape` without
echo; no file created or modified in the data dir across resolves; `test_source` counts;
OIDC state mismatch (callback never sent), 5 min timeout, success + revoke on lock, flow /
source binding; references refused before any request. Unit: mapping table for 11 target
kinds, validators reused (VNC 8-byte cap, bidi, PEM, hardened kubeconfig), `Debug` and
events carry no values, zeroize-on-drop type checks, proptests on every parser. Store: CRUD
without secret material, credential-kind checks, in-use rules, corrupt row, v5 → v7
migration keeping credential links, secrets and folder defaults.
