# ADR-0016: External secrets from HashiCorp Vault / OpenBao (KV v2)

Status: Proposed · 2026-11-04 (Phase A3; amends ADR-0009 `external_ref`, extends ADR-0013, ADR-0014)

## Context
ADR-0009 stores `external_ref { provider, reference, target_kind }` and refuses it at connect
(`credential.kind_unsupported`). A3 resolves it at connect time from HashiCorp Vault or OpenBao
(API-compatible fork) KV v2, with short-lived tokens and nothing cached on disk. The Vault server
is often internal with a private CA, and the provider's own login (token, AppRole, OIDC) needs
secrets of its own.

## Decision

### 1. Secret sources (new store object)
- Table `secret_source(id, name, kind CHECK (kind = 'vault'), address, namespace NULL,
  auth_method CHECK (auth_method IN ('token','approle','oidc')), auth_mount, credential_id NULL,
  oidc_role NULL, options_json, created_at, updated_at)` (migration `0007_secret_sources.sql`).
  `address` is `https://` (http only for `127.0.0.1`/`[::1]` with `allowHttp`, audited);
  `namespace` becomes `X-Vault-Namespace`.
- Auth material lives in the vault as ordinary credentials:
  - `token` → an `api_token` credential (the Vault token);
  - `approle` → new kind **`vault_approle`** (fields: —; secrets: `role_id`, `secret_id`;
    both sealed, since a `role_id` is half the login) — the 16th kind, amends ADR-0009 §1/§2
    (valid only as a source credential, rejected for every protocol);
  - `oidc` → no stored secret, only `oidc_role`.
- Trust: `known_vault_certs` through `mooring-http` (ADR-0014 §1): pin, `caPem` option, TOFU.

### 2. `external_ref` mapping (amends ADR-0009 fields; secrets still none)
- Fields become `{ provider: "vault", source: <secret_source id>, reference, target_kind,
  version|null, fieldMap|null }`. `reference` = `<mount>/<path>` (segments
  `[A-Za-z0-9._-]+`, no `..`, no empty segment, ≤ 1 KiB; each segment percent-encoded on use).
  `version` pins a KV version (else latest).
- `target_kind` ∈ the kinds that carry secrets and are valid for a protocol (`user_password`,
  `domain_user`, `ssh_key`, `x509`, `api_token`, `kube_token`, `kubeconfig`, `vsphere_user`,
  `vnc_password`, `vnc_user_password`, `sudo_become`); never `external_ref`, `prompt` or
  `vault_approle`. The ADR-0009 matrix uses `target_kind` for compatibility.
- KV keys default to the target kind's field and secret names (`username`, `password`,
  `domain`, `private_key`, …). `fieldMap { <kind name>: <kv key> }` renames (keys must be names of
  the kind, values ≤ 128 B). Fields of the stored `external_ref` cannot carry the target's plain
  fields, so everything comes from KV. Required names missing → `credential.external_shape`.
- Resolved values go through the target kind's **own validators and caps** (ADR-0009 §5,
  `kubeconfig` through the hardened parser) before a `ConnectSecret` is built.

### 3. Resolution at connect (src-tauri `connect_plan`, crate `mooring-secrets`)
1. Get a token for the source from the in-memory token cache, or log in:
   - token: use the stored token; `GET /v1/auth/token/lookup-self` once per process; a token
     whose policies include `root` is **refused** (`credential.external_root_token`);
   - AppRole: `POST /v1/auth/<mount>/login { role_id, secret_id }`;
   - OIDC: §4.
2. `GET /v1/<mount>/data/<path>[?version=N]`, body cap 1 MiB + the target kind's caps, read
   into `Zeroizing<Vec<u8>>`, parsed by a hand-written deserializer straight into
   `SecretString` values (no intermediate `serde_json::Value`). `data.metadata.deletion_time`
   non-empty or `destroyed: true` → `credential.external_not_found`.
3. Build the target credential in memory → `ConnectSecret` → drop everything after the
   handshake (ADR-0004). Reconnect (ADR-0011) re-resolves on every attempt.
- **Never fall back**: no secret value is cached anywhere, not in memory between connects, not
  on disk, not as a previous version. Any failure closes with `credential.external_unavailable`
  and a category (`network | tls | auth_failed | forbidden | not_found | shape | locked`).
- Token cache: `HashMap<SourceId, VaultToken { token: Zeroizing<String>, expires: Instant,
  renewable, accessor_hash }>`, memory only. Expiry = `lease_duration` from the login /
  lookup response; refresh when < 10 % or < 30 s remains (`POST /v1/auth/token/renew-self` if
  renewable, else re-login). On vault lock and on exit: AppRole/OIDC tokens are revoked
  (`POST /v1/auth/token/revoke-self`, best effort, 3 s) and zeroized; stored `token`-method
  tokens are only dropped from memory (they are the user's, not ours to revoke).
- KV v2 secrets carry no lease; dynamic engines (database, SSH OTP, PKI) are out of A3.

### 4. OIDC login in an isolated window (ADR-0013 builder, zero capability)
- Rust: `POST /v1/auth/<mount>/oidc/auth_url { role, redirect_uri, client_nonce }` with
  `redirect_uri = http://localhost:8250/oidc/callback` (the Vault CLI convention; must be in the
  role's `allowed_redirect_uris`) and a random 32-byte `client_nonce`.
- A window `oidc-<sourceId>` opens `auth_url`. Allowed navigation origins: the IdP origin of
  `auth_url` plus the source's `allowedOrigins` (≤ 16). `on_navigation` **intercepts** any
  navigation whose origin and path equal `redirect_uri`: Rust takes `code` and `state`, refuses
  the navigation, closes the window and calls `GET /v1/auth/<mount>/oidc/callback?code&state&
  client_nonce`. No loopback listener is opened. `state` must equal the one in `auth_url`.
- Ephemeral storage by default (IdP sign-in each time); timeout 5 min; one flow per source.
- The window carries no Mooring command and never sees the Vault token.

### 5. 1Password and Bitwarden
Deferred (owner decision 2): 1Password needs the `op` CLI (process spawning, its own session),
a Connect server or an SDK with a native core; Bitwarden's Rust SDK is under a non-OSI licence
and `bws` is a CLI. `provider: onepassword|bitwarden` keeps validating and storing, and connect
keeps returning `credential.kind_unsupported`.

### 6. Library
Our own client in `mooring-secrets` on `mooring-http` (seven endpoints). **Not** `vaultrs` 0.8.0
(MIT, 2026-03-17, maintained): it builds its own `reqwest` 0.13 client, so our pin/TOFU verifier
and ring-only rule (`aws-lc-*` banned, ADR-0011) do not apply, and it deserialises secrets into
`serde_json::Value`/`String`. No new third-party crate.

### 7. IPC (ADR-0008 style)
```
secret_source_list()                               -> SecretSource[]   # no secrets
secret_source_create({ name, address, namespace|null, authMethod, authMount, credentialId|null,
                       oidcRole|null, options: { caPem|null, allowHttp, allowedOrigins[] } }) -> SecretSource
secret_source_update({ id, ...same }) -> SecretSource
secret_source_delete({ id })  -> void        # refused while an external_ref uses it (source.in_use)
secret_source_test({ id })    -> { ok, method, ttlSeconds|null, renewable, policiesCount, error|null }
secret_source_logout({ id })  -> void        # revoke + forget the cached token
external_ref_test({ credentialId }) -> { ok, version|null, present: string[], missing: string[], error|null }
```
`external_ref_test` returns names only, never values. Error codes: `credential.external_unavailable`,
`credential.external_shape`, `credential.external_not_found`, `credential.external_root_token`,
`source.in_use`, `source.not_found`. Audit: `secret.login { source, method, ttl }`,
`secret.resolved { connection, credential, source, reference, version }` (the reference is
inventory-class, R-INV-CRED), `secret.failed { connection, source, category }`,
`secret.revoked { source }`, `secret.source_changed { source, changed[] }` (warning on `caPem`,
`allowHttp`).

## Alternatives considered
- Caching resolved secrets in the vault for offline use: contradicts "nothing cached" and
  turns Vault into a sync source. Rejected.
- Vault Agent / `vault` CLI hand-off: process spawning and a token sink on disk. Rejected.
- OIDC with a loopback HTTP listener (the CLI way): opens a port a T2 process can race;
  navigation interception needs none. Kept only as the fallback if a WebView engine does not
  report the redirect to `on_navigation` (test gate below).
- One kind per provider instead of `external_ref`: ADR-0009 already chose the reference model.

## Security consequences
- T1: nothing of the external secret reaches disk; the vault holds only the source's login.
- T2: tokens and values live in process memory during login/connect (as all secrets do).
  New residue R-EXT-STR where `mooring-http`/hyper buffers the response before we own it.
- T3: Vault TLS through our verifier; a changed pin is a hard stop.
- T5: can trigger resolution for connections it can open anyway; never receives a value or a
  token; cannot drive the OIDC window (no capability).

## Test plan
- Unit: reference/`fieldMap` validation; KV response parser (shapes, deleted, destroyed,
  oversize, non-string values, duplicate keys); target-kind validation reuse; token cache
  expiry/renew/revoke on lock; root-token refusal.
- Integration: a Vault mock in `mooring-testsrv` (token, AppRole, OIDC with a fake IdP page,
  KV v2 versions, 403/404/5xx) and an `#[ignore]` lab test (`MOORING_LAB_VAULT_ADDR`, read-only
  `kv get`). E2E per OS: the OIDC redirect is intercepted (the gate for §4).
- Fuzz: `vault_kv_response`, `vault_login_response`, `external_ref_parse`, `oidc_callback_url`.

## Open questions for the owner
1. Is OpenBao/Vault KV v2 enough for A3, or are dynamic secrets (database, SSH OTP) needed?
2. Confirm deferring 1Password and Bitwarden to B.
3. May `token`-method sources use a long-lived token at all, or only AppRole/OIDC?
4. Should a resolved secret be copyable (copy-password button) or connect-only (proposed:
   connect-only in A3)?

## Sources
HashiCorp Vault API docs: KV v2 (`/data/:path`, `version`, metadata), AppRole login, token
`lookup-self`/`renew-self`/`revoke-self`, JWT/OIDC `oidc/auth_url` and `oidc/callback`
(`client_nonce`); OpenBao API compatibility notes; crates.io API (2026-11-04) `vaultrs` 0.8.0 and
its workspace `Cargo.toml` (`reqwest` 0.13).
