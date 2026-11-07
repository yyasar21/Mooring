# ADR-0026: Dynamic Vault secret engines, 1Password Connect and Bitwarden Secrets Manager

Status: Accepted 2026-11-08 (owner decisions 35–38 at the recommended defaults: 1Password via Connect, Bitwarden via `bws`, PKI revokeCertOnDisconnect off, ssh_sign as the `certificate` role) · 2026-11-07 (Phase A5 / v0.2.0; extends ADR-0016 §1–§3, ADR-0009 `external_ref`,
ADR-0020 §3 process pattern, ADR-0024 §1; owner decisions 8–9 revisited)

## Context
`mooring-secrets` resolves `external_ref { provider: vault, source, reference, target_kind,
version, fieldMap }` from KV v2 only (`client.rs::read_kv2`, `engine.rs`, `resolve.rs`), with an
in-memory `TokenCache` that renews and revokes **our** tokens on lock/exit (`cache.rs`). KV
values carry no lease. Owner decision 8 deferred dynamic engines (database, PKI, SSH CA/OTP) and
decision 9 deferred 1Password/Bitwarden (kinds reserved in `RefProvider`). The owner's stance
is "no cloud dependency": Vault/OpenBao are self-hosted; Bitwarden can be self-hosted with
Secrets Manager; 1Password cannot be self-hosted at all — only its **Connect** server runs
on-premises and syncs from 1password.com. The Bitwarden Rust SDK (`bitwarden-core` 4.0.0) is
`GPL-3.0-only OR LicenseRef-Bitwarden-SDK` — not on the allow-list; `bws` is a CLI.

## Decision

### 1. `external_ref` gains `engine` (Vault sources; ADR-0016 §2 fields unchanged otherwise)
| `engine` | `reference` | request | yields → `target_kind` | lease |
| --- | --- | --- | --- | --- |
| `kv2` (default) | `<mount>/<path>` | `GET /v1/<mount>/data/<path>` | as today | none |
| `database` | `<mount>/<role>` | `GET /v1/<mount>/creds/<role>` | `username`, `password` → `user_password` | `lease_id`, `lease_duration`, `renewable` |
| `ssh_sign` | `<mount>/<role>` | `POST /v1/<mount>/sign/<role> { public_key, valid_principals?, ttl?, cert_type: user }` | `signed_key` → `ssh_key.certificate` (or `ssh_sk_key.certificate`) next to the vault's own key | none (cert TTL) |
| `ssh_otp` | `<mount>/<role>` | `POST /v1/<mount>/creds/<role> { ip, username }` | `key` → `user_password.password` (one use) | `lease_id` (revoked by first use) |
| `pki` | `<mount>/<role>` | `POST /v1/<mount>/issue/<role> { common_name, ttl?, alt_names? }` | `certificate`, `private_key`, `ca_chain` → `x509` | `lease_id` when the role is configured for leases; `serial_number` |
- `ssh_sign` is a **modifier**: the credential is the user's `ssh_key` / `ssh_sk_key` with
  `external_ref` as *secondary role `certificate`* (ADR-0009 §3 gains role `certificate`,
  `connection_credential.role` CHECK extended) — the private key stays in the vault; only the
  public key goes to Vault. `principals` (≤ 16, ≤ 64 B each) and `ttl` (≤ 24 h) are fields.
- `ssh_otp`/`pki`/`database` are primary credentials via `target_kind` as in ADR-0016; `pki`
  values feed the `x509` validators and caps (64 KiB each).
- Parsers: one hand-written deserializer per response shape into `SecretString` (ADR-0016
  pattern), fuzz target per shape.

### 2. Lease lifecycle (`mooring-secrets::leases`, rust-core)
```rust
pub struct Lease { id: Zeroizing<String>, source: SecretSourceId, session: SessionId,
                   expires: Instant, renewable: bool, kind: LeaseKind }
pub struct LeaseRegistry;   // memory only; maintain() every 30 s: renew at 2/3 TTL
                            // (PUT /v1/sys/leases/renew { lease_id, increment }); revoke
                            // (PUT /v1/sys/leases/revoke) on session close, vault lock, exit
```
- Renew failure → the session keeps running (the DB account may be dropped by Vault; the
  server decides) and `secret.lease_renew_failed { session, category }` is audited; the header
  shows "lease expired". Revoke is best effort (3 s), audited `secret.lease_revoked`.
- Reconnect (ADR-0011) resolves a **new** lease; the old one is revoked first. PKI: revoke by
  serial (`POST /v1/<mount>/revoke`) only when the connection option `revokeCertOnDisconnect`
  is set (default off: revocation lists grow).
- Never cached: a lease id is not a secret value but is treated as one (RAM only, zeroized).

### 3. 1Password — **Connect server** (`provider: onepassword`, new source kind)
- `secret_source.kind = 'onepassword'`, `address = https://connect.example.test:8080`, auth
  `token` → an `api_token` credential (the Connect bearer token), trust through `mooring-http`
  + `known_onepassword_certs` (ADR-0014 §1 pins/TOFU/`caPem`). Reference =
  `op://<vault>/<item>[/<section>]/<field>` (ADR-0009 source 16; parsed with caps, fuzzed);
  resolution: `GET /v1/vaults?filter=title eq "<vault>"` → `GET /v1/vaults/{id}/items?filter=
  title eq "<item>"` → `GET /v1/vaults/{id}/items/{id}` → fields by `label`/`id` (and
  `?attribute=otp` → the TOTP seed field type). Default field names per `target_kind` as
  ADR-0016 §2; `fieldMap` renames. UUIDs are accepted in place of titles.
- Why not the `op` CLI + Service Account: spawns a process whose token must enter its
  environment, and every call goes to 1password.com — a cloud round-trip per connect. Connect
  keeps the resolve path on the LAN; the cloud dependency is 1Password's own (the owner
  accepts it by choosing 1Password at all). Why not the 1Password Rust SDK
  (`onepassword-sdk` 0.1.0): native core, 23 downloads, no track record.

### 4. Bitwarden — **Secrets Manager** via `bws` (`provider: bitwarden`, new source kind)
- Bitwarden SM is available on a self-hosted Bitwarden server (not Vaultwarden) and the public
  API's values are end-to-end encrypted with the SDK's own `EncString` scheme; re-implementing
  it would be "our own crypto over an unversioned format" (R-* class we refuse). The SDK cannot
  be linked (licence). So: `bws` **CLI**, ADR-0020 §3 pattern — absolute path from a fixed list
  (`/usr/local/bin/bws`, `/opt/homebrew/bin/bws`, `%LOCALAPPDATA%\Programs\bws\bws.exe`,
  `%ProgramFiles%\bws\bws.exe`; a path chosen in Settings is refused unless it is in the
  list), no shell, environment cleared except `BWS_ACCESS_TOKEN` (the machine access token, a
  new secret of kind **`bitwarden_access_token`** (19th kind, secret `access_token`, source
  credential only) and `BWS_SERVER_URL` = the source `address` (self-hosted), argv
  `secret get <uuid> --output json`, `stdin` null, 30 s deadline, stdout cap 1 MiB parsed
  into `SecretString` (hand-written, fuzzed), stderr capped and redacted. Reference =
  `<secret uuid>` or `<project>/<key>` (resolved via `secret list --project-id`). `bws` ≥ 1.0
  version check (`bws --version`) once per process; absent → `secret.tool_missing`.
- Why not `bw` (personal vault CLI): a session key (`BW_SESSION`) that unlocks the *whole*
  vault for the child; Secrets Manager scopes a token to projects. Deferred.

### 5. Common rules (ADR-0016 carried over)
No fallback, no caching of values, resolve per connect/reconnect, revoke/forget on lock and
exit (`bws` has nothing to revoke: the token is the user's), target-kind validators and caps,
`external_ref_test` returns names only. `secret_source_test` per kind (Connect `GET /heartbeat`
+ `/v1/vaults`; `bws` `--version` + `project list`). Audit `secret.resolved` gains `engine`
and `provider`; new `secret.lease_*`, `secret.tool_spawned { provider, exit }`. Codes:
`credential.external_engine`, `secret.lease_failed`, `secret.tool_missing`, `secret.tool_version`,
`secret.tool_failed`, `source.kind_unsupported`.

## Alternatives considered
- Vault Agent sidecar / templates: process + token sink on disk (ADR-0016 rejected).
- `vaultrs`: still builds its own `reqwest`/TLS (ADR-0016 §6). Rejected.
- 1Password `op` CLI: §3. 1Password Connect also rejected as "cloud" → then 1Password is not
  offered at all (owner decision 35).
- Bitwarden public API + own `EncString` decryption: §4. Bitwarden SDK: licence.
- A plugin/subprocess protocol for arbitrary secret tools (`mooring-secret-helper`): more
  general, but every helper becomes a trusted executable; not now.

## Security consequences (T-SEC deltas)
- T2/T4: `bws` is a trusted executable from a fixed path; a writable path in that list is
  the same class as `ping` in ADR-0020 (R-NET-PROBE) but now carries a secret in the child's
  environment for the child's lifetime — **R-SEC-CLI** (accepted per source, opt-in; the
  Settings card names the path and its SHA-256 is pinned after the first use, `secret.tool_changed`
  warning when it changes).
- T3: Connect and Vault through our verifier; `bws` uses its own TLS to the server URL (no
  pin of ours) — documented in the Settings card.
- Leases: a crashed Mooring leaves leases to expire by TTL (Vault's design); lock/exit revoke
  ours. Dynamic DB users appear in the target's audit under Vault-generated names, which the
  session header shows for correlation.
- T5: can trigger resolution (as today) and read lease *state* (expiry, not ids).
- New kinds: `bitwarden_access_token`; new tables: none (sources reuse `secret_source` with
  `kind` CHECK extended: `vault | onepassword | bitwarden`). No new crate.

## UI
Secret-source form per kind (Vault: unchanged; 1Password Connect: address, token credential,
CA; Bitwarden: server URL, access-token credential, `bws` path from the list); `external_ref`
form gains `engine`, principals/TTL (ssh_sign), common name (pki); session header chip "lease
expires in …" with renew/failed states; credential role "certificate" on SSH connections.

## Test plan
- Unit: reference parsers (`op://`, project/key), response deserializers per engine (shapes,
  oversize, non-string), lease math (2/3 renew, clock skew), revoke on lock/close/exit order.
- Integration: Vault mock gains `database/creds`, `ssh/sign`, `ssh/creds`, `pki/issue`,
  `sys/leases/*`; a Connect mock (`/v1/vaults`, `/items`, filters, 401/404); a scripted fake
  `bws` (test-only path override; version mismatch, bad JSON, slow → deadline, stderr noise).
- Fuzz: `vault_db_creds`, `vault_ssh_sign`, `vault_pki_issue`, `connect_item_json`,
  `bws_secret_json`, `op_reference_parse`.
- Manual gate: lab OpenBao (`MOORING_LAB_VAULT_ADDR`, read-only roles), self-hosted Bitwarden.

## Owner decisions needed
35. 1Password through Connect (recommended) — or not at all under "no cloud dependency".
36. Bitwarden through the `bws` CLI (recommended, R-SEC-CLI) — or defer Bitwarden again.
37. PKI `revokeCertOnDisconnect` default off (recommended).
38. `ssh_sign` as a secondary role `certificate` on the SSH key credential (recommended) vs a
    standalone `external_ref` kind that embeds the key.
