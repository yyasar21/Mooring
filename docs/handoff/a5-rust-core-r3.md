# A5 — rust-core R3: dynamic secrets, 1Password Connect, Bitwarden `bws` (ADR-0026)

Branch `worktree-agent-a48efc5d6b5f743f3`, worktree
`/home/claude/nexus/.claude/worktrees/agent-a48efc5d6b5f743f3`, rebased on `main` (0450043; no
Rust changes there since eea1e00). ADR-0026 still says *Proposed*. I applied the owner's
accepted defaults from the a5-architect decision table: 35 (1Password via **Connect**), 36
(Bitwarden via the **`bws` CLI**, R-SEC-CLI), 37 (`revokeCertOnDisconnect` off by default)
and 38 (`ssh_sign` as the secondary role `certificate`). The architect should flip the status
line.

**No new crate, no new dependency, no manifest, lockfile, workflow or capability change.**
`tokio` `process` was already on in the workspace. SHA-256 comes from `mooring-core`'s
RustCrypto `sha2`, through a new `credential::fingerprint::sha256`.

## Done

### Core (`mooring-core`)
- New kind **`bitwarden_access_token`**. Its only secret is `access_token` (new
  `SecretName::AccessToken`), it has no plain fields, and it is a secret-source login only
  (`Consumer::SecretSource`, no protocol row). **Numbering:** it is appended last in
  `CredentialKind::ALL` (index 17). R4 inserts `ssh_sk_key` *before* it, which gives the
  ADR's order (18th `ssh_sk_key`, 19th `bitwarden_access_token`). R4's migration 0010 then adds
  `'ssh_sk_key'` to the `kind` CHECK.
- New role **`Role::Certificate`** (`"certificate"`, `Role::ALL`), and a new field
  `Connection.certificate_credential`. `check_compatible` has two rules:
  - The `certificate` role takes only an `external_ref` with `engine: ssh_sign`, and only
    on SSH.
  - An `ssh_sign` reference is refused in every other role, with an English sentence for
    the UI.
- New `ExternalRefFields` fields:
  - `engine` (`kv2` default, not serialised, so stored rows are unchanged), `principals`,
    `ttl`, `common_name`, `alt_names` and `username`.
  - `ExternalRefFields::new(..)` builds a value with all of these unset.
  - `external_engine.rs` checks each engine's target kind: `database` / `ssh_otp` →
    `user_password`, `ssh_sign` → `ssh_key`, `pki` → `x509`.
  - It also checks parameter ownership and caps: ≤ 16 principals or alt names, ≤ 64 B per
    principal, TTL 1..=86400 s, `common_name` required for PKI, OTP `username` required.
    Dynamic engines take no `version` and no `fieldMap`.
  - A dynamic reference is `<mount…>/<role>` (`VaultPath::mount_role`).
- Every reference now needs a `source` on input, for every provider. `op://` and Bitwarden
  references are validated there:
  - `external_refs.rs`: `parse_op_reference` (`op://v/i`, `op://v/i/f`, `op://v/i/s/f`, ≤ 256
    B per segment, no `?#\`, no control or bidi characters) and `parse_bws_reference`
    (`<uuid>` | `<project uuid>/<key>`).
  - Fuzz entry: `credential::fuzz_op_reference`.
- `SourceKind::{Onepassword, Bitwarden}` and `SourceKind::login_kind` (Connect →
  `api_token`, `bws` → `bitwarden_access_token`). `SecretSourceInput.kind` defaults to
  `vault`, so A3 payloads still parse. Rules:
  - Non-Vault sources take token only and have no namespace.
  - `options.bwsPath` is Bitwarden-only and must be one of `BWS_PATHS`. The four ADR
    templates are matched as strings; `%VAR%` is expanded at run time.
  - A Bitwarden source refuses `caPem`, because `bws` does its own TLS.
- `CertProtocol::Onepassword` → `known_onepassword_certs`.
- `ssh_cert.rs`:
  - `ssh_public_key_line` builds the public half from the `public_key` field, or from the
    clear half of an OpenSSH key without the passphrase.
  - `check_signed_certificate` refuses a certificate for another key, a host certificate,
    one that is not valid now, or anything malformed.
- Test fixtures (public material only): `testdata::SSH_CA_*`, deterministic Ed25519 subject
  and CA keys.
- `ConnectSecret::PrivateKey` gains `certificate: Option<String>`. It is the stored
  `ssh_key.certificate` or one Vault just signed.

### Store (`mooring-store`)
- Migration **`0009_dynamic_secrets.sql`** (FK-off rebuild like 0003 / 0007, `LATEST = 9`):
  - `credential.kind` CHECK gains `bitwarden_access_token`.
  - `secret_source.kind IN ('vault','onepassword','bitwarden')`, plus `CHECK (kind =
    'vault' OR (auth_method = 'token' AND namespace IS NULL))`.
  - `connection_credential.role` gains `certificate`.
- Secret sources:
  - Reads and writes `kind`, and checks the login credential's kind per source kind.
  - Refuses a kind change on update.
  - `changed` lists include `bwsPath`.
- The `certificate` role is read, written and resolved like `gateway` / `become`.

### `mooring-secrets`
- Dynamic engines (`client_dynamic.rs`, `wire_dynamic.rs`, `engine_dynamic.rs`):
  - Endpoints: `database/creds`, `ssh/sign` (only `public_key`, `cert_type: user`, comma
    principals, `ttl: "<n>s"`), `ssh/creds` (OTP, `{ip, username}`), `pki/issue`,
    `pki/revoke`, `sys/leases/renew` / `revoke`.
  - Responses are parsed by hand-written shapes. Lease ids are capped (1 KiB, visible
    ASCII), held as secrets and capped at a 30-day TTL. `ca_chain` ≤ 16 and PEM ≤ 64 KiB
    each.
  - **Database creds without a lease id → `secret.lease_failed`**, and the credential is not
    used.
  - When the target kind's validators refuse a credential, its lease is **revoked before
    the error returns**.
  - An OTP lease is not kept: the first use consumes it.
  - PKI certificate and chain are joined into `cert_pem` and the key goes to `key_pem`. The
    certificate is revoked by serial only with `ResolveCtx.revoke_cert` (default off).
- `leases.rs` — `LeaseRegistry`, memory only:
  - `maintain()` renews at 2/3 of the TTL (`renew_due`, overflow safe) without holding the
    lock across I/O. A failed renewal marks the lease `renew_failed`, the session goes on,
    the failure is audited, and there are no retry storms.
  - `release(owner, reason)` and `drain_for_lock(reason)` take leases out synchronously;
    `Released::retire()` revokes them best effort, 3 s each, with the token that issued
    them.
  - Lock epoch (L-34 for leases): a lease from a resolve that started before a lock is
    refused and revoked.
  - `status(owner)` reports engine, expiry, renewable and state, never the id.
  - `spawn_maintainer(LEASE_TICK = 30 s)`.
- `SecretsEngine` dispatches on source kind × engine:
  - `resolve_in(.., &ResolveCtx { owner, ip, revoke_cert })`; `resolve` is the no-owner
    form, whose leases are revoked at once.
  - `sign_ssh_key(.., public_key_line)` → `SignedCertificate`.
  - A provider that does not match the source kind → `source.kind_unsupported`. `ssh_sign`
    outside the certificate role → `credential.external_engine`.
  - `test_ref` works for all providers. A dynamic engine issues once and revokes at once.
    `ssh_sign` → engine error ("tested by connecting"). A shape refusal comes back as the
    missing / extra lists.
- **1Password Connect** (`op_client.rs`, `op_wire.rs`):
  - Runs on `mooring-http` (`CertProtocol::Onepassword`, our pins / TOFU / `caPem`, 1 MiB
    cap, redirects refused, `Authorization: Bearer` redacted).
  - Resolution steps: vault by `name eq` (or a 26-character id) → item by `title eq` (or id)
    → item. Each step needs exactly one match. If the server returns an item with another
    id, it is refused.
  - Field mapping: by label or id, or a `fieldMap` rename. `username` / `password` fall back
    to `purpose`, and `otp_seed` to the `OTP` field type (`otpauth://…secret=` unwrapped).
    A **top-level field beats a sectioned one**, and **two candidates at the same level are
    refused**.
  - A one-field reference fills a kind that has exactly one required value; otherwise →
    `credential.external_engine`.
  - Lists are capped (1000 summaries, 256 fields, 64 sections, labels ≤ 256, no control
    characters).
- **Bitwarden `bws`** (`bws.rs`, `bws_wire.rs`):
  - Executables: `BwsConfig::system()` (the expanded templates, absolute paths only, no
    `PATH`) or `BwsConfig::custom(path)` (the test-only override).
  - Each run gets `env_clear` + `BWS_ACCESS_TOKEN` + `BWS_SERVER_URL` (+ `SystemRoot` and
    `CREATE_NO_WINDOW` on Windows), `stdin` null and a pinned argv: `--version`,
    `secret get <uuid> --output json`, `secret list <project> --output json`,
    `project list --output json`.
  - Caps and deadline: stdout 1 MiB and stderr 16 KiB (never surfaced), 30 s, then kill.
  - `--version` must be ≥ 1.0, checked once per path and process.
  - The binary's SHA-256 is pinned, and a change → `secret.tool_changed` plus a re-check.
  - A value maps as is when the kind needs one required value; otherwise it must be a JSON
    object of strings, mapped like KV, with `fieldMap`. With project/key, duplicate keys are
    refused.
- New error codes: `credential.external_engine`, `secret.lease_failed`, `secret.tool_missing`,
  `secret.tool_version`, `secret.tool_failed`, `source.kind_unsupported` (category `tool`
  added).
- New audit events: `secret.resolved` now carries `provider` and `engine`, plus
  `lease_issued`, `lease_renewed`, `lease_renew_failed`, `lease_revoked`, `tool_spawned` and
  `tool_changed`.
- Fuzz entries for QA (`mooring_secrets::fuzz`): `fuzz_vault_db_creds`,
  `fuzz_vault_ssh_sign`, `fuzz_vault_pki_issue`, `fuzz_connect_item_json` and
  `fuzz_bws_secret_json`, plus `mooring_core::credential::fuzz_op_reference`. All have
  proptest never-panic coverage.

### SSH (`mooring-proto-ssh`)
- When a `PrivateKey` secret carries a certificate, `authenticate_openssh_cert` runs first.
  A certificate that does not parse, or that is for another key, is skipped. A server
  refusal falls back to the plain key.
- The test server trusts a CA (`ServerSpec.trusted_ca`). New tests for that are in
  `tests/auth.rs`.

### Audit (`mooring-audit`)
- New variants. Wire names: `secret_lease_issued`, `secret_lease_renewed`,
  `secret_lease_renew_failed`, `secret_lease_revoked`, `secret_tool_spawned`,
  `secret_tool_changed`.
- `secret_resolved` gains optional `provider` and `engine`. An A3 row re-serialises
  byte-identically (tested in `chain_tests_a5.rs`).

### App (`src-tauri`)
- `connect_plan::plan(.., session)`: leases belong to the session id.
  - `prefetch` first revokes the session's old leases (reconnect, reason `reconnect`), then
    resolves.
  - An `ssh_otp` reference gets the target IP: a literal, or the first DNS answer.
  - SSH `certificate` role: the public line comes from the stored `ssh_key` (field, or
    opened from the vault) or from a resolved `ssh_key` primary. Vault signs it and the
    certificate is attached to `ConnectSecret::PrivateKey`. A role without a key primary →
    `credential.external_engine`.
  - 1Password and Bitwarden references now resolve at connect.
- `SecretsRuntime`:
  - The lease maintainer starts with the renewer.
  - `release_session` is called from `session_task::finish`, from SSH or graphical open
    failures after the plan, and through `TaskContext.secrets` (kube: `None`).
  - `lease_status`.
  - `on_lock` / `shutdown` drain **leases before tokens** and revoke them in that order.
  - Bitwarden logins open `access_token`.
  - `ipc_error` maps the new codes.
- `session_list` rows gain `leases: [{engine, expiresInSeconds, renewable, state}]`, omitted
  when empty. This was done instead of a new command, so there is no capability or gate
  change.
- `ConnectionDto.certificateCredentialId`. It is set with `connection_set_role_credential
  {role: "certificate"}`. `connection_update` keeps the stored value, so UIs that do not know
  the role cannot wipe it.
- Secret sources:
  - `secret_source_create/update` take an optional `kind` (update without `kind` keeps the
    stored one; the kind is immutable).
  - The DTO reports `kind` and `options.bwsPath`.
  - A `bwsPath` change is a **warning** `secret_source_changed`.
  - `credential_external_test` works for every provider.
- Golden: `ipc-codes.json` has the 6 new codes. `kinds.snapshot.json` has the new row and the
  `external_ref` fields `engine`, `ttl`, `common_name`, `username`; the original 1-space
  format is kept, so the diff is minimal.

### Mocks
- `mooring-testsrv::vault`:
  - `DynamicConfig` (mounts, DB TTL / renewable, a `ssh_signed_key` fixture, a PKI
    certificate and key, `pki_lease`).
  - Knobs `raw_dynamic_body` and `lease_renew_fails`.
  - Lease bookkeeping: `lease_events()`, `live_leases()`, `sign_requests()`,
    `set_dynamic()`.
  - Dynamic routes need a live token (403 otherwise). A private key sent to `ssh/sign` is a
    **violation**.
- `mooring-testsrv::onepassword`: a new Connect mock (`/heartbeat`, vault and item filters,
  item reads, 401). Knobs: raw item body, an off-host 302, padding.
- Fake `bws`: `crates/mooring-secrets/tests/bws_fake.rs`, `#![cfg(unix)]`, a `/bin/sh` script
  written per test, serialized because of `ETXTBSY`.

## UI contract (U3)
- **Secret-source form per kind.** The payload is `secret_source_create/update({ kind,
  name, address, authMethod: "token", credentialId, options })`.
  - Vault: unchanged.
  - 1Password Connect: `address` (e.g. `https://connect.example.test:8080`), an `api_token`
    credential, `options.caPem`.
  - Bitwarden: the server URL as `address`, a `bitwarden_access_token` credential, and
    `options.bwsPath` picked from the four fixed templates or `null` (first found). Say that
    `bws` uses its own TLS, so there is no CA field.
  - `secret_source_test` → `policiesCount` is the number of vaults / projects for these
    kinds.
- **`external_ref` form.**
  - `provider` and `source` are required for every provider.
  - `engine` (Vault only): `kv2 | database | ssh_sign | ssh_otp | pki`. Each engine fixes
    the target kind, so preselect it and lock it.
  - `ssh_sign`: `principals: string[]` (≤ 16) and `ttl` (seconds, ≤ 86400).
  - `pki`: `common_name` (required), `alt_names: string[]`, `ttl`.
  - `ssh_otp`: `username` (required).
  - Dynamic engines take no `version` and no `field_map`.
  - 1Password `reference`: `op://vault/item[/section]/field`, or `op://vault/item` with
    `field_map`.
  - Bitwarden `reference`: `<secret uuid>` or `<project uuid>/<key>`.
  - Arrays are not in the kinds table (it has no array field type), so render them as chips.
- **SSH connection** gets a "Certificate (Vault SSH CA)" picker that lists only
  `external_ref` credentials with `engine: ssh_sign`. It saves through
  `connection_set_role_credential({id, role: "certificate", credentialId|null})` and reads
  `ConnectionDto.certificateCredentialId`.
- **Session header chip**: poll `session_list()`. For `leases[]`, show "lease expires in …"
  for `active`, a warning state for `renew_failed`, and an error state for `expired`. Never
  show an id (none is sent).
- New error codes need English copy: `credential.external_engine`, `secret.lease_failed`,
  `secret.tool_missing` ("bws not found at …"), `secret.tool_version`, `secret.tool_failed`,
  `source.kind_unsupported`.
- `ipc.kinds.ts` must gain the `bitwarden_access_token` row and the four new `external_ref`
  fields, or the kinds snapshot vitest fails.

## Left open
- **PKI has no connect consumer.** `x509` is not an SSH, RDP or VNC login, and the kube plan
  does not take `external_ref` (it did not before R3 either). So PKI resolves only in tests
  and `credential_external_test`. As a result, the `revokeCertOnDisconnect` connection
  option is not wired: the engine flag `ResolveCtx.revoke_cert` exists and the app passes
  `false`.
- **`bws` pin is per process.** The SHA-256 pin is in memory, so a binary swapped between
  two app runs is not reported. Persisting it needs a store key (an `app_settings` entry),
  which is a small follow-up.
- `bws` with a cleared environment: the real CLI may want `HOME` or a state directory. Check
  this at the manual gate against a self-hosted Bitwarden. If `HOME` is needed, it is an ADR
  amendment, not a silent addition.
- `database/creds` is a GET, so `mooring-http`'s GET retry (502–504) could issue twice and
  leave one lease to expire by TTL. A per-request no-retry flag in `mooring-http` would fix
  this.
- The Connect vault filter is `name eq "…"` (the real Connect API), not the ADR's `title eq`.
  `op://…?attribute=otp` is not accepted; the TOTP seed comes from the `OTP` field type.
- A crashed app leaves leases to Vault's TTL (as in the ADR).
- Jump hosts still refuse `external_ref` credentials.
- Disk: the target hit 0 bytes three times. Besides `incremental/`, I deleted my **own**
  test executables younger than 60 min, and `libmooring_app_lib.a`, to finish the runs.
  Nothing else was touched.

## Decision needed
- None new. The architect should mark ADR-0026 *Accepted* (decisions 35–38 as applied).
- QA should wire the six fuzz targets to the entries listed above, and add the
  Connect / dynamic-Vault seeds to `fuzz/corpus`.
- Security review: the R-SEC-CLI surface is `bws.rs`, and the token sits in the child's
  environment only. The `ssh/sign` violation trap proves no private key leaves.

## Test evidence
```
cargo fmt --all --check                                   clean
cargo clippy --workspace --all-targets -- -D warnings     clean
cargo test -p mooring-core       193 passed
cargo test -p mooring-store      105 passed (incl. certificate_role_holds_an_ssh_sign_reference)
cargo test -p mooring-audit       40 passed
cargo test -p mooring-secrets     68 passed (dynamic_vault 8, onepassword_connect 4, bws_fake 4)
cargo test -p mooring-testsrv     92 passed
cargo test -p mooring-proto-ssh  130 passed (certificate auth + fallback)
cargo test -p mooring-proto-rdp   77 passed
cargo test -p mooring-app        lib 442 passed / 1 ignored (connect_plan::dynamic_tests 4),
                                 e2e_flow 55 passed
MOORING_BLESS=1 cargo test -p mooring-app golden          ipc-codes.json re-blessed (+6)
```
