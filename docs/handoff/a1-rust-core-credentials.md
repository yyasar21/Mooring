# A1 — rust-core handoff: typed credentials (ADR-0009)

Branch `worktree-agent-a12323ee4fecb8e36`, based on `main` at `692a7b7` (the ADR-0009 UI merge
is included, so the UI tests and the Rust suites run against the same tree). Not merged.

## Done

- **mooring-core `credential` module** (`crates/mooring-core/src/credential/`):
  - `CredentialKind` covers the 15 kinds, with `snake_case` wire names.
  - Each kind has a field struct with `deny_unknown_fields`. `CredentialFields` validates on input and again on every read from the store.
  - `SecretName` is a closed set of 10 names. `Role` is `primary`, `gateway` or `become`.
  - The `KindSchema` table (`credential_kinds()`) is also the protocol matrix:
    - `valid_for(kind, protocol, role)` answers from it.
    - `incompatibility_reason(...)` returns the UI sentence verbatim, for example "SSH key is for SSH, not RDP sign-in.", including the ADR footnotes.
    - `check_compatible` follows `external_ref.target_kind`.
  - Parsers, each capped:
    - `parse_account` handles NetBIOS ≤ 15 characters and the forbidden-character set, and UPN with a DNS domain ≤ 253. `Account::for_credssp` is included.
    - TOTP: RFC 4226 HOTP plus RFC 6238 TOTP, on `hmac` 0.13 with `sha1`/`sha2` 0.11. RFC test vectors for SHA-1, SHA-256 and SHA-512 are included.
    - Base32 seeds via `data-encoding`: at most 128 bytes of text, at least 10 bytes decoded.
    - OpenSSH public key and certificate fingerprints, and private-key inspection (fingerprint without the passphrase, FIDO `sk-*` detection), via `ssh-key`.
    - X.509 PEM leaf fingerprint via `pem-rfc7468` plus SHA-256 of the DER.
    - Kubeconfig:
      - Parsed with `saphyr-parser` at event level into a capped tree: 1 MiB, depth 32, 100k nodes, one document.
      - Rejected: anchors, aliases, tags and duplicate keys.
      - Also rejected: `exec`, `auth-provider`, `tokenFile`, `client-certificate`, `client-key` and cluster `certificate-authority` paths.
      - Extracts up to 64 context names plus `current-context`.
  - Size caps follow ADR-0009 §5. VNC passwords are limited to 8 bytes; longer input is rejected with "…not truncated". Single-line text refuses control, bidi and invisible characters; PEM and YAML may contain `\n`, `\r` and `\t`.
  - Proptests check that every parser never panics (account, fields, seed, TOTP, SSH public key, certificate, private key, X.509, kubeconfig).
  - `Connection` gains `username_override`, `domain_override`, `gateway_credential` and `become_credential`.
- **mooring-core `connect` (ADR-0004 types)**:
  - `ConnectSecret` gains `DomainPassword`, `Agent { fingerprint }`, `Token`, `ClientCert`, `Kubeconfig` and `Prompt(PromptAccount)`.
  - `ConnectParams` gains `r#become: Option<Become>`.
  - Every secret-holding type has a redacting `Debug`.
  - `PromptPurpose::Credential` is new. `SessionEvent::Prompt` gains `account: Option<PromptAccount>`.
  - `SessionInput::CredentialAnswer { id, username, domain, password }` is new; the password is redacted in both `Debug` and `Serialize`.
- **mooring-proto-ssh**:
  - The `prompt` kind raises a single sign-in form. Answering with an empty username and password closes the session with "authentication cancelled".
  - The broker refuses an answer of the wrong shape (a text answer to the form, or the reverse).
  - `DomainPassword` signs in as `user@DOMAIN` (NetBIOS) or as the UPN.
  - `Agent { fingerprint }` pins one agent key. An explicit `ssh_agent` credential uses the agent even when implicit agent fallback is off.
  - FIDO2 `sk-*` keys are refused up front with "this credential is not supported for ssh in this version".
  - `become` (new `become_.rs`):
    - The target user is checked first: `[A-Za-z0-9._-]`, at most 64 characters, no leading `-`. This happens before connecting, because the user is typed into a shell.
    - After the shell opens, Mooring types a fixed `sudo -p '[mooring] become password: ' -i -u <user>`, `su - <user>` or `doas -u <user> -s`.
    - The password is written once, only when the prompt is detected (exact match for sudo, a heuristic for su and doas), and only within the first 4 KiB of output. It never goes into the UI stream.
- **mooring-store** (migration `0003_typed_credentials.sql`, schema v3), exactly as ADR-0009 §4:
  - `credential` is rebuilt, plus `credential_secret` (`WITHOUT ROWID`), the two override columns and `connection_credential`.
  - The runner honours `-- mooring:foreign_keys=off`: foreign keys off before `BEGIN`, `pragma_foreign_key_check` must be empty before `COMMIT`, foreign keys back on in every case.
  - The legacy row move is done in SQL. The reseal is `Store::reseal_legacy(&vault)`, also exposed as `migrate_sealed_names` (the name the brief used); reads go through a fixed alias table until then.
  - API:
    - `create_credential(&vault, name, kind, &fields_json, &Secrets)`
    - `update_credential_fields`
    - `replace_secrets(set, clear)`, which refuses clearing a required secret and refuses a name in both lists
    - `open_secret`
    - `get_credential` and `list_credentials`, returning `CredentialMeta` with `secret_names` and `fingerprint()`
    - `set_connection_role_credential`
    - `resolve_credential(connection, role)`, which applies overrides and returns `Credential(Incompatible)` for an incompatible credential, inherited ones included
    - `effective_credential`, unchanged
  - `connection_create` and `connection_update` check every link against the matrix, and check that overrides fit the effective kind.
  - The `otp` parameters are attached and detached together with `otp_seed`.
- **mooring-audit**: new events `credential_copied {credential, name}` (name `otp` for codes), `credential_otp_attached {credential}` and `credential_prompted {connection, username}`. `credential_used` is unchanged.
- **src-tauri** (ADR-0009 §6 surface, wired in `lib.rs`):
  - Added: `credential_kinds`, `credential_create`, `credential_update_fields`, `credential_replace_secrets`, `credential_copy_secret`, `credential_copy_otp`, `credential_parse_account`, `connection_set_role_credential`.
  - `connection_create` and `connection_update` carry the four new fields.
  - Removed: `credential_update_meta`, `credential_replace_secret`, `credential_copy_password`.
  - `session_open` (`commands/connect_plan.rs`) builds `ConnectSecret` per kind: `user_password`, `domain_user`, `ssh_key`, `ssh_agent`, `prompt`, with `sudo_become` as `ConnectParams.become`. Incompatible kinds give `credential.incompatible`; `external_ref` gives `credential.kind_unsupported`.
  - `session_send` accepts `credential_answer` and audits `credential_prompted` (the username only).
  - New error codes: `credential.incompatible`, `credential.kind_unsupported`, `credential.secret_missing`, `credential.kubeconfig_rejected`, `store.corrupt`.
- **New dependencies** (root `[workspace.dependencies]`, each with a one-line justification):
  - Already in the lockfile tree through russh, der, ssh-key and age: `ssh-key` (=0.7.0-rc.11), `pem-rfc7468` 1, `data-encoding` 2.11, `hmac` 0.13, `sha1` 0.11, `sha2-next` (= `sha2` 0.11, renamed because the workspace `sha2` is 0.10).
  - New to the tree: `saphyr-parser` 0.3 (pure Rust, MIT/Apache-2.0) and its dependency `arraydeque`.
  - Not added: `base32` (`data-encoding` is already present), `serde_yaml`/`serde_yml` (unmaintained; the event parser is smaller attack surface) and `x509-parser` (fingerprinting only needs the PEM → DER bytes).
  - Needs security-reviewer approval.

## Exact IPC shapes (for the UI)

Arguments are camelCase (Tauri). Field and secret keys inside `fields` and `secrets` are `snake_case`, as in `KindSchema`.

```jsonc
// credential_kinds() → KindSchema[]  — byte-identical to apps/desktop/src/lib/ipc.kinds.ts
// (snapshot test src-tauri/src/commands/credentials_tests.rs ↔ kinds.snapshot.json)
[{ "kind": "domain_user", "label": "Domain account", "group": "Windows",
   "protocols": [{ "protocol": "ssh", "roles": ["primary"] },
                 { "protocol": "rdp", "roles": ["primary", "gateway"] }, …],
   "supportsOtp": true,
   "fields": [{ "name": "user", "label": "Account", "secret": false, "required": true,
                "multiline": false, "placeholder": "CORP\\alice or alice@corp.example",
                "copyable": false, "validation": { "maxBytes": 256, "format": "netbios_or_upn" } }, …] }]

// credential_create({ name, kind, fields, secrets }) → CredentialMeta
invoke("credential_create", { name: "ops", kind: "user_password",
  fields: { username: "ops", otp: { digits: 6, period: 30, algorithm: "sha1" } },
  secrets: { password: "…", otp_seed: "JBSW…" } })      // blank secret values are ignored
// CredentialMeta
{ "id": "uuid", "name": "ops", "kind": "user_password",
  "fields": { "username": "ops", "otp": { "digits": 6, "period": 30, "algorithm": "sha1" } },
  "secretNames": ["password", "otp_seed"], "fingerprint": null,
  "createdAt": "2026-11-03T…Z", "updatedAt": "2026-11-03T…Z" }
// ssh_key:   "fields": { "username": "root", "public_key": "ssh-ed25519 …", "fingerprint": "SHA256:…" }, "fingerprint": "SHA256:…"
// kubeconfig: "fields": { "context": "lab", "contexts": ["lab", "lab-admin"] }

// credential_update_fields({ id, name, fields }) → CredentialMeta   (fingerprint/contexts in input = input.invalid)
// credential_replace_secrets({ id, set: { name: string }, clear: string[] }) → null
// credential_delete({ id }) → null
// credential_copy_secret({ id, name }) → { "clearsInMs": 30000 }
// credential_copy_otp({ id }) → { "clearsInMs": 1000, "validForMs": 1000 }   (clearsInMs ≤ validForMs; the code is never returned)
// credential_parse_account({ input: "CORP\\alice" }) → { "form": "netbios", "user": "alice", "domain": "CORP" }

// connection_create / connection_update (all optional fields may be null or omitted)
invoke("connection_create", { folderId, name, protocol, host, port, credentialId,
  usernameOverride: "dba", domainOverride: "CORP", gatewayCredentialId: null,
  becomeCredentialId: "uuid", tags: [] })
// ConnectionSummary adds: "usernameOverride", "domainOverride", "gatewayCredentialId", "becomeCredentialId"
// connection_set_role_credential({ id, role: "gateway" | "become", credentialId | null }) → ConnectionSummary

// session event (channel)
{ "kind": "prompt", "id": 3, "message": "Sign in", "secret": true, "purpose": "credential",
  "account": { "username": "alice", "domain": null, "needs_username": false, "needs_domain": false } }
// other prompts carry "account": null
// session_send input
{ "kind": "credential_answer", "id": 3, "username": "alice", "domain": null, "password": "…" }
// cancel = username "" and password "" → closed { reason: "authentication cancelled" }

// errors: { code, message }; credential.incompatible messages are UI sentences:
{ "code": "credential.incompatible", "message": "SSH key is for SSH, not RDP sign-in." }
```

## Deviations from the ADR / brief (precise)

1. `ConnectParams.become` is spelled `r#become` in Rust (keyword). The wire is unaffected.
2. The reseal method is `Store::reseal_legacy` as the ADR names it. `migrate_sealed_names` is a thin alias for the brief's name.
3. **Placeholders in migrated rows:**
   - A v2 `password` or `ssh_key` row without a username gets `username: "(unset)"`, because `username` is required for those kinds.
   - A migrated `x509` holds `cert_pem: "(sealed until the next unlock)"` until the reseal moves the certificate in.
   - See Decision needed.
4. `credential_copy_otp` returns `{clearsInMs, validForMs}` only. The brief's item 6 said `{code, …}`, but the ADR and the UI's `ipc.types.ts` say the code never comes back, so the code is not returned.
5. `credential_prompted` is written by `session_send` when a non-empty `credential_answer` arrives, not when the prompt opens.
6. `credential_otp_attached` is emitted on create and replace when an `otp_seed` is set.
7. `PromptAccount.needs_domain` is always `false` for SSH. SSH has no domain step: a domain typed in the form becomes `user@domain`.
8. Kubeconfig: users with `username`/`password` (basic auth) are not rejected by the parser, since the ADR list does not name them. Selecting "multiple users per context unless selected" is enforced only through the `context` choice; contexts are not cross-checked against users.
9. Not implemented, because no protocol uses them yet: `Token`, `ClientCert` and `Kubeconfig` connect secrets are typed in core but not built by `session_open`. Only SSH sessions exist; other protocols still fail `session.failed`.

## Left open

- **Reseal call site**: `reseal_legacy` is implemented and tested, but `vault_unlock` does not call it yet. It belongs in `commands/vault.rs::unlock` after the bind: one line plus a test. Until then the alias table makes everything work. I held back so as not to change unlock timing without a review.
- **Fuzz targets**: proptests stand in. There is still no `fuzz/` directory, because cargo-fuzz and nightly are missing here (QA 6b is still open). Targets needed: `kubeconfig::parse`, `fingerprint::{ssh_public_key, ssh_certificate, ssh_private_key, x509_pem}`, `otp::decode_seed`, `parse_account`.
- `become`: no `sudo` password retry, and no detection of the escalation failing (the session just continues as the login user). The su/doas prompt detection is a heuristic.
- The `ssh_agent` pin is not tested against a live agent (tests disable the agent).
- The x509 fingerprint is SHA-256 over the DER of the first certificate block (the leaf); the chain is not validated.
- Folders: `folder_set_default_credential` does not check the matrix, since a folder has no protocol. The check happens at resolve time, as the ADR says.

## Decision needed

1. The placeholders `(unset)` and `(sealed until the next unlock)` in migrated rows: keep them, or make `username` optional for migrated `ssh_key` rows?
2. Call `reseal_legacy` from `vault_unlock` (recommended), or leave it as an explicit maintenance step?
3. `credential_answer` in ADR-0007 (the UI handoff asks the same) and keeping `connection_set_role_credential`: both are implemented.
4. The new dependency `saphyr-parser` and the `sha2` 0.11 alias (`sha2-next`): security-reviewer approval.

## Test evidence

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` (WebView toolchain present, so `mooring-app` and `e2e_flow` are included) were run on Linux. Results are below.

```
cargo fmt --all --check                                      clean
cargo clippy --workspace --all-targets -- -D warnings        clean
cargo test --workspace                                       372 passed, 0 failed, 3 ignored (36 suites)
  mooring-app      lib 54 · e2e_flow 13 (was 9)
  mooring-audit    9
  mooring-core     64
  mooring-proto-ssh lib 52 · auth 9 · credential_kinds 7 (new) · forward 10 · sftp 8 · shell 9 · trust 5 · lab ignored
  mooring-store    lib 18 · credentials 11 · crud 7 · migration_v2 5 (new) · migrations 6 · search 4 · tree_edges 8 · vault_store_integration 6
  mooring-vault    lib 52 (2 ignored, pre-existing) · autolock_table 3 · calibration_props 7 · proptest_round_trip 2 · vectors 3
```
Not run here: cargo-deny, cargo-audit (not installed), pnpm suites (UI untouched by this branch).

New or changed suites:

- **mooring-core**: 64 unit tests, including the RFC 6238 and RFC 4226 vectors, an exhaustive matrix check (14 rows × 6 protocols × 3 roles), parse_account vectors, caps at max and max+1, and proptests.
- **mooring-proto-ssh**: `tests/credential_kinds.rs` (7): prompt form, cancel, domain password, prompt with a domain, become sends the password once, become injection refused, FIDO refused. Broker form round-trip unit tests.
- **mooring-store**: `tests/credentials.rs` (11), and `tests/migration_v2.rs` (5) against a real v2 database with all three legacy kinds. It checks that links survive, `foreign_key_check` is empty, alias reads work before the reseal, reseal idempotence, a crash between credentials, the wrong vault, alias drop on replace, and an empty v2 database. The existing suites were ported.
- **src-tauri**:
  - `credentials_tests` (7, including every kind created from its schema and the **`credential_kinds()` snapshot equal to the UI table**), `credential_copy_tests` (7, including the RFC code on the clipboard at T=59 s and clear ≤ validity) and the tree role/override test.
  - e2e `credential_kinds` (4): prompt over a live SSH session, cancel, become, and an incompatible inherited credential plus `external_ref` refused before any I/O.
  - The hostile corpus and the random suites now cover every new string argument. The vault-gated list has 22 commands.
