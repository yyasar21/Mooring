# ADR-0009: Typed credential model

Status: Accepted · 2026-11-03 (Phase A1 follow-up; amends ADR-0005 schema, ADR-0008 credential
commands, ADR-0004 `ConnectSecret`)

## Context
A1 stores credentials as `kind ∈ {password, ssh_key, certificate}` + `username` + two opaque
sealed columns `secret` / `secret2`. That cannot express an RDP domain, a UPN, an ssh-agent
login, an SSH certificate, a kubeconfig, a bearer token, an Apple Remote Desktop login, a TOTP
seed, a sudo password or "ask me at connect", and the meaning of `secret2` depends on `kind`.

What mature tools model (sources at the end):
- **Devolutions RDM**: credential entries are separate objects linked from sessions; subtypes
  include username/password (+ domain, "prompt for password") and private key (+ passphrase,
  "prompt for passphrase"). An entry's credential source is one of custom, linked, inherited
  (nearest parent folder), *my personal credentials*, find-by-name, privileged account (PAM)
  or none [1][2][3].
- **Royal TS**: credential objects plus *dynamic credentials* resolved at connect by a script;
  shape = username, password, key file path or content, key passphrase [4][5].
- **mRemoteNG**: username / password / domain are plain connection properties with per-property
  inheritance from folders [6].
- **Windows**: two account forms, down-level `DOMAIN\user` and UPN `user@suffix` [7]; NLA
  (CredSSP) needs user + domain + password before the session; RD Gateway has its own
  credential source, often "same as session" [8].
- **OpenSSH**: keys (with passphrase), agent, OpenSSH certificates (`*-cert.pub`, public) and
  FIDO2 `sk-*` keys whose private file is only a key handle needing the authenticator [9].
- **VNC**: RFB security type 2 is password-only DES challenge (8 effective bytes); type 30 is
  Apple Remote Desktop with username + password [10][11].
- **Kubernetes**: a kubeconfig user is client cert/key (`-data` inline or file path), token or
  `tokenFile`, `exec` plugin or legacy `auth-provider` [12].
- **vSphere**: SSO accounts are `user@domain` (e.g. `@vsphere.local`); the REST API trades basic
  auth for a `vmware-api-session-id` [13].
- **HTTP**: Basic (RFC 7617), Bearer (RFC 6750), OAuth 2.0 client credentials (RFC 6749 §4.4).
- **Databases**: user + password and/or TLS client certificate + key (libpq `sslcert`/`sslkey`) [14].
- **2FA**: TOTP (RFC 6238) is a shared seed; hardware keys hold no exportable secret.
- **Secret managers**: Vault AppRole (`role_id` + `secret_id`) [15]; 1Password references
  `op://vault/item/[section/]field` (+ `?attribute=otp`) [16]; Bitwarden Secrets Manager by
  secret id with an access token [17].
- **Privilege escalation**: Ansible `become` = method (sudo/su/doas…), become user, password [18].

## Decision

### 1. `CredentialKind` (mooring-core, `credential.rs`)
A closed enum; each kind declares typed **fields** (non-secret, plaintext JSON) and **secrets**
(each sealed separately). `?` = optional. Kind is immutable after creation.

| kind (wire) | fields (plain) | secrets (sealed) |
| --- | --- | --- |
| `user_password` | `username`, `domain?` | `password`, `otp_seed?` |
| `domain_user` | `user`, `domain`, `form: netbios\|upn` | `password`, `otp_seed?` |
| `ssh_key` | `username`, `public_key?`, `certificate?`, `fingerprint` (derived) | `private_key`, `passphrase?`, `otp_seed?` |
| `ssh_agent` | `username`, `key_fingerprint?` (pin one agent key) | — |
| `x509` | `username?`, `cert_pem`, `fingerprint` (derived) | `key_pem`, `key_passphrase?` |
| `api_token` | `header_name?` (default `Authorization`), `scheme?` (default `Bearer`) | `token` |
| `oauth_client` | `token_url`, `client_id`, `scope?` | `client_secret`, `refresh_token?` |
| `kubeconfig` | `context?`, `contexts` (derived, names only) | `kubeconfig_yaml` |
| `kube_token` | `subject?` (display only) | `token` |
| `vsphere_user` | `upn` (`user@domain`, required form) | `password`, `otp_seed?` |
| `vnc_password` | — | `password` |
| `vnc_user_password` | `username` | `password` |
| `prompt` | `username?`, `domain?` | — (asked at connect) |
| `external_ref` | `provider: vault\|onepassword\|bitwarden`, `reference`, `target_kind` | — (A3) |
| `sudo_become` | `method: sudo\|su\|doas`, `become_user` (default `root`) | `password?` |

- `domain_user` canonical split: input `CORP\alice` → `{user: alice, domain: CORP, form: netbios}`;
  `alice@corp.example` → `{user: alice, domain: corp.example, form: upn}`. Rendering is the
  inverse. NetBIOS domain ≤ 15 chars, no `\/:*?"<>|`; UPN suffix is a DNS name ≤ 253. CredSSP/NTLM
  get `(user, domain)` for netbios and `(upn, "")` for upn. A `user_password` whose `username`
  contains `\` or `@` is stored verbatim (no guessing); the UI offers "convert to domain user".
- **TOTP is an attachable second factor, not a kind**: an optional `otp_seed` secret (base32,
  RFC 6238, decoded ≥ 10 bytes) plus plain `otp: {digits: 6|8, period: 30|60, algorithm:
  sha1|sha256|sha512}` on kinds that log in interactively. Rationale: a code is useless without
  the account it belongs to; a separate kind would need a second link per connection.
- SSH certificates are public and live in `ssh_key.certificate`. FIDO2 `sk-*` keys are accepted
  in `private_key` (it is a key handle); connect fails with `credential.kind_unsupported` until
  the SSH layer supports the authenticator round trip.
- `kubeconfig` must be self-contained: at create/update Rust parses it (capped, untrusted-input
  parser with a fuzz target) and **rejects** `exec`, `auth-provider`, `tokenFile`,
  `client-certificate`/`client-key` paths and multiple users per context unless selected —
  running a command or reading a file named by an imported YAML is code execution / file
  disclosure. `exec` support is a later ADR with an explicit allow-list.
- `external_ref` stores only the reference; resolution (and the provider's own auth, e.g. Vault
  AppRole) is ADR work for A3. Until then the kind validates and stores, and connect returns
  `credential.kind_unsupported`.
- Jump hosts / bastions are **not** a credential kind: they are another connection with its own
  credential (`connection.via_connection_id`, separate ADR).

### 2. Protocol compatibility matrix
✓ valid as primary credential · R = valid in a secondary role (§3) · — = rejected
(`credential.incompatible`).

| kind \ protocol | ssh | rdp | vnc | web | kubernetes | vsphere-console |
| --- | --- | --- | --- | --- | --- | --- |
| user_password | ✓ | ✓ R(gw) | — | ✓ | — ¹ | ✓ |
| domain_user | ✓ ² | ✓ R(gw) | — | ✓ ³ | — | ✓ |
| ssh_key | ✓ | — | — | — | — | — |
| ssh_agent | ✓ | — | — | — | — | — |
| x509 | — | — ⁴ | — ⁵ | ✓ (mTLS) | ✓ | — |
| api_token | — | — | — | ✓ | — | — |
| oauth_client | — | — | — | ✓ | — | — |
| kubeconfig | — | — | — | — | ✓ | — |
| kube_token | — | — | — | — | ✓ | — |
| vsphere_user | — | — | — | ✓ | — | ✓ |
| vnc_password | — | — | ✓ | — | — | — |
| vnc_user_password | — | — | ✓ (ARD/VeNCrypt Plain) | — | — | — |
| prompt | ✓ | ✓ R(gw) | ✓ | ✓ | — | ✓ |
| external_ref | per `target_kind` | ← | ← | ← | ← | ← |
| sudo_become | R(become) | — | — | — | — | — |

¹ Kubernetes removed static basic auth. ² Sent as password auth with `user@domain` (GSSAPI later).
³ NTLM/Negotiate in A2. ⁴ Smart-card RDP later. ⁵ VeNCrypt X509 later.
The matrix is a `const` table in mooring-core (`CredentialKind::valid_for(Protocol, Role)`) and is
served to the UI via `credential_kinds()`; it is the only source of truth.

### 3. Connections, roles, inheritance, overrides
- **Inheritance rules are unchanged** (ADR-0005): connection `credential_id` → nearest folder
  `default_credential_id` → none. The resolver does **not** skip an incompatible inherited
  credential; `session_open` fails with `credential.incompatible` and the UI flags the row.
- Secondary roles, per connection only (no inheritance yet): `gateway` (RD Gateway; may be
  "same as primary" = null with flag) and `become` (`sudo_become` on SSH). Table
  `connection_credential(connection_id, role, credential_id) PK(connection_id, role)`.
- **Per-connection override without duplicating secrets**: `connection.username_override` and
  `connection.domain_override` (nullable). At resolve time they replace the effective
  credential's `username`/`user`/`domain` for kinds that have them (ignored with a validation
  error on create for kinds that do not). Use case: one shared domain password, different admin
  user per server; one `prompt` credential, username pre-filled per host.

### 4. Storage (migration `0003_typed_credentials.sql`)
```
credential(id PK, name, kind TEXT CHECK (kind IN (<15 kinds>)),
           fields_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(fields_json)),
           created_at, updated_at)
credential_secret(credential_id FK→credential ON DELETE CASCADE, name TEXT, sealed BLOB NOT NULL,
                  PRIMARY KEY (credential_id, name)) WITHOUT ROWID
connection + username_override TEXT NULL, domain_override TEXT NULL
connection_credential(connection_id FK CASCADE, role CHECK (role IN ('gateway','become')),
                      credential_id FK→credential ON DELETE CASCADE, PK(connection_id, role))
```
- AAD for each secret = credential id ‖ 0x1F ‖ secret name (`vault.seal(id, name, ..)`, same
  scheme as ADR-0002). Secret names are a closed set per kind; Rust rejects unknown names on
  read and write. A sealed blob cannot move between credentials or between names.
- `fields_json` is validated by the kind's serde type (`deny_unknown_fields`) on every write and
  read; a row that fails to parse yields `store.corrupt`, never a partial credential.
- **Table rebuild**: changing the `kind` CHECK needs the SQLite 12-step rebuild. Dropping
  `credential` with `foreign_keys=ON` would fire `ON DELETE SET NULL` on folders and
  connections, so the migration runner gains a header directive `-- mooring:foreign_keys=off`:
  `PRAGMA foreign_keys=OFF` before `BEGIN`, run script, `PRAGMA foreign_key_check` must be empty
  before `COMMIT`, then `foreign_keys=ON`. Test: credential links survive the migration.
- **Row move** (SQL, no vault needed): `password→user_password`, `ssh_key→ssh_key`,
  `certificate→x509`; `username` → `fields_json`; `secret`/`secret2` copied into
  `credential_secret` under their **legacy names** `secret`/`secret2` (the AAD they were sealed
  with); `setting.credential_reseal_pending = 1`.
- **Reseal** (Rust, first unlock after migration): `Store::reseal_legacy(&vault)` opens each
  legacy secret under its old AAD, writes it under the new name (`password`; `private_key` +
  `passphrase`; for x509 the old `secret` = certificate PEM moves into `fields_json.cert_pem`
  and `secret2` → `key_pem`), deletes the legacy row — one transaction per credential,
  idempotent, flag cleared when none remain. Until then the resolver reads legacy names via a
  fixed kind→name alias table. Downgrade stays refused.

### 5. Size caps (bytes, enforced in mooring-core before SQL and before sealing)
username / user 256 · domain 253 (NetBIOS 15) · password, passphrase, become password 4 KiB ·
VNC password 8 (RFB DES limit; longer input is rejected, not silently truncated) · token,
client_secret, refresh_token 16 KiB · otp_seed 128 · private_key, key_pem, cert_pem,
certificate 64 KiB · public_key 16 KiB · kubeconfig_yaml 1 MiB · reference 1 KiB ·
header_name 64 · token_url 2048 · whole `fields_json` 128 KiB. Text fields reject control,
bidi and invisible characters (`model::is_forbidden`), PEM/YAML allow `\n`/`\r`/`\t` only.

### 6. IPC (replaces the credential block of ADR-0008)
```
credential_kinds()                              -> KindSchema[]
credential_list()                               -> CredentialMeta[]
credential_create({ name, kind, fields, secrets }) -> CredentialMeta   # secrets: { [name]: string }
credential_update_fields({ id, name, fields })  -> CredentialMeta      # kind immutable
credential_replace_secrets({ id, set: { [name]: string }, clear: string[] }) -> void
credential_delete({ id })                       -> void
credential_copy_secret({ id, name })            -> { clearsInMs }      # names flagged copyable
credential_copy_otp({ id })                     -> { clearsInMs, validForMs }
credential_parse_account({ input })             -> { form, user, domain } | IpcError
```
- `KindSchema = { kind, label, group: "Windows"|"SSH"|"VNC"|"Web/API"|"Kubernetes"|"vSphere"|
  "Other", protocols: { protocol, roles: ("primary"|"gateway"|"become")[] }[], supportsOtp,
  fields: FieldSchema[] }`; `FieldSchema = { name, label, secret, required, multiline,
  placeholder, copyable, validation: { maxBytes, format: "text"|"pem"|"base32"|"yaml"|"url"|
  "netbios_or_upn"|"upn"|"enum", options?, pattern? } }`. Labels are English.
- `CredentialMeta = { id, name, kind, fields, secretNames, fingerprint|null, createdAt,
  updatedAt }` — `fields` is non-secret only; `secretNames` reports presence, never content.
- `connection_create/update` gain `usernameOverride|null`, `domainOverride|null`,
  `gatewayCredentialId|null`, `becomeCredentialId|null`; incompatible ids fail with
  `credential.incompatible`. `credential_update_meta`, `credential_replace_secret`,
  `credential_copy_password` are removed in the same release (no external consumers).
- New error codes: `credential.incompatible`, `credential.kind_unsupported`,
  `credential.secret_missing`, `credential.kubeconfig_rejected`, `store.corrupt`.
- Secrets still cross IPC inward only; `credential_copy_*` audit `credential.copied` with
  `{id, name}` (never the value). `prompt` answers arrive via `SessionInput::Answer` (ADR-0007).
- ADR-0004: `ConnectSecret` gains `DomainPassword { user, domain, password }`,
  `Token { header, value }`, `ClientCert { cert, key, passphrase }`, `Kubeconfig { yaml,
  context }`, `Agent { fingerprint }`, plus `become: Option<Become>` on `ConnectParams`;
  hand-written redacting `Debug` for all.

### 7. UI expectations (ui-engineer)
- Kind picker grouped by protocol; when opened from a connection, only kinds valid for its
  protocol/role are enabled, others greyed with the reason. Forms render from `KindSchema`; no
  hard-coded per-kind forms except the account field.
- Account field for Windows kinds accepts `DOMAIN\user` or `user@domain` and shows the split
  live (`credential_parse_account` vectors mirrored in TS tests).
- "Prompt on connect" is a first-class choice in the credential selector, next to "Inherited".
- Show SSH/X.509 fingerprints (`SHA256:…`) and kubeconfig context names; never a secret.
  Secret inputs are write-only: "set" / "replace" / "clear", no reveal.
- Later item (A2): import from `~/.ssh/id_*` (+ `.pub`, `-cert.pub`) and `~/.kube/config`
  through a Rust file picker command; the UI never reads the files.

## Alternatives considered
- Keep `secret`/`secret2` and overload by kind: meaning depends on kind, no room for third
  secret (OTP, refresh token). Rejected.
- One sealed JSON blob per credential: simplest, but every edit re-seals everything and a
  single field cannot be copied/replaced without opening all of them. Rejected; per-field
  sealing is the ADR-0002 design.
- All fields sealed (including username/domain): hides user enumeration but kills listing,
  search and the override feature while locked. Rejected (R-INV accepted, see below).
- mRemoteNG-style credentials as connection properties: duplicates secrets per connection.
  Rejected; overrides cover the legitimate need.
- TOTP as its own kind: needs a second link per connection; rejected for an attachable slot.

## Security consequences
- Username, domain, UPN, OAuth client id, kubeconfig context names and certificate subjects are
  plaintext at rest: a stolen `mooring.db` enables account enumeration (extends R-INV in the
  threat model; security-reviewer to update). Domain is not secret.
- `otp_seed` is secret and sealed. Storing it beside the password collapses two factors into
  "whoever opens the vault"; the UI warns on first use and audits `credential.otp_attached`.
- A kubeconfig may embed tokens and client keys, so the **whole file** is one sealed secret;
  only context names (derived at import) are plaintext. `exec`/file references are rejected.
- `fields_json` is not authenticated (like the rest of the inventory): a writer to the DB can
  change a username or kind, but cannot move or read a secret; kind is re-validated on read
  and secret names must match the kind. A MAC over fields is a candidate for a later ADR.
- Every resolved secret lives in `Zeroizing`/`SecretString` until the handshake ends; the
  `become` password is sent only when the remote sudo prompt is detected, never echoed.
- More parsers (kubeconfig YAML, PEM, OpenSSH public key/cert, base32) ⇒ each gets caps and a
  fuzz target; no new dependency without the usual approval.

## Test plan
mooring-core: per-kind serde round trip, `deny_unknown_fields`, caps (max/max+1), forbidden
characters, `parse_account` vectors (NetBIOS, UPN, malformed, 16-char NetBIOS), matrix table
exhaustive test, override applicability. mooring-store: migration 0003 from a v2 DB with
all three legacy kinds (links on folder/connection preserved, `foreign_key_check` empty),
reseal idempotence and crash between credentials, legacy-name read before reseal, secret
cannot be opened under another id or name, cascade deletes. src-tauri: input validation per
command, `credential.incompatible` on connection create and on session open via inheritance,
kubeconfig with `exec` rejected, `credential_kinds()` snapshot. UI: forms generated from schema
snapshot, account split, no secret in any rendered DOM after save. Fuzz: kubeconfig, PEM,
OpenSSH public key/cert parsers.

## Sources
1. Devolutions, Entry credentials options — https://docs.devolutions.net/rdm/ribbon-menu-bar/edit/entry-credentials-options
2. Devolutions, New-DSCredentialEntry — https://docs.devolutions.net/powershell/de/powershell-commands/new-dscredentialentry.md
3. Devolutions blog, Inheriting credentials in RDM — https://devolutions.net/blog/inheriting-credentials-in-remote-desktop-manager/
4. Royal Apps, RoyalJSONDynamicCredential — https://docs.royalapps.com/r2021/scripting/rjson/available-properties/royaljsondynamiccredential.html
5. Keeper, Royal TS integration — https://docs.keeper.io/en/keeperpam/secrets-manager/integrations/royalts
6. mRemoteNG, Folders and inheritance — https://mremoteng.readthedocs.io/en/latest/folders_and_inheritance.html
7. Microsoft, User name formats — https://learn.microsoft.com/en-us/windows/win32/secauthn/user-name-formats
8. One Identity SPS, RDP scenarios (NLA/CredSSP, RD Gateway) — https://support.oneidentity.com/technical-documents/one-identity-safeguard-for-privileged-sessions/6.0.7/remote-desktop-protocol-scenarios/3
9. OpenSSH PROTOCOL.u2f (FIDO `sk-*` keys) — https://fuchsia.googlesource.com/third_party/openssh-portable/+/refs/heads/main/PROTOCOL.u2f
10. RFC 6143, The Remote Framebuffer Protocol — https://tools.ietf.org/html/rfc6143
11. Suricata, RFB keywords (security types 0/2/30) — https://docs.suricata.io/en/latest/rules/rfb-keywords.html
12. Kubernetes, kubeconfig (v1) — https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/
13. Broadcom, vSphere Automation API session create — https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/session/post
14. PostgreSQL libpq SSL support — https://access.crunchydata.com/documentation/postgresql14/latest/libpq-ssl.html
15. HashiCorp Vault, AppRole auth API — https://developer.hashicorp.com/vault/api-docs/auth/approle
16. 1Password, Secret reference syntax — https://www.1password.dev/cli/secret-reference-syntax
17. Bitwarden, Secrets Manager CLI — https://bitwarden.com/help/secrets-manager-cli
18. Ansible, Understanding privilege escalation: become — https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_privilege_escalation.html
RFCs 6238 (TOTP), 6749 (OAuth 2.0), 6750 (Bearer), 7617 (Basic) are cited by number.
