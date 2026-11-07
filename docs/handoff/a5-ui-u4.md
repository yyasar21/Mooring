# A5 · ui-engineer · U4: dynamic secrets, 1Password Connect, Bitwarden, lease chips (ADR-0026)

Worktree `/home/claude/nexus/.claude/worktrees/agent-a5dcf9c702dee686a`, branch
`worktree-agent-a5dcf9c702dee686a`, from `main` @ `11a2518`. Not merged. No cargo run, no
manifest, lockfile or capability change. The contract is the "UI contract (U3)" section of
`a5-rust-core-r3.md`. Every code the UI shows text for is in `src-tauri/ipc-codes.json`
(`ipc.tauri.u4.test.ts` checks the six new ones).

Harbor note: the new CSS (`styles/a5-secrets.css`) uses today's tokens only: sentence case in the
sans face, plain borders, no HUD brackets, no new `m-micro` labels. The reference test result tags
(present / missing / extra) moved from `m-micro` to a sentence-case tag. Existing `HudLabel`
section headings were left as they are.

## Done

### Failing test on main
- `ipc.kinds.ts` gains the `bitwarden_access_token` row (group "Secret sources", consumer
  `secret_source`, one sealed secret `access_token`, 4 KiB). It also gains the four new
  `external_ref` fields (`engine` enum `kv2…pki`, `ttl`, `common_name`, `username`), byte for byte
  as in `kinds.snapshot.json`. `CREDENTIAL_KINDS` and `CredentialRole` (`certificate`) follow.
  `ipc.kinds.test.ts` passes.

### 1. Settings → Secret sources
- **Types.** `SecretSourceKind`, `SOURCE_KIND_LABEL`, `SOURCE_LOGIN_KIND`, `BWS_PATHS` (the four
  R3 templates), `SecretSourceInput.kind?`, `options.bwsPath?`, `SecretSource.kind` (3 kinds).
- **Dialog** (`SecretSourceDialog.tsx`, `SourceProviderFields.tsx`). On create there is a
  "Provider" choice: Vault / OpenBao, 1Password Connect or Bitwarden. On edit the provider is shown
  and fixed ("The provider of a source cannot change"), and the update still sends `kind`.
  - Vault: as before.
  - 1Password Connect: name, address, a "Connect token credential" (`api_token`), CA and
    loopback http. No namespace and no method.
  - Bitwarden: name, server URL (passed to bws as `BWS_SERVER_URL`), an "Access token
    credential" (`bitwarden_access_token`) and a "bws location" select. The select offers
    "First one found" (`null`) or one of the four fixed paths. It lists where Mooring looks and
    explains R-SEC-CLI (no PATH search, cleared environment, SHA-256 pin). It also says that bws
    uses its own TLS, so there is no CA field.
  - `validateSecretSource` applies the R3 rules per kind: token only, no namespace, `bwsPath`
    for Bitwarden only and from the list, and no `caPem` for Bitwarden.
- **List** (`SecretSourcesCard.tsx`). Each row shows the provider name, and Vault rows also the
  method. Bitwarden rows add "bws: <path | first one found> · own TLS, not pinned by Mooring".
  Test results are per provider and give counts only:
  - Vault: unchanged.
  - Connect: "Connect answered: the token sees N vaults."
  - Bitwarden: "bws ran: the access token sees N projects."
  - Failures: "<provider> test failed (category): <friendly text>."
- **`secret.tool_missing`.** The row shows a note: "bws was not found at <path> / at any of these
  locations", plus the list of paths.
- A `bitwarden_access_token` credential gets the same detail section and Test as a Vault AppRole.
  "Create secret source" opens the dialog with Bitwarden preselected (`SettingsIntent.sourceKind`).

### 2. Secret manager reference credential
- **Form** (`ExternalRefSection.tsx`, `RefEngineFields.tsx`).
  - Every provider needs a source now, and the source list offers only sources of that
    provider.
  - Vault references get a "Vault engine" select: KV v2, Database, SSH sign, SSH OTP, PKI.
    Each option names its target kind and has a hint line. A dynamic engine fixes "Resolves to"
    (shown read-only), clears the version and the field map, and renames the reference field to
    "Role" (`<mount>/<role>`).
  - Database: a note that the role sets the user, grants and lease TTL, and that the lease is
    renewed at 2/3 of its TTL and revoked on close or lock.
  - SSH sign: principals as chips (Enter or comma adds, × or Backspace removes, at most 16) and a
    TTL. A note says only the public key goes to Vault.
  - SSH OTP: "One-time password login" (required).
  - PKI: common name (required), alt names as chips and a TTL. A note says PKI can only be tested
    for now, because no login uses x509.
  - 1Password: `op://vault/item[/section]/field`. Bitwarden: a secret id or
    `<project id>/<key>`.
  - The ADR-0016 field map is reused for KV v2, for a whole 1Password item (`op://vault/item`)
    and for Bitwarden JSON values. Its wording follows the provider (KV key / item field / JSON
    key).
  - "Test reference" works for every provider. A dynamic test that succeeds reads "Vault issued
    Database values with every field the target kind needs. Mooring revoked them at once."
- **Model.** `FormState.lists` holds `principals` / `alt_names`. `buildFields` leaves out `kv2` and
  sends `ttl` as a number and the lists as arrays. `validate.refs.ts` mirrors
  `parse_op_reference`, `parse_bws_reference` and `external_engine.rs::check`: target kind per
  engine, which parameter belongs to which engine, the caps (16 names, 64 B principal, 255 B CN,
  64 B OTP login, TTL 1..=86400), and no version or field map on dynamic engines.
- **Detail card.** It shows Provider, Source (for every provider), Engine, Role/Path, Resolves
  to, Version (KV only), Principals, Common name, Alt names, Login, TTL ("role default"), and for
  Database "Lease: Renewed while the session is open, revoked when it closes".
- **Certificate role.**
  - `credentialValidFor`: the `certificate` role takes only a Vault `ssh_sign` reference, on SSH
    only. An `ssh_sign` reference is refused in every other role, with "pick it as the
    connection's certificate".
  - The connection form has a "Certificate (Vault SSH CA)" picker on SSH. It lists only
    `ssh_sign` references and saves through
    `connection_set_role_credential({role: "certificate"})` after the row is saved
    (`ConnectionSummary.certificateCredentialId`).
  - The SSH key credential's detail card lists each SSH connection that uses the key with a
    certificate: "Certificate: signed by Vault role ops at connect · web01".
- **Errors.** `FRIENDLY` has English text for `credential.external_engine`,
  `secret.lease_failed`, `secret.tool_missing`, `secret.tool_version`, `secret.tool_failed` and
  `source.kind_unsupported`.

### 3. Sessions: lease chip
- `SessionInfo.leases?: LeaseInfo[]` (`engine`, `expiresInSeconds`, `renewable`, `state`).
  `session_list` was added to `POLLED_COMMANDS`; it is already passive in `ipc-passive.json`, so
  `polled.test.ts` stays green.
- `stores/leases.ts`:
  - It reads each row defensively; a malformed row is dropped, never shown.
  - It keeps the largest seconds-left it has seen as the TTL estimate, and a jump upward means a
    renewal.
  - `leaseChip()` texts:
    - "Lease · renews in 23 min" (renewable)
    - "Lease · expires in …" (not renewable)
    - "Lease · renewing"
    - "Lease · renewal failed, expires in …" (warning)
    - "Lease expired" (error)
    - "Lease revoked" (after the tab closes)
  - With several leases, the worst one speaks for the tab.
- `components/terminal/LeaseChip.tsx`.
  - `LeasePoller` (in `TabStrip`) polls `session_list` every 15 s while a session is connecting
    or connected.
  - The chip sits on the tab. Its tooltip is "Database lease for Vault role reporting." plus what
    the state means: engine and role only, the role taken from the connection's reference, never
    an id. The same text is in the tab's accessible name.
  - A reconnecting tab with no session id hides the old chip.
- A lease refusal at connect closes the tab with the `secret.lease_failed` text: "Vault did not
  hand out a lease for the dynamic credential, so Mooring did not use it and did not connect. …".
  A renew failure is the warning chip and its tooltip.

### 4. Mock transport
- `ipc.mock.leases.ts` (new):
  - `dynamicRefTest`: database / OTP / PKI issue-and-revoke names; `ssh_sign` →
    `credential.external_engine`.
  - `providerRefTest`: Connect fake items, and the one-value rule for 1Password field references
    and `bws`.
  - `MockLeaseBook`: issue, lazy renewal at 2/3 of the TTL, `renew_failed`, expiry, release on
    close, drain on lock, and the R3 audit events.
- `ipc.mock.secrets.ts`:
  - Per-kind source checks (login kind via `SOURCE_LOGIN_KIND`); the kind is immutable on update.
  - Connect and `bws` tests. The `bwsFound` knob gives `secret.tool_missing`.
  - `credential_external_test` for every provider, with `source.kind_unsupported` on a mismatch.
- `ipc.mock.ts`:
  - A database reference on SSH issues a lease. Knobs: `leaseTtl` (3600), `leaseRefused` (→
    `secret.lease_failed`) and `leaseRenewFails`.
  - `session_list` rows carry `leases`.
  - `lockBackend` drains the leases.
- `ipc.mock.creds.ts` validates the new fields like R3: `source` is required for every provider,
  plus the reference shapes and the engine rules.
- `ipc.mock.tree.ts` stores the `certificate` role and clears it when its credential is deleted.
- Seed:
  - Sources `src-op` "infra connect" (1Password Connect, `cr-op-token` api_token) and `src-bws`
    "team secrets" (Bitwarden, `cr-bws-token`).
  - Credential `cr-db-dyn` "reporting db (dynamic)" (Vault `database/reporting` on `src-ops`).
  - Connection `c-report` "pg-reporting" (SSH, Production / Databases), which signs in with it.
    Opening it shows the lease chip. The mock creates sessions on open, so the seed is a
    connection that opens a leased session, not a pre-opened session (a seeded live session
    would be adopted as a tab on every unlock).
- All mock files stay under 500 lines (largest: `ipc.mock.ts` 328).

## Left open
- **Lease TTL is estimated.** `session_list` sends seconds left, not the TTL. The chip learns the
  TTL from the first read and from renewals. If the first read comes late in a lease's life, the
  "renews in" figure is short until the next renewal. Fix: add `ttlSeconds` to `LeaseInfoDto`
  (rust-core, one field).
- **`revokeCertOnDisconnect`** (PKI) has no UI, because R3 left it unwired.
- **Jump hosts** still refuse `external_ref` credentials (R3). The Connect via picker does not
  warn about it before save.
- **Graphical sessions** (RDP/VNC) show the chip from the same `session_list` field. The mock
  issues leases for SSH only.
- **The certificate role is saved separately** from `connection_update`, after it. If the role
  save fails, the dialog says "The connection was saved, but its certificate was not: …" and
  keeps the form open.

## Decision needed
- **Seed change (qa).** The new seed sources, credentials and the `pg-reporting` connection
  change counts and texts that existing tests asserted. I updated them:
  - vitest: `secretSources.test.tsx`, `ipc.secrets.test.ts`, `backup.test.tsx`,
    `ipc.test.ts`, `credentials.test.ts`.
  - The external_ref schema render test skips the engine-only fields.
  - The 1Password form test now needs a source (an R3 behaviour change).
  - e2e: `secrets-sync.e2e.mjs`'s "API token" kind button needs `exact: true` (the seeded
    `connect token` row has the same prefix). Its delete flow now says "used by 2 references". It also deletes
    the dynamic reference before the source goes, and ends on the row being gone instead of
    "No secret sources", because the Connect and Bitwarden seeds stay.

  qa should confirm these edits in their files.

## Test evidence
Linux x86_64, 2026-11-08, `node_modules` symlinked from `/home/claude/nexus` (not committed).

```
pnpm typecheck   ok (packages/ui, apps/desktop)
pnpm lint        ok (0 problems)
pnpm test        Test Files 88 passed (88) · Tests 649 passed (649)   (main: 84 files, the kinds snapshot test failing)
pnpm build       ok
make e2e         flows 5/5 · kube 6/6 · vsphere 4/4 · secrets-sync 7/7 · a4 11/11 · a5 6/6 — 39 passed, 0 failed
a5.e2e.mjs       6/6 (new: "dynamic secret: a database reference, a connection that uses it, the lease chip")
```

New vitest files (27 tests):
- `components/terminal/leases.test.tsx`:
  - The chip after opening `pg-reporting` ("Lease · renews in 40 min"; tooltip "Database lease
    for Vault role reporting"; nothing id-like in the DOM).
  - No chip for a static credential.
  - `renew_failed` → warning, expired → error.
  - "Lease revoked" after close.
  - A lease refusal gives the contract text.
  - The lock drains the leases.
  - Decoder and lease math.
- `components/settings/sourceKinds.test.tsx`:
  - Connect and Bitwarden rows and their tests (counts only, `secret_tool_spawned` audited).
  - The tool-missing note with the four paths.
  - Creating a Connect source and a Bitwarden source (fixed path, no CA).
  - Editing keeps the provider.
  - The per-kind form rules, and `testText` per provider.
- `components/credentials/refEngines.test.tsx`:
  - Database: target fixed, role only, stored shape, detail rows, Test issues and revokes.
  - SSH sign: chips, TTL cap, stored shape. The primary picker refuses it, the certificate
    picker offers only it, and the SSH key detail shows "Certificate: signed by Vault role ops at
    connect · web01".
  - OTP login required; PKI common name required and the test-only note.
  - A Bitwarden reference and its Test.
  - `validate.refs` rules and `buildFields`/`initialState` round trip.
- `lib/ipc.tauri.u4.test.ts`:
  - `kind`/`bwsPath` on `secret_source_create`, the certificate role, `session_list` polled.
  - The six R3 codes have copy.

Screenshots (dark and light, 1280×800, mock transport, JPEG) in `docs/handoff/img/a5-ui-u4/`:
- `01-sources`
- `02-bws-missing`
- `03-new-connect-source`
- `04-new-bitwarden-source`
- `05-ref-database`
- `06-ref-ssh-sign`
- `07-ref-pki`
- `08-lease-chip`
- `09-lease-refused`

Fonts fall back to system faces in this worktree (`node_modules` is a symlink outside Vite's
`fs.allow`); layout and colours are correct.
