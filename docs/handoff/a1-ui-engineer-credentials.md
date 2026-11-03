# A1 — ui-engineer handoff: typed credentials (ADR-0009)

Branch `worktree-agent-a9c08b4c86bad932a`. The UI side of ADR-0009 is built against `MockTransport`, in the bridge-console design language (cyan = selection, focus and "can sign in"; magenta = danger and the TOTP warning; Chakra Petch titles).

## Done
- **IPC** (`lib/ipc.types.ts`, `lib/ipc.ts`):
  - New commands: `credential_kinds`, `credential_create {name, kind, fields, secrets}`, `credential_update_fields`, `credential_replace_secrets {id, set, clear}`, `credential_copy_secret {id, name}`, `credential_copy_otp {id}` → `{clearsInMs, validForMs}`, `credential_parse_account {input}`, `connection_set_role_credential {id, role, credentialId}`.
  - `CredentialMeta` now carries `fields`, `secretNames` and `fingerprint`.
  - Connections gain `usernameOverride`, `domainOverride`, `gatewayCredentialId` and `becomeCredentialId`.
  - `credential_update_meta`, `credential_replace_secret` and `credential_copy_password` are removed.
- **Mock**:
  - `lib/ipc.kinds.ts` holds the full 15-kind table.
  - `lib/ipc.mock.creds.ts` validates the way the ADR describes: `deny_unknown_fields`, caps, required secrets, kubeconfig `exec`/`auth-provider`/file paths → `credential.kubeconfig_rejected`, `credential.incompatible` on connection create/update and session open, `credential.secret_missing`.
  - Seeds cover nine kinds and the roles.
- **Shared rules** in `lib/credentials.ts`: account parsing (mirrors `parse_account`), forbidden characters, paste detection, field validation, matrix lookup with the ADR footnote reasons, and override applicability.
- **Credentials view** (replaces both dialogs; title bar, sidebar key icon and palette open it). It has two panes:
  - **List**: each credential shows its kind badge, account, `SHA256:` fingerprint and a used-by count (connections in any role plus folder defaults).
  - **Kind picker**:
    - Grouped Accounts / SSH / Certificates & tokens / Kubernetes / VNC / Other. Each row has a six-cell matrix strip: lit = sign-in, outlined = secondary role only.
    - Opened for a protocol (`showCredentials({mode:"new", protocol})`, from the connection dialog's "New…"), it greys out incompatible kinds and gives the reason.
    - A paste zone detects OpenSSH/PEM keys, X.509 certificates and kubeconfigs, and opens the right form with the paste already in place.
  - **Editor** (`CredentialEditor` + `formModel.ts` + `fields.tsx`) renders only from `KindSchema`:
    - The account field (format `netbios_or_upn`) shows the user/domain/form split live.
    - Small enums are segmented controls. An enum without options reads the derived `contexts`, which gives the kubeconfig context picker.
    - Secrets are write-only. Edit mode shows Stored / Replace / Clear (no Clear on required secrets). Multiline secrets are masked; pasting a different kind's blob switches the form.
    - Short secrets get a byte counter (VNC: 9 / 8 bytes, "rejected, not truncated").
    - The `ssh_key` public-key line shows a live `SHA256:` fingerprint (WebCrypto, public data only).
    - The optional TOTP section (seed + digits/period/algorithm) carries the ADR warning.
    - There are explanatory notes for `prompt` and `external_ref`, and "Convert to domain user" on a `user_password` whose username contains `\` or `@`.
- **Secret handling**: secret inputs are uncontrolled. Their values never enter React or zustand state; state keeps only filled / bytes / problem / context names. On submit the values are read once and the inputs are wiped before the IPC call returns.
- **Connection dialog**:
  - The `CredentialPicker` listbox is filtered by the matrix. Incompatible credentials stay visible under "Not usable here", disabled, with the reason; the keyboard skips them. "Ask at connect" is its own group.
  - Username and domain override fields are disabled when the effective kind has nothing to override.
  - RD Gateway picker on RDP; Become (sudo) picker on SSH.
  - A choice that no longer fits after a protocol change is dropped, with a note.
  - An incompatible inherited folder credential is flagged.
- **Inspector**:
  - Role rows (Sign-in / RD Gateway / Become). The account is shown after overrides, with an "override" tag, plus fingerprint, secret names and a hot frame when the effective credential is incompatible.
  - "Copy secret" menu built from schema `copyable` ∩ `secretNames`, plus "Copy OTP code", which shows an SVG ring countdown over the code's remaining validity.
- **Session prompt**: `PromptPurpose` gains `"credential"`. `CredentialPrompt` collects username, domain and password, pre-filled from the prompt's `account`; it splits `CORP\bob` and sends `SessionInput::CredentialAnswer`.
- **Audit labels**: `credential_copied`, `credential_otp_attached`, `credential_prompted`.

## What the backend must match (rust-core)
1. **`KindSchema` extras**: the table in `apps/desktop/src/lib/ipc.kinds.ts` is the snapshot to serve. Conventions the UI relies on:
   - `fields` lists plain fields and secrets in display order, with `secret: true` on sealed ones.
   - The TOTP slot is **not** listed. `supportsOtp: true` implies a secret named `otp_seed` and a plain field `otp: {digits, period, algorithm}`.
   - The derived `fingerprint` is on `CredentialMeta`, not in `fields`. The derived kubeconfig `contexts` **is** in `fields.contexts` (string[]).
   - `domain_user.user` has format `netbios_or_upn` and the account split goes into `user`/`domain`/`form`. `kubeconfig.context` is `enum` with no `options`.
   - `copyable: true` on: password (all kinds), passphrase, become password, token, client_secret.
2. **Prompt event for the `prompt` kind**: `{kind:"prompt", id, message, secret:true, purpose:"credential", account:{username|null, domain|null, needs_username, needs_domain}}` (snake_case on the wire). This is new in `PromptPurpose`.
3. **New `SessionInput` variant**: `{kind:"credential_answer", id, username, domain|null, password}`. `password` is a `SecretString`. An empty username and password means the user cancelled, and the session should close with `authentication cancelled`. ADR-0007 should name it; the alternative of three `Answer`s was rejected because the prompt is one form.
4. **`connection_create/update`** take all four new fields every time (the UI always sends them). `connection_set_role_credential {id, role:"gateway"|"become", credentialId|null}` is typed and wired but the UI does not call it yet: the dialog saves roles through `connection_update`. Keep it, or drop it from the ADR.
5. **Error messages**: `credential.incompatible` messages are shown verbatim in the dialog footer. Please use the matrix reason ("SSH key is for SSH, not RDP sign-in.").
6. **Audit events**: copies are recorded as `credential_copied {credential, name}`, where `name` is `"otp"` for codes. The mock also records `credential_prompted {connection, username}`. If Rust names them differently, update `EVENT_LABEL` in `AuditView.tsx`.
7. **`credential_copy_otp`**: `clearsInMs` ≤ `validForMs`. The UI rings over `validForMs` against the `otp.period` from fields.

## Left open
- `credential_parse_account` is typed and wired but the forms use the TS mirror for live feedback. Rust stays authoritative on save. The TS vectors in `lib/credentials.test.ts` should be copied into the mooring-core tests, or the reverse.
- Kubeconfig contexts are previewed in TS from the typed YAML (only `name:` lines under `contexts:`, capped). Rust derives the stored list.
- The A2 import from `~/.ssh` and `~/.kube/config` is not started (it needs a Rust file picker).
- Folder default credential is still a plain `<select>` with no matrix filter, because a folder has no protocol.
- The `connection_set_role_credential` decision above.
- The Design plugin's accessibility review was not run. Checked by hand: every action is keyboard-reachable (listbox and menu have arrow, Enter and Escape handling), focus is visible, and disabled options keep their reason as text.

## Decision needed
- Does `credential_answer` go into ADR-0007 as proposed (item 3)?
- Keep or drop `connection_set_role_credential` (item 4)?

## Test evidence
- `pnpm install && pnpm typecheck && pnpm lint && pnpm test && pnpm build` are clean. Vitest: 14 files, **105 tests** (the 46 existing ones are kept or ported to the new API, plus 59 new):
  - The schema-driven form renders every one of the 15 kinds (`it.each` over the table: every field present, every secret input is a password or masked textarea with `autocomplete=new-password`, TOTP section exactly when `supportsOtp`).
  - Account parsing: 6 valid and 11 invalid vectors, plus the inverse rendering.
  - The matrix is checked exhaustively against the ADR table (15 kinds × 6 protocols × 3 roles), with footnote reasons and `external_ref` following `target_kind`.
  - Picker filtering, incompatible connection update, override applicability.
  - Secret fields never echo into the DOM, inputs, or the credentials/ui/tree stores after submit.
  - Paste-detect switches to SSH key with the key in place and nothing in the ui store.
  - Kubeconfig context picker, VNC byte counter, convert to domain user, used-by counts.
  - Copy-secret menu entries, copy-OTP countdown with fake timers (18 s → 8 s → gone), prompt-at-connect answer and the `CORP\bob` split, wire decode of the credential prompt.
- Build: main JS 362 kB (was 303 kB), terminal chunk 444 kB, CSS 65 kB, no warnings.
- Screenshots were taken with Playwright (`playwright-core` from the scratchpad, not added to the project) driving `/usr/bin/google-chrome` against `vite dev`, at 1440×860. Each exists as `-dark.png` and `-light.png` under `docs/handoff/img/a1-credentials/`:
  `01-kind-picker`, `02-domain-user-split` (with TOTP warning), `03-kubeconfig-contexts`, `04-ssh-key-edit` (stored secrets, fingerprint), `05-vnc-byte-counter`, `06-connection-picker-rdp` (disabled kinds with reasons), `07-inspector-otp` (ring countdown), `08-inspector-roles` (override, RD Gateway), `09-prompt-at-connect`.

## Dependencies added
None.
