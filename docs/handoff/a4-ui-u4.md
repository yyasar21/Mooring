# A4 · ui-engineer · U4: the Directory (LDAPS) source in the import wizard (ADR-0019 §4, I2)

Worktree `agent-a3be83c0e92126810`, branch `worktree-agent-a3be83c0e92126810`, from `a4` @ `c3f1940`
(U1 wizard + I2 commands merged). Not merged. No cargo, manifest, lockfile or capability change; the
contract is `docs/handoff/a4-rust-core-i2.md` "UI contract" checked against `src-tauri/ipc-manifest.json`
(`ldap_import_test`, `ldap_import_preview`, `main` only) and `ipc-codes.json` (eight `ldap.*`). The U1
extension point was used as written: the tile got a handler, the wizard a `directory` step, and the
shared preview / apply steps and `import_apply` / `import_discard` work unchanged on a directory plan.

## Done

| Commit | What |
| --- | --- |
| `9b9ef95` | **IPC.** `lib/ipc.types.import.ts`: `LdapScope`, `LdapKind`, `LDAP_LIMITS` (5 000 / 256 chars / 64 KiB), `LDAP_CREDENTIAL_KINDS` (`domain_user`, `user_password`), `LdapImportTestArgs`, `LdapBindInfo { host, port, boundAs }`, `LdapImportPreviewArgs` (`scope?`, `filter?`, `sizeLimit?`), `ImportPlanFormat = ImportFormat \| "ldap"` on `ImportPreview.format`, the new warning code `path_truncated`; `ImportIpc` gains `ldapImportTest` / `ldapImportPreview`. `TauriTransport`: two lines, camelCase args as given. **Mock** `lib/ipc.mock.ldap.ts` (fixture + pure helpers) and the two methods on `MockImportBase`: an AD-style forest at `DC=example,DC=test` (`OU=Servers` {DC01, FS01 Windows → RDP; `OU=Web` WEB01, WEB03; `OU=Database` PG02 → SSH}, `OU=Workstations` {two Windows 11, one pre-staged account without `dNSHostName` → `skipped(invalid)`, `entry 8`}, `OU=Lab` with two `ipHost` / `device` objects for the OpenLDAP kind (`ipHostNumber` → host, SSH), one computer nine OUs deep → cut at eight + `path_truncated`). Rules mirrored from I2: `ldaps://` only (`ldap.insecure`), URL / DN parsing (`ldap.invalid`, `ldap.dn_invalid`; a base outside the fixture or an unknown OU → `ldap.dn_invalid` like rc 32), kind / scope / filter / `sizeLimit` checks (`input.invalid`; 0 → `ldap.invalid`; clamp at 5 000; **more matching entries than the cap → `ldap.size_limit`**, see Decision needed), credential lookup (`credential.not_found`, `credential.incompatible` for every other kind), the native trust dialog per unpinned `host:port` (`ldapTrust` queue: `trust` pins and audits `cert_decision { protocol: ldap }`, `reject` → `http.trust_rejected`, `no_dialog` → `http.trust_prompt`; a `caPem` skips the dialog and never pins), `ldapRejects` (default `cr-legacy`) → `ldap.bind`, `ldapFaults` queue (`ldap.unavailable` / `ldap.timeout` / `ldap.response` / `http.tls`), substring filter on `cn` / `dNSHostName` (plain text: `*)(objectClass=*` matches nothing), scope `base` / `one` / `sub`, duplicates against the store (WEB01 ↔ `c-web01`; `dc01` in the seed inherits the Desktops folder's `cr-ad`, so DC01 is not one), one shared `prompt` "Directory account (example.test)" / "Directory account", audit `ldap_bind { host, success }`, `import_refused { code }`, `import_previewed { format: ldap }` and never a DN, bind name or entry. `finishPreview` (duplicates, plan store, audit) factored out of `importPreview` so both sources share it. `stores/errors.ts`: the eight `ldap.*` texts plus `credential.incompatible` / `credential.not_found` (both in `ipc-codes.json`, neither had text). |
| `7307b55` | **Wizard.** `SourceTiles` enables the tile (hint "Computers from Active Directory or OpenLDAP") and emits `SourceId`; `ImportWizard` / `ImportCard` take `SourceId`; `useImportWizard` holds `source`, the `LdapForm`, its errors and the bind result, and lands the directory on the same `preview` step (`run` takes a fetch thunk and the step to fall back to). Step rail "Directory → Preview → Apply". **`DirectoryForm.tsx`**: Server (`ldaps://` placeholder `ldaps://dc01.example.test:636`), Base DN, Scope (Subtree / One level) and Directory kind (Active Directory / OpenLDAP) as segmented controls with a hint naming the object classes and the RDP-by-OS rule, Name filter (optional; "matched as plain text: `*`, `( )`, `\` and the like are escaped, never interpreted"), Bind credential (`<select>` of `domain_user` + `user_password` only, "name · account (kind)", "New credential…" opens the credential dialog), the shared `CaPemField`, Size limit (text input, default 5000, 1..5000). The dock (same `imp-dock` as the file step) shows "Not tested yet" and, after **Test bind**, `host:port` and "Bound as *name*, then disconnected. Nothing was searched." (`role=status`); any change to url / base DN / kind / credential / CA clears it. **`ldapForm.ts`**: client-side checks mirroring Rust's (`ldap://` named as insecure, `ldaps://host[:port]` only, loose RFC 4514 DN, filter ≤ 256 without control chars, size 1..5000, `checkCaPem`), `toTestArgs` / `toPreviewArgs` without empty optionals. Errors from Rust are `describeError` text under the form (`imp-error`); the certificate prompt is Rust-native, the step only shows `http.trust_rejected` / `http.trust_prompt` text. Back from the preview discards the plan and keeps the form; Back from the form returns to the grid; choosing the tile again starts a fresh form. Focus lands on the Server field. |

Screenshots (`docs/handoff/img/a4-ui/`, 1440×860 @2x, `vite dev` + `e2e/boot.html`, system Chrome through
the `playwright` library; dark and light each): `23-import-ldap-form` (the filled form), `23-import-ldap-bound`
(dialog element after Test bind), `23-import-ldap-error` (`ldap.bind` text for the rejected credential),
`23-import-ldap-preview` (the whole forest: OUs, RDP / SSH, the duplicate, the shared prompt, `entry 8`
skipped, `path_truncated`).

## Tests (20 new, 521 → 541; 69 → 71 files)

- `lib/ipc.ldap.test.ts` (10): bind names (`EXAMPLE\admin`, `deploy`), host / port parsing, argument checks in
  Rust's order with `import_refused` codes and no `ldap_bind` row; vault gate; wrong credential → `ldap.bind`
  + `success: false`; trust dialog reject / no dialog / trust / pinned, `cert_decision` rows, `caPem` bypass;
  transport faults; the AD mapping (counts 12 / 8 / 1 / 0 / 1 / 1, folder parents, cut at eight, protocols,
  no port / user, duplicate, prompt credential, `entry n` refs, nothing DN-like in the audit); base DN, one
  level, filter, escaped filter, foreign DN, bad scope / filter; OpenLDAP mapping; size limit / clamp / 0;
  apply through `import_apply` (OUs, one prompt written once, duplicate skipped), discard, `plan_expired`.
- `lib/ipc.tauri.import.test.ts` (+1, +2 manifest rows): the two command names and argument shapes.
- `components/import/ldap.test.tsx` (9): defaults, focus, the step rail, the credential list limited to
  bindable kinds, English only; validation before any bind (`ldap://` → insecure text, DN, size, cleared on
  edit, no `ldap_bind` audit); Test bind result and its clearing; `ldap.bind`, `http.trust_rejected`,
  `ldap.unavailable` texts without Rust's reasons; preview into the shared step with the duplicate badge
  and the prompt credential, no opt-in switches, Back keeps the form and discards the plan, apply + report
  + audit format `ldap`; `ldap.size_limit` text, `path_truncated` and `invalid` wording, no DN in the DOM;
  OpenLDAP + one level + a fresh form from the grid; `ldapForm` helpers and argument builders.
- `components/import/wizard.test.tsx`, `components/onboarding/onboarding.test.tsx`: the tile is enabled and
  opens "Import from Directory (LDAPS)" on the Directory step.
- `stores/errors.codes.test.ts`, `lib/polled.test.ts` unchanged and green: every new `FRIENDLY` key and every
  code the mock throws is in `ipc-codes.json` (the mock's fault codes are literals in a `switch`).

## Shared files touched (append-only unless noted)

- `lib/ipc.ts`: two `TauriTransport` lines under "ADR-0019 §4 (directory importer, I2)".
- `lib/ipc.types.import.ts`: the I2 block, `ImportPlanFormat`, `path_truncated`, two `ImportIpc` methods;
  **one edited line** (`ImportPreview.format`).
- `lib/ipc.mock.import.ts`: the I2 block and `finishPreview` (the body of `importPreview` moved there).
  `lib/ipc.mock.ts` untouched (still 504 lines, pre-existing).
- `stores/errors.ts`: ten rows appended to `FRIENDLY`.
- `components/import/importText.ts`: `sourceKind`, the `path_truncated` text, the tile hint.
- `styles/import.css`: the `data-soon` rules removed, `.imp-dir*` rules added.
- `components/onboarding/onboarding.test.tsx`: one assertion (`toBeDisabled` → `toBeEnabled`).

## Decision needed

- **Size limit: error, not a truncation warning.** The task brief asked for a "size-limit truncation
  warning"; the I2 contract (ground truth) stops the run with `ldap.size_limit` once one entry over the cap
  arrives (abandon, nothing held) and has no warning code for it. The UI follows Rust: the text says why and
  how to narrow the search. If a partial import is wanted instead, rust-core needs a `size_limit` warning code
  and a plan built from the first *n* entries; the preview step would then light the warnings counter as it
  does for `path_truncated`.
- `http.trust_prompt`'s shared text ("Run Refresh now or Sync now …") predates the importer; it only shows when
  the native dialog could not be opened (tests, headless). A neutral wording ("… try the action again from the
  main window") would fit all three callers; one string in `errors.ts`.

## Left open

- Scope `base` is accepted by Rust but not offered (it returns the base object itself, never a computer).
- The credential picker is a plain `<select>`, like `KindCredentialSelect`, but for two kinds; if a third
  bindable kind appears, pass a list to `KindCredentialSelect` instead of keeping a second control.
- No saved directory source or re-run; the form is per wizard open (ADR Left open).
- The `description` attribute Rust requests is not mapped (I2 Decision needed 3); nothing in the UI shows it.
- QA: `e2e/` can drive the directory step with the same mock (`ldapTrust`, `ldapRejects`, `ldapFaults`
  knobs); the screenshot script's steps (tile → fill → Test bind → Preview → Import) are a usable outline.

## Test evidence

```
Linux x86_64, 2026-11-06, worktree agent-a3be83c0e92126810 @ 7307b55 (+ this note)
pnpm install --offline ok · pnpm typecheck ok (packages/ui, apps/desktop) · pnpm lint ok (0 problems)
pnpm test 71 files, 541 passed (was 69 / 521 on the merged a4 head)
pnpm build ok (no chunk warning)
every new file ≤ 260 lines; lib/ipc.mock.import.ts 328; lib/ipc.mock.ts 504 (pre-existing)
screenshots: 8 files 23-import-ldap-{form,bound,error,preview}-{dark,light}.png in docs/handoff/img/a4-ui/
```
