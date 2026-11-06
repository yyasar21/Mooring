# A4 · ui-engineer · U5: UI alignment with rust-core F2 (review 7 L-39 / L-41 / L-43)

Worktree `agent-a795e8d9b43874cef`, branch `worktree-agent-a795e8d9b43874cef`, from `a4` @ `eec26f0`
(F2 handoff indexed). Not merged. No cargo, manifest, lockfile or capability change. The contract is
`docs/handoff/a4-rust-core-f2.md` "UI contract" checked against `src-tauri/ipc-codes.json` (the three
new codes are there; `errors.codes.test.ts` pins them). Two files outside `apps/desktop/src` were touched
on the brief's say-so: `apps/desktop/e2e/a4.e2e.mjs` (the Q1 TODO) and `docs/qa/native-dialogs.md` (one row).
No new screen: every change is a line of text, a decoded field or a mock rule, so no screenshots this round.

## Done

| Commit | What |
| --- | --- |
| `f8702df` | **Codes.** `stores/errors.ts`: `update.downgrade` ("older than an update this install already verified … nothing was installed"), `ldap.bind_declined` ("you did not confirm the sign-in … Mooring did not send the credential; nothing was searched"), `ldap.confirm_required` ("needs a confirmation dialog and none could be shown; run the import again from the main window"). `errors.codes.test.ts`: a pinned test that the three have text, are in `ipc-codes.json` and carry no Turkish. |
| `8604807` | **Updater (L-39).** `UpdateSettings.lastVerified: string \| null`; `decodeUpdateSettings` in `ipc.decode.update.ts` (string or null; `""` and a wrong type → null, so an older Rust without the field still decodes); `TauriTransport.updateSettingsGet/Set` run through it. `UpdatesCard`: "Last verified update: x. Older versions are refused from now on." under "Last checked" when the floor is set (`data-testid="update-last-verified"`). Mock (`ipc.mock.update.ts`): `updateSettings.lastVerified` knob, `semverBelow`, `checkFloor` on check and install (`update.downgrade` + `update.refused { code }`, no `update.check` row), the floor rises after the package verified and before the write (so `update.install_failed` still raises it, `update.signature` does not), monotonic. Tests: mock (floor from check and install, monotonic, failed write), `semverBelow`, decoder, transport round-trip (with and without the field), card (hidden until set; shown; downgrade alert text + audit). |
| `f24ec10` | **Import (L-41).** `ImportWarningCode` gains `key_files_only_for_known_location`; `importText.ts` text ("Private keys are only read when importing from ~/.ssh/config itself, not from a chosen file; the key-file option was ignored."). `PreviewOptions` takes `known: boolean` and renders the key-file switch **only** on the known-location path; a picked OpenSSH file shows no opt-in at all (the plaintext switch never applied to OpenSSH). Mock: `importKeyFiles` on a `pickId` source is ignored and the plan carries the warning with `sourceRef: "importKeyFiles"`; nothing under `~/.ssh` is "read". Tests: mock (picked file → agent credentials, no skipped key, the warning last, count 5; off → no warning), wizard (no switch on a picked ssh config; the warning text when Rust sends it anyway). |
| `f961362` | **Directory sign-in (L-43).** Mock: `ldapSignIn: ("confirm" \| "decline" \| "no_dialog")[]` queue (empty = confirm) and `ldapConfirmed` (`credentialId@host:port`, cleared by `lockBackend`); order trust → confirm → bind as in Rust; `decline` → `confirm_refused { kind: ldap_bind, target, reason: declined }` + `import_refused { code }` + `ldap.bind_declined`, no `ldap_bind` row; `no_dialog` → `ldap.confirm_required`; a confirmed pair is silent for test and preview until lock; another credential or host:port asks again. `DirectoryForm`: a note under the bind credential ("The first sign-in to a server with this credential asks you to confirm in a Mooring dialog (“Sign in to host:port”) before the password is sent. Cancelling sends nothing. The confirmation is remembered until the vault locks.", `data-testid="ldap-signin-note"`) and the dock's idle text mentions the confirmation. Tests: mock (decline / no dialog / confirm, scope per credential and host, certificate dialog first, lock clears, nothing DN-like in the audit), component (note text, both friendly texts, no bind on decline, remembered pair). |
| `789cd9c` | **QA doc.** `docs/qa/native-dialogs.md` row 6 "Directory sign-in" (how to raise it, what a refusal audits) and a "Row 6 scope" check (lock → asks again; per credential / host:port; the dialog names the display name and host only). |
| `4ce6f8b`, `b612744` | **E2E.** `e2e/a4.e2e.mjs`: the Q1 TODO flow — tile → form (ldap:// refused client-side) → trust + declined sign-in (alert text, `confirm_refused` details, no `ldap_bind`) → confirmed Test bind ("Bound as EXAMPLE\admin … Nothing was searched") → Preview with the pair remembered (a queued `decline` is never consumed) → counts 2/5/1/0/0/0, duplicate badge, no opt-ins, no DN → "Import 6 items" → report 2/4/1/0/1 → Open folder → "Imported from LDAP directory" in the tree; audit: two `ldap_bind`, one `cert_decision`, `import_previewed` / `import_applied` format `ldap`, no bind name / DN / secret. `setMock` gains `ldapSignIn` / `ldapTrust`. The stale assertion "the LDAPS tile waits for U4" (failing on `a4` since U4 merged) now asserts the tile is enabled. |

## Shared files touched (append-only unless noted)

- `lib/ipc.ts`: the two `updateSettings*` lines now `.then(decodeUpdateSettings)` (edited).
- `lib/ipc.types.update.ts`, `lib/ipc.types.import.ts`: one field / one union member / one doc line each.
- `lib/ipc.mock.update.ts` (+30), `lib/ipc.mock.import.ts` (328 → 350).
- `components/import/PreviewNotes.tsx`: new `known` prop (one edited signature, one early return); `ImportWizard.tsx` passes it.
- `lib/ipc.update.test.ts`: the settings `toEqual` gained `lastVerified: null` (edited); `lib/ipc.tauri.a4.test.ts`: the settings calls now pin a reply (edited).

## Left open / decision needed

- **`confirm.busy` / `confirm.cooldown` on the sign-in** are not simulated by the mock (the vSphere / sync mocks do not simulate the Gate's cool-down either); the friendly texts exist and show if Rust sends them. If QA wants an E2E for the cool-down, the mock needs a shared Gate model.
- **N-54 (empty stored password → `ldap.bind` before any network)** cannot be mirrored: the mock never sees a password. The existing `ldap.bind` text covers it.
- The sign-in note says "remembered until the vault locks" (F2: in memory, not the store). If the reviewer flips the order to confirm-before-trust, only the mock's order and the E2E's `cert_decision` count change.
- `update.downgrade` from a **background** check: the store treats it like any failed check (`error` text, no badge). Rust audits it; the card shows the alert only on the next manual check. Fine for 0.1.x.
- The Updates card shows the floor as a plain line; there is no way to lower it from the UI (by design, monotonic).

## Test evidence

```
Linux x86_64, 2026-11-06, worktree agent-a795e8d9b43874cef @ b612744 (+ this note)
pnpm install --offline ok · pnpm typecheck ok · pnpm lint ok (0 problems)
pnpm test 71 files, 549 passed (was 71 / 541 on a4 @ eec26f0)
pnpm build ok (built in 5.0 s, no chunk warning)
make e2e (MOORING_E2E_BROWSER=/usr/bin/google-chrome): flows 5, kube 6, vsphere 4, secrets-sync 7, a4 11 — 33 passed, 0 failed
  (a4 was 9/10 on a4 @ eec26f0: "the LDAPS tile waits for U4" failed since U4 merged)
largest touched files: e2e/a4.e2e.mjs 434, lib/ipc.mock.import.ts 350, components/import/ldap.test.tsx 246
```

New tests (8): `errors.codes.test.ts` "the F2 codes … have friendly text and are Rust codes";
`ipc.update.test.ts` "L-39 (F2): the verified floor …", "semverBelow …", "decodeUpdateSettings …";
`updates.test.tsx` "F2 (L-39): the verified floor is shown …" (+1 assertion in the first test);
`ipc.import.test.ts` (+6 assertions, L-41); `wizard.test.tsx` "F2 (L-41): a picked ssh config never offers …";
`ipc.ldap.test.ts` "F2 (L-43): the first bind of a pair asks …"; `ldap.test.tsx` "F2 (L-43): explains the native sign-in …";
`e2e/a4.e2e.mjs` "import wizard: LDAPS form → …".
