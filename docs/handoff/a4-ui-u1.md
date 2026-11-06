# A4 · ui-engineer · U1: import wizard and first-run onboarding (ADR-0019 §6)

Worktree `agent-a3be8422c6159718f`, branch `worktree-agent-a3be8422c6159718f`, from `a4` @ `0c219aa`
(I1 import commands merged). Not merged. No cargo, no manifest, lockfile or capability change; the
contract is `docs/handoff/a4-rust-core-i1.md` "UI contract" checked against `src-tauri/ipc-manifest.json`
and `ipc-codes.json`. Built concurrently with U2 (Updates / Network cards): nothing under
`settings/UpdatesCard*`, `inspector/Network*`, `ipc.mock.update.ts`, `ipc.mock.net.ts` was touched.

## Done

| Commit | What |
| --- | --- |
| `f7ff48c` | **IPC.** `lib/ipc.types.import.ts`: `ImportFormat`, `KnownLocation`, `ImportFormatInfo`, `ImportPick { pickId, fileName, size }` (no bytes: the WebView never sees the file), `ImportSource = { pickId } \| { known }`, `ImportPreview` (items, credentials with `hasSecret`, skipped with reasons, warnings with codes, counts), `ImportReport`, `ImportIpc` (`importFormats`, `importPick`, `importPreview`, `importApply`, `importDiscard`). `TauriTransport` names `import_formats` / `import_pick` / `import_preview` / `import_apply` / `import_discard` with camelCase args. **Mock** `lib/ipc.mock.import.ts` (`MockImportBase`, now the last link before `MockTransport`) + `lib/ipc.mock.import.data.ts` (one realistic plan per format: nested folders, every protocol, `prompt` credentials, skipped `unsupported` / `invalid` / `encrypted`, the warning codes of each importer). Rules mirrored from I1: picks are single use and vault-gated, `import_formats` is static; the Termius plaintext credentials become `prompt` + `password_dropped` without the opt-in and `user_password` / `ssh_key` with `hasSecret: true` with it; mRemoteNG is always `prompt`; OpenSSH `IdentityFile`s are `ssh_agent`, with `importKeyFiles` a readable one becomes `ssh_key` and the unreadable one is `skipped(key_unreadable)`; duplicates are flagged by `(protocol, host lower-cased, effective port, user)` against the store (`web01`, `pg-primary`, `app-stage`, `dc01` in the seed); plans are held 10 min, ≤ 8 (`import.limits`), single use, dropped by every lock, `import.plan_expired` afterwards; apply writes one new root under the top folder, lifts the children of an excluded folder, unlinks an excluded credential, never writes an unreferenced `prompt` / `ssh_agent`, and audits `import_previewed { format }` / `import_applied { format, counts }` / `import_refused { code }` without a file name. Knobs: `importPicks` (queue of `{ fileName, size, error }` or `null` = cancel), `importKnown` (which known locations exist), `expireImportPlans()`. `stores/errors.ts`: text for the eight `import.*` codes (`import.encrypted` → "This file is encrypted. Export it unencrypted from the source tool, then import it again.", DOCTYPE, limits, ZIP container, too large, format, plan expired, not found). |
| `7d8276d` | **Settings → Import** (`components/import/ImportCard.tsx`, before About): kicker "Bring your connections", the source grid `SourceTiles.tsx` — Royal TS, Remote Desktop Manager, Termius, mRemoteNG, PuTTY, OpenSSH config as bevelled tiles (name + what to export), "Import from ~/.putty/sessions" / "Import from ~/.ssh/config" shortcuts under the two formats with a `knownLocation`, and the **Directory (LDAPS)** tile, disabled, "Coming in this release" (the I2 extension point, see below). **Wizard** `ImportWizard.tsx` + `useImportWizard.ts` (state; the plan lives in Rust, the hook holds its DTO, exclusions and opt-ins): step rail File → Preview → Apply (`vs-steps`). *File*: the dock shows the picked name and size ("ops-team.rtsz · 47 KB"), "Choose file" calls `import_pick` (Rust dialog, extension filter), a cancelled dialog changes nothing; the known-location shortcut skips the dialog and previews at once. *Preview* (`PreviewTree.tsx`, `PreviewNotes.tsx`): six counters (skipped / warnings light up), the opt-in box (Termius: "Import plaintext passwords and keys", off, explains that the export file stays on disk; OpenSSH: "Import private keys from ~/.ssh", off), each change re-runs the preview (a pick is single use in Rust, so a file source asks the dialog again; the known location just re-runs), "Skip duplicates" (on by default, counts them), the manifest tree with a checkbox per folder / connection (protocol pip, `user@host:port`, "Duplicate, skipped" badge with the existing connection's name in the title, All / None, "n of m items selected"), the credential list (name, kind label, "has secret" mark, checkbox), skipped items with their reason in plain words, warnings grouped by code with their source refs, the mRemoteNG "passwords are never imported" banner. *Apply*: `import_apply({ planId, exclude, duplicates })`, the report counters, "Open folder" → workspace view + the new root selected and expanded; Close. Cancel / Escape / unmount → `import_discard` (also for a plan that arrives after the close). Errors are `describeError` text under the step; a refused file clears the consumed pick so Preview is disabled until the dialog runs again; `import.plan_expired` on apply returns to the file step. Focus follows the step (first checkbox of the tree, the report line, the dock button). |
| `6e32409` | **First-run card** (`components/onboarding/OnboardingCard.tsx`, `stores/onboarding.ts`): in the workspace's empty state while the tree is loaded with no connection — "Nothing is moored here yet", three paths: **Start from scratch** (dismisses, opens the connection dialog in the root folder), **Import from another tool** (the wizard on its source grid; it is rendered by `Workspace`, not the card, so a finished import that fills the tree does not unmount it mid-flow), **Read the user guide** (copies the About `User guide` link, "Link copied." status, no `<a>`), and **Not now**. The dismissal is stored per vault id (`sync_status.vaultId`, passive) under `localStorage["mooring.onboarding"]` like the theme; another vault on the same machine gets its own first run; a tree with a connection never shows it. `wipe()` resets the store on lock. |

Screenshots (`docs/handoff/img/a4-ui/`, 1440×860, `vite dev` + `e2e/boot.html`, system Chrome through the
`playwright` library; dark and light each): `10-onboarding`, `11-wizard-source` (from the card),
`12-settings-import`, `13-import-card` (element), `14-wizard-file`, `15-wizard-file-picked`,
`16-wizard-preview` (Royal TS: nested folders, duplicate badge, skipped, warning), `17-wizard-report`,
`18-imported-tree` (the new root selected in the sidebar), `19-wizard-termius-secrets` (opt-in on, two "has
secret" marks, the lit opt-in box), `20-wizard-openssh` (known location, key-file opt-in, four warnings),
`21-wizard-mremoteng` (banner), `22-wizard-error` (`import.encrypted`).

## Extension point for I2 (Directory / LDAPS)

`components/import/importText.ts` `SOURCE_TILES` has the `ldaps` row; `SourceTiles.tsx` renders it disabled
with "Coming in this release" and a tree glyph. To wire the LDAPS form: give `SourceId` `"ldaps"` a handler
in `SourceTiles` (`onChoose` currently ignores it), add a `directory` step to `useImportWizard` that calls
`ldap_import_preview` and lands on the same `preview` step (the `ImportPreview` DTO is shared, so
`PreviewTree` / `PreviewNotes` / apply work unchanged once `importApply` is routed to `ldap_import_apply`
for a directory plan). Nothing else in the wizard assumes a file.

## Tests (31 new, 450 → 481; 60 → 64 files)

- `lib/ipc.import.test.ts` (13): formats; demo / queued / cancelled picks, vault gate; every format previews
  with matching counts and no secret-shaped field; duplicates; Termius opt-in both ways; mRemoteNG never
  carries a password; OpenSSH known location, key files, `import.not_found` + `import_refused` audit; parser
  refusals audited without the file name; single-use pick; apply into a new root (skips duplicates by
  default, parents before children); duplicates imported on request, excluded folder lifts, excluded
  credential unlinks; secrets only with the opt-in, no unreferenced prompt; plan TTL, cap, lock, discard.
- `lib/ipc.tauri.import.test.ts` (2): the five command names and argument shapes against a fake
  `invoke`; every command is in `ipc-manifest.json` for `main` only.
- `components/import/wizard.test.tsx` (9): pick → preview → untick a folder → apply → report → Open
  folder selects the root and closes; cancel discards the plan; Termius opt-in re-runs the preview and
  discards the first plan; OpenSSH known location, key-file opt-in, `import.not_found` text; mRemoteNG
  banner; `import.encrypted` / `import.unsupported_container` text and the consumed pick; duplicates
  switch and `import.plan_expired`; cancelled dialog; the card's seven tiles, two shortcuts, disabled
  LDAPS tile with its description, Escape closes, the shortcut lands on the preview, no Turkish.
- `components/onboarding/onboarding.test.tsx` (7): shows on an empty tree only; Start from scratch opens
  the dialog in `f-root`; the wizard from the card survives the tree filling; copy link; Not now persists
  per vault across lock / unlock and not for another vault id; English only.
- `stores/errors.codes.test.ts` and `lib/polled.test.ts` unchanged and green: every `import.*` key is in
  `ipc-codes.json`, the mock throws only Rust codes (the refusal codes are literals in a `switch`).

## Shared files touched (append-only unless noted)

- `lib/ipc.ts`: five `TauriTransport` lines under "ADR-0019 (importers, I1)".
- `lib/ipc.types.ts`: `import type { ImportIpc }`, `export * from "./ipc.types.import"`, and **one
  edited line**: `interface Ipc extends …, SyncIpc, ImportIpc` (U2 will need the same line for its
  interfaces; a two-way merge is one token).
- `lib/ipc.mock.ts`: **one edited line**, `MockTransport extends MockImportBase` (was `MockSecretsBase`),
  plus the import. If U2 also inserts a base at the end of the chain, chain them (either order works:
  `MockImportBase` only needs `folders`, `connections`, `credentialRows()`, `lockBackend()`). The file was
  already 501 lines before this task and is unchanged in length.
- `stores/errors.ts`: eight `import.*` rows appended to `FRIENDLY`.
- `components/settings/SettingsView.tsx`: `<ImportCard />` before `<AboutCard />` (+ import, doc line).
- `components/Workspace.tsx`: the onboarding branch of `EmptyState` and the hosted wizard.
- `stores/app.ts`: `useOnboarding.getState().reset()` in `wipe()`.
- `test/harness.ts`: onboarding store reset in `freshBackend`.
- `styles/app.css`: `@import "./import.css" layer(components)`.
- Not touched: `errors.codes.test.ts`, `polled.test.ts` (no new polled command; the guards pass as they are).

## Left open

- The preview tree is a list of labelled checkboxes, not an ARIA `tree` (Tab moves through the rows;
  Space toggles). A roving-tabindex tree with ← → collapse would be nicer for 20 000-item plans; the
  mock plans have ≤ 8 rows, so it waited.
- Unticking a folder leaves its children ticked and lifts them a level (I1 rule); the row only greys the
  folder. A hint line ("its contents move up a level") could be added to the row on hover.
- `import_pick` for the key-file / plaintext re-run: a file source re-opens the native dialog because a
  pick is single use (`Picks`, B-4). If rust-core lets a pick survive a refused or re-run preview (as
  `sftp.exists` keeps one for the overwrite retry), `setOption` can drop the second dialog.
- Royal TS / RDM element names are unconfirmed in I1; nothing in the UI depends on them.
- QA: `e2e/` could drive the wizard with the same mock; the screenshot script's steps
  (tile → Choose file → Preview → Import n items → Open folder) are a usable outline.

## Decision needed

- The onboarding card's "Start from scratch" opens the connection dialog directly. ADR §6 says "format
  tiles + Start empty" on the card itself; the three-path card with the wizard behind the import path
  was the task's wording. Say if the tiles should sit on the card too (it is `<SourceTiles>` with
  `onChoose` → `setImporting` + preset format, ten lines).
- Settings → Import sits between Vault sync and About. Move it up (after Auto-lock) if import should be
  the first thing a new user sees in Settings.

## Test evidence

```
Linux x86_64, 2026-11-06, worktree agent-a3be8422c6159718f @ 6e32409
pnpm typecheck ok (packages/ui, apps/desktop) · pnpm lint ok (0 problems)
pnpm test 64 files, 481 passed (was 60 / 450)
pnpm build ok (index 350 kB, mock chunk 92 kB — dev only; no chunk warning)
every new file ≤ 250 lines; lib/ipc.mock.ts 501 (pre-existing)
screenshots: 26 files 10-…22-…-{dark,light}.png in docs/handoff/img/a4-ui/
```
