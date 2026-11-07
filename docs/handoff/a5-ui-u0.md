# a5 U0 — ui-engineer handoff: back to the saved item after create/update; AppRole guidance

Owner feedback (2026-11-07): after "Create credential" the form stayed open and nothing said the
credential had been saved. Branch `worktree-agent-a7055b7e5a99b42d7`, rebased on `main` 9da0f2f.

## Done
- **Credential create/update** closes the editor, selects the row in the list and opens a new
  read-only **detail card** (`components/credentials/CredentialDetail.tsx`), built in the
  right-panel DETAILS style: a kind badge and the protocol matrix in the header; Test (for
  `external_ref` and `vault_approle`), Edit and Delete with an inline confirm; Credential section
  (kind, account, fingerprint, the *names* of sealed secrets, updated, "used by N connections /
  M folder defaults"); "Signs in to" protocol chips (role tags gateway/become; an `external_ref`
  follows its `target_kind`). A list row click now opens this card; Edit opens the form, and
  Cancel in the form goes back to the card.
- **Toasts**: `stores/toast.ts` + `components/Toasts.tsx`. They sit bottom right above the
  telemetry strip and leave after 4 s or on dismiss. They are portalled to `<body>` and use a
  bare `aria-live="polite"` region with no role, so the shell grid and the screens' own
  `role=status` lines are unchanged. The texts are "Credential saved", "Connection created",
  "Connection saved" and "Secret source saved", with no values.
- **"New…" round trip**: the connection form's credential "New…" and a new "New…" next to the
  RD Gateway picker send `returnTo { dialog, role, draft }` with the credentials pane
  (`stores/ui.ts`: `ConnectionDraft`, `CredentialReturn`, `ConnectionResume`). On save, the
  connection form reopens with every field kept, including the edited protocol options
  (`useOptionsDraft` takes initial drafts), and the new credential is preselected in the picker
  that asked for it. Cancelling the kind picker returns to the form unchanged. The draft is
  credential ids and plain fields only.
- **AppRole guidance**: in the connection picker's disabled `vault_approle` entry ("Vault AppRole
  is only for secret sources."), I added the hint "Use it in Settings → Secret sources, then
  create a Secret manager reference credential." and an **Open Secret sources** link. Tab from
  the open listbox reaches the link, and Enter/Escape work on it. The link closes the dialog,
  switches to Settings and opens **New secret source** with that AppRole preselected
  (`SettingsIntent`, consumed once by `SecretSourcesCard`). The AppRole detail card lists the
  sources that sign in with it, shows the same hint and has a **Create secret source** button
  that does the same thing. The `external_ref` detail card shows provider, source (name + address,
  or "Unknown source"), path, the kind it resolves to, version and field map.
- **Connection form save**: it now reveals the row: ancestor folders are expanded, the row is
  selected and the DETAILS panel is opened. A toast follows.
- **Secret source form save**: the dialog closes back to the list, and the saved source is
  highlighted (`data-selected`, `aria-current`) and scrolled into view. A toast follows.

## Test evidence
- New: `apps/desktop/src/components/credentials/returnFlow.test.tsx` (9 tests: create →
  detail + toast + no secret in DOM; edit → detail; connection New… round trip with draft and
  preselection, then connection create → tree selection + DETAILS; picker cancel; RD Gateway
  New…; connection update toast; AppRole picker hint → Settings with the AppRole preselected;
  AppRole detail → Create secret source → new source selected; external_ref detail source/path).
- Updated for the new behaviour (save lands on the detail card, Edit opens the form):
  `credentials.test.tsx` and `externalRef.test.tsx`.
- `pnpm typecheck`, `pnpm lint`, `pnpm test` (76 files, 576 tests) and `pnpm build` are all green
  after the rebase.
- `make e2e` (Playwright, preinstalled Chromium works here): `flows`, `kube`, `vsphere` and `a4`
  pass. **`secrets-sync` fails 2 tests**, and only because they assert the old "form stays
  open after save" behaviour. See "Left open".
- Screenshots (gitignored, `apps/desktop/e2e/results/`): `u0-credential-detail.png`,
  `u0-approle-detail.png`, `u0-external-ref-detail.png`, `u0-external-ref-detail-light.png`
  (the script that takes them is `e2e/results/u0-shots.mjs`, which is also gitignored).

## Left open
- **qa-engineer** (`apps/desktop/e2e/**` is outside my scope): `secrets-sync.e2e.mjs` needs
  an Edit click after each save:
  - `createApiToken` (line ~71): wait for `view.getByRole("article", { name: \`${name} details\` })`
    instead of the `Edit ${name}` form.
  - The `external_ref` test (lines ~188 and ~198): after clicking the list row, and again after
    "Save credential", click `view.getByRole("button", { name: "Edit", exact: true })` before
    using the `Edit db via vault` form.
- `KindCredentialSelect`'s "New <kind>…" (the secret-source and sync dialogs) still opens the
  credentials view without a return trip. The brief limited the return trip to the connection
  form and the RD Gateway picker, so it can be added later with the same `returnTo` mechanism.
- The Become (sudo) picker has no "New…" button, as before.

## Decision needed
None.
