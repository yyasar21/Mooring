# A5 · ui-engineer · Harbor W3: data table (M5), connection dialog (L1), credentials (L2), palette (L3), audit (L4), ready page (L5), W2 leftovers

Worktree `/home/claude/nexus/.claude/worktrees/agent-a97d514ae9040c721`, branch
`worktree-agent-a97d514ae9040c721`, from `main` @ `47c648a` (W2 merged). Not merged. No cargo
run, no manifest, lockfile or capability change, no new dependency. `invoke()` is still only in
`lib/ipc.ts`. Plan: `docs/design/review-2026-11/README.md` §4, §7 (M5, L1–L5), §8.

Orchestrator decisions applied: Settings stays one scrolling page with section navigation; the
host-key dialog starts on "Reject and disconnect".

## Done

### M5 data table (`2292344`)
- `packages/ui/src/DataTable.tsx` (+ `.dt` rules in `primitives.css`):
  - sticky 32 px header, 36 px rows, tabular numbers, a natural sort (`web2` before `web10`)
  - sortable columns are buttons in the header; `aria-sort` is `ascending`, `descending` or
    `none` on sortable columns only
  - with `onSelect` it is a `grid`: one tab stop on the rows; ↑ ↓ Home End PageUp PageDown move and
    select; Enter activates (or selects); Space selects; a double click activates
  - without `onSelect` it is a plain `table`
  - `rowLabel` sets a row name; without it the name comes from the cells, as before
  - `onKeyDown` hands other keys to the caller; keys typed into a control inside a row are left
    alone (a row's Delete button keeps Enter)
  - `selectOnFocus` (SFTP) selects the row that takes focus, like the old listbox
- Users:
  - **Kubernetes pods**: `grid "Pods"`. Row names stay the cells' text, so e2e
    `row /pod/` and the "header + 5 pods" row counts still hold. The counter reads
    "5 of 5 pods" (it had no label).
  - **SFTP remote pane**: `grid "Remote files in <path>"`. Rows keep the option names
    ("logs, folder", "README.md, 1.3 KiB"). Folders stay above files when sorted by name. Keys are
    unchanged (Enter, Backspace, F2, Delete).
  - **Audit log**: the entry list is the table (a grid since L4).
  - **vSphere**: new "Imported VMs" section in a synced vCenter root folder's details,
    `grid "Synced VMs"` (name, folder under the root, Synced / Missing). Enter or a double click
    selects the VM in the tree.
  - **Credentials**: see L2.

### L2 credentials (`cc33782`)
- `credentials/CredentialsTable.tsx`: `grid "Stored credentials"`.
  - Columns: Name (with the kind code), Type, Account, Used by, Updated, and an actions column
    that keeps **"Delete <name>"** with its "Confirm delete" step.
  - Filter field ("Filter credentials") and kind chips (All, Passwords, Keys, Domain, External,
    a radiogroup "Kind"), plus "Sorted by …".
  - Row name = the old button text (kind label, name, account, fingerprint, "N used"), so
    `/^Secret manager reference db via vault/` still matches.
- Detail page (`CredentialDetail.tsx`, still `article "<name> details"`): Edit / Delete / Test
  above `tablist "Credential sections"`:
  - **Overview**: the old card, unchanged
  - **Used by (N)**: connections with their role (Sign-in, Sign-in (folder default), RD Gateway,
    Become, Certificate) and folder defaults, each a jump to Hosts (`CredentialUsage.tsx`)
  - **Audit**: the rows of the last 500 audit entries that name the credential (read-only
    `audit_tail`)
- `SectionTabs.tsx` is the shared tab strip; `InspectorTabs` now wraps it (same ids and names).
- **Editor as a side sheet** (`dialog "New credential"` / `"Edit <name>"`, non-modal ARIA, a
  scrim):
  - It holds the kind picker and the schema editor.
  - Escape and the scrim cancel the way Cancel does.
  - While it is open, the page behind is `aria-hidden` and `inert`.
  - The `[data-secret]` assertions and the N-6 "no pasted blob in the view's state" test are
    unchanged and pass.

### L4 audit (`ba0001c`, follow-up `fb7e705`)
- `group "Filters"`:
  - "Filter audit entries" (text)
  - "Event type", "Connection" and "Time" selects; Time is any, last hour, 24 hours, 7 or
    30 days
  - "Clear filters" and "N of M loaded entries"
- The logic is pure (`audit/auditFilter.ts`). The filters apply to the loaded pages;
  "Load older entries" is unchanged.
- The table is `grid "Entries, newest first"`. A row opens `complementary "Entry <seq>"`
  (`AuditDrawer.tsx`) with:
  - the event label and code
  - local and UTC time
  - each detail key on its own line, with names resolved next to their ids
  - the previous hash
- Escape or "Close entry details" closes the drawer and returns to the row. The chain status
  keeps `role="status"`.
- **Export: no button.** `src-tauri/src/lib.rs` `generate_handler!` registers `audit_tail` and
  `audit_verify` only (see Decision needed).

### L1 connection dialog (`4a17175`)
- One scrolling form with `nav "Connection sections"`: General, Sign-in, Gateway (jump hosts, and
  the RD Gateway credential on RDP), then Display (RDP, VNC, web options) or Advanced
  (Kubernetes, vCenter options). A click focuses the section heading. The section in view is
  `aria-current` (scroll spy).
  - Like Settings, it is one page, not separate panes: every field stays in the DOM, so the
    e2e flows that edit "Connect via", the credential picker or the vCenter switches did not
    change.
- Protocol: radio cards in `fieldset "Protocol"` (native radios: arrows move).
- Inline validation (`dialogs/connectionForm.ts`):
  - Name and Host are checked when left after typing, and on Create. Port is checked as it is
    typed.
  - Errors sit under the field (icon and text), linked with `aria-describedby`. The nav item gets
    a dot ("has errors").
  - The footer `role="alert"` says "Fix N fields to continue". It is a button that focuses the
    first problem, and a blocked Create does the same.
  - **Create stays enabled.**
- "Create and connect" on new connections (not for a vCenter) saves, then opens the session.
- Kept: labels Name / Host / Folder / Tags, "Create connection", "Save connection",
  "Save overlays", dialog names. Name gets the initial focus (`Modal` honours
  `data-autofocus`).
- Split: `ConnectionParts.tsx` (cards, nav, section, field error), `SignInFields.tsx`.

### L3 command palette (`5bfa538`)
- Groups in one listbox:
  - **Recent**: connections opened in this unlocked run, newest first, at most 6. Ids in memory
    only (`stores/recent.ts`), dropped on lock, never written to disk.
  - **Connections**: unchanged ranking from `connection_search`.
  - **Actions**: new connection / folder / credential, Import connections…, Go to Hosts /
    Credentials / Audit log / Settings, Show or hide details, Switch theme, Close tab and Detach
    tab (with an active tab), Lock vault.
  - **Settings**: listed when the query matches them; a row opens that card.
- Every action row shows its chord (`Kbd`: mod 1–4, mod I, mod W, mod ⇧ D, mod ⇧ L). The active
  connection row shows ↵.
- Actions match their label first, then extra words ("password" finds New credential).
- `openSettingsCard` now takes any card heading id.

### L5 ready page and canvas (`608596a`)
- `ReadyPage.tsx`: a selected connection with no tab open gets
  `region "<name>, ready to connect"` where "Nothing open yet" was. It shows:
  - protocol, host:port, folder
  - who signs in, marked "(folder default)" when inherited
  - the Connect via route and tags
  - **Connect** (primary) and **Edit connection**
- The duplicate "Connect" is scoped by the region name. Existing queries already scope the
  inspector's "Connect" to `complementary "Details"`. A vCenter and synced VMs keep their own
  panels; the vSphere e2e "a vCenter has no session" check still passes.
- RDP / VNC: the desktop is letterboxed and centred on `--surface-3` (not the terminal black) with
  an e2 shadow, and says "Waiting for the first frame…" until one arrives.

### W2 leftovers
- `24b95e6` **CredentialPrompt and SmartCardPinDialog on the TrustDialog shell**:
  - decision header with a key icon; the card's question in the mono well
  - safe action first; Escape answers empty (cancel); Tab stays inside
  - focus starts on the field: the password when the username is known, otherwise the
    username; the PIN
  - Secret handling is kept and tightened. Both fields are uncontrolled through
    `useSecretInput` (React holds only `empty`), read once, emptied before sending and again on
    unmount. The prompt password was already uncontrolled; it now also clears on unmount.
  - Tests (`terminal/promptDialogs.test.tsx`) walk the fiber tree (`reactStateHolds`).
- `68a8811` **Forward count and Disconnect**:
  - "Forwards" shows a badge with the open-forward count. "N forwards open" is its accessible
    description, so the name stays "Forwards".
  - `stores/forwardCounts.ts`: the forwards panel writes the count on every change. The header
    reads `forward_list` (passive) on mount and every 10 s while its tab is shown.
  - SSH and RDP/VNC headers get **Disconnect** (`stores/sessions.disconnect.ts`): a
    `session_close` that keeps the tab, closed with code `user` ("Disconnected by you."), with
    Reconnect.
- `f76aece` **L-49 mock**:
  - `MockAgentCards` holds a card for `CARD_LIFETIME_MS` (3600 s) after a PIN.
  - A sign-in inside the hour connects without asking. Finding the card does not extend the
    lifetime, as with the real agent.
  - `transport.agentCards.forget()` ends the lifetime early (e2e).
- `6d0d361`: with the new header buttons the session name could shrink to two letters. The host
  now gives way first.

### e2e changes (qa-owned, listed per commit)
- `cc33782` `secrets-sync.e2e.mjs` "external_ref credential": the reference is opened with
  `grid "Stored credentials" → row /^Secret manager reference db via vault/` (was
  `list → button`, same name).
- `f76aece` `a5.e2e.mjs` smart card flow, renamed "… a reopen within the agent lifetime does not
  ask; after it, Escape cancels":
  - the second open connects without a PIN dialog, and the PIN was asked once
  - the flow closes that tab, calls `transport.agentCards.forget()` through the probe, and the
    third open asks the PIN, where Escape cancels as before
  - "Escape never connects" now expects 2 connects
- Unchanged contracts: `toolbar "Session tools"` and its button names, "Detach to window",
  "Trust and connect" / "Reject and disconnect", treeitem names, "New connection",
  `dialog "New connection" / "Edit connection"`, labels Name / Host / Folder, "Create
  connection", `table "Forwards on this session"`, kube `row /pod/` and the row counts,
  `region "Credentials"`, "New credential", the kind picker buttons, the editor forms and
  `article "<name> details"`.

## Left open
- **vSphere table scope.** The design row names vSphere among the table users, but no vSphere
  list existed. The new imported-VMs grid in the synced root folder is my reading. A VM list
  with live power state needs one `vsphere_vm_power` call per row; I did not add that.
- **Audit filters are client-side** over the loaded pages (200 per page). A filter over the whole
  log needs a filtered `audit_tail` from rust-core (event, connection, since).
- **Credential Audit tab** reads the last 500 entries; older rows are not shown (the tab says so).
- **The palette's Recent** is per unlocked run only. Persisting it would put host ids on disk
  outside the vault; not done.
- The connection dialog's Gateway section shows the RD Gateway *credential*. The gateway host,
  port and Basic switch stay in the RDP options (Display), where `RdpGatewaySection` lives.
  Moving them changes `gateway.test.tsx` and the `options.gateway` save path; left for a later
  pass.
- The credential detail header still truncates the kind blurb next to the matrix strip at
  440 px (pre-existing).
- The "Unused" flag, column chooser and a vault switcher from the mockups are not built (marked
  as not shipped in README §6).

## Decision needed
1. **Audit export (rust-core).** No export command is registered (`generate_handler!` has
   `audit::audit_tail` and `audit::audit_verify` only), so there is no button. Proposal:
   - `audit_export { format: "csv" | "jsonl", filter?: { event?, connection?, since? } }`
   - Rust writes through the native save dialog (like `vault_export_pick`) and returns
     `{ rows, path_name }`.
   - The redaction is the log's own. Each export is audited (`audit.exported`).
   - The UI then adds "Export…" to the filter bar with the current filters.
2. **"Create and connect" for synced VMs.** It is hidden for any `vsphere-console` protocol.
   That is right for a vCenter, and a new connection is never a synced VM, so no case is lost
   today. Confirm.
3. **Validation timing.** Name and Host show errors only after the user typed in them and left,
   or on Create, not on a bare Tab through an empty field. Port errors show as typed. Confirm
   this is the wanted strictness.

## Test evidence
- `pnpm typecheck` ✓ · `pnpm lint` ✓ · `pnpm build` ✓
- `pnpm test`: **118 files / 903 tests**, all green (W2 ended at 108 / 866). The contrast and
  alias gates are included.
- New tests:
  - `components/dataTable.test.tsx`
  - `vsphere/vmTable.test.tsx`
  - `credentials/credentialsView.test.tsx`
  - `audit/auditFilters.test.tsx`
  - `dialogs/connectionDialog.test.tsx`
  - `components/palette.test.tsx`
  - `components/readyPage.test.tsx`
  - `terminal/promptDialogs.test.tsx`
  - `terminal/agentLifetime.test.tsx`
  - `components/headerActions.test.tsx`
- Updated tests:
  - `sftp.test.tsx`, `ClusterBrowser.test.tsx`, `audit.test.tsx`, `components.test.tsx`
  - `forwards.test.tsx`, `credentials.test.tsx`, `returnFlow.test.tsx`, `dialogs.test.tsx`
  - `options.test.tsx`, `kube.options.test.tsx`, `gateway.test.tsx`, `connection.test.tsx`
  - `skKey.test.tsx`
  - Role changes (list→grid, listbox→grid); protocol picks use the radios; "Save is disabled"
    checks became the footer summary check.
- `make e2e` (Playwright, mock transport, headless Chromium): **42/42 passed**:
  - flows 5
  - kube 6
  - vsphere 4
  - secrets-sync 7
  - a4 11
  - a5 9
- Screenshots: `docs/design/review-2026-11/after-w3/`, 16 screens × light and dark (32 JPEGs,
  2.9 MB). Mock transport, 1440×900, deviceScaleFactor 1, JPEG q78, WebGL off. Screens:
  - `01-credentials-detail`, `02-credential-used-by`, `03-credential-editor-sheet`
  - `04-audit-filters-drawer`, `04b-audit-filtered`
  - `05-new-connection-errors`, `05b-edit-connection-gateway`
  - `06-palette-hub`, `06b-palette-settings`
  - `07-ready-page`
  - `08-ssh-header-forwards`
  - `09-kube-pods-grid`
  - `10-sftp-files-grid`
  - `11-smart-card-pin`, `11b-sign-in-prompt`
  - `12-rdp-session`
