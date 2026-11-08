# A5 · ui-engineer · Harbor W2: session header (M2), inspector tabs (M4), settings nav (M6), toasts and strips (M7), trust dialogs (M8), L-53

Worktree `/home/claude/nexus/.claude/worktrees/agent-a0bc68e673c9872a7`, branch
`worktree-agent-a0bc68e673c9872a7`, started from `main` @ `b6614ef` (W1 merged), rebased onto
`main` @ `5e287a9` (review-9 fixes). Not merged. No cargo
run, no manifest, lockfile or capability change, no new dependency. `invoke()` is still only in
`lib/ipc.ts`. Plan: `docs/design/review-2026-11/README.md` §4, §7 (M2, M4, M6, M7, M8), §8.

Orchestrator decisions on the W1 questions, applied: rail re-press returns to Hosts (unchanged),
the default theme follows the OS (unchanged), and the AA-tuned token values stay.
`mockups/harbor.css` now carries the same values (light success `#176f32`, warning `#8a5c00`,
text-3 `#5f6670`, input border `#7d858f`; dark text-3 `#959ba4`, input border `#747a83`).
README §4.1 still lists the proposal values; update it if the table should match.

## Done

### L-53 (security review 9): backup secrets out of React state
- `settings/useSecretInput.ts`: an uncontrolled password field.
  - React state holds only `empty`.
  - `take()` reads the value once and empties the field.
  - A stable callback ref empties the field when it leaves the page (dialog closed, step changed).
- `ExportDialog` and `ImportDialog` use it for:
  - the master password
  - the backup passphrase and its repeat
  - the source vault password
- The export form check (`exportFormProblem`) runs on submit. Only its message is kept in
  state. The strength hint is computed in `onChange`, and only its level and text are stored.
- Tests (`settings/backup.secrets.test.tsx`, helper `test/reactState.ts`):
  - The helper walks the React fiber tree: every hook's state and every component's props,
    including a controlled input's `value`.
  - It has a positive control, and both new tests fail on the old dialogs (checked).
  - Each secret is in no state or props while typed.
  - Every field is empty after an attempt and after the dialog closes.
- Same fix, same reason: the keyboard-interactive answer field (`PromptModal`, often an OTP or a
  password) is uncontrolled now.

### M2 session header
- `SessionHeader.tsx` heads every SSH, RDP/VNC and web tab:
  - the folder breadcrumb (`nav "Folder"`)
  - the name, and `host:port` in mono
  - a status pill with label and timer ("Connected · 00:12:31")
  - the tab's own controls
- `stores/sessionClock.ts` stamps when a tab came up. One `useSessions` subscription covers every
  path: events, attach, adopt after unlock, kube, web. `sessionStatus()` is the shared
  vocabulary: Connected, Connecting, Waiting for you, Reconnecting, In its own window, Closed,
  Disconnected. The inspector's Session row uses it too.
- SSH: `toolbar "Session tools"` is a segmented control. Terminal, Forwards and Files keep their
  names and `aria-pressed`.
- **"Detach to window"** is an icon button. The accessible name and the tooltip are unchanged.
  The RDP/VNC tab uses the same button.
- RDP/VNC (`toolbar "Remote desktop tools"`) and web (`toolbar "Web window controls"`) put their
  toolbars into the header. The tools wrap to a second row before the name is truncated.
- The "RDP" / "Web" micro labels are gone (the tab icon carries the protocol).
- The panels use a flex frame (`.session-frame`: header, optional strip, body) instead of an
  absolute toolbar.
- `stores/tree.folderPath` now stops on a folder cycle (hostile synced data). The header reuses it.

### M4 inspector tabs
- `inspector/InspectorTabs.tsx`: `tablist "Details sections"` with Properties, Network and
  History. It uses a roving tab stop; ←/→/Home/End move and select.
- Panels are linked with `aria-controls` / `aria-labelledby`.
- Rows without network tools (Kubernetes, vSphere console) have no Network tab.
- The chosen tab survives moving between rows. When the row has no Network tab, the inspector
  falls back to Properties.
- History is a placeholder: "Session history for this connection arrives in a later release",
  with a pointer to the audit log.

### M7 toasts and inline strips
- `stores/toast.ts`: `push(title, { detail, tone })`, with tone success, info or warning.
  - A toast with a detail stays 7 s instead of 4 s.
  - `Toasts.tsx` shows a status icon, the title, the detail line and a dismiss button
    (`"Dismiss: <title>"`).
  - The call sites add the object as the detail: connection name, credential name, source name.
  - The biometric suspension notice is a warning toast: "<Touch ID> unlock turned off" plus the
    reason.
- `StatusStrip.tsx` replaces the floating "Link lost" box of a closed terminal.
  - It is a full-width strip between the header and the terminal: icon, title from the close
    code, "Disconnected: <reason>", hint, and Reconnect.
  - It has `role="status"` and keeps the class `dropped`, which a smart-card test looks up.
  - The title is "Connection lost" for an unknown code and "Host key rejected" for a terminal
    whose host key was rejected.
- The remote-desktop banners lose the HUD styling. "Link lost · reconnecting to …" is now
  **"Connection lost · reconnecting to …"**; `RemoteSessionTab.test` is updated.

### M8 one trust and confirmation pattern
- `dialogs/TrustDialog.tsx` holds the pattern:
  - `DecisionHeader`: a tone icon and the title
  - `FingerprintWell`: a mono, selectable, wrapping well
  - `DecisionActions`: the safe action first
  - `TrustDialog`: the in-session `alertdialog` shell
  - `ConfirmDialog`: a modal confirmation on `Modal`
- `Modal` takes an optional `tone`. The decorative state dot and the HUD classes are gone.
- Users:
  - **host key**: the well shows the key line from Rust; buttons "Reject and disconnect" and
    "Trust and connect"
  - **server certificate** and **RD Gateway certificate**: the fingerprint well first, then
    subject, issuer, validity and names; Reject, Trust once (gateway only) and Trust and
    remember
  - **keyboard-interactive** prompts
  - **Expose this forward?** (SSH and pod forwards): the well shows "Listening on <address>"
  - **Install … and restart?**: the well shows the version
- All dialog names and button names are unchanged: "Verify host identity", "Verify server
  certificate", "RD Gateway certificate", "Expose this forward?", "Install 0.2.0 and restart?"
  and every button. The confirmations keep role `dialog`.

### M6 settings navigation and search
- The page is split in two. On the left: a **Find a setting** search and the sections, grouped
  as Vault, Trust and audit, and Application. On the right: one column of cards in the same
  order.
- A section click marks the item `aria-current` and focuses the card heading.
- The search hides the cards and nav items it does not match. Escape clears it. When nothing
  matches, the nav says so.
- The search lives in `useUi.settingsQuery`. `showSettings` (and so `openSettingsCard`) clears
  it, so a deep link always shows its card.
- **All card heading ids are unchanged.** Every card stays mounted; a hidden card keeps its state.
- Card eyebrows (Vault, Audit, Trust, Devices, Application, External secrets, …) are removed.
  `SettingsCard` has no `kicker` prop.
- Deviation from the plan row: the cards stay on one scrolling page rather than one page per
  section. This keeps every settings test and e2e flow unchanged. It is easy to switch later:
  the nav already has one entry per section.

### Token migration
- All app stylesheets and inline styles now use Harbor names. A script rewrote the 1:1 aliases.
- `--fs-s` (12.5 px, off-scale) became `--fs-13`, so some secondary text is 0.5 px larger.
- Glow, bevel and `--bar-h` leftovers are replaced.
- Credential kind codes are neutral badges. The matrix cells drop a raw `#fff`.
- Kube ready and RBAC-allowed dots and the vSphere powered-on dot use **success**, and they are
  round (were accent diamonds).
- The command palette shows `ProtocolIcon` (same accessible name) and a chevron for actions,
  instead of text pips and "::".
- `styles/aliases.test.ts` fails if any app stylesheet or `primitives.css` references an alias
  again. The aliases stay defined in `tokens.css` for one release.

### Review-9 UI follow-ups (from `a5-rust-core-review9-fixes.md`)
- **L-52 import summary**:
  - Types: `ImportConflict.kind` gains `trust`, the resolution gains `kept_local`, and
    `ImportResult.trustAdded` is optional.
  - The summary says "N trusted host keys or certificates added", or "No … were added" for 0. It
    shows nothing when the backend omits the field.
  - A trust conflict reads "`host:port` (trust, `known_hosts`) — already trusted on this device:
    the local entry kept, the imported one dropped".
  - The mock merge returns one trust conflict and `trustAdded: 2`; replace returns the backup's
    trust count.
  - Tests: `backup.test.tsx`.
- **L-48 `forward_refused`**:
  - Audit label: "Web proxy refused a destination outside the allowed origins". The target shows
    in the details.
  - Mock: `webViaRefuse(connectionId, target)` records the row, only for a window through jump
    hosts.
  - Test: `audit.test.tsx`.
- **L-49 PIN lifetime**:
  - The PIN dialog says the card stays loaded in ssh-agent for 60 minutes
    (`CARD_LIFETIME_MINUTES`, which mirrors `CARD_LIFETIME_SECS` = 3600). It also says the PIN is
    asked again after that.
  - Test: `smartCard.test.tsx`.
  - Note for qa: the mock still asks the PIN on every open. The a5 e2e "reopening asks again"
    flow relies on that, while real Rust now finds the key in the agent for an hour. Left
    unchanged.
- **L-50 `secret.tool_changed`**:
  - The friendly text: "The bws binary changed since Mooring last trusted it. Test the source in
    Settings → Secret sources to trust it again."
  - A reference test on the credential card adds a note: **"The bws binary changed. Test the
    source to trust it again."** with an **Open Secret sources** button.
  - Audit label: "bws binary changed: refused until the source is tested".
  - Mock knob `bwsChanged`: Bitwarden references refuse (audit `secret.tool_changed`) until the
    source is tested.
  - Test: `credentials/bwsChanged.test.tsx`.

### e2e changes (qa-owned, listed)
- `a4.e2e.mjs`: the two network-card flows click the **Network** tab in Details first. The
  Kubernetes check also asserts there is no Network tab (commit `ccca0a1`).
- The inspector now has its own tabs, so unscoped tab queries were narrowed (commit `c3ec9d2`):
  - `kube.e2e.mjs`: `openCluster` looks up the session panel as
    `region "Sessions" → tabpanel`, and the "cluster tab + exec tab" count is scoped to
    `tablist "Open sessions"`.
  - `flows.e2e.mjs`: three tab counts are scoped to `tablist "Open sessions"`.
- No accessible name in the contract changed: "Trust and connect", "Reject and disconnect",
  `toolbar "Session tools"` and its tool buttons, "Detach to window", treeitem names, card
  heading ids and the dialog names.

## Security sign-off note (M8 and L-53), for the security reviewer
- **What each answer sends is unchanged.**
  - Host key: `yes` / `no`.
  - Certificates: `yes` / `once` (gateway only) / `no`, through `CERT_ANSWER`.
  - The serious-problem checkbox still gates both trust buttons.
  - Buttons are still disabled once an answer has been sent.
  - `PromptModal` still picks the dialog by the typed `purpose`, never by the message text.
- **Initial focus is never on a trust button.**
  - Changed: the host-key dialog used to focus "Trust and connect" (Enter trusted). It now
    focuses "Reject and disconnect", like the certificate dialogs.
  - `TrustDialog` moves focus to the safe control again for each new prompt id.
  - Confirmations focus Cancel.
- **Escape always rejects or cancels.**
  - Host key: `no`. Certificates: `no`. Server prompt: the empty answer.
  - Confirmations call `onCancel`.
  - Tab stays inside the trust dialogs.
- Server-controlled text (the prompt message, certificate subject, issuer and names) is still
  rendered as plain text in the well or the details list.
- No new IPC, no change to what is stored or trusted. Test:
  `dialogs/trustDialog.test.tsx` covers focus, Escape, the Tab trap, the answers and the well.
  The existing certificate and gateway tests still pass.
- L-53: see above. The values still cross IPC once, as before (R-IPC-BUF). The React copies are
  gone, and the DOM fields are emptied after the call and on close.

## Left open
- **M5** (data table) and **L1–L5** (connection dialog with section nav, credentials list and
  detail, command palette as hub, audit filters and export, the "ready to connect" page) are not
  started.
- The forwards count badge on "Forwards" in the segmented control is not shown yet. The panel
  owns the list, and a count needs a shared store. The design also shows a header "Disconnect"
  button; closing the tab is the only way today.
- `CredentialPrompt`, `SmartCardPinDialog` and the `m-hud` / `m-micro` / `m-display` helper
  classes elsewhere still use W1's plain versions of the old classes. They render correctly but
  are not rebuilt on the M8 shell. A later sweep can move them.
- README §4.1 token table: see the note at the top.

## Decision needed
1. **Settings: one scrolling page with nav (shipped) or one page per section (plan row M6)?**
   The current form keeps all contracts. Per-section pages would change the settings tests and
   `openSettingsCard`.
2. **Host-key focus change.** It is safer and matches the certificate dialogs, but keyboard users
   who pressed Enter to trust must now Tab once. Confirm with security.

## Test evidence
- `pnpm typecheck` ✓ · `pnpm lint` ✓ · `pnpm build` ✓
- `pnpm test`: 108 files / 866 tests, all green (W1 ended at 100 / 818), contrast gate included.
- New or changed tests:
  - `settings/backup.secrets.test.tsx`
  - `components/SessionHeader.test.tsx`
  - `components/statusStrip.test.tsx`
  - `inspector/inspectorTabs.test.tsx`
  - `dialogs/trustDialog.test.tsx`
  - `settings/settingsNav.test.tsx`
  - `styles/aliases.test.ts`
  - `credentials/bwsChanged.test.tsx`
  - updated: `backup.test.tsx`, `audit.test.tsx`, `smartCard.test.tsx`, `network.test.tsx`, `RemoteSessionTab.test.tsx`, `CertificateTrustDialog.test.tsx`
- `make e2e` (Playwright, mock transport, headless Chromium), on the rebased branch:
  **42/42 passed**:
  - flows 5
  - kube 6
  - vsphere 4
  - secrets-sync 7
  - a4 11
  - a5 9
- Screenshots: `docs/design/review-2026-11/after-w2/`, 14 screens × light and dark (28 JPEGs,
  2.4 MB). Mock transport, 1440×900, deviceScaleFactor 1, JPEG q78, WebGL off. Screens:
  - `01-host-key`
  - `02-ssh-session-header`
  - `03-inspector-network`, `03b-inspector-history`
  - `04-expose-forward`
  - `05-closed-terminal-strip`
  - `06-rdp-certificate`, `06b-rdp-session-header`
  - `07-toast`
  - `08-command-palette`
  - `09-credentials`
  - `10-settings`, `10b-settings-section`, `10c-settings-search`
