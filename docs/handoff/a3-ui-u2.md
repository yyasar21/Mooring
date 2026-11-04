# A3 · ui-engineer · U2: vSphere import wizard, synced tree, power menu, consoles (ADR-0015)

Worktree `agent-af45fa41c391b4cef`, branch `worktree-agent-af45fa41c391b4cef`, from `a3` @ `27433f2`
(all A3 Rust work). Not merged. Built against **rust-core V2's exact contract**
(`a3-rust-core-v2.md`, `src-tauri/ipc-manifest.json`, `ipc-passive.json`, `ipc-codes.json`); where U1
had assumed, the UI now follows Rust. No `cargo` was run here.

## Done

| Commit | What |
| --- | --- |
| `ca454ba` | **IPC alignment.** `VsphereStatus` gains `lastReport` and `scheduled`; `syncFolderId` is documented as derived. `MockVsphereBase` now matches V2: `vsphere.not_found` for refresh/disable while sync is off, idempotent `vsphere_sync_enable`, a failed first import removes the empty root, the two-miss rule (`missing` → deleted, a return → `present` counted as `changed`), a failed refresh writes nothing and shows on the status, `vsphere.wrong_state` / `vsphere.tools_missing` for guest actions, `vsphere.vmrc_disabled` and `vsphere.not_confirmed` for VMRC, `http.trust_prompt` from the scheduler (`vsphereScheduledTick`) with `http.trust_rejected` / a `cert_decision` audit on the manual refresh, V2's audit names (`vsphere_sync_started/finished/failed`, `vsphere_power` with every outcome, `vsphere_console`), and `connection_options_set` can no longer change `syncFolderId`. Test knobs: `confirmPower`, `confirmTrust`, `vsphereHidden`, `vsphereUntrusted`, `vsphereDown`. `FRIENDLY` has plain text for every `vsphere.*` and `http.trust_*` / `http.tls` code (`vsphere.rate_limited` keeps Rust's message, which carries "retry in N s"); `describeCode()` maps a bare status code. The pending skips for the vSphere codes and passive commands are gone (Rust ships them). |
| `857bc47` | **Import wizard** (`components/vsphere/ImportWizard.tsx`) from the vCenter inspector: Sign-in (auto `vsphere_test`, result or error, "Test again") → Folder (any non-synced folder, default the vCenter's own) → Import (`vsphere_sync_enable`, then the counts of `vsphere_status.lastReport`; "Show the folder" selects and expands the new root). **Sync panel** (`SyncPanel.tsx`) on the vCenter connection and on the synced root folder: Refreshed (relative), Next (`lastRefresh + refreshMinutes`, "manual only", or "paused" when `scheduled` is false), Last error (code → text, so `http.trust_prompt` reads "Run Refresh now to review and trust it; the scheduler cannot ask"), the four counters, Refresh now, Disable sync… with a confirm that offers *Keep as ordinary folders* / *Remove folder and VMs*. **VM panel** (`VmPanel.tsx`, `PowerMenu.tsx`): power state polled with `vsphere_vm_power` every 10 s only while the row is in the inspector; the Power menu is disabled with the reason until `allowPowerActions` is on, items that do not fit the state are greyed with the reason, `stop`/`reset` are magenta with "may lose data"; the outcome line distinguishes *requested* / *Cancelled in the dialog* / a refusal — no second confirm in the UI (the dialog is Rust's). Guest identity (`vsphere_vm_identity`, once per row + Reload) and the consoles: *Open in vSphere Client* (reports the `web-<vCenterId>` label) and *VMRC* (disabled unless `allowVmrc`). A `missing` VM shows only why nothing works. The vCenter row no longer offers "Connect" (it has no session), and a VM row offers the consoles instead. |
| `b1dee19` | **Tree.** Rows inside a synced subtree carry `SyncBadge` (vCenter glyph + source name on the root, glyph only below, `aria-label` "synced from X"), `aria-readonly`, `data-sync`, and are not draggable; a drop onto a synced folder, F2, and the toolbar's New connection / New folder are refused with `READONLY_REASON` (the tree's alert line / button titles). `missing` VMs are dimmed, struck through and labelled. Enter on a VM row opens its vSphere Client window. **Dialogs.** A VM row's connection dialog becomes "Edit VM overlays": name, host, port, protocol and folder disabled, no Delete, the vCenter options section hidden (refresh/power/VMRC belong to the vCenter row), credential / overrides / tags saved as before. A synced folder's dialog becomes "Folder default credential": name disabled, no delete. |
| `75b0de6` | **Tests** (below) and the tracer update. |
| (this) | Screenshots and this note. |

Screenshots in `docs/handoff/img/a3-ui/`, dark and light, 1440×860, `playwright` headless Chromium against `vite dev` + `MockTransport`:
- `21-vsphere-import`: the wizard's last step after the import, with the synced subtree already in the tree.
- `22-vsphere-vm`: `app-vm-01` in the inspector with the power menu open (opt-in on), `build-vm` missing.
- `23-vsphere-status`: the synced root folder with the sync panel showing `http.trust_prompt` and a missing VM, and the disable confirm.

## Shared files touched (for the merge against U3)
Only vSphere-related lines; nothing reorganised. `lib/ipc.ts`, `lib/ipc.mock.ts` (497 lines) and `stores/sessions.ts` are **untouched**.
- `lib/ipc.types.vsphere.ts` (rewritten, vSphere only), `lib/ipc.types.ts` (one comment on `syncState`).
- `lib/ipc.mock.vsphere.ts` (rewritten; still the `MockKubeBase ← MockVsphereBase ← MockSecretsBase` chain).
- `lib/ipc.a3.test.ts`: the vSphere `describe` block moved out to the new `lib/ipc.vsphere.test.ts`; header comment and the unused `VsphereConnOptions` import adjusted. The secrets/sync blocks are untouched.
- `stores/errors.codes.test.ts`: the six vSphere entries of `PENDING_A3_CODES` replaced by one comment.
- `lib/polled.test.ts`: the two vSphere entries of `PENDING_RUST` replaced by a comment; the tracer self-check now expects `["audit_verify", "forward_list", "kube_pods", "vsphere_status", "vsphere_vm_power"]` (U3 will add `sync_status` to that line if its panel polls).
- `stores/errors.ts`: one appended block of vSphere / `http.*` texts plus `describeCode()`.
- `components/inspector/Inspector.tsx`, `components/tree/{Sidebar,TreeRowView}.tsx`, `components/dialogs/{ConnectionDialog,FolderDialog}.tsx`, `styles/app.css` (one `@import`).
- Deleted: `components/inspector/VsphereImport.tsx` (U1 placeholder).

## Left open
- **vCenter instance UUID** (V2 left open): the Client window opens `/ui/`, not the VM's summary page; the UI only reports the label.
- **"Create SSH/RDP connection from this VM"** (ADR-0015 §2): not built; needs a prefilled `ConnectionDialog` (`Dialog` in `stores/ui.ts` has no prefill shape). The identity panel shows host name and IP to copy by hand.
- **Client window events**: `vsphere_console` has no `onEvent`; the UI does not track whether the window is still open (V2 suggests polling `web_list`).
- **No E2E** for the vSphere flows; `e2e/flows.e2e.mjs` could drive the same mock (the screenshot script's steps are a usable outline).
- **Line budget**: `lib/ipc.mock.vsphere.ts` is 306 lines, `components/vsphere/vsphere.test.tsx` 377; the shared files at 497 were not touched.
- `mock.vsphereStatus` on a vCenter without sync answers an empty status rather than `vsphere.not_found`; V2 does not say which.

## Decision needed
1. rust-core / owner: should the VM row's `vsphere-console` options be meaningful at all? The UI hides the vCenter options section on VM rows (power / VMRC / refresh are read from the **vCenter's** options, as V2 does); if Rust ever reads a VM row's own options, the section must come back.
2. architect: the Enter / double-click action on a VM row is "open the vSphere Client window" (no session). Fine, or should it open the VM panel only?
3. rust-core: `vsphere_status` for a vCenter whose sync is off — empty status (what the mock does) or `vsphere.not_found`?

## Test evidence
`pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm lint`, `pnpm test`, `pnpm build` green in `apps/desktop`.
**Vitest: 51 files, 390 passed, 1 skipped** (baseline at `27433f2`: 49 files, 373 passed, 1 skipped). The one skip is pre-existing and not vSphere.
- `lib/ipc.vsphere.test.ts` (12): sign-in test and import shape; `syncFolderId` derived across option writes; failed import removes the root; the two-miss rule with restore; failed refresh shows on the status; scheduler `http.trust_prompt` → manual refresh rejects / trusts and audits; the read-only matrix with overlays surviving a refresh; disable keep / drop; power opt-in, cancelled / done / wrong_state with the audit outcome list; Tools needed for guest actions; consoles (client label, `vmrc_disabled`, `not_confirmed`, no ticket in the audit) and identity; locked vault and unavailable vCenter.
- `components/vsphere/vsphere.test.tsx` (10): the wizard end to end (default parent, chosen parent, report, "Show the folder" selection) and its error paths; tree badges, `aria-readonly`, no drag, F2 / drop / toolbar refusals, missing-row styling; the folder dialog (default credential only) and the VM dialog (overlays only, options hidden, tags saved); power polling starts and stops with the inspector (fake timers, `POLL_MS`), menu disabled with the reason until opt-in, item fit and destructive flags, focus on the first enabled item; done / cancelled / refused outcomes with no UI confirm and Escape returning focus; Client and VMRC consoles, Enter on the row, the missing-VM panel; the sync panel's fields, `http.trust_prompt` text, Refresh now updating counts and the tree, polling, manual-only schedule, the disable confirm (Cancel, keep, remove) and the inspector returning to the vCenter.
- `lib/polled.test.ts`: every `setInterval` in the app reaches only passive commands; `vsphere_status` and `vsphere_vm_power` are now checked against `ipc-passive.json` (no skip). `stores/errors.codes.test.ts`: every `vsphere.*` / `http.trust_*` code the mock throws or `FRIENDLY` names is in `ipc-codes.json` (no skip).
