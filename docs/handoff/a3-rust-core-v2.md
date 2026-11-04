# A3 — rust-core V2: vSphere sync, scheduler, power, consoles (ADR-0015)

Branch: worktree `agent-a5e290ecf4330a19a`, from `a3` @ 6bd87c9. Not merged.
No new third-party dependency. `src-tauri/Cargo.toml` gains the workspace crates
`mooring-http` and `mooring-vsphere` (Cargo.lock: `mooring-app` dependency list only).
**Capability change:** nine `allow-vsphere-*` entries in `src-tauri/permissions/mooring-main.toml`
(main window only) — security review required.

## IPC for U2 (exact JSON; args camelCase, every command main-window only)

The command names follow ADR-0015 §5 and the U1 typed IPC (`ipc.types.vsphere.ts`), not the
task's working names: `vsphere_import_start` = `vsphere_sync_enable` (options are set before
with `connection_options_set`), the power **action** is `vsphere_vm_action`, the passive power
**state** is `vsphere_vm_power`.

```jsonc
// vCenter connection: protocol "vsphere-console", host/port of the vCenter, primary credential
// of kind "vsphere_user". Options (connection_options_get/set), every field optional on write:
{ "syncFolderId": "uuid" | null,     // read-only: filled from the synced root, ignored on write
  "refreshMinutes": 60,              // 15..=1440, null = manual only (default 60)
  "allowPowerActions": false,        // enabling it is audited weakened=true (warning)
  "allowVmrc": false,                // ditto (owner decision 7)
  "caPem": null }                    // VMCA root, certificates only

vsphere_test({ connectionId })                         -> { "version": "8.0.3.00400", "build": "24322831", "user": "alice@example.test" }
vsphere_sync_enable({ connectionId, parentFolderId })  -> FolderDto  // root named after the connection; runs the import; a failed import removes the empty root again
vsphere_sync_disable({ connectionId, keep })           -> null       // keep=true: detached into ordinary folders/connections
vsphere_refresh({ connectionId })                      -> { "added": 1, "changed": 2, "missing": 1, "deleted": 0, "at": "2026-11-04T10:00:00Z" }
vsphere_status({ connectionId })        /* passive */  -> { "lastRefresh": "…"|null, "lastError": "vsphere.rate_limited"|null, "running": false,
                                                            "lastReport": SyncReport|null, "scheduled": true }
vsphere_vm_power({ connectionId: vmRowId }) /* passive */ -> { "state": "POWERED_ON" | "POWERED_OFF" | "SUSPENDED" }
vsphere_vm_action({ connectionId: vmRowId, action: "start"|"shutdown"|"reboot"|"stop"|"reset" })
                                                       -> { "outcome": "done" | "cancelled" }   // "cancelled" = No in the native dialog
vsphere_vm_identity({ connectionId: vmRowId })         -> { "hostName": "…"|null, "ip": "198.51.100.2"|null, "family": "LINUX"|null }
vsphere_console({ connectionId: vmRowId, kind: "client" | "vmrc" })
                                                       -> { "windowLabel": "web-<vCenterConnectionId>" | null }  // null for vmrc
```

Tree rows (`tree_list`, `folder_*`, `connection_*`) carry, only inside a synced subtree:
`FolderDto.syncSource` (vCenter connection id; also on the synced root) and
`FolderDto.externalId` (`datacenter-1`, `domain-c1`, `standalone-datacenter-1`, `host-7`; absent
on the root); `ConnectionDto.syncSource`, `.externalId` (`vm-42`), `.syncState`
(`"present"|"missing"`). Absent keys = an ordinary row. VM rows are `vsphere-console`
connections whose host/port are the vCenter's.

Error codes (all in `ipc-codes.json`): `tree.synced_readonly`, `vsphere.auth_failed`,
`vsphere.forbidden`, `vsphere.rate_limited` (message ends "retry in N s" when vCenter sent
`Retry-After`), `vsphere.not_found` (also: sync not enabled), `vsphere.too_large`,
`vsphere.tools_missing`, `vsphere.wrong_state`, `vsphere.power_disabled` (opt-in off),
`vsphere.power_denied` (vCenter 403 on a power call), `vsphere.not_confirmed`, `vsphere.busy`,
`vsphere.invalid`, `vsphere.failed`, `vsphere.unavailable`, `vsphere.vmrc_disabled`,
`vsphere.vmrc_unavailable`, `http.trust_prompt` (scheduler only), `http.trust_rejected` (No in the
certificate dialog), `http.trust_mismatch`, `http.trust_store`, `http.tls`.

Read-only rule (store): create / rename / move / delete of folders and connections inside a
synced subtree, and moving anything into one, fail with `tree.synced_readonly`. Allowed overlays,
kept across refreshes: a VM row's credential, tags, username/domain override, role credentials,
options; a synced folder's default credential (and sort).

## Done
- **Store, migration `0006_vsphere_sync.sql`** (schema 6): `folder.sync_source` (FK → vCenter
  connection, `ON DELETE CASCADE`), `folder.external_id`, `folder.sync_kind`, `folder.sync_data`,
  `folder.missing_streak`; `connection.sync_source` / `external_id` / `sync_state` / `sync_data` /
  `missing_streak`; unique `(sync_source, external_id)` on both, one synced root per source.
  "Synced" = `sync_source IS NOT NULL` (no separate flag column). `Store::sync_enable`,
  `sync_disable(keep)`, `synced_rows`, `apply_inventory_diff(source, &SyncPlan)` (one
  transaction: upserts parents first → streak reset → `missing` marks → deletions children
  first; any failure rolls back), `connection_sync`, `sync_flags`, `sync_sources`,
  `StoreError::SyncedReadOnly`. The store has no vSphere types: `SyncNode { externalId, kind,
  parent, name, data }`. Names are sanitised (`synced_display_name`: controls / bidi dropped,
  whitespace collapsed, ≤ 120 chars, the id when empty). `syncFolderId` is derived, never stored.
- **mooring-core**: `ProtocolOptions::Vsphere(VsphereConnOptions)` for `vsphere-console`
  (existing `{}` rows parse as defaults; `deny_unknown_fields`).
- **mooring-vsphere**: `vsphere.auth` → `vsphere.auth_failed`; `Session::logout_shared(&self)`,
  `Session::version()`, `Session::allow_ticket_hosts`, `parse_vmrc_ticket_for`; `InventoryItem` /
  `ItemKind` deserialise (stored as `sync_data`), `ItemKind::depth` public.
- **mooring-audit**: `vsphere_sync_started { connection, trigger: manual|schedule|import }`,
  `vsphere_sync_finished { added, changed, missing, removed, ms }`, `vsphere_sync_failed { code }`,
  `vsphere_power { vm, action, outcome: requested|done|already|cancelled|power_disabled|<code> }`
  (stop/reset at warning severity), `vsphere_console { vm, kind }`; certificate answers use the
  existing `cert_decision` (`protocol: vsphere`).
- **App** (`vsphere_sync.rs`, `scheduler.rs`, `commands/vsphere{,_confirm,_console,_login,_vm}.rs`):
  `VsphereHub` in `AppState` (session cache per vCenter and lock epoch, single-flight refresh that
  joins a running one, status, 10 s power cache, scheduler handle). Scheduler: one task per synced
  vCenter with `refreshMinutes`, interval ± 10 % jitter (OsRng), starts on unlock / sync enable /
  options change, `on_lock` aborts every task, bumps the epoch, drops and logs out every session;
  a refresh that finishes after a lock writes nothing (`vault.locked`). Logins read the
  credential from the vault per login and per re-login (closure returns `None` when locked).
- **Native dialogs** (`Confirm` trait; `DialogConfirm` = `tauri-plugin-dialog` `message()` with
  `OkCancelCustom`, parented to main, `dialog_open` auto-lock exemption held via `Prompt`):
  power (names action, VM name + moid, vCenter name + host; stop/reset add "This is like pulling
  the plug: unsaved data in the guest may be lost."), TOFU certificate (subject, issuer,
  fingerprint; "Trust" pins into `known_vsphere_certs`, audited), VMRC hand-off. Tests inject
  `FixedConfirm` (`test-util`).
- **Consoles**: `client` builds an ADR-0013 `WebPlan` for `https://<vc>/ui/` (no instance UUID yet,
  so no deep link), label `web-<vCenterId>`, ephemeral, allow-list = the vCenter origin; a second
  call navigates the open window. `vmrc`: opt-in → dialog → ticket → **Rust** opens it with the
  OS handler (`OsOpener`: `open` / `xdg-open` / `rundll32 url.dll,FileProtocolHandler`, fixed
  argv, no shell; `tauri-plugin-opener` is not a dependency and the ticket never reaches the
  WebView or a log).
- Guard rows, manifest, passive list (`vsphere_status`, `vsphere_vm_power`), `ipc-codes.json`
  regenerated with `MOORING_BLESS=1`.

## Decisions taken (please confirm)
1. **VMRC ticket host**: accepted when it equals the connected host **or** one of the DNS SANs
   of the vCenter certificate this login accepted (pinned / trusted once / CA-valid), max 16.
2. **VM cap**: default 5 000 per vCenter (hub knob, ceiling 20 000 in the crate), unchanged.
3. **Refresh interval**: ADR range 15..=1440 min (the task's "min 5 min" is satisfied).
4. **VMRC hand-off from Rust** (ADR §4.2) instead of returning the URL to the UI.
5. A failed first import removes the empty synced root (no half-bound vCenter).

## Left open
- vCenter instance UUID for the Client deep link (no `/api` source) — the window opens `/ui/`.
- `vsphere_sync_disable` while a refresh is in flight: the refresh then fails (`vsphere.not_found`
  / FK) and writes nothing; not separately tested.
- The Client web window gets no `onEvent` channel (events dropped); U2 can poll `web_list`.
- Lab test (`MOORING_LAB_VCENTER`, read-only) still not written.

## Test evidence
`cargo fmt --all && cargo clippy -p mooring-store -p mooring-vsphere -p mooring-app --all-targets
-- -D warnings` clean (also `-p mooring-core -p mooring-audit`); `cargo test -p mooring-store
-p mooring-vsphere -p mooring-app` green: app lib 210 (+1 ignored, as before), e2e_flow 16,
store lib 34 + integration 50, vsphere 25 + 21; core 139 + 9, audit 30.
- Store (`sync_tests.rs`, 8): enable idempotent + derived `syncFolderId`; import with sanitised
  names and FTS; rename / move / first miss / second-miss delete with streak reset; a bad plan
  rolls back; the read-only matrix (create/rename/move/delete, moves in and out) with overlays
  surviving a refresh; disable keep / drop; deleting the vCenter cascades.
- App against `mooring-testsrv::vcenter` (`vsphere_sync_tests.rs`, 8): import tree shape → diff
  (rename, vMotion, add, missing, delete on the second miss); overlays + `tree.synced_readonly`
  + detach; TOFU in the Rust dialog (reject → `http.trust_rejected`, scheduler → `http.trust_prompt`,
  accept pins and audits); power off without opt-in (no dialog, no call), cancelled (no call),
  approved (one `stop` on the wire, dialog names VM / vCenter / data loss, audit); persistent
  429 → `vsphere.rate_limited`, nothing written, recovers; single-flight join; scheduler runs,
  lock stops it, the server session count drops to 0, no refresh while locked; Client window plan
  (label, URL, allow-list) and VMRC opt-in / cancel / SAN ticket host / ticket not audited.
  `scheduler` jitter bounds.
- `e2e_flow/vsphere.rs`: vault → credential → vCenter → options → import with TOFU → read-only
  tree → reset approved → VM gone twice → lock refuses and logs out.
- Goldens regenerated with `MOORING_BLESS=1`: `ipc-codes.json` (+22), `ipc-manifest.json`
  (+9 commands), `ipc-passive.json` (+2).
