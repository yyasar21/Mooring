# ADR-0015: vSphere inventory sync, power actions and VM consoles

Status: Accepted · 2026-11-04 (Phase A3; extends ADR-0005, ADR-0009, ADR-0013, ADR-0014)

## Context
A3 imports a vCenter's datacenters, clusters, hosts and VMs into a synced folder, shows power
state, refreshes on a schedule and opens VM consoles. vCenter usually runs a VMCA self-signed
certificate. The `vsphere_user` credential (UPN + password) and the `vsphere_console` protocol
exist (ADR-0009, `Protocol::VsphereConsole`). There is no mature Rust vSphere crate, and the
WebMKS HTML5 SDK (`wmks.js`) is Broadcom-licensed and not redistributable. CLAUDE.md forbids
hypervisor writes by agents; power actions are a user feature, never exercised against a lab.

## Decision

### 1. Client: thin REST on `mooring-http` (ADR-0014 §1), no SOAP in A3
- Crate `mooring-vsphere` (`forbid(unsafe)`): typed requests for the vSphere Automation REST
  API (`/api/...`, vCenter 7.0+). Responses deserialise into **our** models (bounded strings:
  names ≤ 255 B, ids ≤ 64 B ASCII `[a-z0-9-]`; unknown fields ignored), body cap 8 MiB per call.
- Session: `POST /api/session` with Basic `upn:password` → token (`Zeroizing<String>`, memory
  only), header `vmware-api-session-id` afterwards, `DELETE /api/session` on close, on vault lock
  and on exit. A 401 re-logs in once with the vault credential (vault must be unlocked; a locked
  vault stops refresh and actions). `otp_seed` on `vsphere_user` is unused by the API.
- Trust: `known_vsphere_certs`, ADR-0011 decision table (pin first, `caPem` option for the VMCA
  root, TOFU prompt with fail-then-reconnect). One vCenter connection = one trust entry.
- Limits per vCenter: ≤ 4 concurrent requests, ≤ 10 req/s, 30 s per request; a refresh is
  single-flight (a second trigger joins the running one).

### 2. Inventory into a synced, read-only subtree
- A vCenter is an ordinary connection (`protocol: vsphere_console`, host = vCenter FQDN,
  credential `vsphere_user`) whose options say `VsphereConnOptions { syncFolderId|null,
  refreshMinutes: 15..=1440 (default 60) | null, allowPowerActions: false, caPem|null }`.
- `vsphere_sync_enable` creates the root folder `<connection name>` and binds it. Tree shape:
  `Datacenter → Cluster → Host → VM`; standalone hosts go under a pseudo-cluster
  "Standalone hosts". vSphere VM folders, resource pools and vApps are ignored in A3.
- Calls: `GET /api/vcenter/datacenter`, `/cluster?datacenters=`, `/host?clusters=` (and
  standalone `?datacenters=`), `/vm?hosts=<host>` (per host, keeps each list under the API's
  4 000-result limit), `GET /api/vcenter/vm/{vm}/guest/identity` lazily (inspector only).
  Caps: 64 datacenters, 512 clusters, 2 000 hosts, 20 000 VMs per vCenter; above a cap the
  refresh fails with `vsphere.too_large`, nothing is written.
- Store, migration `0006_synced_folders.sql`:
  `folder.sync_source TEXT NULL` (connection id of the vCenter, on the root and every child),
  `folder.external_id TEXT NULL`, `connection.sync_source TEXT NULL`,
  `connection.external_id TEXT NULL` (`vm-42`), `UNIQUE(sync_source, external_id)` on both,
  `connection.sync_state TEXT CHECK (sync_state IN ('present','missing'))`.
- **Read-only rule, enforced in `mooring-store`** (not only in the UI): inside a synced
  subtree, create/rename/move/delete of folders and connections fail with
  `tree.synced_readonly`. Allowed overlays survive refreshes: a connection's credential, tags,
  username/domain overrides and console options, and a folder's default credential.
- Refresh = fetch all → diff by `external_id` → one SQL transaction: add, rename, move (VM to
  another host), mark `missing`; a VM that is `missing` on two consecutive refreshes is
  deleted (with its overlays). Names are sanitised (`model::is_forbidden`, 120 chars). Audit
  `vsphere.sync { connection, added, changed, missing, deleted, ms }`. A failed refresh changes
  nothing and is shown on the folder.
- The scheduler runs only while the vault is unlocked and the app is open; it never touches
  the idle clock. "Create SSH/RDP connection from this VM" copies host name / IP from
  `guest/identity` into a normal (non-synced) folder.

### 3. Power state and actions
- State: `GET /api/vcenter/vm/{vm}/power` → `POWERED_ON | POWERED_OFF | SUSPENDED`, from the
  list call during refresh and on demand in the inspector (cached 10 s).
- **Proposed A3 set** (owner decision 1): `start`, guest `shutdown`, guest `reboot`
  (`POST /api/vcenter/vm/{vm}/guest/power?action=…`, needs VMware Tools), and hard `stop` /
  `reset` (`POST /api/vcenter/vm/{vm}/power?action=…`). Not in A3: `suspend`, snapshots,
  reconfigure, migrate, delete.
- Off by default per vCenter (`allowPowerActions`, enabling it is audited at warning severity,
  review 5 L-22). Each action is **confirmed in a native dialog opened by Rust** naming the VM
  and the vCenter (as `sftp_pick_local`, ADR-0010): an IPC call alone cannot power a VM off,
  so a compromised WebView (T5) cannot either. Hard `stop`/`reset` add "this is like pulling
  the plug" to the dialog text. Audit `vsphere.power { connection, vm, action, outcome }`
  before and after; at most one action in flight per VM.

### 4. Console
Three paths, in this order of preference for A3:
1. **Open in vSphere Client** (always available): an ADR-0013 web window for
   `https://<vcenter>/ui/` deep-linked to the VM's summary page. No secret in the URL; the user
   signs in inside the ephemeral window, with copy username/password buttons. Needs the vCenter
   certificate trusted by the OS (ADR-0013 decision 6).
2. **VMRC hand-off** (opt-in per connection): `POST /api/vcenter/vm/{vm}/console/tickets`
   `{ "type": "VMRC" }` → a short-lived single-use ticket URL, opened by **Rust** with the OS URL
   handler (`open` / `xdg-open` / `ShellExecuteW` via a fixed argv; the WebView gets no opener
   permission). The ticket goes to another local process (VMware Remote Console, proprietary),
   which T2 could read anyway; it is never logged. Audit `vsphere.console { vm, kind: vmrc }`.
3. **Native WebMKS** (`type: WEBMKS` → `wss://<host>/ticket/<id>`, subprotocol `binary`): the
   traffic is RFB with VMware extensions (PNG/"WMV" frames seen in practice). A3 runs a
   **spike only** (rust-core, behind a cargo feature, lab read-only) to measure whether
   `mooring-proto-vnc` over a WebSocket transport, with `FrameSink`, covers it. Shipping it is a
   separate ADR (A4): it adds a hostile PNG decoder (`png` 0.18 is in the lockfile) and an
   undocumented protocol. We never load `wmks.js` or any remote console script in our windows.

### 5. IPC (ADR-0008 style)
```
vsphere_test({ connectionId })              -> { version, build, user }     # login + logout
vsphere_sync_enable({ connectionId, parentFolderId }) -> Folder
vsphere_sync_disable({ connectionId, keep: bool })    -> void   # keep=true detaches into normal folders
vsphere_refresh({ connectionId })           -> SyncReport { added, changed, missing, deleted, at }
vsphere_status({ connectionId })            -> { lastRefresh|null, lastError|null, running }   # passive
vsphere_vm_power({ connectionId: vmConnectionId }) -> { state }            # passive
vsphere_vm_action({ connectionId: vmConnectionId, action: "start"|"shutdown"|"reboot"|"stop"|"reset" })
                                            -> { outcome: "done"|"cancelled" }
vsphere_vm_identity({ connectionId: vmConnectionId }) -> { hostName|null, ip|null, family|null }
vsphere_console({ connectionId: vmConnectionId, kind: "client"|"vmrc" }) -> { windowLabel|null }
```
Error codes: `tree.synced_readonly`, `vsphere.auth_failed`, `vsphere.too_large`,
`vsphere.power_disabled`, `vsphere.tools_missing`, `vsphere.unavailable`.

### 6. Network tools (note; separate small ADR in A4)
Roadmap item "ping, TCP port check, traceroute, WireGuard status" is **not** designed here.
Recommendation for that ADR: TCP connect check and "TCP ping" (connect latency, tokio, ≤ 10
probes, 1 s timeout, connection's own host/port only, so a T5 cannot port-scan arbitrary
targets); ICMP and traceroute only as a hand-off to the OS `ping`/`traceroute`/`tracert` with a
fixed argv and an address validated as IP/DNS (no raw sockets, no privileges); WireGuard
status read-only via `wg show <iface> dump` only if `wg` exists and runs unprivileged, else
"unavailable". Output is capped and sanitised like kube logs.

## Alternatives considered
- SOAP/vim25 (`AcquireTicket`, `PropertyCollector`): needed for vCenter < 7 and VM folders, but
  an XML parser of hostile input and a much larger surface. Rejected for A3.
- `govc` / PowerCLI subprocess: another credential store, process spawning. Rejected.
- Hosting `wmks.js` in a web window with an injected ticket: licence, and a secret in page
  script (T5). Rejected.
- Treating synced items as normal editable items: the next refresh would silently undo edits.
  Rejected in favour of explicit overlays.
- Power actions confirmed in the WebView: T5 could confirm itself. Rejected.

## Security consequences
- T3: vCenter TLS through our verifier with TOFU; the session token never leaves Rust.
- T4: hostile JSON is capped before parsing; inventory names are sanitised before the store.
- T5: can trigger refreshes and open consoles; cannot power a VM without the native dialog.
- New risks: R-VS-POWER (a user error powers off production; mitigated by opt-in + dialog),
  R-VS-VMRC (ticket handed to a proprietary local process), R-INV grows by the VM inventory.

## Test plan
- Unit: model caps; diff (add/rename/move/missing → delete on the second miss); read-only store
  matrix (every tree command inside/outside a synced subtree); options validation.
- Integration: a vCenter mock (`mooring-testsrv`, hyper) with session, inventory pages,
  401 → re-login, 4 000+ VMs on one host (refused), slow responses (rate limit), power and ticket
  endpoints recording calls; the power dialog replaced by a test `Confirm` trait.
  `#[ignore]` lab test (`MOORING_LAB_VCENTER`): login, list, logout — **no power calls**.
- Fuzz: `vsphere_inventory_json`, `vsphere_session_token`, `vsphere_ticket_url`.

## Open questions for the owner
1. Power set for A3: all five actions behind opt-in + native dialog (proposed), or only
   `start`/guest `shutdown`/guest `reboot`?
2. Is VMRC hand-off wanted at all (it relies on a proprietary client)?
3. Delete a VM entry after two missed refreshes (proposed), or keep it until pruned by hand?
4. Do you need VM folders / resource pools (needs SOAP or the newer `/api/vcenter/folder` tree)?

## Owner decisions (2026-11-04)
6. Power actions: all five (power on, shutdown guest, reboot guest, power off, reset) are
   allowed in A3, each behind the per-connection opt-in and the Rust-native confirmation dialog;
   power off / reset additionally show a "may lose data" warning. Every action is audited.
7. VMRC hand-off is an opt-in per connection; the "Open in vSphere Client" web window is the
   default console path.

## Sources
Broadcom vSphere Automation API 8.0.3 reference: `Vm Console Tickets` (`POST
/api/vcenter/vm/{vm}/console/tickets`, `VMRC`/`WEBMKS`), `VmConsoleTicketsCreateSpec`;
PowerShell SDK `VMware.Sdk.vSphere.vCenter.Vm` 8.0 `TicketsApi.ps1`; openSUSE openQA issue 106083
(WebMKS: `wss://<host>/ticket/<id>`, subprotocol `binary`, RFB-like traffic with PNG frames).
