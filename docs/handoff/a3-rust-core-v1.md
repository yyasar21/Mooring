# A3 — rust-core V1: `mooring-vsphere` (ADR-0015)

Branch: worktree `agent-a90ba6c81609c04aa`, from `a3` @ 24b2b88. Not merged.
**New crate (workspace + default member): security review required before merge.** No new
third-party dependency: `url` 2.5.8, `base64`, `bytes`, `secrecy`, `zeroize`, `time`, `serde`
were already in the lockfile (dev: `hyper`/`hyper-util`/`http-body-util` as in mooring-http).
`Cargo.toml` (members) and `Cargo.lock` (+ the crate's own entry only) touched for the member.

## Public API (for V2 / K4 / UI)
```rust
// session.rs
let s: Session = VsphereClient::login(base: Url, upn: &str, password: &SecretString, http: HttpConfig).await?;
//   http.protocol must be CertProtocol::Vsphere; base_url is replaced by base's origin;
//   max_body lowered to 8 MiB. Trust prompts arrive as VsphereError::Http(HttpError::TrustPrompt)
let s = s.with_reauth(Arc::new(|| vault_unlocked().then(|| Credential { upn, password })));
s.generation();            // re-logins so far
s.logout().await?;         // DELETE /api/session; 401 (already expired) is Ok
// inventory.rs
s.datacenters().await?; s.clusters(&dc).await?;
s.hosts(HostScope::Cluster(&c) | HostScope::Standalone(&dc) | HostScope::Datacenter(&dc)).await?;
s.vms(&VmFilter { vms, names, folders, datacenters, hosts, clusters, resource_pools, power_states }).await?;
s.vm(&id).await? -> VmDetails { id, name, power_state, guest_os, cpu_count, memory_mib, instance_uuid, guest: Option<GuestIdentity> }
s.guest_identity(&id).await? -> Option<GuestIdentity { host_name, ip_address: Option<IpAddr>, family, .. }>
s.inventory(&Caps { datacenters: 64, clusters: 512, hosts: 2000, vms: 5000 /* ≤ 20 000 */ }).await? -> Inventory
diff(&old: &Inventory, &new: &Inventory, &prev_streak: &BTreeMap<ExternalId, u8>) -> InventoryDiff {
    added /* parents first */, removed /* children first */, changed: Vec<Change { old, new, renamed, moved, details_only }>,
    missing /* first miss: mark 'missing' */, restored /* back: mark 'present' */, missing_streak /* persist this map */ }
Inventory::from_items(store_rows) // V2 rebuilds `old` from the store (ids unique, parents present, kinds nested)
// power.rs
s.power_state(&id).await? -> PowerState::{PoweredOn, PoweredOff, Suspended}
let ok = PowerApproval::new(&id, action, options.allow_power_actions, dialog_confirmed)?; // power_disabled / not_confirmed
s.power(&id, ok, &audit /* impl PowerAudit { before, after(outcome: Result<PowerOutcome, code>) } */).await?
    -> PowerOutcome::{Done, AlreadyInState}
PowerAction::{On, ShutdownGuest, RebootGuest, Off, Reset}: as_str() "start|shutdown|reboot|stop|reset", parse(),
    is_destructive() (Off, Reset → "may lose data"), requires_confirmation() (all), requires_tools() (guest ops)
// console.rs
s.vsphere_client_url(&id, vcenter_instance_uuid: Option<&str>)? -> Url  // also free fn vsphere_client_url(&base, ..)
s.vmrc_ticket(&id).await? -> VmrcUrl; url.expose_for_open(now)? -> &str (≤ VMRC_TICKET_TTL = 60 s); Debug redacted
// errors
VsphereError::code(): vsphere.auth | forbidden | rate_limited (retry_after()) | not_found | too_large | tools_missing |
    wrong_state | power_disabled | not_confirmed | busy | invalid | failed | unavailable | http.* (trust/TLS, pass-through)
impl From<VsphereError> for MooringError
// fuzz (mooring_vsphere::fuzz): fuzz_inventory_json, fuzz_session_token, fuzz_ticket_url
```

## Done
- **Session**: Basic `upn:password` built in `Zeroizing`; token = JSON string, 1..=256 visible
  ASCII, held in `Zeroizing<String>` behind a mutex; sent as `vmware-api-session-id` (redacted by
  mooring-http). One re-login per expired token: a generation counter joins concurrent 401s, the
  closure is called once, the credential is dropped right after; a second 401 → `vsphere.auth`.
  A 401 on a POST re-sends it once (vCenter did not run it). UPN `user@domain`, no `:`/space.
- **Caps / models**: every body ≤ 8 MiB before parsing (10 MB refused, test); ids
  `[a-z0-9-]{1,64}` (path/query safe, no encoding needed → id injection impossible by type);
  names ≤ 255 B, no control/bidi chars; lists via `Capped<T, N>` — elements past the cap are
  skipped as `IgnoredAny` (no allocation) and turn into `vsphere.too_large`; per-list caps 64 /
  512 / 2 000 / 4 000 (API limit per VM list). Wrong types, unknown enum values, bad IPs fail the
  response (`vsphere.failed`). **Unknown fields are ignored** (ADR-0015 §1 wording; vCenter
  updates add fields, `deny_unknown_fields` would break refreshes) — the task's "deny where
  stable" was resolved in favour of the ADR.
- **Inventory walk**: datacenter → `cluster?datacenters=` → `host?clusters=` and
  `host?datacenters=&standalone=true` (pseudo-cluster `standalone-<dc>`, "Standalone hosts") →
  `vm?hosts=<host>` one per host. Caps counted while walking; any overflow or a duplicate id
  fails the whole refresh, nothing returned. Sequential (the 10 rps bucket dominates anyway).
- **Diff**: pure, deterministic; the two-miss rule applies to every kind (a host/cluster that
  disappears also waits one refresh); a miss, a present refresh, a miss again is never deleted.
- **Power**: paths `…/vm/{vm}/power?action=start|stop|reset`, `…/guest/power?action=shutdown|reboot`.
  `ALREADY_IN_DESIRED_STATE` → `AlreadyInState`; `NOT_ALLOWED_IN_CURRENT_STATE` → `wrong_state`;
  guest 503 / `SERVICE_UNAVAILABLE` → `tools_missing`. Never retried. One action per VM in flight
  (`vsphere.busy`); the approval is bound to its VM and action and consumed.
- **Console**: deep link verified as
  `https://<vc>/ui/app/vm;nav=v/urn:vmomi:VirtualMachine:<vm>:<uuid>/summary` where `<uuid>` is
  the **vCenter Server instance UUID** (not the VM's) — source: William Lam, "Generating a vSphere
  UI link to a specific virtual machine" (2023-04). Always `https`, same host/port as the base;
  without a UUID → `https://<vc>/ui/`. VMRC: body `{"type":"VMRC"}`, ticket must be
  `vmrc://…@<same host>/?moid=<same vm>`, ≤ 2 KiB, no fragment.
- **Rate limits**: mooring-http defaults (10 rps, 4 concurrent, 30 s) unchanged; GET 429/502–504
  retried with backoff (3 attempts); a final 429 → `rate_limited` with `Retry-After` (≤ 1 h).

## Left open
- **TODO(merge)**: tests use an in-test hyper mock (`tests/common/mod.rs`); switch to QA's
  `mooring-testsrv::vcenter` when it lands (it was not in this worktree).
- QA: cargo-fuzz targets `vsphere_inventory_json`, `vsphere_session_token`, `vsphere_ticket_url`
  for the three `fuzz::*` entries (proptests cover them here). `fuzz/` untouched.
- V2: single-flight refresh, 10 s power-state cache, scheduler, store transaction, audit events
  (`vsphere.sync`, `vsphere.power` via `PowerAudit`, `vsphere.console`), logout on vault lock/exit
  (`Session` has no async `Drop`; the token is zeroized on drop but the server session lingers
  until its idle timeout if `logout()` is not called).
- The vCenter instance UUID has no obvious `/api` source; V2/K4 need to get it (user option,
  or a later SOAP-free endpoint) — until then the link opens `/ui/`.
- `/api/vcenter/host` `standalone` filter and `Vm.Info.identity` (7.0 U1+) are from the API
  reference, not lab-verified; the `#[ignore]` lab test (`MOORING_LAB_VCENTER`, read-only) is not
  written yet.
- R-EXT-STR: the token is copied into a `HeaderValue` per request (not zeroized; same as K1).

## Decision needed
- **VM cap**: task says 5 000 per import (default here), ADR-0015 says 20 000 per vCenter (the
  configurable ceiling here). Confirm the default.
- **VMRC ticket host**: refused when the ticket's host differs from the host we connected to.
  A vCenter reached by IP or alias will issue tickets for its FQDN and fail; relax to "any host
  of the vCenter's certificate SANs"?
- **Error codes**: ADR §5 names `vsphere.auth_failed` / `vsphere.unavailable`; the task names
  `vsphere.auth`. Implemented `vsphere.auth`; ADR or code should be aligned.

## Test evidence
`cargo fmt --all && cargo clippy -p mooring-vsphere --all-targets -- -D warnings` clean;
`cargo test -p mooring-vsphere`: unit 25 (error mapping, ids/injection, names, UUID, capped
arrays, model fixtures incl. unknown fields / wrong types / huge arrays / bad IP, session token
and UPN/base rules, filter query encoding, caps, power table / approval / guest mapping, client
URL forms, ticket validation / TTL / redaction, diff add/rename/move/details/missing×2/restore/
children-first, 2 proptests over the fuzz entries), `session` 7 (Basic → header, logout,
wrong password, refused inputs before I/O, re-login with closure, locked vault, no 401 loop,
logout after expiry), `inventory` 8 (full tree + standalone, idempotent re-diff, caps, 4 001 VMs
on a host, 10 MB body, hostile documents, duplicate VM, details + guest identity / tools
missing / 404, 429 backoff + `Retry-After`, filters on the wire), `power_console` 6 (five
endpoints + audit, tools missing / already / wrong state, no POST retry, VM-bound approval,
busy, re-login during power, power state, VMRC ticket validation + TTL + redaction).
