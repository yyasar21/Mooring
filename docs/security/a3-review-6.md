# A3 security review 6 — Kubernetes, vSphere, external secrets, vault sync (ADR-0014..0017)

Reviewer: security-reviewer · 2026-11-04 · Range `git diff 1b79c1b..HEAD` (`49d7b98`, 116
commits, 589 files, +54 234 / −679). Focus: `crates/mooring-http`, `crates/mooring-proto-kube`,
`crates/mooring-vsphere`, `crates/mooring-secrets`, `crates/mooring-sync`,
`crates/mooring-core/src/{credential/kubeconfig,secret_source,options,known_certs}`,
`crates/mooring-store/src/{sync,sync_rows,secret_sources}.rs`, `crates/mooring-vault/src/subkey.rs`,
`src-tauri/src/{guard,commands/{kube*,vsphere*,secret_sources*,sync*},kube_sessions,
vsphere_sync,secrets_runtime,oidc_window,sync_runner}.rs`, `src-tauri/capabilities/`, the
golden files, and `apps/desktop/src/lib/ipc*.ts` / `main.tsx`. `crates/mooring-testsrv` was read
as test scope only.

Inputs:
- [ADR-0014](../adr/0014-kubernetes-sessions.md) (+ amendment `kube.refused`),
  [ADR-0015](../adr/0015-vsphere-integration.md), [ADR-0016](../adr/0016-external-secrets.md),
  [ADR-0017](../adr/0017-vault-sync-and-signin.md), with the owner decisions.
- Handoffs `a3-rust-core-{k1..k4,v1,v2,e1,e2,s1,s2,f1}.md`, `a3-ui-u1..u4.md`,
  `a3-qa.md`, `a3-qa-q2.md`, `a2-rust-core-review5-nits.md`.
- [Review 5](a2-review-5.md) and the [threat model](threat-model.md).

Evidence gathered here (Linux x86_64, no build, no test run — the orchestrator runs the gate):
- `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok.
- `cargo audit --no-fetch --db <cargo-deny's copy, 2026-11-03>`: 1 vulnerability,
  RUSTSEC-2023-0071 (`rsa`, R-RSA, already ignored in `deny.toml`); warnings only otherwise
  (`zbus_names`/`zvariant*`, `basic-toml`, `proc-macro-error`, `atomic-polyfill`, `glib`
  unsound — all pre-A3, none in the A3 tree). `cargo audit` cannot fetch the DB itself here.
- `cargo tree -i` for every package added to `Cargo.lock` (table below); the sources of
  `rusty-s3` 0.11.0, `kube-client` 5.0.0 (`config` feature wiring), `rfd` 0.17.2 (dialog result
  mapping) and the `unsafe` count of each new crate were read from the registry.
- **Not run:** builds, tests, `cargo geiger`, `gitleaks`, `semgrep`, `pnpm audit`, cargo-fuzz,
  any per-OS WebView check.

## Verdict: `APPROVE WITH NITS`

No blocker. The four new external trust boundaries are built on one shared, reviewed HTTP
stack (`mooring-http`: our rustls/ring verifier, pin before CA, resumption off, no proxy, no
env, redirects refused, body caps, `http://` only to loopback IP literals), and each one holds
its ADR's central property:

- **Kubernetes is read-only by construction.** Every request — JSON, log stream, WebSocket
  upgrade — goes `kube::Client → ReadOnlyGuard → Bearer → HttpService`. The guard matches a
  closed table of 13 literal routes before any byte leaves; it refuses absolute URIs,
  percent-encoded or dot segments, `Impersonate-*`, unknown or repeated query keys (so no
  `dryRun`, no multi-`command` argv), and `POST` exec. kube's own config loaders are banned by
  clippy `disallowed-methods`; kubeconfig resolution is ours and refuses exec, auth-provider,
  basic auth, impersonation, `proxy-url` and unknown user keys. The F1 body deadline
  (`buffered_service`) is approved: lists/gets/reviews now fail after `timeouts.request`;
  streams keep their byte caps. Every cluster, exec, log stream and pod forward ends on lock.
- **vSphere power needs opt-in + a native dialog**, built only then as a `PowerApproval`; the
  VMRC ticket is `Zeroizing`, redacted in `Debug`, host-checked (connected host or ≤ 16 DNS
  SANs of the accepted certificate), single-moid, 60 s TTL, and handed to a fixed argv.
  Synced subtrees are read-only in the store and never leave the device.
- **External secrets**: tokens live in memory only (`Zeroizing`), root tokens are refused,
  ours are revoked on lock/exit, `credential_external_test` returns names only, and the OIDC
  window has an empty capability, a state-bound callback interception and a Vault
  `client_nonce`, so a code that leaks to a local listener is useless.
- **Vault sync** is authenticated end to end: MSY1 binds every header byte (vault, device,
  counter, parent hash, header hash) as AAD under an HKDF subkey of the DEK; rollback and fork
  are hard stops; the remote header must equal the local one byte for byte before anything is
  opened; history walks are bound by the authenticated parent hash.

There is **one Medium**, M-16: every Rust-native confirmation this phase adds (power action,
VMRC, the sync and vSphere trust prompts, fork resolution) puts the **confirming** button
first, i.e. on Return, and a T5 can raise them at will — for example while the user is typing
into a terminal. That turns "an IPC call alone can never answer one" into "one stray Enter
does". It does not stop the merge; it lands before the A3 tag.

## Findings

Numbering continues from review 5 (last used: B-5, M-15, L-32, N-38).

| ID | Sev | Where | Finding | Exact fix |
| --- | --- | --- | --- | --- |
| **M-16** | Medium | `src-tauri/src/commands/vsphere_confirm.rs:64` (`OkCancelCustom(ask.ok, "Cancel")`), used by `vsphere_vm.rs:184` (power), `:233` (VMRC) and the vSphere TOFU prompt; `src-tauri/src/commands/sync_gate.rs:82` (`YesNoCancelCustom(PIN, ONCE, "Cancel")`), `:100` (fork confirmation); `rfd` 0.17.2 sets no default button, so each OS defaults to the **first** (NSAlert: Return = first; TaskDialog: first; GTK: first button focused) | The native dialog is the control that keeps a compromised WebView (T5) from powering off a VM, pinning a certificate or discarding a fork. But T5 decides *when* it appears: `vsphere_vm_action` (or `vsphere_console`, `sync_now`) can be invoked any number of times, and the dialog steals focus from whatever the user is doing. An Enter typed into an SSH or kube exec terminal right then confirms "Power off" / "Reset" / "Trust and remember". There is also no single-flight: concurrent calls stack dialogs. | **rust-core.** 1. Put the refusing choice first so Return refuses: e.g. `OkCancelCustom("Cancel", ask.ok)` and map the result **by label only** (`Custom(s) if s == ask.ok` → yes; everything else → no), likewise `YesNoCancelCustom("Cancel", ONCE, PIN)` in the sync Gate (drop the `Res::Yes/No` arms, which are positional). 2. At most one native confirmation open per process; a second request while one is open fails `confirm.busy` without a dialog. 3. After a cancelled destructive dialog (power off/reset/reboot, fork), refuse new ones for the same target for 10 s (`confirm.cooldown`, audited). Tests: `FixedConfirm` records the button order; a second concurrent `action` gets `confirm.busy`; cancel → immediate retry refused. **QA:** per-OS manual check that Return/Escape refuse on all five dialogs |
| L-33 | Low | `src-tauri/src/oidc_window.rs:303` (`.incognito(true)` only), `:304` (`initialization_script`, top frame only) | The OIDC window repeats the two web-window gaps review 5 closed elsewhere: on **Windows** `incognito(true)` without a `data_directory` puts every OIDC window into the shared InPrivate session of the main WebView2 environment (L-29 class: IdP cookies outlive one sign-in and are shared between sources), and the init script does not reach iframes (N-32 class) | Use `web::ephemeral_storage(state, "oidc-<sourceId>", StorageOs::current())` as `vsphere_console::client_plan` does (own profile dir on Windows, removed on `Destroyed`, swept at start), and `initialization_script_for_all_frames`. Test: the Windows plan of an OIDC window has its own directory |
| L-34 | Low | `src-tauri/src/secrets_runtime.rs:235-245` (`on_lock` spawns `revoke_all`); `oidc_window.rs:156-178` (`begin`: `await begin_oidc` then insert + `open`); `crates/mooring-secrets/src/cache.rs:152` (`put` has no lock check) | A login (AppRole, OIDC code exchange) or an `oidc_begin` that is in flight when the vault locks completes **after** `revoke_all` drained the cache: the fresh token is cached while locked (it is never revoked by that lock), and `begin` can open the IdP window over the lock screen. ADR-0016: "tokens do not outlive the lock". The drain itself also runs only when the spawned task is first polled | Give `SecretsRuntime` a lock epoch (as `VsphereHub` has): `on_lock` bumps it and drains the cache **synchronously** (`std::mem::take` under the mutex, revoke in the background); `TokenCache::put` takes the epoch seen at login start and drops (and revokes, when ours) a token from an older epoch; `oidc_window::begin` re-checks `ready.unlocked()` after `begin_oidc` and after `open` (close + `locked`). Tests: lock during a delayed mock login → cache empty and `revoke-self` sent; lock during `begin` → no window |
| L-35 | Low | `crates/mooring-sync/src/merge.rs:246-256` (`merge_lines`), `crates/mooring-core/src/known_certs/mod.rs:257-267` (`check`: any matching pin → `Trusted`) | Owner decision 10 syncs the trust stores. Two devices that first see a host concurrently and accept **different** certificates (one of them on a hostile network) both keep their line: the merge adds both, and from then on *every* device accepts either certificate without a mismatch. Without sync the second device would have hard-stopped. The merge cannot see that the lines name the same host (salted HMACs) | **rust-core (Tauri layer).** After every apply, for each connection `host:port` in the store and each `CertProtocol`, count distinct fingerprints pinned; if > 1, audit `sync_trust_conflict { protocol, connection }` (warning) and surface it in `sync_status.conflicts` so the user removes the wrong one. SSH `known_hosts` is exempt where the key types differ. Test: two scripted devices pin different fingerprints for `rdp.example.test:3389` → one conflict entry after the merge |
| L-36 | Low | `src-tauri/src/commands/vsphere_confirm.rs:166-180` (`OsOpener`), `vsphere_vm.rs:245` | The VMRC ticket URL is an **argv** of `xdg-open` / `open` / `rundll32` and then of VMRC itself. On Linux `/proc/<pid>/cmdline` is readable by every local user unless `/proc` is mounted `hidepid`; on Windows any same-user process can read command lines. A local observer can redeem the single-use ticket before VMRC does (a console on that VM as the user). This is how VMRC hand-off works everywhere; the 60 s TTL and single use bound it | **architect / docs.** Record as accepted risk **R-VMRC-ARGV** (done in the threat model), keep VMRC opt-in and off by default, and say in the VMRC option help that the ticket is visible to other local users on shared machines. No code change required |
| L-37 | Low | `src-tauri/src/commands/sync_join.rs:160-163` (`save_header` after the rows were applied and the store rebound) | If writing the joined header fails, the store is bound to the joined vault while the bootstrap header stays on disk: after a restart nothing opens, and a retry is refused (`sync.store_not_empty`). Availability only, but the user can lose the fresh device's state silently (S2 "Left open") | Write the joined header to `<header>.join-tmp` (fsync) **before** the apply, and rename it over the bootstrap header right after a successful apply; on start, a leftover `.join-tmp` with a store bound to its vault id completes the rename, otherwise it is removed. Test: an injected header-write failure leaves a device that unlocks with either the bootstrap or the joined password |
| L-38 | Low | `src-tauri/tests/e2e_flow/support.rs:81-180` (`vault_gated_codes`, 44 rows) vs `src-tauri/src/guard/table.rs` (103 commands) | The locked-vault matrix misses every A3 command that is gated *indirectly*: `kube_open` (gated by `state.ready()` in `connect_plan::kube`), `kube_contexts` (`with_ready`), `vsphere_console` (`vm_target` → `with_ready`), and the session-bound `kube_access`/`kube_namespaces`/`kube_pods`/`kube_pod`/`kube_exec_open`/`kube_logs_open` (gated because `kube_sessions::close_all` ends every cluster on lock). They are all safe today (read here), but nothing pins it, and three of them are passive | **qa-engineer.** Add `kube_open`, `kube_contexts` and `vsphere_console` to `vault_gated_codes_a3` (`vault.locked`), and a lock test that a cluster session id used after the lock gets `session.not_found` for each of the six session-bound kube commands. Add a golden check that every `guard::COMMANDS` row is either in the gated list or in an explicit, commented `NOT_GATED` list (`app_info`, `vault_*`, `session_list`, `secret_source_revoke`, `secret_source_oidc_status`, …), so a new command cannot be forgotten |
| N-39 | Nit | `src-tauri/src/commands/vsphere_console.rs:51-81` (`open_client`) | The vSphere Client window is a new web-window build path without the N-30 post-check: a lock between `vm_target` and `build()` leaves it visible | Call `web_cmds::hide_if_locked` after `build()` (and after the `reopen` + `show`) as `web_open` does |
| N-40 | Nit | `src-tauri/src/kube_sessions.rs:132-138` (`set_client`: `ended()` check, then store) vs `:209-230` (`teardown`) | Check-then-set race: a lock between the check and the store leaves the client (and its token) in a torn-down control until the cluster task ends | Take the `client` mutex first and test `ended` while holding it; `teardown` sets `ended` under the same mutex |
| N-41 | Nit | `crates/mooring-secrets/src/client.rs:193` (`token_from`: `policies`, `token_policies`) vs `:214` (`lookup_self` also checks `identity_policies`) | Login responses are not checked for `identity_policies` containing `root`. Vault refuses `root` on identities today, so this is consistency, not a hole | Check `identity_policies` in `token_from` too; one unit vector |
| N-42 | Nit | `src-tauri/src/commands/secret_sources.rs:184-193`, `:170-172` | `secret_source_create` lists both `caPem` and `allowHttp` as changed when either is set; `allowedOrigins` (the OIDC window's navigation allow-list) is not treated as weakening; `caPem` is not fingerprinted as `connection_options_set` does (L-22) | List only the set fields; `allowedOrigins` added → `warning`; add the SHA-256 of each `caPem` certificate to the event |
| N-43 | Nit | `src-tauri/src/oidc_window.rs:251-256`, `src-tauri/src/web/window.rs:61` | Every refused navigation is one hash-chained audit row. A hostile IdP page (or web page) looping `location = …` writes rows without bound. Pre-existing for `web-*`, extended to `oidc-*` | Per window: audit the first 16 refusals, then one `…_suppressed { count }` row on close; close an OIDC window after 64 refusals (`failed: navigation_flood`) |
| N-44 | Nit | `crates/mooring-sync/src/backend/s3.rs:121-128`, `:134-142`; `rusty-s3` 0.11.0 `credentials/mod.rs:29-30` | Correction to S2 "Left open": rusty-s3 keeps the **secret** in `Zeroizing<String>`; the **session token** is a plain `Option<String>`, and each presigned path (signature, `X-Amz-Security-Token`, valid 300 s) is an unzeroized `String` that the storage side also logs. Within R-EXT-STR | Pass the token only when set (already), wrap the signed path in `Zeroizing<String>` on our side, and shorten `SIGN_TTL` to 60 s (requests are sent at once). Document under R-EXT-STR |
| N-45 | Nit | `src-tauri/src/commands/sync_gate.rs:82-91` | The trust dialog text is fine, but the fingerprint shown is the only thing the user can verify, and "Trust once" is offered for a storage endpoint that background runs will hit again (they then fail `http.trust_prompt`) | Keep "Trust once" but say "for this sync only"; together with M-16 make Cancel the default |
| N-46 | Nit | `src-tauri/Cargo.toml:23` (tauri pinned) — `wry` not pinned | L-32 asked for `wry` too (storage semantics behind L-29/L-33). It is held only by `Cargo.lock` (0.57.1) | A unit test that reads `Cargo.lock` and fails unless `wry == 0.57.1` and `tauri-runtime-wry == 2.12.3`, with a comment pointing at this review |

### Closure of review 5 items in this range
| ID | Status | Evidence |
| --- | --- | --- |
| L-29 | **fixed (code); Windows E2E owed** | `src-tauri/src/web/mod.rs:118-122`, `:211-215` (`Storage::EphemeralDirectory` on Windows), `web/window.rs:114` (`incognito(true).data_directory(dir)`), `web/sweep.rs` (`ephemeral_profiles`). The vSphere Client window uses it (`vsphere_console.rs:145`). The OIDC window does not: L-33 |
| L-30 | **fixed** (macOS identifier stores excepted, upstream) | `commands/tree.rs:165-176` (`delete_folder_with` → `purge_deleted`), `:238` (window destroyed before the directory), `commands/vault.rs:104` + `web/sweep.rs:64` (`orphan_stores` after unlock); tests `web/web_tests.rs:188-196` |
| L-31 | **open** | No per-OS QA result yet; R-WEB-UI stays open |
| L-32 | **partly fixed** | `src-tauri/Cargo.toml:23` `tauri = "=2.12.5"`. `wry`: N-46 |
| N-30 | fixed | `commands/web.rs:157` `hide_if_locked`, used at `:264` and `commands/detach.rs:151`. New path missing it: N-39 |
| N-31 | fixed | `mooring-core/src/options/conn.rs:185` `is_localhost_subdomain`, refused in validation (`:239`) and in `web/policy.rs:97` |
| N-32 | fixed | `web/window.rs:26-39` (`showPicker`, drop), `:110` `initialization_script_for_all_frames` (OIDC: L-33) |
| N-33 | fixed | `useKnownCerts.ts:43` labels from Rust `host`/`port`; `lib/hostHash.ts` is mock-only (`ipc.mock.remote.ts:25`) |
| N-34 | fixed | `apps/desktop/src/components/dialogs/options/VncOptions.tsx:50-57` (danger styling + warning), `lib/validate.options.ts:227` |
| N-35 | fixed | `Cargo.toml` russh features `["ring", "rsa"]`; `mooring-proto-ssh/src/algos.rs:116` `compression_is_none_only` |
| N-36 | fixed | `DetachedApp.test.tsx` has no `skipIf` any more |
| N-37 | fixed | `commands/web.rs:110` `check_clear` runs before the wipe closure (`:134` `clear_data_with`) |
| N-38 | fixed | `src-tauri/src/lib.rs:278` drops every directive containing `[`; the span-scoped cases are tested |
| N-28 (c) | **fixed** | `apps/desktop/src/lib/ipc.ts:291` (`TauriTransport` chosen synchronously in Tauri), `:302-306` `bootTransport` imports `ipc.mock.demo` dynamically only when no transport is set; no static `ipc.mock*` import outside the mock files. The chunk is still emitted into `dist/` but never requested inside Tauri |
| L-28 | **partial (carried)** | Still missing: `cut_text`, `framebuffer_ops`, `rdp_reactivation`, the pinned upstream IronRDP targets and a green nightly run. A3 adds 17 targets (37 total) |
| M-14 | upstream half open | unchanged |
| L-24 note | fixed | `docs/user-guide/troubleshooting.md` "Getting diagnostic output" |

## Rulings

### 1. Guard and capabilities
1. **Every new command is main-only: confirmed.** `src-tauri/src/guard/table.rs:70-110`: all
   34 A3 rows are `Scope::Main`; `Scope::Session` is unchanged (six rows). `mooring-main.toml`
   and `ipc-manifest.json` are kept equal to the table by `guard::capability_tests`.
2. **`oidc-*` and `web-*` get nothing: confirmed.** `capabilities/oidc.json` has
   `permissions: []` and no `remote`/`webviews`/`local`/`platforms`; `guard::caller`
   (`guard/mod.rs:38-46`) refuses every label except `main` and `detached-<non-empty>`, so
   `oidc-…` falls to `ipc.forbidden` before the auto-lock hook; tested
   (`capability_tests.rs:120-129`). The vSphere Client window is a `web-<vcenterId>` window
   with the same empty capability.
3. **Passive list: minimal, approved.** New passive entries: `kube_access`, `kube_namespaces`,
   `kube_pods`, `vsphere_status`, `vsphere_vm_power`, `secret_source_oidc_status`,
   `sync_status`. All are polled reads; none opens a dialog, writes the store or logs in
   (`vsphere_vm_power` uses an *existing* session only, `vsphere_vm.rs:73-89`). Being passive
   they cannot keep the vault open; all are dead after a lock (sessions closed, hub cleared).
4. **Vault gate:** correct for every A3 command, but the matrix is incomplete (L-38).

### 2. Kubernetes (ADR-0014)
5. **`ReadOnlyGuard`: approved** (`crates/mooring-proto-kube/src/guard.rs:186-268`,
   `query.rs:75-140`). It sits on *both* clients (`client.rs:102-111`), under kube and above
   the bearer and transport, so neither kube nor our code can send around it. Route kinds fix
   the method (`Read` = GET/HEAD without upgrade, `Upgrade` = GET + websocket, `Post` = the
   three self-reviews, which have no persistent effect). Values are percent-decoded strictly and
   then checked per kind: `command` ∈ the five shells (one occurrence only, so no argv),
   `limitBytes ≤ maxLogBytes`, `tailLines ≤ 10 000`, `limit ≤ 500`.
6. **Exec, port-forward, logs: approved.** An interactive shell in a pod is by nature not
   read-only *inside* the pod; that is owner decision 3 and is recorded as R-KUBE-EXEC. Pod
   forwards bind loopback only (`portforward.rs:183`, `commands/kube_forward.rs:85`), like SSH
   loopback forwards (same-user T2 can use the port). Log lines are sanitised (CSI/OSC/DCS,
   C0/C1, bidi) before the UI; 8 streams per cluster, byte-capped.
7. **Kubeconfig resolve: approved** (`mooring-core/src/credential/kubeconfig/resolve.rs:26-46`,
   `:193`, `:236-262`): allow-listed keys only; `exec`, `auth-provider`, basic auth,
   impersonation, `proxy-url` and any unknown user key are refused; `insecure-skip-tls-verify`
   becomes a TOFU prompt, never a skip; keys must be unencrypted single PEM blocks; caps on every
   blob. kube's own loaders are unreachable (`crates/mooring-proto-kube/clippy.toml`).
8. **`peek_exp`: approved** (`kubeconfig/jwt.rs:19-41`): unverified, display and early-expiry
   only, never a trust decision, capped, fuzzed (`jwt_exp_peek`).
9. **F1 `buffered_service`: approved** (`crates/mooring-http/src/service.rs:49-54`, `:92-96`).
10. **Lock: approved.** `kube_sessions::close_all` (`kube_sessions.rs:241-262`, called from
    `commands/vault.rs:143`) tears every cluster down synchronously (logs aborted and audited,
    forwards dropped, exec children closed, client and token dropped). Race: N-40.

### 3. vSphere (ADR-0015)
11. **Power: approved with M-16.** Opt-in checked first (audited `power_disabled`), then the
    native dialog naming VM, moid, action, vCenter and host (`vsphere_vm.rs:142-170`), then
    `PowerApproval::new(…, allow, yes)`; `requested` / outcome audited. A lock during the
    dialog is safe: the hub drops sessions on lock and a fresh login needs the vault.
12. **VMRC ticket: approved** (`crates/mooring-vsphere/src/console.rs:56-160`): never in a DTO,
    a log or an error; redacted `Debug`; `expose_for_open` only inside the TTL; host = the
    connected host or a DNS SAN of the accepted certificate (≤ 16), exactly one `moid`, no
    fragment, ≤ 2 KiB visible ASCII. argv exposure: L-36 / R-VMRC-ARGV.
13. **Synced subtree: approved.** Store-level `SyncedReadOnly` on create/rename/move/delete and
    on identity fields of synced connections (`mooring-store/src/connections.rs:100-117`,
    `:205-208`, `sync.rs:153-158`); overlays (credentials, options) stay editable by design.
    Synced rows are excluded from MSY1 (`sync_rows.rs:150-363`, `sync_source IS NULL`).
    Inventory caps (5 000 VMs default, 20 000 ceiling) and names without control or bidi
    characters (`ids.rs:70-89`) bound the hostile vCenter.
14. **Scheduler and lock: approved** (`vsphere_sync.rs:225-240`, `:296-308`): epoch bump, timers
    stopped, sessions logged out in the background, results of a pre-lock refresh dropped.
15. **Client web window: approved** (`vsphere_console.rs:37-81`): https only, allow-list = the
    vCenter origin only, ephemeral (own profile on Windows), no secret in the URL. N-39.

### 4. External secrets (ADR-0016)
16. **Token flows: approved.** Stored `token` → `lookup-self` (root refused); AppRole login never
    retried, `role_id` sealed; OIDC with `client_nonce` (32 random bytes, Rust only), `state`
    compared in constant time, the redirect never loaded (`oidc.rs:166-178`), 5-minute
    timeout, one flow per source. Root: N-41.
17. **`TokenCache`: approved with L-34.** `Zeroizing` tokens, capped lifetime, renew at the
    refresh threshold or drop, revoke ours (`revoke-self`, 3 s) on lock and exit.
18. **`credential_external_test`: names only, approved** (`RefTestDto`: `present` / `missing` /
    `extra` key names, version, error code). `ResolvedSecrets` holds `Zeroizing<Vec<u8>>`.
19. **OIDC window: approved with L-33.** Empty capability, `devtools(false)`, new windows,
    downloads and permissions denied, navigation = IdP origin + `allowedOrigins`; a
    foreign-state callback ends the flow; closed on lock (`fail_all`). If an engine ever lets the
    `http://localhost:8250` redirect load (the per-OS E2E gate of ADR-0016 §4 is still owed), a
    local listener gets a code that cannot be exchanged without the nonce.
20. **Audit: approved with N-42/N-43.** `secret_refused` rows carry action and a static
    detail or an origin (never a path or query); `caPem`/`allowHttp` changes are `warning`.
    `source.in_use` / `credential.in_use` refusals plus `ON DELETE RESTRICT` as a backstop.
21. **Secret sources are not synced** (`sync_rows.rs:264-297`); an `external_ref` credential
    synced to a device without the source fails closed (`credential.external_not_found`).
22. **No source TOFU command yet** (`secret_source_trust`, F1 left open): fail-closed
    (`category: tls`, `caPem` as the way out). When it lands, its DTO field and command come
    back here.

### 5. Vault sync (ADR-0017)
23. **MSY1: approved** (`crates/mooring-sync/src/blob.rs`): total, allocation-free decoder with
    length window and invariants before decryption; AAD = bytes 0..125; random 24-byte nonce;
    key = HKDF-SHA256(DEK, vault_id, "mooring sync v1") through `mooring-vault::SubKey`
    (RustCrypto `hkdf`, zeroized); test vectors pinned.
24. **Integrity rules: approved** (`engine.rs:131-200`, `:225-256`, `:410-431`): wrong vault →
    `WrongVault`; blob not paired with the remote header, or remote header ≠ local header →
    `HeaderMismatch` (the remote header is never parsed during normal runs); remote missing after
    a sync → rollback; lower counter → rollback; equal counter with another hash, or no
    authenticated parent chain to our last blob → fork. Alarms are sticky until
    `sync_resolve_fork` (native confirmation, M-16). A first sync or a join accepts any
    authenticated blob (TOFU on the generation, R-SYNC-OP).
25. **S3: approved.** rusty-s3 presigns (`rustcrypto` feature only, `aws-lc-rs` off),
    conditional headers are signed, writes never retried, ETag-guarded, 64 MiB cap, our
    verifier and `known_sync_certs`. N-44.
26. **Native trust prompt (three buttons): approved with M-16 / N-45.** Background runs never
    prompt. Only the Gate pins (`KnownCerts::add_and_save`).
27. **`vault_join` (vaultId + password deviation): approved.** The remote header is parsed
    through `Header::from_bytes` (KDF floor and ceiling), must carry the requested id and no
    upgrade flag, and must unlock with the typed password; a storage operator cannot forge a
    header that does (no password, no DEK). The bootstrap store must be empty. L-37.
28. **Trust files:** the apply holds every trust file's write lock (`sync_local.rs:28-36`), so
    no write is torn. The S2 lost-update window (a pin written between the snapshot read and the
    apply is dropped; a pin removed in that window comes back) is fail-safe (a re-prompt or a
    kept hard stop) — accepted. Conflicting pins: L-35.
29. **What is synced** — folders, connections, credentials (still sealed under the DEK), trust
    stores, tombstones — and what is not (header as its own object, audit log, per-device
    settings, web stores, keyring wrap, secret sources, vSphere subtrees): **matches ADR-0017.**
    Anyone with bucket read access gets the Argon2id-wrapped header and can attack the master
    password offline, exactly like a stolen vault file (T1). Recorded as R-SYNC-OP.

### 6. UI
30. **No secret in DTO, state or fixture:** U3 forms send secrets inward only; the DTOs above
    carry names, ids, counts and codes. `invoke()` appears only in `apps/desktop/src/lib/ipc.ts`.
31. **The sync banner showing `lastError.message` verbatim (U4 decision 2): acceptable.** Every
    `SyncError` message is static text or a status/counter (`mooring-sync/src/error.rs`), and the
    same rule (no secret in an `IpcError`) applies everywhere.

### 7. Dependencies
| Crate | Version | License | Reached from | `unsafe` | Ruling |
| --- | --- | --- | --- | --- | --- |
| `kube` / `kube-client` / `kube-core` (`client`, `ws`; no TLS, no `config` use) | 5.0.0 | Apache-2.0 | proto-kube | 0 | **Approved** |
| `k8s-openapi` (`v1_33`) | 0.29.0 | Apache-2.0 | proto-kube | 10 | **Approved** (generated types) |
| `tokio-tungstenite` / `tungstenite` (`handshake` only) | 0.30.0 | MIT / MIT OR Apache-2.0 | mooring-http, kube | 0 / 5 | **Approved**; frames capped at 1 MiB |
| `rusty-s3` (`rustcrypto` only) | 0.11.0 | BSD-2-Clause | mooring-sync | `forbid` | **Approved**; N-44 |
| `hyper` 1, `hyper-util`, `http-body-util`, `tower(-service)` | — | MIT | mooring-http (runtime), testsrv | — | **Approved** (already in the tree via Tauri) |
| `x509-parser` (`default-features = false`) | 0.18.1 | MIT OR Apache-2.0 | mooring-http | `forbid` | **Approved** (as in review 5) |
| `hkdf` | 0.13 | MIT OR Apache-2.0 | mooring-vault | RustCrypto | **Approved** |
| `httpdate` | 1.0.3 | MIT OR Apache-2.0 | testsrv (dev) | — | **Approved**, dev only |
| `jsonpath-rust` → `pest`/`pest_derive`/`pest_meta`/`pest_generator`, `pest_stack_guard` → `stacker` + `psm` (cc-built asm shim; `ar_archive_writer`, `object` at build time), `ucd-trie` | 1.0.12 / 2.9.5 / 0.1.25 / 0.1.32 | MIT, MIT OR Apache-2.0 | kube-client `config` (forced by `client`) | psm 24, stacker 20 | **Accepted, compiled but not executed** (R-KUBE-CFG): jsonpath runs only in kube's auth-provider token path, which our banned loaders would reach. Ask upstream (kube-rs) to make `config` optional under `client` |
| `serde-saphyr` → `granit-parser`, `encoding_rs`(+`_io`), `simdutf8`, `annotate-snippets`, `unicode-width`, `nohash-hasher`, `anstyle`, `multiversion_no_op`, `either` | 2.1.0 / … | MIT OR Apache-2.0 (+BSD-3 for encoding_rs) | kube-client `config` | encoding_rs 193, simdutf8 142 | **Accepted, compiled but not executed** (R-KUBE-CFG): kube's YAML kubeconfig loader; our parser is `saphyr-parser` 0.3 (event level, capped). Same upstream ask |
| `serde-value`, `ordered-float` 2 | 0.7.0 / 2.10.1 | MIT | kube-core | 0 / 12 | **Approved** |
| `hyper-timeout`, `tower-http` 0.7.1 (duplicate of 0.6.11) | 0.5.2 / 0.7.1 | MIT OR Apache-2.0 / MIT | kube-client | 0 | **Approved**; the duplicate costs build time only |

`aws-lc-*`, `openssl-sys`, `native-tls`, `libz-sys` (new edges): none (`cargo deny` bans ok;
`openssl-probe` is pure Rust, as before).

## Conditions before the A3 tag
1. **M-16** fixed with its tests and the per-OS Return/Escape check.
2. L-33..L-35, L-37, L-38. L-36 is documentation (done here) plus the option help text.
3. Carried: L-28 remainder and one green nightly fuzz run; L-31 per-OS QA; the ADR-0013 E2E
   plan per OS; the ADR-0016 §4 OIDC interception E2E per OS (does `on_navigation` see the
   `localhost:8250` redirect on WebView2, WKWebView and WebKitGTK?); the Windows L-29 E2E.
4. Nits as scheduled; N-46 with the next dependency bump.
5. Unchanged: `security.yml` green (cargo-deny, cargo-audit, gitleaks, semgrep, pnpm audit),
   `mooring-app` built and tested on macOS, Windows and Linux.

## Test evidence
```
Linux x86_64, 2026-11-04, HEAD 49d7b98, no build
cargo deny check                     advisories ok, bans ok, licenses ok, sources ok
cargo audit --no-fetch --db ~/.cargo/advisory-db/advisory-db-3157b0e258782691
                                     1403 advisories, 825 crates: RUSTSEC-2023-0071 (rsa, R-RSA, ignored in deny.toml);
                                     warnings: atomic-polyfill, basic-toml, proc-macro-error, zbus_names, zvariant,
                                     zvariant_derive (unmaintained), glib 0.18 (unsound) — none introduced by A3
cargo tree -p mooring-app -i serde-saphyr|jsonpath-rust|psm   <- kube-client (config, forced by `client`)
cargo tree -p mooring-app -i rusty-s3                         <- mooring-sync (direct)
cargo tree -p mooring-app -i tokio-tungstenite                <- mooring-http, kube-client
grep guard/table.rs Scope::Session                            6 rows (unchanged); A3 rows all Scope::Main
capabilities/oidc.json, web.json                              permissions: []
Cargo.lock                                                    tauri 2.12.5 (pinned), wry 0.57.1 (lock only)
```
Not run: builds and tests (orchestrator gate), cargo-geiger, gitleaks, semgrep, pnpm audit,
cargo-fuzz, the per-OS WebView checks.

## Re-review 6b (fix round 7 + Q3)

Reviewer: security-reviewer · 2026-11-05 · Range `git diff 7b02715..HEAD` (`7527a7d`): rust-core
fix round 7 (`05248c8`..`5e3172c`, [`a3-rust-core-fix-7.md`](../handoff/a3-rust-core-fix-7.md)),
QA Q3 (`3c514ce`..`ca2df57`, [`a3-qa-q3.md`](../handoff/a3-qa-q3.md),
[`docs/qa/native-dialogs.md`](../qa/native-dialogs.md)) and the UI text for the two new codes
(`7527a7d`). Sources read from the registry: `tauri-plugin-dialog` 2.8.4 (`src/desktop.rs`
`show_message_dialog`, `Cargo.toml` features) and `rfd` 0.17.2 (`backend/gtk3`, `backend/win_cid`
and `backend/macos` `message_dialog.rs`). No build, no test run.

### Verdict: `BLOCKER` (A3 tag)

**M-16 is reopened as B-6.** The button order is now right. The label-only mapping is also
right for the results *we* receive. The problem is upstream of us: `tauri-plugin-dialog`
rewrites the OS result **by position** before we see it. It turns rfd's positional `Cancel`
into `Custom(<label in the cancel slot>)`, on every desktop OS. Escape and closing the dialog
both produce that positional `Cancel`.

The fix moved the confirming label into the cancel slot. So **Escape or the close box now
confirms** on Windows and Linux. On the sync trust dialog, that answer is "Trust and remember".
Before the fix, Return confirmed and Escape refused. Now Return refuses and Escape confirms.
Either way one key does it, and Escape is the key a user presses to get rid of a dialog they
did not expect. A T5 creates exactly that situation.

The other rows are either fixed, or partial with a small, exact gap (below). The single-flight
and cool-down gate, the L-34 epoch, the L-37 staging and N-43/N-44 are sound in design. The two
new error codes leak nothing.

### Closure of review 6
| ID | Status | Evidence / gap |
| --- | --- | --- |
| **M-16** | **reopened → B-6** | Order fixed: `src-tauri/src/commands/vsphere_confirm.rs:83` `OkCancelCustom("Cancel", ok)`, `commands/sync_gate.rs:73` `YesNoCancelCustom(CANCEL, ONCE, PIN)`, `:116` (fork). Label-only mapping fixed: `vsphere_confirm.rs:87-89`, `sync_gate.rs:77-84`. **Gap:** `tauri-plugin-dialog` 2.8.4 `src/desktop.rs:236-239` maps `(rfd Cancel, OkCancelCustom(_, cancel))` → `Custom(cancel)`, and `:249-251` maps `(rfd Cancel, YesNoCancelCustom(.., cancel))` → `Custom(cancel)`. The block has no `cfg`: its comment says "on Linux", but it runs on every desktop OS. rfd returns a positional `Cancel` in three cases. GTK: `GTK_RESPONSE_DELETE_EVENT` from Escape or the window close (`backend/gtk3/message_dialog.rs:204-215`, the async path; it also returns `Cancel` for the second button). Windows TaskDialog: `IDCANCEL` under `TDF_ALLOW_DIALOG_CANCELLATION`, i.e. Escape, Alt+F4 or the close box (`win_cid/message_dialog.rs:137`, `:181`). macOS: any modal end that is not a button press (`macos/message_dialog.rs:135`). So `confirmed(Custom("Power off"))` is true for Escape. The unit test `results_are_mapped_by_label_never_by_position` (`vsphere_confirm.rs:244`) feeds `Res::Cancel` straight in and never sees the plugin's rewrite. Fix: B-6 below |
| └ single flight | **fixed** | `src-tauri/src/confirm_gate.rs:106-139`: one process-wide `open` flag under a mutex. It is one gate, shared through `AppState::confirm` (`state.rs:186`, `:242`) and `VsCtx`, so vSphere and sync dialogs exclude each other. A dropped `Slot` frees the gate and counts as cancelled (`:81-85`). No `timeout` or `select!` wraps an `ask` (grep), so the gate cannot be freed while the OS dialog is still up |
| └ cool-down | **fixed, one gap** | `confirm_gate.rs:110-114`: 10 s per `kind:target` after a cancelled destructive dialog. Scopes: `vsphere_vm.rs:178` (power), `:243` (VMRC, not destructive), `vsphere_login.rs:157`, `sync_gate.rs:191`, `sync.rs:306`. Granularity per target, not per action: **accepted**, it is the stricter reading. **Gap:** `crates/mooring-vsphere/src/power.rs:33` `is_destructive` covers only `Off \| Reset`. Review 6 and row 1 of `docs/qa/native-dialogs.md` say off/reset/**reboot**, and a guest shutdown or reboot of a production VM is just as disruptive. Fix: `destructive: a != PowerAction::On` at `vsphere_vm.rs:178`; keep `is_destructive` for the "may lose data" wording |
| └ audit rows | **fixed, nit** | `confirm_refused { kind, target, reason }` (`confirm_gate.rs:122-129`) carries names only (`<connection>/<moid>`, `host:port`, connection id). A T5 that loops a command while a dialog is open writes one hash-chained row per call. Same class as N-43: see N-47 |
| └ new codes | **fixed** | `confirm.busy` and `confirm.cooldown` (`confirm_gate.rs:130-136`) have static messages, with no target and no timing. They tell a T5 only that a dialog is open or that the user just cancelled, and the T5 knows both already (it received `cancelled`). `ipc-codes.json` is re-blessed; `7527a7d` shows static UI text |
| L-33 | **fixed** | `src-tauri/src/oidc_window.rs:39-41` `storage()` → `web::ephemeral_storage("oidc-<sourceId>")`. The builder sets `incognito(true)`, `initialization_script_for_all_frames` and, on Windows, `data_directory`. The profile is removed on `Destroyed` and swept at start. Nit (no new ID): create the directory with `create_private_dir` before `build()`, as `web_open` does (`commands/web.rs:245-249`) |
| L-34 | **partial** | The epoch covers all four entry paths. **Token method and AppRole:** `crates/mooring-secrets/src/engine.rs:125` reads it **before** `login_material`; `:152` `put(.., epoch)`; a rejected token is revoked when it is ours (`:153-155`); a stored token (`ours = false`) is dropped, not revoked, which is correct. **OIDC:** `begin` re-checks after `begin_oidc` (`oidc_window.rs:199`) and after `open` (`:228`). `complete_oidc` refuses a flow from an older epoch before the code exchange (`engine.rs:333`) and `put`s with `flow.epoch` (`:342`). **Renewer:** `maintain` writes back only through `get_mut`, so a drained entry is never re-inserted. **Drain:** synchronous under the entries mutex (`cache.rs:306-318`, `secrets_runtime.rs:237-248`). **Gaps:** (a) `commands/vault.rs:145` runs `state.secrets.on_lock()` **before** `v.lock_with_reason` (`:151`). A login that starts in between reads the bumped epoch and takes its AppRole material from the still-unlocked vault, so its token is cached *after* the lock. Fix: call `state.secrets.on_lock()` after `lock_with_reason`, as `state.vsphere.on_lock()` is (`on_lock` needs nothing from the vault), or call `drain_for_lock()` a second time there. Test: a delayed `LoginProvider` that reads its material between `on_lock` and the key wipe → cache empty after the lock. (b) Nit: `secrets_runtime.rs:238-239` runs `fail_all` before `drain_for_lock`. Drain first: then the post-open re-check (`oidc_window.rs:228`) cannot land between the two and leave an IdP window over the lock screen. No token can result, because the flow epoch is stale. (c) Nit: `OidcFlow.epoch` is read after the auth-URL request (`engine.rs:314`). Read it at entry; `begin` covers this today |
| L-35 | **partial** | `src-tauri/src/commands/sync_trust.rs:37-74` `conflicts()` and `KnownCerts::distinct_pins` (`mooring-core/src/known_certs/mod.rs:271-279`) run after every `AppLocal::apply` (`sync_local.rs:60-65`, `:109`). The row is `trust_conflict { file, host }`, with no fingerprint. No auto-resolution: accepted. **Gaps:** (a) Nothing surfaces it. The review asked for `sync_status.conflicts`, and an audit row on its own is never seen. Both pins stay trusted (`known_certs/mod.rs:257-267`), so the hostile certificate keeps working unnoticed. (b) SSH is exempt **entirely** (`sync_trust.rs:10`). The review exempted it only *where the key types differ*, and two `ssh-ed25519` keys for one host is the most likely real conflict. Fix: add `sync_status.conflicts: [{ protocol, host }]` plus a UI banner, **or**, stricter, have `check` return `Mismatch` for a host with more than one distinct pin until the user removes one (fail closed). Count `known_hosts` lines per key type. Test: two devices pin different ed25519 keys for `ssh.example.test:22` → one conflict |
| L-36 | documented | R-VMRC-ARGV is in the threat model. The VMRC option help text (UI) is still owed |
| L-37 | **partial** | The header is staged before the apply and renamed after it (`src-tauri/src/commands/sync_join.rs:238`, `:258`, `:267`). `FsHeaderWriter` writes 0600 + `sync_all` (`:64-77`), then rename + directory fsync (`:80-91`). Recovery runs at start (`state.rs:236`). **Gaps:** (a) `sync_join.rs:112-117`: recovery decides that the staged header completes the join, the rename fails again, and the code falls through to `remove_file(&tmp)`. That deletes the only copy of the joined header and leaves the device in exactly the L-37 state (store bound to the joined vault, bootstrap header on disk). Fix: when the rename fails, keep the file and return `staged`. (b) After a failed `commit` the process carries on with the joined vault. If the user then changes the password (or a KDF upgrade runs), `vault.header.json` is rewritten, but the stale staged file stays. At the next start it is installed over the new header, which silently undoes the password change. Fix: install only when the current header's vault id differs from the staged one (the header is still the bootstrap); otherwise remove the staged file. `save_header` should also remove a staged file of the same vault. Test: commit failure → `vault_change_password` → restart → the new password unlocks |
| L-38 | **fixed** | `src-tauri/tests/e2e_flow/gate_matrix.rs:68-92`: every `ipc-manifest.json` command is in exactly one list: the gated rows, the 7 session-bound kube rows (`session.not_found` with the ended cluster's id, `e2e_flow/kube.rs`), or `NOT_GATED`. Duplicates, unknown names and empty reasons fail, and the count comes from the manifest (103 = 57 + 7 + 39). **Every `NOT_GATED` reason checked, all correct:** `app_info`, `credential_kinds`, `credential_parse_account` (no store); the `vault_*` lifecycle; `autolock_get` (in-memory policy); `autolock_set`, `syslog_set`, `sftp_pick_local` (gated, with unit tests); the ADR-0006 session-bound SSH/SFTP/forward/graphical rows and `window_attach`; `web_close`, `web_reload`, `web_zoom`, `web_list` (window-bound, and web windows are hidden while locked); `web_focus`, `web_print` (`unlocked()` at `commands/web.rs:310`, `:332`); `secret_source_revoke` (drops in-memory tokens and must work while locked); `secret_source_oidc_status` (in-memory). Nit: the `web_open` reason says "gated in the Tauri wrapper", but the gate is `web::plan(&state, ..)` (`commands/web.rs:236`), which needs no `AppHandle`. Pin it in the matrix the way `vsphere_console` was pinned through `vm_target` |
| N-39 | **fixed** | `commands/vsphere_console.rs:57-65` `post_open`, called on both the reopen and the build path. Nit: the reopen path still calls `show()` before the check (a one-frame flash). The same path in `web_open` has no check at all: N-48 |
| N-40 | **fixed** | `src-tauri/src/kube_sessions.rs:134-140` and `:213-218`: `ended` is tested and set under the client mutex |
| N-41 | **fixed** | `crates/mooring-secrets/src/client.rs:192-195` (`identity_policies` included) |
| N-42 | **fixed** | `src-tauri/src/commands/secret_sources.rs:177-189`: only the fields set or changed, `caPem` fingerprints, `warning` on an added origin (`:231`). Create (`:203-213`) lists only the fields actually set |
| N-43 | **partial** | Per window, and fresh on every reopen: `register` creates a new `WebEntry` (`commands/web.rs:57-67`), and each OIDC `begin` creates a new `Session` (`oidc_window.rs:217`). The summary row is written on close (`commands/web.rs:82-88`, `oidc_window.rs:78-89`), and an OIDC window is closed at 64 refusals. The `refusals.rs` arithmetic is right: 16 rows, then the summary counts the rest. **Gaps:** (a) `oidc_window.rs:311`: a refusal in any phase other than `Pending` is audited unconditionally, outside the budget. That includes `Exchanging`, `Failed`, and the window after `navigation_flood` until it is destroyed. Count it through `s.refusals.refused()` too. (b) `web/mod.rs:214`: `unwrap_or(true)` audits every refusal of a window whose entry is already gone (between `closed_entry` and `Destroyed`). Use `false`, which also drops the UI event |
| N-44 | **fixed** | `crates/mooring-sync/src/backend/s3.rs:29` `SIGN_TTL` = 60 s; `signed_path!` returns `Zeroizing<String>`; `mooring-http` logs no path or URI (grep). The secret moves into rusty-s3's `Zeroizing`. The STS token stays a plain `String` inside rusty-s3, and the signer's `Url` is transient; both fall under R-EXT-STR. The mock refuses `X-Amz-Expires > 60` |
| N-45 | **fixed** (wording) | `sync_gate.rs:69` "Trust once (this sync only)". The "Cancel by default" half is B-6 |
| N-46 | **fixed** | `src-tauri/src/golden.rs:114-150`: `wry` 0.57.1 and `tauri-runtime-wry` 2.12.3. Extend it: N-49 |

### New findings
| ID | Sev | Where | Finding | Exact fix |
| --- | --- | --- | --- | --- |
| **B-6** | **Blocker (A3 tag)** | `src-tauri/src/commands/vsphere_confirm.rs:75`, `:83`; `commands/sync_gate.rs:73`, `:109`, `:116-117`; upstream `tauri-plugin-dialog` 2.8.4 `src/desktop.rs:226-253` | On **Windows and Linux**, Escape, Alt+F4 or the close box confirms any of the five native confirmations: power (on/off/reset/shutdown/reboot), VMRC, vSphere trust and fork resolution. On the sync trust dialog it answers "Trust and remember". Cause: the plugin turns rfd's positional `Cancel` into `Custom(<cancel-slot label>)`, and M-16 put the confirming label in that slot. This is a regression from review 6, where Escape refused | **Invariant: no confirming label may sit in the first slot (the OS default, Return) or in the plugin's cancel slot (Escape and close).** Two ways to get there. **(1, preferred)** Stop using `show_with_result` for these five dialogs and map rfd's own result. On Windows (`win_cid`) and macOS, rfd returns `Custom(label)` for a click and a positional `Cancel` for Escape/close, so `Custom(s) if s == ok` → yes and everything else → no. On GTK only the **blocking** `GtkMessageDialog::run()` (`gtk3/message_dialog.rs:121-151`) keeps the two apart; the async path does not. rust-core must prove the blocking call is safe beside Tauri's GTK main loop before relying on it. This needs `rfd = { version = "=0.17.2", default-features = false, features = ["gtk3", "common-controls-v6"] }` as a direct dependency of `mooring-app`. It is already in the tree, so no new crate: **approved here**; the orchestrator edits `Cargo.toml`. **(2, no new dependency)** Use three slots, `YesNoCancelCustom(CANCEL, ok, <refusing label>)`, e.g. "Cancel" / "Power off" / "Keep running". The sync trust dialog then needs two steps: first (`Cancel`, `Trust…`, `Cancel`), then (`Trust once (this sync only)`, `Trust and remember`, `Trust once (this sync only)`). **Tests:** a pure `fn slots(&MessageDialogButtons) -> (first, cancel_slot)` that asserts both are refusing for every dialog builder, plus a unit test that replays the plugin's remap table (`Cancel` → cancel-slot label) through `confirmed` / `trust_answer`. **QA:** add "close box / Alt+F4 / Cmd+W refuses" to `docs/qa/native-dialogs.md` (the Escape column is already there) and run it per OS. **Upstream:** report the unconditional remap to tauri-apps/plugins-workspace: DELETE_EVENT and IDCANCEL are not the cancel button |
| N-47 | Nit | `src-tauri/src/confirm_gate.rs:120-129` | `confirm_refused` rows are unbounded: a T5 that calls `vsphere_vm_action` in a loop while a dialog is open writes one hash-chained row per call | Audit the first 16 refusals per `kind:target` per open dialog, then one `confirm_refused_suppressed { count }` when the slot is released |
| N-48 | Nit | `src-tauri/src/commands/web.rs:238-241` (reopen path of `web_open`) | The N-30/N-39 post-check is missing on this branch. If the vault locks after `plan` passes, `show(&w)` makes a hidden web window visible over the lock screen | Call `hide_if_locked` after `show(&w)`, as the build path does (`:272`) |
| N-49 | Nit | `src-tauri/src/golden.rs:114` | B-6 shows that the confirmations' safety depends on how `tauri-plugin-dialog` and `rfd` map results | Add `tauri-plugin-dialog == 2.8.4` and `rfd == 0.17.2` to `LOCKED_WEBVIEW_CRATES`, with a comment pointing at review 6b B-6. Bumping either one needs a security re-read of the result mapping |

### Decision on rust-core's question
- The cool-down stays per target, not per target and action: **accepted** (stricter). It must
  also cover guest shutdown and guest reboot (see the cool-down row).

### Conditions before the A3 tag
1. **B-6** fixed with the slot-invariant tests. Then the per-OS run of
   `docs/qa/native-dialogs.md` on macOS, Windows and Linux: Return, Escape and the close box
   refuse, and a click confirms.
2. One more fix round for L-34 (a), L-35 (a)(b), L-37 (a)(b), N-43 (a)(b) and the guest-power
   cool-down. Each is small and exact.
3. Carried from review 6:
   - the L-28 remainder and one green nightly fuzz run;
   - L-31 per OS;
   - the ADR-0013 E2E plan per OS;
   - the ADR-0016 §4 OIDC interception check per OS;
   - the Windows L-29 E2E;
   - the L-36 VMRC help text.
4. As scheduled: N-47..N-49, L-34 (b)(c), and the L-33, L-38 and N-39 nits.
5. Unchanged: `security.yml` green; `mooring-app` built and tested on macOS, Windows and Linux.

### Test evidence (re-review)
```
Linux x86_64, 2026-11-05, a3 @ 7527a7d, no build, no test run (orchestrator gate)
registry sources read   tauri-plugin-dialog 2.8.4 src/desktop.rs:215-253 (unconditional positional remap)
                        tauri-plugin-dialog 2.8.4 Cargo.toml (default = gtk3; rfd common-controls-v6)
                        rfd 0.17.2 gtk3/message_dialog.rs:121-151 (blocking), :204-215 (async: DELETE_EVENT -> Cancel)
                        rfd 0.17.2 win_cid/message_dialog.rs:137 (TDF_ALLOW_DIALOG_CANCELLATION), :179-199
                        rfd 0.17.2 macos/message_dialog.rs:106-136
grep MessageDialogButtons|show_with_result src-tauri/src   2 builders (vsphere_confirm, sync_gate) cover all 5 dialogs
grep timeout|select! around Prompt::ask / gate::confirm   none
gate_matrix NOT_GATED                                     39 rows, each reason checked against the command source
```
Not run: builds, tests, the per-OS dialog checklist, cargo-fuzz.

## Re-review 6c (fix round 8)

Reviewer: security-reviewer · 2026-11-05 · Range `git diff a17bb6d..4666be7`: rust-core fix
round 8 (`4e99197`..`8e54b12`, [`a3-rust-core-fix-8.md`](../handoff/a3-rust-core-fix-8.md))
and the QA table update in [`docs/qa/native-dialogs.md`](../qa/native-dialogs.md). The B-6 rule
was re-derived from the registry sources: `tauri-plugin-dialog` 2.8.4 `src/desktop.rs:215-257`
and `Cargo.toml`, and `rfd` 0.17.2 `backend/gtk3/message_dialog.rs`,
`backend/win_cid/message_dialog.rs`, `backend/macos/message_dialog.rs` and
`backend/macos/utils/user_alert.rs`. `apps/` was not reviewed: U5 (DTO decoding) is in progress
concurrently. No build, no test run.

### Verdict: `APPROVE WITH NITS` (A3 tag, code)

B-6 is closed. Every native confirmation is now `YesNoCancelCustom("Cancel", ok, "Not now")`.
The plugin's positional remap sends Return and Escape/close to the two refusing labels on all
three desktop OSes, and only the middle button confirms. Every other row of 6b is fixed as
asked. The L-35 fail-closed path is in every consumer, and no trust-once path bypasses it.
Nothing is reopened. One new nit (N-50) is forward-looking. The tag is still conditional on the
per-OS runs below, which cannot be done here. They are conditions, not findings.

### B-6: per-OS, per-slot derivation
`tauri-plugin-dialog` 2.8.4 is built with its default `gtk3` feature, and `rfd` with
`common-controls-v6` (the plugin's `Cargo.toml:65-66`, `:111-114`). `Cargo.lock` `rfd` has no
`ashpd`/zenity edge, so the GTK backend is the one that runs, never the portal or zenity. The
remap (`desktop.rs:228-253`) applies to positional results only: `Yes` → `Custom(slot 1)`,
`No` → `Custom(slot 2)`, `Cancel` → `Custom(slot 3)`. Every `Custom(_)` passes through
unchanged (`:252`).

| OS (backend) | Slot 1 "Cancel" | Slot 2 `<ok>` | Slot 3 "Not now" | Return (OS default) | Escape / close / Alt+F4 / Cmd+W | Other failure |
| --- | --- | --- | --- | --- | --- | --- |
| Linux (GTK3 async, `gtk3/message_dialog.rs:61-73`, `:204-215`) | `GTK_RESPONSE_YES` → `Yes` → `Custom("Cancel")`: refuses | `GTK_RESPONSE_NO` → `No` → `Custom(ok)`: **confirms** | `GTK_RESPONSE_CANCEL` → `Cancel` → `Custom("Not now")`: refuses | No default response is set (`:84-107`). Return activates the focused widget: a selectable label (nothing happens) or slot 1. It never reaches slot 2 without a Tab | `GTK_RESPONSE_DELETE_EVENT` → `Cancel` → `Custom("Not now")`: refuses | (no other response; `unreachable!` is rfd's) |
| Windows (TaskDialog, `win_cid/message_dialog.rs:116-123`, `:137`, `:146`, `:179-199`) | `ID_CUSTOM_YES` (1004) → `Custom("Cancel")` directly: refuses | `ID_CUSTOM_NO` (1008) → `Custom(ok)`: **confirms** | `ID_CUSTOM_CANCEL` (1001) → `Custom("Not now")`: refuses | `nDefaultButton: 0` = the first custom button = slot 1: refuses | `IDCANCEL` under `TDF_ALLOW_DIALOG_CANCELLATION` → `Cancel` → `Custom("Not now")`: refuses | `TaskDialogIndirect` failure → `Cancel` → "Not now": refuses. The `MessageBoxW` fallback (which would show stock Yes/No/Cancel with the confirm on "No") is compiled out, because `common-controls-v6` is forced by the plugin |
| macOS (NSAlert, `macos/message_dialog.rs:53-64`, `:106-136`; CFUserNotification `utils/user_alert.rs:53-57`, `:153-167`) | `NSAlertFirstButtonReturn` / default response → `Custom("Cancel")`: refuses | second / alternate → `Custom(ok)`: **confirms** | third / other → `Custom("Not now")`: refuses | the first button (slot 1): refuses | NSAlert gives a button titled "Cancel" the Escape key equivalent, so Escape and Cmd+. press slot 1: refuses. Any other modal end → `Cancel` → "Not now": refuses | the CFUserNotification cancel / timeout → `Cancel` → "Not now": refuses |

Result: on every OS, only an explicit activation of the middle button yields `Custom(ok)`. Our
mapping is label-only (`vsphere_confirm.rs:100-102` `confirmed` = `Custom(s) if s == ok &&
!refuses(s)`). The `ok` labels are static constants ("Power on", "Shut down", "Restart", "Power
off", "Reset", "Open", "Trust", "Discard and resolve", `ONCE`, `PIN`), none of them refusing, and
no label names two buttons.

**Grep `Res::|MessageDialogResult` in `src-tauri/src`:** no positional confirm remains. The
production matches are `confirmed` (`vsphere_confirm.rs:100-101`) and `remember_answer`
(`sync_gate.rs:91-98`, `Custom(NOT_NOW)` → `Once`, `confirmed(PIN)` → `Pin`, else `Reject`).
`trust_once` (`:85`) delegates to `confirmed`. Every other hit is `plugin_remap` (`#[cfg(any(test,
feature = "test-util"))]`, `:128-146`), a test double, or a test.

**`plugin_remap` replay:** it matches `desktop.rs:228-253` arm for arm (`OkCustom`/`Ok`,
`OkCancelCustom` `Ok`/`Cancel`, `YesNoCancelCustom` `Yes`/`No`/`Cancel`, passthrough). The two
`Cancel` arms are merged, which changes nothing. The doubles (`FixedConfirm::with_result`,
`ScriptedPrompter::with_results`) run OS results through it before the label mapping, so the
tests exercise the real path. Tests: `vsphere_confirm.rs:305` (slot invariant over the six
builders), `:321` (remap of Escape/Return/click), `:348` (label-only), `:366` (doubles,
including Escape on dialog 1 → no dialog 2, and Return on dialog 2 → `Reject`). Weak spot
(accepted): the catalogue at `:290-300` rebuilds the power, VMRC, vSphere and fork rows with
`buttons(<label>)` instead of calling the production builders. All of them go through `buttons()`
(`vsphere_confirm.rs:74`, `sync_gate.rs:75`, `:80`, `:147`), so the invariant still holds.

**Two-dialog sync trust prompt** (`sync_gate.rs:133-143`): dialog 2 is shown only from dialog
1's callback after `trust_once`. The gate slot and the auto-lock dialog guard are held across
both dialogs (`ask_trust`, `:235-251`). A dropped reply (dialog 2 never shown) yields
`unwrap_or(TrustAnswer::Reject)` (`:248`). Escape on dialog 2 keeps the trust-once answer the
user clicked on dialog 1 and never escalates to a pin. **Return on dialog 2 refuses everything:
accepted (owner decision).** It is the fail-closed reading.

### Closure of re-review 6b
| ID | Status | Evidence |
| --- | --- | --- |
| **B-6** | **fixed** | Above. `vsphere_confirm.rs:83-102`, `:106-114` (`slots`), `:128-146`; `sync_gate.rs:70-98`, `:133-150`. QA table: close box / Alt+F4 / Cmd+W column, rows 4a/4b (`docs/qa/native-dialogs.md`). **Owed:** the per-OS run (condition 1). The upstream report text in the handoff is accurate. Filing it is the owner's call; it is not a condition, because N-49 pins both crates |
| M-16 cool-down | **fixed** | `src-tauri/src/commands/vsphere_vm.rs:180` `destructive: a != PowerAction::On`; `is_destructive` keeps the data-loss wording (`:152`). Test `vsphere_sync_tests::power_needs_opt_in_and_the_native_dialog` |
| L-34 (a) | **fixed** | `src-tauri/src/commands/vault.rs:150` `lock_with_reason`, guard dropped, then `:155` `state.secrets.on_lock()`. Every interleaving is now covered. A login that read its material before the wipe either `put`s with the old epoch before the drain (then it is drained) or after it (then `put` refuses the stale epoch). A login that starts after the bump finds the vault locked. Test `secrets_runtime_tests::a_login_that_starts_after_the_lock_epoch_finds_the_key_gone` fails on the old order (per the handoff) |
| L-34 (b) | **fixed** | `src-tauri/src/secrets_runtime.rs:239-240` drain, then `fail_all` |
| L-34 (c) | **fixed** | `crates/mooring-secrets/src/engine.rs:295` epoch read at the entry of `begin_oidc` |
| L-35 (a)(b) | **fixed, fail closed** | `crates/mooring-core/src/known_certs/mod.rs:266-279`: `distinct_pins > 1` → `CertTrust::Conflict`, whatever is presented; `decide` → `CertVerdict::Conflict` (`:104`). `crates/mooring-proto-ssh/src/known_hosts.rs:206-224` `conflicting_key_types` (non-revoked, per algorithm) → `TrustDecision::Conflict` (`:236-238`), checked after the revoked check. Consumers: http `verify.rs:69` → `connect.rs:177` `HttpError::TrustConflict` = `http.trust_conflict`, with a static `Display`; RDP `connect.rs:285` and `tls.rs:189` (rejected inside the verifier); VNC `tls.rs:182` → `connect.rs:275`; SSH `handler.rs:86-96`. All close with `CloseCode::TrustConflict`. **Trust-once cannot bypass it:** http `connect.rs:100-102`, VNC `connect.rs:66-69` and RDP `connect.rs:164-166` add the session pin only when `!has_pin`, so a host with two pins stays `Conflict`. Only `TrustPrompt` is promptable (`vsphere_login.rs:133`, `sync_gate.rs:297`), so a conflict is never prompted. The close reasons and the `sync_status` row carry `host:port` and key-type names only, never a fingerprint. `sync_status.conflicts` (`sync_trust.rs:41-77`, `sync.rs:143-148`) is computed live from the user's own connections. Accepted gaps (handoff "Left open"): a `known_sync_certs` conflict appears only as `lastError.code == "http.trust_conflict"`, and SSH has no UI manager. Both fail closed, so neither one is a hole |
| L-37 (a)(b) | **fixed** | `src-tauri/src/commands/sync_join.rs:112-136`: a failed rename keeps the staged file and returns `staged` (a); the file is installed only when `store` is bound to the staged vault **and** the current header is not the joined vault (b), otherwise removed. `state.rs:316-322`: `save_header_bytes` discards a staged header of the vault it just wrote. Test `sync_tests_6b::a_staged_header_is_neither_lost_nor_installed_over_a_newer_one` |
| N-43 (a)(b) | **fixed** | `src-tauri/src/oidc_window.rs:312-317` (every non-`Pending` phase through `s.refusals.refused()`); `web/mod.rs:215` `unwrap_or(false)` |
| N-47 | **fixed** (design differs, accepted) | `src-tauri/src/confirm_gate.rs:30-33`, `:64-80`, `:161`. One process-wide budget of 16 rows per hour of uptime, then one `confirm_refused_suppressed { count }`, instead of per open dialog. That is a tighter bound on chain growth. A T5 can spend the 16 rows, but the rest is counted, not lost. Loss of the last window's count at exit: accepted |
| N-48 | **fixed** | `src-tauri/src/commands/web.rs:243` (reopen) and `:275` (build) both `post_open` |
| N-49 | **fixed** | `src-tauri/src/golden.rs:114-124`: `tauri-plugin-dialog` 2.8.4, `rfd` 0.17.2, with the re-read obligation in the comment |
| L-38 nit | **fixed** | `src-tauri/tests/e2e_flow/support.rs:163-170` pins `web_open` through `web::plan`; removed from `NOT_GATED` |

### New findings
| ID | Sev | Where | Finding | Exact fix |
| --- | --- | --- | --- | --- |
| N-50 | Nit (forward) | `crates/mooring-secrets/src/error.rs:173-177` | `HttpError::TrustConflict(d)` folds into `SecretsError::Trust(d)` together with prompt, mismatch and rejected. Today nothing prompts from `Trust(d)` (`secret_source_trust` is not built), so this is safe. When F1's trust command lands, it must refuse `d.verdict == TrustVerdict::Conflict` (and `Mismatch` / `Rejected`), and offer the prompt only for `Prompt` | In the future `secret_source_trust`: match `TrustVerdict::Prompt` only, with a test that a conflicting pin gives `http.trust_conflict` and no dialog |

### Conditions before the A3 tag
1. **Per-OS run of `docs/qa/native-dialogs.md`** on macOS, Windows and Linux (GTK): on every
   dialog, including 4a and 4b, Return, Escape, the close box and Alt+F4 / Cmd+W refuse, and a
   click on the middle button confirms. On GTK, also record where the initial focus sits.
2. Carried:
   - the L-28 remainder and one green nightly fuzz run;
   - L-31 per OS;
   - the ADR-0013 E2E plan per OS;
   - the ADR-0016 §4 OIDC interception check per OS;
   - the Windows L-29 E2E;
   - the L-36 VMRC help text (UI).
3. U5 (ui-engineer, in progress): the heterogeneous `sync_status.conflicts` and the new
   `http.trust_conflict` / `trust_conflict` codes are decoded without showing anything beyond
   `name`/`id` and the static message. This gets a short security look at the U5 PR.
4. Unchanged: `security.yml` green (cargo-deny, cargo-audit, gitleaks, semgrep, pnpm audit),
   `mooring-app` built and tested on macOS, Windows and Linux.
5. Nits as scheduled: N-50 with F1; the L-33 `create_private_dir` nit; the N-39 one-frame
   flash.

### Test evidence (re-review 6c)
```
Linux x86_64, 2026-11-05, a3 @ 4666be7, no build, no test run (orchestrator gate)
registry sources read   tauri-plugin-dialog 2.8.4 src/desktop.rs:215-257, Cargo.toml:64-70, :111-114
                        rfd 0.17.2 gtk3/message_dialog.rs:24-151, :204-215
                        rfd 0.17.2 win_cid/message_dialog.rs:43-51, :86-199
                        rfd 0.17.2 macos/message_dialog.rs:42-136, macos/utils/user_alert.rs:40-170
Cargo.lock rfd 0.17.2   deps: gtk-sys, glib-sys, objc2*, windows-sys; no ashpd/zenity (gtk3 backend)
grep "Res::|MessageDialogResult" src-tauri/src   production: confirmed, remember_answer, trust_once only; rest cfg(test|test-util)
grep CertTrust::|TrustDecision::|CertVerdict::Conflict|TrustVerdict::Conflict   every consumer fails closed
grep has_pin around trusted_once / session_pin   http, VNC, RDP add the session pin only without a pin
git diff --stat a17bb6d..4666be7                 56 files; no Cargo.toml / Cargo.lock / capabilities / CSP change
```
Not run: builds, tests, the per-OS dialog checklist, cargo-fuzz.
