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
