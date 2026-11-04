# A3 · ui-engineer · U5: rust-core fix-8 DTO changes (re-review 6b L-35 / B-6)

Worktree `agent-a44c4a3c6db169a5b`, branch `worktree-agent-a44c4a3c6db169a5b`, from `a3` @ `4666be7`
(rust-core fix 8 handoff). Not merged. Mock transport only; no cargo was run. No manifest, lockfile or
`src-tauri/` change. `stores/errors.codes.test.ts` untouched: `http.trust_conflict` is already in
`src-tauri/ipc-codes.json`, so the N-14 guard checks the new `FRIENDLY` key and the mock's throw as is.

## Done

| Commit | What |
| --- | --- |
| `39c90e0` | **`http.trust_conflict` + `CloseCode` `trust_conflict`** (L-35). `FRIENDLY["http.trust_conflict"]` = "This host has two different trusted certificates (synced from another device). Remove one in Settings → Trust before connecting." (fail closed, no host or fingerprint). `CloseCode` / `CLOSE_CODES` gain `trust_conflict`, so `decodeSessionEvent` keeps it (an unknown code still decodes to `unknown`). `ConnectionBanner` `CLOSE_TEXT.trust_conflict` = "Conflicting certificates", hot, hint "… Mooring does not reconnect on its own: remove one in Settings → Trust, then connect again." A `session_open` refused with `http.trust_conflict` keeps the close code (`sessions.ts` `OPEN_FAILURE_CODES`), like `session.trust_mismatch`. The UI never schedules a reconnect itself (Rust does, and `is_retryable` is false); the tab ends `closed` with `reconnect: null`. **Mock:** `knownCerts` holds several pins per `protocol\|host:port` (`pin(t, addedAt, label)` varies the fingerprint; a duplicate fingerprint is kept once), `conflictingPins()` lists the keys with > 1 distinct fingerprint, and `openRemote` fails closed on one before any prompt: `closed { code: "trust_conflict" }` with a reason that names the host only. `known_certs_remove` clears every pin of the host:port (`removePins`). |
| `593d199` | **`sync_status.conflicts` is heterogeneous** (L-35). `SyncConflict = SyncMergeConflict \| SyncTrustConflict` (`{ kind: "trust", id: "<trust file>", name: "<host:port>" }`, no `resolution`); `SyncOutcome.merged.conflicts` stays `SyncMergeConflict[]`. New `lib/ipc.decode.sync.ts`: `decodeSyncConflict` by shape (a merge entry needs a known kind and a valid resolution, a trust entry needs `id` and `name`; anything else is dropped, never thrown), `decodeSyncStatus` applied to the `sync_status` reply and the `sync:status` payload in `TauriTransport`. `stores/sync.ts`: `trustConflicts(s)`, `trustConflictText(c)` = "Two devices trust different certificates for <host:port>. Remove one in Settings → Trust.", and `alarmKey` ranks fork/rollback > `trust:<id/name,…>` > `error:…`, so the shell banner shows a trust conflict as its own alarm ("Certificate trust conflict", `data-kind="alarm"`, button **Open known certificates** → Settings, focus on the Known certificates heading) and a dismissal is per set of conflicting hosts (a new host is a new alarm). `SyncCard`: a persistent `role="alert"` block "Certificate trust conflict" (not dismissable, one row per host with the trust file, the removal note, **Open known certificates**); the merge list now filters to merge entries. `openSettingsCard(id)` is exported from `SyncBanner.tsx` and shared. **Mock:** `remoteTrust: RemoteTarget[]` scripts the two-device apply: the next run keeps the other device's pin beside ours, records `trust_conflict { file, host }` and the status (`syncStatus()` and every event) carries the live `{ kind: "trust", id: "known_<proto>_certs", name }` entries after the merge entries until the pins are removed; `removePins` emits `sync:status` when a conflict clears. |
| `d605807` | **`KnownCertsCard` grouping** (L-35 + B-6 copy). `useKnownCerts` rows gain `conflict`; `groupPins` flags rows whose known host:port has > 1 fingerprint and orders conflicting hosts first, pins of one host adjacent, wire order otherwise (hashed pins without a host cannot be compared: never flagged). Each flagged row shows a hot "Conflict" badge and a left rule (`.trust-row[data-conflict]`, `.trust-conflict`), with its own **Remove…**; the remove dialog adds "This host has conflicting stored certificates (synced from another device); removing clears all of them." Card copy explains conflicts and that the sync storage certificate goes through two system dialogs ("Trust once (this sync only)", then "Trust and remember"), Return/Escape refuse, only a click confirms. |
| `c724ab2` | **Three-button dialog copy** (B-6): `PowerMenu` title, `VsphereOptions` power warning, `VmPanel` VMRC title ("Cancel, Open, Not now"), `SyncCard` fork hint ("Cancel, Discard and resolve, Not now"), `SyncConfigDialog` endpoint hint (two dialogs). Labels match `vsphere_confirm.rs` / `sync_gate.rs`. |
| `d74c26a` | `sessions.ts` back under 500 lines (497). |
| `5ced12f` | **Shell layout fix (found while taking screenshots).** `SyncBanner` returns `null` without an alarm, so in the `42px auto 1fr status` grid the panes took the `auto` row and the status bar the `1fr` row (U4 regression, every view, whenever sync was healthy: status bar ~320 px tall). The banner now renders inside a fixed slot `div[data-slot="sync-banner"]`; test asserts the four grid items. |
| `6b66778` | Screenshots. |

Screenshots (`docs/handoff/img/a3-ui/`, 1440×860, dark + light, `vite dev` + `e2e/boot.html`):
`51-sync-trust-conflict-card` (Vault sync card with the standing alarm), `52-sync-trust-conflict-banner`
(shell banner over the workspace), `53-known-certs-conflict` (grouped, flagged VNC pins).

## Tests (13 new / extended, 432 → 445)

- `lib/ipc.test.ts`: every close code decodes, `trust_conflict` included; unknown → `unknown`.
- `stores/sessions.trust.test.ts`: friendly text without host/fingerprint; `session_open` refused with `http.trust_conflict` → `closeCode: "trust_conflict"`, `reconnect: null`; conflicting pins in the mock → `closed` `trust_conflict`, no prompt, no mock session left.
- `components/remote/RemoteSessionTab.test.tsx`: `CLOSE_TEXT` keys + the new entry.
- `lib/ipc.decode.sync.test.ts` (new): both shapes, every resolution, the exact rust-core JSON, drift dropped, order kept.
- `lib/ipc.tauri.a3.test.ts`: `syncStatus()` decodes the mixed list through the transport.
- `lib/ipc.sync.test.ts`: the scripted two-device apply (audit row without fingerprint, two listed pins, conflict stands across runs, removal clears it and the event follows).
- `components/settings/sync.test.tsx`: card alarm, not a merge row, persistent, link, cleared on removal; fork hint copy; endpoint hint copy.
- `components/SyncBanner.test.tsx`: trust alarm outranks a failed run and survives a good run, dismissal per host set, link focuses the Known certificates heading, `alarmKey` precedence; shell grid slot.
- `components/settings/KnownCertsCard.test.tsx`: grouping/flagging, Remove on either row clears both, `groupPins` order; copy.
- `components/vsphere/vsphere.test.tsx`, `dialogs/options/kube.options.test.tsx`: dialog copy.

## Left open

- SSH `known_hosts` conflicts are listed in `sync_status.conflicts` (`id: "known_hosts"`) and shown in the card/banner with the same text, but the known-certificates manager has no SSH section (no list/remove IPC yet, A2-U2 TODO): the user is sent to Settings → Trust where nothing SSH can be removed. Needs a `known_hosts` list/remove command (rust-core) before the UI can offer it.
- A conflict on `known_sync_certs` surfaces only as `lastError.code == "http.trust_conflict"` (rust-core "Left open"); the card shows the friendly text, the banner "Vault sync failed: …" without a trust link. Fine for now.
- B-6 per-OS manual dialog run (QA) and the E2E flows for the trust conflict (qa-engineer: `secrets-sync.e2e.mjs` `setMock` can take `remoteTrust`).

## Decision needed

- The Vault sync card's trust alarm is deliberately **not dismissable** (only the shell banner is, per host set). Say if the card should offer Dismiss too.

## Test evidence

```
Linux x86_64, 2026-11-05, worktree agent-a44c4a3c6db169a5b @ 6b66778
apps/desktop: pnpm typecheck ok · pnpm lint ok · pnpm test 59 files, 445 passed · pnpm build ok (index 324 kB, no chunk warning)
make e2e: flows 5/5 · kube 6/6 · vsphere 4/4 · secrets-sync 7/7
```
