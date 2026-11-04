# A3 · ui-engineer · U4: sync alarm banner, review-5 UI nits, bundle split

Worktree `agent-a6e9c6bd909006a6a`, branch `worktree-agent-a6e9c6bd909006a6a`, from `a3` @ `729468c`
(U1+U2+U3 merged). Not merged. Mock transport only; no cargo was run. `stores/errors.codes.test.ts`
untouched (rust-core edits it concurrently).

## Done

| Commit | What |
| --- | --- |
| `3fec6ea` | **Global sync alarm banner** (U3 "Decision needed" 2). `components/SyncBanner.tsx`, mounted in `Shell.tsx` as a grid row under the title bar (`42px auto 1fr status`): the shell subscribes once (`useSync.load()` + `watch()` on `sync:status`), so a `fork` / `rollback` alarm or a failed background run (`lastError`, with the `http.trust_prompt` hint) shows wherever the user is. The banner names the problem in one line and offers **Open Vault sync settings** (switches to Settings, scrolls and focuses the Vault sync heading, so the resolve controls are one Tab away) and **Dismiss**. Resolve/disable stay on the card. It hides on the Settings view (the card's own alarm is the one alert there). Dismissal is per alarm (`alarmKey`: `fork:<remote>`, `rollback:<remote>:<last>`, `error:<code>:<lastRun>`) and per unlocked session: `useSync.dismiss()`, cleared by `useSync.reset()`, which `stores/app.ts` `wipe()` now calls on lock (and the test harness on `freshBackend`). **Syncing…** hint: `SyncIndicator` in the title bar, `role="status"`, present in the DOM only while `state === "running"`. Styles in `deck.css` (`.sync-banner`, `.sync-indicator`; hot tokens, light theme through the same tokens). |
| `0f0e99e` | **N-33.** `KnownCert` gains `host?`/`port?`; `decodeKnownCert` reads them (only a non-empty host with a 1..=65535 integer port). `useKnownCerts` labels from the wire and maps `host:port` to connection names with the plain `hostKey`; a hand-written plain line still parses with `plainHost`. **No HMAC in the UI**: `hashHost`/`hostMatches` are used by `MockTransport` alone, whose `knownCertsList` now names pins like `KnownCerts::list_named` (new `connectionHosts()` hook on `MockRemoteBase`, implemented in `MockTransport`). `KnownCertsCard.test.tsx` has a guard that scans every shipped source for `hashHost`/`hostMatches` (mocks, tests and `hostHash.ts` excluded). |
| `667efb2` | **N-34.** `VncConnOptions.allowNoAuth` (+ default `false`) in the mirror; `normalizeOptions` keeps it, `unknownField` accepts it, so a UI save no longer resets Rust's value. `VncOptions.tsx` gets the toggle in the `opt-danger` frame: "Allow servers without authentication", with the warning "A server that offers no authentication is accepted although a password is set: your password proves nothing, and anyone who can reach the port gets the same desktop. Every such connection is recorded in the audit log as weak security." |
| `e89a2b3` | **N-36.** `DetachedApp.test.tsx`: the detached ⊆ manifest check no longer `skipIf`s; it asserts `RUST_DETACHED_COMMANDS` is not null (with the message that `src-tauri/ipc-manifest.json` is committed) and then the set equality. |
| `c8462ec` | **Bundle.** `lib/ipc.ts` no longer imports the mock. Outside Tauri `ipc` starts as a `PENDING` proxy (every call rejects with `internal: transport not ready …`, `on*` subscriptions return a no-op unsubscribe) and `main.tsx` awaits `bootTransport()`, which `import()`s `ipc.mock.demo` (`devTransport()`: detached demo or full mock) unless a transport was already set (`e2e/boot.ts` does `setIpc` before importing `main`, so Playwright keeps its probe). In Tauri `bootTransport` is a no-op and the chunk is never requested. `vite.config.ts` `manualChunks` puts `react`, `react-dom`, `scheduler` in a `react` chunk. Result: `index` 660 kB → **320 kB** (gzip 95 kB), `react` 223 kB, `ipc.mock.demo` 86 kB (lazy), `TerminalView` 444 kB (lazy, as before); Vite's 500 kB warning is gone. |

Screenshots (`docs/handoff/img/a3-ui/`, 1440×860, dark + light, `vite dev` + `e2e/boot.html`):
`41-sync-banner-fork` (fork banner over the empty workspace), `42-sync-banner-error` (failed background
run with the trust hint), `43-sync-indicator` (title bar strip with "Syncing…").

## Files touched

`components/SyncBanner.tsx` (new) + `.test.tsx` (new), `components/Shell.tsx`, `stores/sync.ts`, `stores/app.ts`,
`test/harness.ts`, `styles/deck.css`; `lib/ipc.types.remote.ts`, `lib/ipc.decode.session.ts`, `lib/hostHash.ts` (comment),
`lib/ipc.mock.remote.ts`, `lib/ipc.mock.ts`, `components/settings/useKnownCerts.ts`, `components/settings/KnownCertsCard.test.tsx`,
`lib/ipc.remote.test.ts`, `lib/ipc.tauri.remote.test.ts`; `lib/validate.options.ts` + `.test.ts`,
`components/dialogs/options/VncOptions.tsx`, `options.test.tsx`; `components/detached/DetachedApp.test.tsx`;
`lib/ipc.ts`, `lib/ipc.mock.demo.ts`, `main.tsx`, `vite.config.ts`, `components/kube/ClusterBrowser.test.tsx` (spies the
installed mock instead of the module-level `ipc`, which is now the pending proxy before `freshBackend`).

## Left open
- `main.tsx` uses top-level `await` (target es2022 / safari15 both support it; `e2e/boot.ts` already did). If the
  release-engineer's WebView floor is older than Safari 15 / WebView2 ≥ 89, the await must become a `.then`.
- The banner does not show while the vault is locked (the Shell is unmounted; `useSync.reset()` on lock). The next
  unlock reloads `sync_status` and the alarm reappears undismissed — intended, as "per session" means per unlocked session.
- `allowNoAuth` has no connect-time effect in the mock (as with the other L-27 paths; Rust owns it and audits it).
- `DetachedApp.test.tsx` "SSH: attaches, streams output…" failed once in isolation with `term?.output` undefined and passed
  on every rerun (3/3) and in the full gate: a pre-existing timing flake, not touched this round.

## Decision needed
1. owner: should the banner also cover `state: "disabled"` after a `sync.store_not_empty` / wrong-vault join, or is the card enough?
2. owner / security-reviewer: the error banner shows `lastError.message` from Rust verbatim (same text as the card). Fine as long as
   `IpcError` messages stay secret-free (rule 4), but say if a code-only banner is preferred.

## Test evidence
- Gate in `apps/desktop`: `pnpm typecheck` 0 errors, `pnpm lint` 0 problems, `pnpm test` **58 files, 431 passed, 1 skipped**
  (baseline on `a3` @ `729468c`: 56 files, 405 passed, 1 skipped), `pnpm build` green with no chunk-size warning.
- `make e2e` (Playwright, `vite dev` + mock through `e2e/boot.html`): 5/5 flows pass with the lazy transport.
- New/updated tests:
  - `components/SyncBanner.test.tsx` (5): silent while healthy, fork banner → settings view with the card's alarm as the only
    alert and the heading focused; dismiss per alarm (rollback dismissed, resolved, a new fork shows again, lock clears);
    trust-prompt error banner cleared by a successful run; `Syncing…` only while running; `alarmKey`.
  - `lib/ipc.tauri.remote.test.ts`: `host`/`port` decoded, invalid ones dropped. `lib/ipc.remote.test.ts`: the mock names a
    pin only for a matching connection (case-insensitive) and never across protocols.
    `components/settings/KnownCertsCard.test.tsx` (+2): labels follow the wire's `host`/`port`; no shipped module names `hashHost`/`hostMatches`.
  - `lib/validate.options.test.ts`: `allowNoAuth` known, kept, type-checked, default false. `components/dialogs/options/options.test.tsx` (+1):
    toggle off → warning on → saved → reloaded and kept across a second save.
  - `components/detached/DetachedApp.test.tsx`: manifest check fails instead of skipping.
