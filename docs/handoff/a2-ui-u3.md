# A2 · ui-engineer · U3: web session tab, detach / attach, detached window route

Worktree `agent-af65e297f798ac9ca`, branch `worktree-agent-af65e297f798ac9ca`, from `a2` @ `d3d749f`. Not merged.
Built against the exact IPC JSON in `a2-rust-core-r5.md` and checked with `MockTransport`, in vitest and in the browser.

## Done

| Commit | What |
| --- | --- |
| `e393463` | **Decoder.** `attached` decodes as its own `SessionEvent`. `decodeSessionEvent` stays strict: only exact kind strings are recognised, and anything else (`"Attached"`, `"attach"`, a non-string kind, a non-object) still becomes `closed` "unrecognised session event". |
| `76b93ad` | **Mock.** Web windows: a second `web_open` moves the events to the new channel (as in R5). `webSimulate` reports navigated, title, blocked, download_blocked and a native close, with the audit entries. `webDemo` (on in `vite dev`) adds an SSO origin refusal and a download refusal. `web_focus`/`web_print` refuse while locked. Detach (`lib/ipc.mock.detach.ts`): each session has a route (`main`/`detached`). `session_attach` moves both sinks and sends `detached` to the view that lost them; credits reset and the next frame is full. `window_attach` sends `attached` to main. While detached, `closed` reaches main as well. The browser has no second window, so `window_detach` simulates one (`phantomDetach`: it takes the sinks and acks every frame). `viewOf(sessionId)` is the mock as seen from `detached-<sessionId>`: only the six commands, only for that id, and no `listen`; anything else gives `ipc.forbidden` and is recorded in `mock.forbidden`. An SSH attach refuses `onFrame` and reports 0×0. |
| `7d81777` | **Web tab** (`components/web/WebSessionTab.tsx`, `stores/web.ts`). Web connections open with `web_open`, never `session_open`. The tab is a control card:<br>- the page title from `WebEvent.title`, sanitised again in the UI (controls, bidi and zero-width characters stripped, whitespace collapsed, 256 chars);<br>- the current origin;<br>- Focus, Reload, Print, Zoom −/+/reset (browser steps 25–500 %, set optimistically so double clicks step correctly), Clear site data… (confirm dialog, focus on Cancel; audited) and Close window;<br>- "Blocked navigation" and "Download blocked" notices with the refused origin (newest first, at most 5, dismissable), with an Edit connection shortcut for blocked origins;<br>- an Ephemeral or Persistent storage badge from the *effective* `web_list` value.<br>Focus and Print are disabled while the vault is not unlocked. A native close turns the tab into "Window closed" with Reopen window. Closing the tab calls `web_close`. After an unlock, `adoptWeb` lists the windows (`web_list`, passive) and calls `web_open` again, which moves their events to the new tab's channel.<br>**Detach / attach in main.** There is a "Detach to window" button in the SSH and RDP/VNC toolbars; the tab-strip icon is shown only for SSH/RDP/VNC and enabled only when connected. `detach` calls `window_detach` and **keeps** the tab. `DetachedPlaceholder` ("Open in a separate window", Bring back) appears on `detached`, not before. Bring back calls `window_attach`. On `attached`, `attachHere` calls `session_attach` with fresh channels (`onFrame` only for rdp/vnc), drops queued frames, takes the desktop size, and bumps `attachEpoch` so the terminal resends its size. SSH gets a dim "[back from its own window…]" line. Detached session ids are kept across a lock (`sessions.detach.ts`), so an adopted tab stays a placeholder instead of pulling the session back.<br>**Refactors for the detached window:** `TerminalView` takes `onData`/`onResize`/`blocked` props and holds no store; the terminal output buffer moved to `stores/output.ts`. |
| `e3b9e2c` | **Detached route.** `Root.tsx` is the router. `#/detached/<id>` (id `[0-9A-Za-z-]{1,64}`) mounts `DetachedApp` instead of `App`, so the main boot (`app_info`, `vault_status`, `listen("vault:locked")`, tree, credentials) never runs there. The route is fixed at boot (`lib/route.ts`), so a hash change cannot turn a detached window into the main UI. `useDetachedSession` attaches once and renders either the terminal or `RemoteCanvas`, with a slim bar (protocol, state, Stats, Bring back). It uses only `session_attach`, `session_send`, `session_frame_ack` and `window_attach`; `session_close` and `session_screenshot` are granted but not used. It reads no vault store. Banners cover attaching, a failed attach, the session going back to main, the session ending, and a prompt ("bring it back to answer"). In `vite dev`, the route gets a demo session behind `viewOf` (`lib/ipc.mock.demo.ts`). |
| (this) | Screenshots and this note. |

Screenshots in `docs/handoff/img/a2-ui/`, dark and light, 1440×860. They were taken with `playwright` (apps/desktop devDependency) and Chrome (SwiftShader) against `vite dev`:
- `09-web-tab`: edge-lb, with the title, the origin, the Ephemeral badge, and both demo notices.
- `10-detached`: the detached window at `#/detached/r-0001` (an RDP demo session).
- `10-detached-main` (extra): main with the dc01 placeholder after Detach to window.

## Left open
- **E2E:** not added. `e2e/harness.mjs` drives one page on one MockTransport, and a second window would be a second JS context with its own mock, so a real detach flow is not cheap there. **For QA:** run these flows against the real app on each OS:
  1. Detach an RDP and an SSH tab.
  2. Check that the detached window calls nothing outside the six (devtools are off, so read the audit or `ipc.forbidden` in the Rust logs).
  3. Bring back, and close the window natively.
  4. Lock while detached: the window must hide.
  5. Open a web window and trigger a blocked navigation and a download.
  The vitest suites below cover the same paths against the mock.
- **Detached view without options:** the view cannot read `connection_options_get`, so it never offers the clipboard on focus and does not show VNC view-only. Rust enforces both, so this is only a missing indicator. A view-only toggle there would need a seventh permission (`session_set_view_only`).
- **Prompts in the detached view** are not answered there. The view shows "bring it back to answer", and main gets no prompt event while detached. Answering a reconnect certificate prompt in the detached window would need `PromptModal` without the sessions store.
- **No "copy username/password/OTP" buttons on the web card.** The ADR puts them in the placeholder tab; the card points to the inspector's existing copy buttons. Moving them onto the card is a small follow-up.
- `sessions.ts` is at 475 lines and `ipc.mock.ts` at 485. The new logic went into new modules: `sessions.detach.ts`, `web.ts`, `output.ts` and `ipc.mock.detach.ts`.
- The main bundle is 508 kB minified (Vite's 500 kB warning). MockTransport ships in it, as before.

## Decision needed
1. **rust-core: protocol in the route, or a lenient attach.** `#/detached/<sessionId>` does not carry the protocol, and `session_list` is forbidden in that window. So the view attaches with `onFrame` first and, on `input.invalid`, again without it (SSH). That costs one refused call per SSH detach. Options: Rust accepts and ignores `onFrame` for SSH, or the URL becomes `#/detached/<sessionId>/<protocol>`.
2. **rust-core: does a detached view's own re-attach send `detached` to itself?** React StrictMode in dev mounts twice, so the view calls `session_attach` twice. The UI ignores the stale channel either way; the mock sends nothing to the same view.
3. Inherited from U1: should `web_list` be in `POLLED_COMMANDS`? U3 still does not poll it. It is called after `web_open` and on unlock only.

## Test evidence
- `pnpm install --frozen-lockfile`, `pnpm lint`, `pnpm typecheck`, `pnpm test` and `pnpm build` are green from the worktree root.
- **Vitest: 42 files, 305 passed, 0 skipped** (baseline 38 files, 279 tests).
- **New test files:**
  - `lib/ipc.mock.detach.test.ts` (7): the web lifecycle and notices, lock refusals, the demo, the phantom detach/attach cycle with acks and full frame, a real view with `closed` reaching both views, the `ipc.forbidden` matrix (`vault_status`, `app_info`, `session_set_view_only`, `session_list`, another id, `window_detach`, `listen`), and SSH `onFrame`/0×0/lock.
  - `components/web/WebSessionTab.test.tsx` (8): `web_open` (and no `session_open`), title/origin/badge, title sanitising, every control and the zoom steps, the locked state, clearing with confirmation and audit, notices with origin, Edit connection, dismiss and the cap, the persistent badge, native close and Reopen, and re-adoption after a lock on a new channel.
  - `components/detached/detach.test.tsx` (4): no placeholder before `detached`; the placeholder after it; Bring back → `window_attach` → `attached` → `session_attach` with a frame channel (credits 0, full frame, `attachEpoch` 1); SSH without `onFrame`, with the gap note and the size resent; no detach for web or when locked (friendly error); a lock keeping the placeholder, then bringing back after unlock.
  - `components/detached/DetachedApp.test.tsx` (6): route parsing; **the mock's six = the `detached-*` entries of `src-tauri/ipc-manifest.json`** (skipped with a message if the file is absent); the SSH and VNC flows, each asserting that **every invoked command is in the manifest's detached set**, that `vault_status` and `listen` are never called, and that `mock.forbidden` is empty; a failed attach that only ever calls `session_attach`; and the main route still booting `App`.
- **Extended tests:**
  - `ipc.remote.test.ts`: the strict `attached` decoding; the channel move on reopen.
  - `sessions.test.ts` / `sessions.remote.test.ts`: detach keeps the tab; a takeover is played through `viewOf`.
  - `sessions.trust.test.ts`: the unused-variable lint error that was already on `a2` is fixed.
