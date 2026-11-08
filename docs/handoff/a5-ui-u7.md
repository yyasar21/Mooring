# A5 · ui-engineer · U7: web windows through jump hosts, cluster hop prompts, winget, lease TTL

Worktree `/home/claude/nexus/.claude/worktrees/agent-a27e310d210148232`, branch
`worktree-agent-a27e310d210148232`, from `main` @ `73ec34a` (R6 merged). Not merged. No cargo run,
and no manifest, lockfile or capability change. The contract is the "UI contract" section of
`a5-rust-core-r6.md`, plus the `kube_open` channel from `a3-rust-core-k4.md` and `a5-rust-core-r1.md`.

## Done

### 1. Web windows through jump hosts (R6)
- **Wire.** `web_open` → `WebOpened { windowLabel, viaHops? }`, decoded by `decodeWebOpened`.
  `web_list` rows gain `viaHops?`. Both use `decodeViaHops`: an integer 1..3, anything else is
  dropped (a direct window).
- **Opening state.** `openWeb` sets `WebTab.viaHops` from the connection's `via` before it calls
  `web_open`. While the tab is `connecting`, the card shows a spinner (`role=status`) with
  "Opening through N jump hosts…" and "Each jump host signs in first. This can take up to 90
  seconds." The spinner stops under `prefers-reduced-motion`.
  - **No cancel.** The contract has no cancel command. "Close tab" is offered while opening. A tab
    closed meanwhile closes the window with `web_close` as soon as `web_open` returns. Before this
    change the window was left open with no tab.
- **Open window.** The toolbar chip reads "via bastion01 (SOCKS)" (hop names in order, else "N
  jump hosts"). Its tooltip says host names resolve on the last hop and certificates are checked
  as usual.
- **Refusals** (`components/web/WebVia.tsx`, `WEB_OPEN_ERROR`), shown in the card with
  `role=alert`. `Tab.openError` keeps the code.
  - `web.via_unsupported` → "Jump hosts are not available for web windows on macOS", next step:
    use the jump host's SSH dynamic forward (SOCKS) in a browser, or remove the jump hosts.
    `FRIENDLY` was reworded the same way.
  - `session.hop_failed` → "A jump host could not be used". The reason is **Rust's message**
    ("jump host 1 asked a question a web window cannot answer …"), because R6's text names the
    hop and is safe. The hint says to open the jump host once as an SSH session to trust its key,
    and to give it a stored credential.
- **Form.** `supportsVia("web")` is now true, so the "Connect via" picker is shown for web
  connections and the refusal note is gone. `WebViaNote` adds:
  - with hops, the SOCKS sentence and "a web window cannot answer a jump host's questions";
  - on macOS (`isMac()`), always, the note `role=note`: "On macOS, this build cannot open web
    windows through jump hosts. Opening is refused; use an SSH session's dynamic forward instead."
- A closed web tab no longer also gets the terminal-style "Link lost" overlay. The web card
  already has the reason, Reopen and Close tab, and the overlay repeated the reason.

### 2. `decodeWebEvent`
- An unknown kind (or a non-object) now returns `null` and is **ignored**. It is no longer read as
  `closed`. Only `{ kind: "closed" }` closes the tab. Dev builds log
  `console.warn("mooring: ignored an unknown web window event", <kind, capped 40>)`; nothing else
  from the message is logged. `no-console` is disabled on that one line, with a reason.
- `TauriTransport.webOpen` drops `null` events.

### 3. Kubernetes: hop prompts and `hop_status`
- `kubeOpen({ connectionId, onEvent })` now passes a channel, as `kube_open` requires since K4.
  It returns `{ sessionId }` only.
  - **The UI was out of date here.** It called `kube_open` without `onEvent` and read identity and
    server from the result, which does not match the Rust command.
- `ClusterEvent` = `connected { server, identity, contextNamespace }` | `prompt` | `hop_status` |
  `closed`. `decodeClusterEvent` reads `connected` field by field (capped) and passes the other
  three to `decodeSessionEvent`, so a malformed `hop_status` closes, as on SSH. Other kinds are
  ignored, with a dev warning.
- `openCluster(tabId, connectionId, sink)` sets the handle id at once. On `connected` it fills
  `useKube.clusters` and sets the tab to `connected`. Every other event goes to the sessions
  store's own `onEvent(tabId, gen)`, the same handler SSH tabs use. Prompts therefore open the
  same `PromptModal` (host key trust, keyboard-interactive, credential, certificate), named "Jump
  host X: …". They are answered with `session_send` on the cluster handle. `hop_status` fills
  `Tab.hops`.
- `Workspace` now shows the `HopStrip` on cluster tabs. `ClusterBrowser` shows the
  `hop_failed` / `hop_lost` hint under the close reason.

### 4. winget
- `UpdateManualReason` gains `"winget"` (`ipc.types.update.ts`, `REASONS`).
- The copy is "Installed with winget — update with winget upgrade yyasar21.Mooring." The offer
  shows the command in a `<code>` row with "Copy winget command" (it copies `WINGET_COMMAND`)
  instead of the release-page row.

### 5. Lease TTL
- `LeaseInfo.ttlSeconds?: number | null`. `decodeLease` keeps a positive number. Anything else is
  `null`, and a bad value never drops the row.
- `nextView` uses Rust's TTL when present, so "renews in" is exact. The old estimate (the largest
  seconds-left seen) remains for builds that do not send it.
- The chip tooltip (and so the tab's accessible name) ends with the remaining time, for example
  " Expires in 50 min (TTL 1 h).". It is left out once the lease is revoked or expired.

### 6. Copy
- "Security key (FIDO2)" → "SSH security key (FIDO2)", matching Rust's kind label, in:
  - `FRIENDLY["credential.use_sk_kind"]`;
  - the `UseSkKindNote` sentence and its button "Create SSH security key (FIDO2) credential";
  - the Settings → SSH row "SSH security keys (FIDO2) sign through your ssh-agent".

### 7. Mock backend
- **Web via.**
  - Knobs `webViaSupported` (false = macOS) and `webViaDelayMs` (per hop).
  - Each hop must already be trusted and must not be a `prompt` credential. Otherwise the open
    fails with `session.hop_failed` and R6's exact sentence. Nothing is trusted for the user.
  - Audit rows `session_hop_open` / `session_hop_close` (`protocol: web`) and
    `forward_opened` / `forward_closed` (`id: web-via`, `reason: web_via`).
- **Seed.** New connection **`c-wiki` "stage-wiki"** (web, Staging, via `bastion01`). It opens
  once bastion01's key is trusted, for example after opening stage-app or bastion01 as SSH.
  Backup export counts went from 14 to 15 connections.
- **Kube.** `kubeOpen` emits `connected` later on the channel. With `via` it runs a
  `MockHopChain`, the same as SSH. Hop answers are routed by `session_send` on the handle. A
  failed hop closes the cluster with `closed { hop_failed }`, and closing a cluster emits
  `closed { user }`.
  - New abstract hooks in `MockWebBase`: `viaHopsOf`, `hopTrusted` and `hopChainOf`.
- **Updates.** `updateMode = { installMode: "manual", manualReason: "winget" }`. Install refuses
  with `update.manual_only` and Rust's message (`WINGET_MANUAL_TEXT`).
- **Leases.** `session_list` lease rows carry `ttlSeconds` (the issued TTL).

## Left open
- **Kubernetes Tauri transport drift (not fixed, needs its own round).** `kube_open` is aligned
  now, but other kube commands in `TauriTransport` still use the A3 U1 names and shapes, which
  K4 changed:
  - `kube_logs` / `kube_logs_stop` are now `kube_logs_open` / `kube_logs_close`;
  - `kube_watch` / `kube_unwatch` do not exist;
  - exec goes through `session_open({ kube })`, but Rust has `kube_exec_open({ sessionId,
    namespace, pod, container, command, size, onEvent })`.

  On a real build, logs, watch and exec from the cluster browser should therefore fail. The mock
  hides this. I kept to the brief. Tell me if this round should fix it: it is UI-only, but it
  needs the K4 shapes checked against `ipc-manifest.json`.
- **Prompt before the handle id.** If a `kube_open` channel prompt arrived before the invoke reply
  (an IPC ordering edge), `answer` would find no `sessionId` and send nothing. Rust's `kube_open`
  is synchronous and the chain runs in a task, so in practice the reply comes first. Not handled.
- **The kube API server certificate prompt** (`certificate_trust` on the cluster channel) now also
  reaches `PromptModal`, because the decoder accepts it. The mock never sends one, so it is not
  tested here.
- **No interactive hop prompts for web windows.** Option (a) of R6 Decision needed 2 is in place.
  If (b) is chosen, R6 can now emit new `WebEvent` kinds without closing tabs.
- **e2e (qa scope, `apps/desktop/e2e` not touched).** Suggested flows:
  1. Open "stage-wiki" before trusting bastion01: the card shows "A jump host could not be used"
     with the SSH-session hint. Open bastion01 as SSH and trust it, press Reopen window: the chip
     reads "via bastion01 (SOCKS)".
  2. Put stage-cluster behind bastion01 (Connect via): the hop trust dialog, the hop strip, then
     the cluster browser.
  3. Settings → Updates with the winget mode: copy the command.

## Decision needed
- **Seed change (qa).** `c-wiki` uses bastion01, so deleting bastion01 now also names stage-wiki
  ("Used by: stage-app, stage-wiki."). I updated `via.test.ts`, `via.test.tsx` and `backup.test.tsx`.
- **Web "Link lost" overlay removed** for closed web tabs (above). It was a duplicate, but it is a
  visible change.

## Test evidence
Linux x86_64, 2026-11-08. `node_modules` is symlinked from `/home/claude/nexus` and not committed.

```
pnpm typecheck   ok (packages/ui, apps/desktop)
pnpm lint        ok (0 problems)
pnpm test        Test Files 97 passed (97) · Tests 713 passed (713)
pnpm build       ok (index chunk 471 kB)
```

New:
- `components/web/webVia.test.tsx` (6):
  - the opening state (spinner text, 90 s, Close tab), then `connected`, the SOCKS chip and the
    hop/forward audit rows, and `forward_closed` on close;
  - an untrusted hop → `session.hop_failed` with Rust's sentence, the title and hint, and nothing
    trusted; Reopen works after trusting;
  - macOS → `web.via_unsupported` title and next step;
  - a tab closed while opening → the window is closed when it arrives;
  - a direct window has no chip;
  - `decodeWebEvent` ignores unknown kinds with a dev warning, and `closed` still closes.
- `components/kube/kubeHops.test.tsx` (4):
  - hop trust dialog and hop strip on a cluster tab, answered by `session_send` id 1000 on the
    handle, then `connected` with the identity;
  - reject → `hop_failed`, the failed chip and the hint;
  - a hop credential prompt;
  - `decodeClusterEvent`.

Updated:
- `ipc.tauri.a3.test.ts`: `kube_open` with a channel, `hop_status` and `connected` decoded from
  it.
- `ipc.tauri.remote.test.ts`: an unknown web event is ignored, not `closed`; `viaHops` on
  `web_open` and `web_list`.
- `leases.test.tsx`: the `ttlSeconds` decode, the exact renewal figure, the remaining-time
  tooltip.
- `updates.test.tsx`: the winget row and copy.
- `ipc.update.test.ts`: winget decode and the install refusal.
- `ipc.kube.test.ts`: `connected` on the channel.
- `via.test.ts` / `via.test.tsx`: web takes jump hosts, the SOCKS note, the macOS note.
- `skKey.test.tsx`: the new wording.
