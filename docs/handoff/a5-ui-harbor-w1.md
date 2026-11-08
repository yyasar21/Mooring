# A5 · ui-engineer · Harbor W1: Phase 1 (Q1–Q9), navigation rail (M1), tree (M3)

Worktree `/home/claude/nexus/.claude/worktrees/agent-afb28bb48ea5fd18c`, branch
`worktree-agent-afb28bb48ea5fd18c`, from `main` @ `0eaafdb`. Not merged. No cargo run, no
manifest, lockfile or capability change, no new dependency. Plan:
`docs/design/review-2026-11/README.md` §4 (Proposal A, decided 2026-11-07: neutral blue, left
rail, ships with v0.2.0), §7 rows Q1–Q9, M1, M3, and §8.

## Done

### Phase 1
- **Q1 tokens** (`packages/ui/src/tokens.css`, `apps/desktop/src/styles/app.css` `@theme`). The
  Harbor light and dark sets: canvas and surfaces, borders (input border ≥ 3:1), three text tiers
  (lowest ≥ 4.5:1), one blue accent, success, warning, danger and info, elevation e1–e3, a 4 px
  grid, 4/6/8 radii, 120/200 ms motion. `prefers-contrast: more` raises the hairlines and the
  lowest text tier. The bridge-console names (`--bg`, `--line`, `--text-faint`, `--hot`,
  `--glow-*`, `--fs-2xs` …) are **aliases for one release**, so screens not migrated yet still
  render. Remove them in 0.3.
  - Tuned against the proposal so every checked pair passes, including the pairs on
    `surface-2`, the canvas and the selection. Light: success `#176f32` (was `#1a7f37`, 4.4:1 on
    its pill), input border `#7d858f` (was `#8b939d`, 2.9:1 on the canvas), text-3 `#5f6670`,
    warning `#8a5c00`. Dark: text-3 `#959ba4`, input border `#747a83`.
- **Contrast gate (§8)**: `apps/desktop/src/styles/contrast.ts` + `contrast.test.ts` (runs in
  `pnpm test`). It reads `tokens.css`, resolves `var()` chains per theme, composites translucent
  tints over the surface they sit on, and checks 33 text pairs (≥ 4.5:1) and 9 non-text pairs
  (≥ 3:1: input border, focus ring, switch track, selected-tab indicator, status dots) in both
  themes. It also checks that the deprecated aliases still resolve.
- **Q2 type**: no `text-transform` or letter-spacing left in any stylesheet. Everything is IBM
  Plex Sans, sentence case, nothing below 11 px. **Chakra Petch imports removed** (4 font files
  no longer in `dist/`).
- **Q3 decoration removed**: the deck grid, scanlines, reticle, `.m-hud` corner brackets (the
  class is now a plain hairline frame), `deck-open`, the `pop-in` brightness flash, the tree
  live-link line, the palette stagger, the airlock rings and sweep, and every glow and
  text-shadow. `.deck` is kept as a hook (a test looks it up). Unlock/create is a plain card;
  the "Not initialised" and "Sealed" chips are gone.
- **Q4 status vocabulary**: `StateDot` is a round 8 px dot with `tone` ok / wait / busy / err /
  neutral (busy is a small spinner, stopped under reduced motion), plus `state` for backwards
  use and `dotTone()`. `.chip[data-tone]` takes success / warning / danger / info (`ok` and
  `hot` still work as aliases). "Waiting for you" is warning everywhere (tab, inspector, status
  bar). Pod status: Running → success; Restarting, Not ready, Unknown → warning; Failed →
  danger; Pending and Completed are neutral.
- **Q5** switch: 32×18 track, round thumb, accent when on (the exposure switch is danger when
  on). `role="switch"` is unchanged.
- **Q6** buttons: filled primary, bordered secondary, subtle, danger as text, plus
  `btn-danger-solid`. Sizes `btn-sm` 24, default 28, `btn-lg` 36.
- **Q7** the details pane renders only in Hosts.
- **Q8** status bar: "Vault unlocked · N sessions open · N waiting for you · Audit chain
  verified / broken at entry N · Mooring 0.2.x". Build OS, arch and debug are only in
  Settings → About. The clock is gone.
- **Q9** Appearance: `settings/AppearanceCard.tsx` (System / Light / Dark radios). `stores/ui.ts`
  has `themePref` and `setThemePref`; `theme` is still the resolved value, so TerminalView is
  unchanged. System follows `prefers-color-scheme` live (`main.tsx` listener) and is the default
  when nothing is stored. `toggleTheme` (palette "Switch theme") stores the opposite of what is
  painted.

### M1 navigation rail
- `components/NavRail.tsx`: `nav "Views"` with Hosts, Credentials, Audit (visible label, accessible
  name **"Audit log"**) and Settings at the bottom. `aria-current="page"` marks the open view.
  mod+1…4 work everywhere; inside a terminal on Linux/Windows the chord is mod+Shift+digit
  (matched on `code`).
- Pressing the open view again returns to Hosts. The old title-bar buttons toggled this way, and
  `a4.e2e` `closeSettings` and `secrets-sync.e2e` rely on it.
- Credentials, Audit log and Settings take the full width. Their "Back to sessions" buttons are
  removed; `settings.test.tsx` now uses the rail's Hosts.
- Title bar: mark, "Mooring", "Local vault" (a static label where a vault switcher will go),
  search button "Search hosts, credentials and commands" (opens the palette), sync pill, help,
  Lock.
  - Sync pill: "Synced" (success) or "Sync paused" (danger), a button to Settings → Sync. Nothing
    while sync is off. The existing `.sync-indicator` "Syncing…" status shows while a run is in
    progress.
  - The theme toggle is gone from the title bar.

### M3 tree
- Connection rows show a `ProtocolIcon`: an inline SVG, `role="img"` named after the protocol
  (the name the pip carried), with a labelled status dot ("session connected" / "session
  connecting") on its corner. Tabs use the same icon (warning dot while a prompt waits).
  `ProtocolPip` stays for details and the palette, with full names (Web, Kubernetes, vSphere).
- Folder rows: chevron, folder icon, name, and a count of the connections inside, sub-folders
  included (`subtreeCounts`).
- Filter field "Filter by name, host or tag" (`searchbox "Filter connections"`). It shows the
  matches and the folders above them, all expanded; a matching folder name brings its subtree.
  Escape clears it, and an empty result says "No connections match." The logic is in
  `tree/treeFilter.ts`.
- Header (`tree/SidebarToolbar.tsx`): "Connections", the "New folder" icon button (name and
  read-only title unchanged), and a **New** split button.
  - The main part keeps the accessible name **"New connection"**.
  - The arrow, "More ways to add" (`aria-haspopup="menu"`), opens a menu: Connection…, Folder…,
    Import connections…. ↑↓ move, Esc closes and returns focus, Tab and an outside click close.
  - The tree's Credentials shortcut moved to the rail.
- All treeitem names are unchanged.

### Contracts kept
`nav "Views"`, its buttons "Credentials", "Audit log" and "Settings", `tree "Connections"`,
`nav "Connection tree"`, every treeitem name, "New connection", "New folder" (and its read-only
title), `complementary "Details"`, `contentinfo "Status"`, "Lock", "Trust and connect", "Reject
and disconnect", `toolbar "Session tools"`, `.sync-banner`, `.deck` with four grid children.

### e2e change (qa-owned, same commit `51b4894`)
In `apps/desktop/e2e/a5.e2e.mjs`, "dynamic secret", the flow clicked the tree's "New
connection" while in the Credentials view, where the tree is no longer shown. It now clicks the
rail's **Hosts** first and drops the later "Credentials" click whose comment was "back to the
sessions".

## Left open
- **`@fontsource/chakra-petch`** is still a dependency in `packages/ui/package.json` and the
  lockfile. Nothing imports it now. Orchestrator: remove it (manifest + lockfile).
- **Pre-existing e2e failure, not from this wave.** `kube.e2e.mjs` "exec opens a terminal tab for
  the chosen container and the shell echoes" times out at "exec shell echo".
  - It fails the same way on `0eaafdb` with this wave's changes removed (baseline export run
    in a scratch copy).
  - Cause: `e2e/boot.ts` copies output into the probe only from `transport.sessionOpen`. Since
    `f585905` the mock runs exec through `kubeExecOpen`, so `probe.output` stays empty.
  - qa: wrap `kubeExecOpen`'s `onEvent` in `boot.ts` the same way. Because `make e2e` stops at
    the first failing file, I ran the remaining suites directly (see Test evidence).
- Kept from the old system, to be migrated by later rows:
  - settings-card eyebrows ("Vault", "Audit", "Trust"): M6
  - credential kind codes and list cards: L2
  - palette text pips: L3
  - the SSH tool bar ("Detach to window") and session header: M2
  - inspector tabs: M4
  - "Link lost" box and toasts: M7
  - trust dialogs: M8
- The vault label is static ("Local vault"). The help button opens the command palette, which
  lists the shortcuts. There is no help page yet.
- Rows that still use the deprecated alias tokens render correctly, but they are not yet tuned
  one by one to Harbor (for example `kind-badge`, `matrix-cell`, the kube and vSphere chips).

## Decision needed
1. **Rail re-press.** Pressing the open rail item returns to Hosts. This keeps the e2e flows
   that close Settings by pressing it again. A pure rail would ignore a re-press. Keep it, or
   ask qa to switch those flows to "Hosts" and drop the toggle?
2. **Default theme.** With no stored choice, the app now follows the OS. It used to default to
   dark, so users on a light OS will see the light theme after the update. Users who chose a
   theme keep it.
3. **Token deviations** from the proposal (listed under Q1) are small and keep AA on every
   surface. Please confirm, or update `harbor.css` to match.

## Test evidence
- `pnpm typecheck` ✓ · `pnpm lint` ✓ · `pnpm test`: 100 files / 818 tests, all green (was 98 /
  716) · `pnpm build` ✓ (no Chakra Petch assets in `dist/`).
- New or changed unit tests:
  - `styles/contrast.test.ts`: 89 cases
  - `tree/tree.test.tsx`: filter, counts, icons, status dot, filter UI, split-button menu and
    keyboard
  - `dialogs.test.tsx`: mod+1…4 mapping; rail switching, `aria-current`, re-press, Details and
    tree only in Hosts
  - `SyncBanner.test.tsx`: the sync pill states
  - `settings.test.tsx`: rail round trip; the Appearance radios
  - `stores/ui.test.ts`: the three-state preference and live System
  - `Telemetry.test.tsx`: plain words, no build internals
  - `kube/ClusterBrowser.test.tsx`: the new tones
- e2e (Playwright, mock transport, headless Chromium 1243): all six suites in one run on the
  final commit, **41/42 passed**. The one failure is the kube exec test described under Left
  open, which also fails on `0eaafdb`. Flows, vSphere, secrets-sync, a4 and a5 all pass.
- Screenshots in `docs/design/review-2026-11/after-w1/`, made with the mock transport at
  1440×900, deviceScaleFactor 1, JPEG q78, WebGL off so xterm uses its DOM renderer. 11 screens
  × 2 themes, before (from `0eaafdb`) and after, 3.7 MB in total.
  - `before/` and `after/`, named `NN-screen-{light,dark}.jpg`
  - Screens: vault create and unlock, workspace with details, SSH terminal, command palette,
    new connection, host-key prompt, credentials list and detail, audit log, settings.
