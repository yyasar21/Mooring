# A1 — ui-engineer handoff, visual redesign v2 ("bridge console")

Branch `worktree-agent-ab9626a90a6a131ef`. Replaces the v1 look the product owner rejected
("safe, generic, boring"). Visual and markup changes only; no store, IPC or behaviour changes
except the new telemetry strip.

## Design rationale
1. Ground: near-black with a teal cast (`--void #03070a`, panes `#04090d`), so cyan reads as light, not paint.
2. Two hues with fixed meanings (orchestrator override of "one accent"): **signal cyan `#29e6f2`** = selection, focus, connected/live; **hot magenta `#ff3b8d`** = danger and "waiting for you" (prompts, rejected keys, broken chain). `--ok`/`--warn`/`--danger` now map onto these two.
3. Glow only on active things: the selected tree row, live links, the connected tab rail, focus rings, primary hover. Resting chrome is hairlines.
4. Material: HUD frames are hairline boxes with corner brackets that light when active. Overlays are glass (`backdrop-filter`). The deck has a static 24 px grid and scanlines at 1.8 % opacity, painted once.
5. Type: Chakra Petch (squared, chamfered letterforms) is the display face and the uppercase tracked micro-label face. IBM Plex Sans stays for body text, IBM Plex Mono for hosts and the terminal.
6. Signature: the airlock unlock screen (hatch over range rings, one arrival sweep, a pressure bar while Argon2id runs, then the deck opens from a horizontal seam).
7. Tree: each connected host gets a lit protocol pip and a "link" line running from its name to its state diamond. While connecting, the line is dashed.
8. The tab rail pulses while connecting, is lit when connected and frayed when closed. Tabs are chamfered.
9. The terminal sits in a static CRT-style bezel (inset vignette, no curvature, no flicker, nothing animated over the canvas). The inspector is a HUD readout with `[ SECTION ]──` labels. The status bar is a telemetry strip.
10. Motion runs once or is state-driven: the airlock sweep and hatch, the deck opening, palette rows sliding in (staggered by 18 ms), selection glow fades, the connecting pulse. Nothing idles except the connecting pulse and the 1 Hz clock. `prefers-reduced-motion` collapses everything.

## Done
- `packages/ui/src/tokens.css`: colour, glow, focus-ring, texture, bracket, radius, bevel, type-scale, tracking and motion tokens for dark and light. Light is a quiet "daylight console" with glows off.
- `packages/ui/src/primitives.css` (new export `@mooring/ui/primitives.css`): `.m-display`, `.m-micro`, `.m-kbd`, `.m-pip` (+ `data-live`), `.m-hud` (+ `data-active`, `data-tone="hot"`), `.m-hud-label`, `.mooring-line`, `.state-dot` (diamond), `.btn*`, `.icon-btn`, `.field*`, `.scrim`, `.pop`.
- Primitives: `ProtocolPip` gained `live`; `Kbd` uses a CSS class; new `HudLabel`.
- `apps/desktop/src/styles/airlock.css` and `deck.css` hold the screen styles. All component CSS is imported into `@layer components` so Tailwind utilities on an element keep precedence (this fixed a palette-positioning clash).
- Screens: `VaultGate` (airlock), `Shell` (wordmark + mark, the "seek" field), new `Telemetry` (vault, links, waiting prompts, audit chain via `auditVerify` every 60 s and on view change, build, local clock), `Sidebar`/`TreeRowView` (live pips, link line), `TabStrip`, `Workspace` (bezel, reticle empty state, "Link lost" banner), `Inspector`, `CommandPalette`, `AuditView`, `Modal`, `PromptModal` (hot frame).
- All accessible names, roles and copy that tests or users rely on are unchanged.

## Left open
- The telemetry strip calls `auditVerify` on mount, every 60 s and when the view changes. With a large real log that may be expensive. If so, rust-core should expose a cheap cached status, or the interval should be raised.
- `framer-motion` was not needed; all motion is CSS.
- The Design plugin's accessibility review was not run here. Checked by eye: contrast of `--text-faint` on `--bg-sunken` is low by design and used only for metadata. Body and value text are above 7:1 in dark mode.
- The light theme is correct but understated. It has had less polish than dark.

## Decision needed
- Confirm the two-hue rule (cyan = live/selection/focus, magenta = danger/attention), so other agents do not add a third semantic colour.
- Is a 1 Hz clock in the strip acceptable for battery? It re-renders one `<time>` only.

## Test evidence
- `pnpm install && pnpm typecheck && pnpm lint && pnpm test && pnpm build` clean. Vitest has 9 files and 41 tests passing: the 40 existing tests plus `Telemetry.test.tsx`, which covers vault state, link count, a broken-chain readout and the waiting-prompt cell. Build: main JS 303 kB, terminal chunk 444 kB, CSS 53 kB, no warnings.
- Screenshots were taken with Playwright (`playwright-core` from `/opt/node-tools`, not added to the project) driving `/usr/bin/google-chrome` against `vite preview`, at 1440×860, dark and light: `docs/handoff/img/a1-ui-v2/`
  `01-unlock`, `02-shell-empty`, `03-palette`, `04-tofu-prompt`, `05-shell-ssh`, `06-inspector` (copy countdown), `07-audit`, `08-dialog` — each as `-dark.png` and `-light.png`.

## Dependencies added
- `@fontsource/chakra-petch` ^5.3.0 (packages/ui, OFL font files only, no JS): display face for titles and micro-labels. Only the latin and latin-ext subsets at weights 500 and 600 are imported, which adds about 60 kB of woff2.
