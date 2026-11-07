# Mooring UI design review, November 2026

Review of the v0.1.1 desktop UI and a redesign proposal. Requested 2026-11-07 ("can the UI be much, much
better"). **Direction changed the same evening (22:13):** the owner now wants a corporate,
enterprise-grade UI. That replaces the sci-fi-film direction from 2026-11-03. The review below judges
the current "bridge console" UI against that new target, and both proposals are enterprise
directions.

No product code was changed. This folder holds the captures, the review, two directions, static
HTML mockups and a phased plan.

```
current/    one sample capture of the pre-redesign UI (the full set of 84 was not kept in the
            repository; the table below names what was captured — regenerate with the mock
            transport and Playwright if a side-by-side is needed)
mockups/    static HTML mockups: harbor.css (proposed tokens + components), shell.js (shared chrome)
proposal/   mockups rendered with Playwright (1440x900 @1.5x)
```

Open a mockup in a browser: `mockups/workspace-ssh.html`. Add `?theme=dark` for the dark theme and
`&variant=teal` for the alternative.

## 1. Summary

**Top 5 problems**

1. **The visual language is a film prop, not a work tool.** Tracked all-caps Chakra Petch on every
   label, button, folder and column. HUD corner brackets on panes, dialogs, toasts and the terminal.
   Scanlines, a grid on the background, cyan glows and a reticle on empty states. All of it reads
   as a game UI to an enterprise buyer, and the caps cost reading speed.
2. **Contrast fails WCAG AA where the most text sits.** `--text-faint` (`#4b6670`) is 3.0 to 3.3:1 on
   dark surfaces and 3.0:1 in light, and it is used for 10 px micro labels, `dt` keys and
   placeholders. Field borders are 1.5 to 1.6:1, below the 3:1 non-text minimum. In light mode the
   accent (`#007f8c`) is 4.4:1 and is used for 10 px button text.
3. **Navigation and context are confused.** Credentials, Audit log and Settings open in the centre
   column. The connection tree and the connection inspector stay on screen, so the Credentials
   view shows three unrelated columns plus the details of `dc01`. Views sit as text buttons in
   the title bar next to a "Light/Dark" toggle and "Lock".
4. **One accent colour carries too many meanings, and status has no vocabulary.** Magenta means
   danger, warning, "waiting for you", Delete, a restarting pod and a TOTP advisory. Cyan means
   selection, focus, connected, primary action and "stored". There is no green, no amber, no
   neutral pill, and connected state is a glowing diamond.
5. **Data views are not real tables, and forms are long single scrolls.** The audit log has no
   column sorting, event filters or detail drawer, and key:value pairs run together in mono. The
   credential list is a stack of cards with cryptic codes (ASK, REF, DOM, KCFG, ROLE, S3). Settings is
   one 720 px column of eight cards. The new-connection dialog is a scroll with no section
   navigation. Toggles look like square checkboxes.

**Proposed direction (A, "Harbor"):** a calm, neutral enterprise shell. IBM Plex Sans in sentence
case on a 4 px grid, one restrained blue accent, a real semantic status palette, and subtle
elevation instead of glow. Navigation moves to a rail. Each view gets the whole width (tree and
inspector only in Hosts), sessions get a header with breadcrumb and live status, and data views
are sortable tables. Light and dark are equally finished.
**Alternative (B, "Harbor Teal"):** the same system with Mooring's teal as the only accent and the
bollard mark in the title bar and on unlock. That keeps a small brand signature and nothing else.

**Quick wins (each ≤ 1 day):** sentence case and the sans face for all UI text. Raise `--text-faint`
and the field borders to AA. Split the status colours (success, warning, danger, info). Remove the
scanlines, grid, reticle, HUD brackets and the deck-open animation. Make the Switch a real switch.
Hide the inspector outside the workspace. Move the theme toggle into Settings. Turn the "BUILD DEV
BROWSER/MOCK" telemetry text into a plain status bar.

## 2. How the captures were made

Vite dev server on :1421 with the mock transport; `e2e/boot.html` for a fresh vault, Playwright
Chromium 1440x900, deviceScaleFactor 2, both themes (`mooring.theme` in localStorage). xterm's WebGL
renderer paints nothing in headless Chromium, so the capture disabled `webgl2` and xterm fell back
to its DOM renderer. **That is a capture artefact, not a product bug.** Images were re-encoded as
JPEG (q78) because the workspace disk was nearly full; each is < 400 KB.

| # | Screen | Files |
| --- | --- | --- |
| 01 | Create vault, weak-password error | `current/01-vault-create-*.jpg`, `01b-…` |
| 02 | Unlock | `current/02-vault-unlock-*.jpg` |
| 03 | First run (empty vault) | `current/03-onboarding-empty-*.jpg` |
| 04–05 | Empty workspace, tree + details (SSH, RDP) | `current/04-…`, `05-…`, `05b-…` |
| 06 | Command palette (empty, query) | `current/06-…`, `06b-…` |
| 07 | New connection: SSH, RDP, RDP gateway, validation | `current/07-…` to `07d-…` |
| 08 | Credentials list, detail, editor, new-kind picker | `current/08-…` to `08d-…` |
| 09 | Audit log | `current/09-audit-log-*.jpg` |
| 10 | Settings, top + one capture per card (8) | `current/10-settings-*.jpg` |
| 11 | Host-key confirmation (in-app alert dialog) | `current/11-confirm-host-key-*.jpg` |
| 12 | SSH: terminal, forwards, files | `current/12-…` to `12c-…` |
| 13 | Credential prompt at connect | `current/13-credential-prompt-*.jpg` |
| 14 | RDP certificate trust, RDP session | `current/14-…`, `14b-…` |
| 15 | VNC session, link-dropped banner | `current/15-…`, `15b-…` |
| 16 | Web session | `current/16-web-session-*.jpg` |
| 17 | Toast ("Credential saved") | `current/17-toast-saved-*.jpg` |
| 18 | Kubernetes cluster, pod selected | `current/18-…`, `18b-…` |
| 19 | vSphere details, vSphere session | `current/19-…`, `19b-…` |

## 3. Review

Severity: **S1** blocks the enterprise direction or fails accessibility · **S2** clear usability
cost · **S3** polish.

### 3.1 Cross-cutting

| Sev | Problem | Where | Why it hurts the corporate goal |
| --- | --- | --- | --- |
| S1 | Tracked uppercase display face (`.m-display`, `.m-micro`, `.btn`, `.tree-folder`, `.chip`, `.prop-grid dt`) | every screen | Caps plus 0.12–0.14em tracking read slowly and shout. "CONNECT", "COPY SECRET", "PRODUCTION" are louder than the content. Enterprise apps (Fluent, HIG, JetBrains) use sentence case. |
| S1 | `--text-faint` 3.0–3.3:1, field borders 1.5:1, light accent 4.4:1 on 10 px text | `tokens.css` | Fails WCAG 1.4.3 and 1.4.11. Procurement accessibility audits will flag it. |
| S1 | HUD frames (`.m-hud`), scanlines, nav grid, reticle, deck-open clip animation, `pop-in` brightness flash | panes, dialogs, toasts, terminal, empty states, unlock | Decoration with no information. It reads as a theme, not a product, and the brightness flash is uncomfortable for photosensitive users. |
| S1 | Single accent + single "hot" colour for all state | `--ok`, `--warn`, `--danger` all alias two hues | Warning, error and "your turn" look identical. Success is the same cyan as selection and primary. |
| S2 | Views as text buttons in the title bar; theme toggle labelled with the *other* theme ("Light") | `Shell.tsx` TitleBar | No clear primary navigation. A theme toggle in primary nav is unusual, and its label inverts meaning. |
| S2 | Inspector and tree stay visible in Credentials, Audit, Settings | `Shell.tsx` grid | Three to four columns, two of them unrelated to the task. The credential view is squeezed to about 500 px. |
| S2 | 10 px type (`--fs-2xs`) everywhere for labels, buttons, chips; body 13 px | `tokens.css` | 10 px is below every desktop guideline. With caps it is the main readability problem. |
| S2 | Buttons have no clear hierarchy: primary is an outline with a soft fill, secondary a darker outline, ghost text only, all uppercase | `primitives.css` | In light mode "Save" (primary) looks disabled (`10-settings-top-light`). |
| S2 | Protocol and credential codes as 3–4-letter tags (VMK, KCFG, DOM, ROLE, ASK, REF, S3) | tree, palette, credentials | Users must learn a code book. Icons plus full names are standard. |
| S2 | Status bar shows build internals ("BUILD DEV BROWSER/MOCK DEBUG", "LINKS 0 CONNECTED") in caps | `Telemetry.tsx` | Developer telemetry presented as product UI. |
| S3 | Radius 2–3 px and clip-path chamfers on tabs, keycaps, pips | primitives | Chamfers are the sci-fi signature. Enterprise UIs use 4–8 px radius tiers. |
| S3 | Motion: rail pulse, blinking diamond, staggered palette slide-in, glow transitions | primitives, deck | Ambient motion with no user trigger. Reduced-motion is honoured, but the default should be calm too. |

### 3.2 Per screen

**Create / unlock vault (01, 02).** S1: a giant reticle with tick marks, a corner-bracket card, and
a two-line all-caps H1 ("CREATE YOUR VAULT"). The crypto line ("ARGON2ID · XCHACHA20-POLY1305") is
tracked caps at 10 px, about 3:1. S2: the error state only colours the border magenta, so the
reason sits in small text below. S3: "NOT INITIALISED" status chip in the card corner is jargon.

**First run (03).** S2: the three choice tiles are equal weight, so "Start from scratch" is not the
obvious primary. The tile borders are chamfered and do not read as buttons. "NOT NOW" is a
tracked-caps ghost button. The tree shows a lone "ALL CONNECTIONS" root.

**Workspace, tree, details (04, 05).** S1: folders in caps compete with hosts. Every row has a tag
pip, so the eye scans codes, not names. S2: the inspector is a long scroll of four bracketed
sections (Connection, Credential, Network tools, port check). Network tools belong on a tab, not
under properties. S2: the "DETAILS … HOST" pane header is cryptic. S3: the tree "live link" line
from the name to a diamond is clever but noisy at 10+ live sessions.

**Command palette (06).** Good bones (it groups, previews keys, uses fuzzy search). S2: results are
connections only, so there are no commands ("Lock vault", "New credential", "Open settings").
Breadcrumbs are caps. S3: the `>` prompt and caret glow lean on the terminal metaphor.

**New connection (07).** S1: one long scroll with protocol options appended at the bottom, and
the gateway is buried. On a 900 px window the RDP options are below the fold. S2: the protocol is a
plain select, though it is the most consequential choice. The credential select packs a code
chip, label and a grey explanation into one line that truncates ("the RD Gateway gets the
sign-…"). S2: validation is silent. A click on Create with empty fields does nothing visible
(`07d`).

**Credentials (08).** S1: three columns plus the unrelated inspector (`08b`). S2: the list is
cards with a code tag and "1 USED" stacked vertically, so it cannot be sorted or scanned as a
table. The protocol support row ("SSH RDP VNC WEB K8S VMK") lights some tags in cyan with no
legend. Delete is a bare magenta word next to Edit. S2: in the editor (`08c`) the TOTP warning is a
magenta block with a magenta bracket frame, styled like an error. S3: "Back to sessions" sits at
the bottom of the list column.

**Audit log (09).** S2: there are no column sorts, no filters by event type, actor or time, no
row detail and no export. The details column runs key:value pairs together in mono and
truncates ("peer identity: …"). The "#" column is right-aligned far from the time. The chain-intact
status is a cyan chip, the same look as a selected tab.

**Settings (10).** S1: one long page of eight cards, each with an eyebrow (VAULT / AUDIT / TRUST)
plus a caps title. The page uses 720 px of a 1180 px pane and the right side stays empty while the
inspector shows `dc01`. S2: toggles are square boxes with an inner square, so they read as
checkboxes. The segmented control (UDP/TCP/TLS) and the save buttons are caps. Each card has its own
Save with no dirty indicator. S3: there is no search or section nav, so finding "Updates" means
scrolling.

**Host-key and certificate confirmations (11, 14).** These are the most important security
moments, and the styling is mostly right (an alert dialog, the fingerprint shown, the safe default).
S2: the fingerprint block uses a magenta left rule like an error. "REJECT AND DISCONNECT" is ghost
caps, and the primary is an outline, so the hierarchy is weak. Compare with macOS/Windows trust
sheets: title, plain sentence, fingerprint in a mono well, then "Trust and connect" (primary) and
"Cancel".

**SSH tab (12).** S2: the tool switcher (TERMINAL / FORWARDS / FILES) and "DETACH TO WINDOW" form a
second caps bar with no host, status or duration. The terminal sits inside an inset bezel with
corner brackets, which costs 16 px on every side. S2: in Files (`12c`) the left "This computer"
column is mostly explanatory text, the toolbar mixes caps verbs with a lone outlined "DOWNLOAD", and
Delete is magenta while disabled.

**RDP / VNC / web (14b, 15, 16).** S2: the toolbar mixes caps buttons with a sentence-case status
("Remote copies: automatic"). The NLA chip has no explanation. The remote canvas is top-aligned
over the grid background instead of centred on a neutral surface. S2: the link-dropped banner
(`15b`) is a floating glass HUD box. It should be an inline status strip with Reconnect.

**Kubernetes (18).** The closest to an enterprise data view. S2: status chips are caps outlines,
and RESTARTING is a glowing magenta box. RBAC permissions show "ALLOWED" in caps beside cyan
diamonds. The read-only banner is cyan, the same as selection. The column headers are not
sortable. S3: the "5 / 5" counter beside the search has no label.

**vSphere (19).** Same patterns as Kubernetes: caps toolbar, the power menu as text.

**Toasts (17).** S3: a corner-bracket frame and a cyan diamond for success. It sits over the
inspector. There is no title or secondary line, and the dismiss button is hard to see.

### 3.3 Against best-in-class

- **Royal TS / Remote Desktop Manager:** dense trees with icons and full protocol names, a ribbon
  or toolbar of verbs, and a properties dialog with left-hand section navigation. Mooring already
  has the depth (gateway, become credentials, overrides). It lacks their structure: section nav,
  tables and a clear primary action.
- **Termius:** hosts as a scannable list with OS/protocol icons, connection state as a small
  coloured dot, and a session header with host and status. It is calm and neutral, and colour
  appears only for state.
- **JetBrains (New UI) / VS Code:** an activity rail for top-level areas, tool windows that
  collapse, a 13 px UI sans and a strict 4 px rhythm. Status lives in a quiet bottom bar.
- **Linear / Raycast:** the command palette is the hub for every verb, not only navigation. The
  keyboard hint sits on every row. Elevation is subtle and there are no glows.
- **Fluent / Apple HIG:** sentence-case controls, a semantic colour set (success, warning, danger,
  info) kept apart from the accent, real switches, and focus rings as a two-ring outline.

## 4. Proposal A: "Harbor" (primary)

**Principles.** Content first, chrome quiet. One accent, used for primary action, selection and
focus. Status uses its own four colours and always pairs colour with a label or icon. Sentence
case everywhere. Mono only for hosts, paths, fingerprints and the terminal. Elevation, not
glow. Every view owns the full width.

### 4.1 Tokens (`mockups/harbor.css`)

| Group | Light | Dark | Notes |
| --- | --- | --- | --- |
| canvas / surface / surface-2 / surface-3 | `#f6f7f9` / `#ffffff` / `#f1f3f5` / `#e9ecef` | `#1b1c1f` / `#1f2023` / `#26272b` / `#2e3035` | Neutral greys, no blue-teal cast |
| border / strong / input | `#e1e4e8` / `#c9ced4` / `#8b939d` (3.1:1) | `#33353a` / `#43464c` / `#6c727b` (3.1:1) | Input border meets 1.4.11 |
| text / 2 / 3 | `#1b1f24` 16.6:1 / `#59616b` 6.3:1 / `#646b75` 4.8:1 | `#e3e5e8` 12.9:1 / `#a9aeb6` 7.3:1 / `#8a9099` 4.6:1 | Lowest tier passes AA |
| accent | `#1a5fb4` 6.3:1 | `#5b9cf5` 5.8:1 | Primary, selection, focus, links |
| success / warning / danger | `#1a7f37` / `#9a6700` / `#c62828` | `#4fbf72` / `#d9a53a` / `#f0706a` | Each ≥ 4.8:1. Pill backgrounds are 13 % tints. |
| radius | 4 (controls) · 6 (cards, menus, tabs) · 8 (dialogs) | same | Replaces 2–3 px plus chamfers |
| elevation | e1 hairline shadow · e2 popover · e3 dialog | darker, with a 6–8 % white ring | Replaces `--glow-*`, `--text-glow` |
| spacing | 4 · 8 · 12 · 16 · 20 · 24 · 32 | | 4 px grid. Row 28, table row 36, title 40, tab 36, status 24 |
| motion | `cubic-bezier(.2,0,0,1)`, 120 ms (hover/press), 200 ms (dialogs, panels) | | No ambient animation. A spinner only while connecting. |

**Type.** IBM Plex Sans (already shipped) for all UI. IBM Plex Mono for host, path, fingerprint
and terminal. Chakra Petch is dropped, which removes 4 font files. Scale 11 / 12 / 13 / 14 / 16 / 20 / 24 with
line-heights 16 / 16 / 20 / 20 / 24 / 28 / 32. Weights 400 body, 500 labels and buttons, 600 headings.
No letter-spacing except −0.01em on 20+.

### 4.2 Layout

```
┌ Title 40: [mark Mooring · Personal vault ▾] [  Search hosts, credentials and commands  Ctrl K ] [Synced] [?] [Lock] ┐
├ Rail 64 ┬ Connections 264 ─┬ Tabs 36 ─────────────────────────────────────────┬ Details 320 ───────┤
│ Hosts   │ Connections [+New]│ [▣ web01 ●  ×][▭ dc01 ● ×][▣ ask-me ● ×] +          │ web01         ⋯     │
│ Creds   │ [Filter…        ] │ Production › Web tier                               │ host · SSH · tags   │
│ Audit   │ ▾ Production   4  │ web01 ops@web01:22  ● Connected 00:12:31  [Terminal|Forwards 2|Files] ⧉ ↗ [Disconnect]
│         │   ▾ Web tier   3  │ ┌───────────────────────── terminal ────────────────┐ Properties|Network|History
│         │     ▣ web01 ●     │ │                                                     │ Connection, Credential,
│ Settings│                   │ └─────────────────────────────────────────────────────┘ Port forwards       │
├─────────┴───────────────────┴─────────────────────────────────────────────────────┴─────────────────────┤
│ ● Vault unlocked   2 sessions open   ⛨ Audit chain verified                 Auto-lock in 14 min  0.2.0 │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **Navigation rail** (Hosts, Credentials, Audit, Settings at the bottom). The tree and the
  inspector appear only in Hosts. Credentials, Audit and Settings get the full width, with their own
  list | detail split.
- **Title bar:** the vault switcher (ready for multiple vaults), search as the command hub,
  sync state as a pill, help, and Lock. The theme moves to Settings → Appearance (System / Light /
  Dark).
- **Session header** for every tab: a folder breadcrumb, the host in mono, a status pill with
  duration, the view switcher as a segmented control (Terminal / Forwards *n* / Files for SSH;
  Display / Clipboard / Stats for RDP/VNC), and window actions.
- **Inspector** with tabs: Properties | Network | History. The network tools move off the long
  properties scroll.
- **An unopened connection** gets a "ready to connect" page with the key facts and a primary
  Connect, not a blank panel.
- **Command palette as the hub:** groups for Connections, Actions (lock, new connection, new
  credential, import, settings pages) and Recent. Every row shows its shortcut.

### 4.3 Components

| Component | Today | Harbor |
| --- | --- | --- |
| Status | glowing diamond, rail under tab | 8 px dot (tree/tabs) and pill with label (headers, tables): Connected · Connecting (spinner) · Needs input (amber) · Failed (red) · Closed (neutral) |
| Protocol | 3-letter pip, lit when live | 16 px icon (terminal, monitor, globe, hexagon, server). A full-name badge only in tables and details. |
| Buttons | caps outline variants | filled primary, bordered secondary, subtle (text), danger text. Sentence case 13/500. Sizes 24/28/36. |
| Fields | 28 px sunken, caps label above | 32 px, 3:1 border, sentence-case label, optional marker, hint and error text with icon |
| Switch | square inside square | 32×18 track, round thumb, `role="switch"` |
| Tables | grid divs, caps headers | sticky 32 px header, sortable columns with an indicator, 36 px rows, tabular numerals, row selection, column chooser later |
| Dialogs | glass + HUD brackets | solid surface, e3, 8 px radius, a header with close, left section nav for long forms, a footer with summary and actions |
| Toasts | bracket frame + diamond | e2 card, status icon, title + secondary line, dismiss. Bottom right, above the status bar. |
| Empty states | reticle + caps headline | icon, one-line title, one sentence, primary action and shortcut hint |
| Callouts | magenta or cyan block | info / warning / danger callout with icon and a tinted background |

### 4.4 Mooring identity in A

In A, the identity is the wordmark, the bollard mark in neutral ink, and the product name on the
unlock screen. The blue accent is chosen for trust and familiarity in enterprise settings, not for
brand.

## 5. Proposal B: "Harbor Teal" (alternative)

The tokens, layout and components are identical. Two things change:

- Mooring teal is the only accent: light `#0b6f7a` (5.9:1), dark `#3fbccb` (7.2:1). It replaces
  the blue everywhere the accent appears.
- The bollard mark sits on a teal tile in the title bar and on the unlock screen.

B keeps continuity with the v0.1 brand, the landing site and the release artwork. The trade-off is
that teal is closer to the success green, so the dots and pills must keep their labels or icons. A
avoids that by separating hue families. **Recommendation: A for the product UI.** Use B if the
owner wants the app to match the existing site and icon without rebranding them.

## 6. Before and after

| Screen | Before | After (A light / A dark / B) |
| --- | --- | --- |
| Workspace, live SSH tab | `current/12-ssh-terminal-dark.jpg`, `…-light.jpg` | [light](proposal/workspace-ssh-light.jpg) · [dark](proposal/workspace-ssh-dark.jpg) · [B light](proposal/workspace-ssh-light-teal.jpg) · [B dark](proposal/workspace-ssh-dark-teal.jpg) |
| Connection details / inspector | `current/05b-tree-details-rdp-*.jpg` | [light](proposal/connection-details-light.jpg) · [dark](proposal/connection-details-dark.jpg) |
| Credential detail | `current/08b-credential-detail-*.jpg`, `08c-…` | [light](proposal/credential-detail-light.jpg) · [dark](proposal/credential-detail-dark.jpg) |
| Settings | `current/10-settings-top-*.jpg`, `10-settings-0*` | [light](proposal/settings-light.jpg) · [dark](proposal/settings-dark.jpg) |
| New connection (RDP + gateway, error) | `current/07c-…`, `07d-…` | [light](proposal/new-connection-light.jpg) · [dark](proposal/new-connection-dark.jpg) |
| Vault unlock (error) | `current/02-vault-unlock-*.jpg`, `01b-…` | [light](proposal/vault-unlock-light.jpg) · [dark](proposal/vault-unlock-dark.jpg) · [B](proposal/vault-unlock-light-teal.jpg) |

Sources: `mockups/<name>.html`. The mockups show some things the product does not have yet, and
they are marked here so nobody mistakes them for shipped scope:

- inspector History tab and Notes field
- split terminal
- configurable clipboard timeout
- biometric unlock (planned for A5)
- vault switcher
- "Unused" credential flag
- last-session line
- certificate expiry in the ready page

Each needs data from rust-core or an ADR before the UI can show it.

## 7. Implementation plan

Rules for every phase: the UI keeps handling credential ids only, no new dependencies (Plex is
already bundled and the icons are hand-drawn inline SVG), accessible names stay the contract for
e2e, and every change ships with tests and before/after screenshots.

### Phase 1: quick wins (≤ 1 day each, ~1 week total)

| # | Change | Files | Risk | Test impact |
| --- | --- | --- | --- | --- |
| Q1 | New neutral token set (Harbor light + dark), semantic status colours, AA text tiers, 3:1 input borders. Keep the old names as aliases for one release. | `packages/ui/src/tokens.css`, `apps/desktop/src/styles/app.css` (@theme) | Low: visual only | None functional. Refresh screenshots. |
| Q2 | Sentence case + Plex Sans: drop `text-transform`/tracking from `.m-display`, `.m-micro`, `.btn`, `.chip`, `.tree-folder`, `dt`, headers. Remove Chakra Petch imports. | `primitives.css`, `deck.css`, `credentials.css`, `tools.css`, `kube.css`, `remote.css`, `vsphere.css`, `import.css`, `airlock.css`, `tokens.css` | Low | None: names come from DOM text, and CSS casing does not change the accessible name. Check `toHaveTextContent` with caps: none found. |
| Q3 | Remove the decoration: scanlines, deck grid, reticle SVG, `.m-hud::before` brackets (keep the class as a plain border), `deck-open`, `pop-in` brightness, the tree "live link" line, the palette stagger | `deck.css`, `primitives.css`, `airlock.css`, `Workspace.tsx` (EmptyState), `VaultGate.tsx` | Low | `querySelector(".deck")` in one test stays (class kept). |
| Q4 | Status vocabulary: `StateDot` → round dot with `ok/wait/err/neutral`. `.chip[data-tone]` gains `success/warning/danger/info`. Map "waiting for you" → warning, failures → danger. | `packages/ui/src/MooringLine.tsx`, `primitives.css`, `deck.css`, `kube/podStatus.ts` | Low | Unit tests that assert `data-state`/`data-tone` values need the new tone names (kube pod status tests). |
| Q5 | Real switch control (`Toggle.tsx` already has `role="switch"`, so this is restyle only) | `settings/Toggle.tsx`, `tools.css` | Low | None (`getByRole("switch")` unchanged). |
| Q6 | Button hierarchy: filled primary, bordered secondary, subtle, danger-as-text. Sizes 24/28/36. | `primitives.css` | Low | None. |
| Q7 | Show the inspector only in the workspace view | `Shell.tsx` | Low | e2e `getByRole("complementary", { name: "Details" })` is used only from the workspace. Verify the a4 flows. |
| Q8 | Status bar: plain words ("Vault unlocked · 2 sessions · Audit chain verified"), build info moved to About | `Telemetry.tsx`, `deck.css` | Low | `Telemetry.test.tsx` text assertions change. |
| Q9 | Theme moves to Settings → Appearance (System/Light/Dark) and the palette ("Switch theme") | `Shell.tsx`, new `settings/AppearanceCard.tsx`, `stores/ui.ts` (add `system`) | Low–med | `ui.test.ts` toggle test extends to a 3-state setting. Nothing in e2e uses the title-bar toggle. |

### Phase 2: medium (2–5 days each, ~3 weeks)

| # | Change | Files | Risk | Test impact |
| --- | --- | --- | --- | --- |
| M1 | Navigation rail. Credentials, Audit and Settings take the full width. Title bar = vault, search, sync, help, Lock. | `Shell.tsx`, `deck.css`, `stores/ui.ts` | Med: layout and shortcuts | Keep `nav[aria-label="Views"]` and the button names "Credentials", "Audit log", "Settings" (the rail label may say "Audit" with `aria-label="Audit log"`). "Back to sessions" (settings.test.tsx:112, credentials, audit) becomes the rail's Hosts item: update 3 tests or keep a visually hidden button. |
| M2 | Session header: breadcrumb, mono host, status pill with timer, segmented view switch, window actions | `SessionToolbar.tsx`, `Workspace.tsx`, `remote/RemoteSessionTab.tsx`, `web/WebSessionTab.tsx`, `deck.css`, `remote.css` | Med | `toolbar "Session tools"` stays. Tool buttons keep their names and `aria-pressed`. "Detach to window" → "Open in new window" changes `detach.test.tsx:34` and the e2e flows. Keep the old name or update both. |
| M3 | Tree: protocol icons replace pips, status dot, folder icon + count, filter field, "New" split button | `tree/TreeRowView.tsx`, `tree/Sidebar.tsx`, `packages/ui/src/ProtocolPip.tsx` (→ `ProtocolIcon`), `deck.css` | Med | Treeitem names (`"web01, web01.example.test"`) must not change. The pip `aria-label` moves to the icon. |
| M4 | Inspector tabs (Properties / Network / History placeholder) | `inspector/Inspector.tsx`, `NetworkCard.tsx` | Med | e2e `region "Network"` lives under a tab now. Flows must click "Network" first (a4 e2e, network.test.tsx). |
| M5 | Data table primitive (sticky header, sortable, keyboard row selection), used by Audit, Credentials list, Files, Kubernetes pods, vSphere | new `packages/ui/src/DataTable.tsx` + css, `audit/AuditView.tsx`, `credentials/CredentialsView.tsx`, `sftp/RemotePane.tsx`, `kube/ClusterBrowser.tsx` | Med–high: many views | Use `role="grid"`/`table` with `row` names equal to the current ones. Kube e2e `getByRole("row", { name: /pod/ })` must keep matching. The credential list changes from list to table, so `credentials.test.tsx` queries change. |
| M6 | Settings with section nav and search; one page per section; autosave or a page-level dirty bar | `settings/SettingsView.tsx`, cards → pages, `tools.css` | Med | Card headings keep their ids (`autolock-title` and the rest, used by `openSettingsCard`). Settings tests query by heading. Add a nav click step. |
| M7 | Toasts with status icon, title + detail; inline status strips replace the floating "Link lost" box | `Toasts.tsx`, `Workspace.tsx`, `remote/ConnectionBanner.tsx`, `deck.css` | Low | `role="status"` unchanged. Reconnect button name unchanged. |
| M8 | Confirmation dialogs (host key, certificate, expose forward, install update): one pattern with mono fingerprint well, primary "Trust and connect", secondary "Cancel" | `terminal/PromptModal.tsx`, `remote/CertificateTrustDialog.tsx`, `forwards/*`, `settings/UpdatesCard.tsx`, `dialogs/Modal.tsx` | Med: security UX | Button names ("Trust and connect", "Reject and disconnect") are e2e contracts. Keep them. Security-reviewer sign-off required. |

### Phase 3: large (1–2 weeks each)

| # | Change | Files | Risk | Test impact |
| --- | --- | --- | --- | --- |
| L1 | Connection dialog with left section nav (General, Sign-in, Gateway, Display, Advanced), protocol as radio cards, inline validation with an error summary in the footer, "Create and connect" | `dialogs/ConnectionDialog.tsx`, `dialogs/options/*`, `credentials/CredentialPicker.tsx` | High: largest form | e2e `addConnection` uses labels Name/Host/Folder + "Create connection". Keep them. The protocol select becomes a radiogroup, so `dialogs.test.tsx` and e2e that pick a protocol change. |
| L2 | Credentials as list table + detail page with tabs (Overview, Used by, Audit); editor as a side sheet | `credentials/*`, `credentials.css` | High | `credentials.test.tsx`, `returnFlow.test.tsx`, `connection.test.tsx` and the a4 e2e change their queries. The `[data-secret]` assertion stays (no secret in the DOM). |
| L3 | Command palette as the hub: actions, settings pages, recent items; per-row shortcuts | `CommandPalette.tsx`, `lib/fuzzy.ts`, `lib/shortcuts.ts` | Med | New tests for action results. Existing connection results unchanged. |
| L4 | Audit log: filters (event type, connection, time), row detail drawer with structured fields, CSV/JSON export through a Rust command | `audit/AuditView.tsx`, `lib/ipc.ts` (export, rust-core first) | Med | New. Chain-status assertions keep `role="status"`. |
| L5 | Unopened-connection "ready" page and RDP/VNC canvas centring on a neutral surface | `Workspace.tsx`, `remote/RemoteCanvas.tsx`, `remote.css` | Low–med | e2e that double-click a row still open a session. The page adds a "Connect" button with the same name as the inspector one: scope queries. |

**Order:** Q1–Q9 in one PR series (no behaviour change, screenshots only). Then M1 + M3 together
(the shell), then M2/M4/M7/M8, then M5 + L2 (tables), M6, L1, L3, L4, L5. Each PR updates the e2e
names it touches in the same PR (qa-engineer owns `apps/desktop/e2e/**`).

## 8. Accessibility checklist (exit gate for each phase)

- [ ] Text contrast ≥ 4.5:1 (≥ 3:1 for 18 px+/14 px bold) in both themes. Run the token pairs
      through a contrast check in CI (a script over `tokens.css`).
- [ ] Non-text contrast ≥ 3:1 for input borders, focus ring, switch track and selected tab indicator.
- [ ] No text below 11 px. Body 13 px, tables 13 px, captions 12 px.
- [ ] State is never colour-only: every dot has a label, tooltip or `aria-label`, and pills carry text.
- [ ] Visible focus on every control: a 2 px accent ring with a 2 px surface gap, never removed.
      Tree and table rows use an inset ring.
- [ ] Full keyboard paths: rail (Ctrl+1…4), tree (arrows, type-ahead), tabs (Ctrl+Tab, Ctrl+W),
      palette (Ctrl+K), dialogs (Esc closes, Enter submits, focus trapped and returned).
- [ ] Roles: `tree`/`treeitem`, `tablist`/`tab`/`tabpanel`, `grid` or `table` with sortable
      `aria-sort`, `switch`, `alertdialog` for trust prompts, `status` for toasts.
- [ ] Errors: field-level text linked with `aria-describedby`, and a footer summary that moves focus to
      the first invalid field.
- [ ] `prefers-reduced-motion`: no animation beyond opacity. `prefers-contrast: more` raises
      borders and the lowest text tier (in `harbor.css`).
- [ ] The terminal keeps its own theme, with user-selectable contrast and font size in Appearance.
- [ ] Hit targets ≥ 24×24 px (WCAG 2.5.8). Icon buttons are 28 px.
- [ ] No Turkish strings. All copy in plain English, sentence case.

## 9. Decisions for the owner

**Decided 2026-11-07 (owner):** 1 → **A, neutral blue**; 2 → **left rail**; 3 → the site, README
art and app icon follow the new look; 4 → ships **with v0.2.0** (A5 wave W4, after the A5 feature
waves, so new screens are built once in the new system). The 2026-11-03 sci-fi direction is
retired.

Original questions:

1. A (neutral blue) or B (Mooring teal) as the accent.
2. Rail vs. top tabs for primary navigation (the proposal uses the rail; JetBrains, Teams and
   VS Code users expect it).
3. Whether the site, README art and app icon follow the new look (only needed for A).
4. Whether Phase 1 ships in 0.1.2 or waits for 0.2.0 with the rest.
