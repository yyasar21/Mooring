# A4 · ui-engineer · site: landing page updated to A1–A3 complete, A4 in progress

Worktree `agent-ab89de0b7e14f05c7`, branch `worktree-agent-ab89de0b7e14f05c7`, from `a4` @ `95a015f`.
Scope `site/**` plus this note and its screenshots. No build step, no dependency, no JS change; the
design system (Chakra Petch / IBM Plex, bridge-console tokens, bezel hero, ruled pillars) is kept.
Source of truth for every status: `README.md` (banner, feature table, comparison), `docs/roadmap.md`,
`CHANGELOG.md`, `docs/user-guide/external-secrets.md`, ADR-0009/0011/0014/0015/0016/0017.

## Done

| Commit | What |
| --- | --- |
| `0ab1c68` | **Brand icon.** `site/favicon.svg` was still the monochrome placeholder bollard; it is now a copy of `packaging/icon.svg`. `favicon-32.png` and `assets/apple-touch-icon.png` re-rendered from it with `rsvg-convert`. The nav mark stays the hexagon glyph the page already used (the app's `BrandMark` glyph is not in `site/`; swapping it is a follow-up if the owner wants the two to match). |
| `ca1a2fa` | **Gallery assets.** Nine A2/A3 handoff screenshots (1440×860 dark) converted with Pillow to the existing pair per shot, `NN-name-dark.webp` (q82) + `-720.webp` (q80): RDP certificate trust, VNC view-only, isolated web session, Kubernetes pods, Kubernetes logs, vSphere import wizard, VM power menu, secret sources + vault sync settings, sync-fork banner. `02-shell-empty` and `06-inspector` removed from the gallery and from `assets/shots/`. Largest file 101 KB (`15-kube-logs-dark.webp`); the thumbnails together add about 150 KB of lazy weight. |
| `ddccac1` | **Content.** Hero status note, `<meta name="description">`, OG/Twitter descriptions and the JSON-LD description now say pre-release, A1–A3 complete (SSH, RDP, VNC, isolated web sessions, read-only Kubernetes, vSphere sync/power/consoles, Vault/OpenBao references, encrypted sync), six security reviews, v0.1.0 in progress. Telemetry strip gains "Reviews: 6 published" linking `docs/security/`. **Why Mooring** keeps seven pillars: per-field AEAD folded into the vault card, the Rust-core card folded into "secrets never reach the UI", the TOFU card now covers RDP/VNC certificates; new cards "Bring your own secret manager (Vault / OpenBao)" (links the user guide and ADR-0016) and "Read-only by construction (Kubernetes, vSphere inventory)" (ADR-0014/0015). **Features**: every `data-status` taken from the README table; A2/A3 lines added in their groups (sync + join under Vault, detach under Organise, RDP/VNC/web details, Kubernetes exec/logs/forward, vSphere wizard/power/consoles, secret references, syslog mirror); a new **Release** group; `data-status="planned" data-phase="A4"` only on importers, network tools, signed installers, updater, Homebrew tap. The odd seventh group spans the row at ≥1000 px (`site.css`, one rule) so the grid has no empty cells. **Credential kinds**: "Seventeen", all 17 marked present (`vault_approle`, `s3_access_key` added), fine print explains the three Vault/S3 kinds. **Download**: a magenta status note says every build before v0.1.0 is a pre-release (unsigned or ad-hoc signed, no updater) and points at the cosign verification in `docs/release.md`. **Comparison**: RDP/VNC and vSphere console "Yes", team sharing "Encrypted multi-device sync (S3)", intro matches the README. **Roadmap**: A0–A3 done with exit dates and review numbers, A4 in progress as a bullet list (new `.bullets` style), "After A4" (FIDO2 `hmac-secret` and biometric unlock factors, jump hosts as connections, dynamic Vault engines, winget), B. **FAQ**: production-readiness, data-leaves-the-machine and the old "when will RDP…" entries rewritten; new "Can Mooring change my cluster or my VMs?" and "Which tools can I import from?". `sitemap.xml` lastmod 2026-11-06. |

Screenshots (`docs/handoff/img/a4-ui/`, Playwright 1.56 library + `/usr/bin/google-chrome`, GitHub API
mocked with a `v0.1.0-rc.3` pre-release and 128 stars): `50-site-dark.png`, `50-site-light.png`
(1440 wide, full page), `51-site-lightbox-dark.png` (gallery dialog on the Kubernetes shot),
`52-site-mobile-dark.png` (390 wide, full page).

## Test evidence

- Own checker (`html.parser` tag balance, unique ids, every `img` has `alt`, every relative
  `href`/`src`/`data-full` exists under `site/`, every `#anchor` has a target, every
  `github.com/yyasar21/Mooring/blob|tree/main/...` path exists in `git ls-tree main`, no file over
  400 KB under `site/`, no Turkish characters apart from the author's name in the copyright and
  JSON-LD): all pass. `lang="en"`, one `h1`.
- `npx html-validate@9.5.5 site/index.html`: 8 findings, all stylistic and all present before this
  change (lower-case doctype, title longer than 70 characters, `aria-label` on `dl`/`ul`, the
  scrollable table region's landmark name, "prefer `<section>`"). No structural errors; the previous
  handoff's vnu run (0 errors) covers the same markup patterns.
- Rendering: no page errors or console errors in dark, light or mobile; mobile `scrollWidth` 390
  (no horizontal scroll); lazy thumbnails load; lightbox opens, captions count "n of 12";
  feature filter buttons still match the three statuses. Colours and fonts are unchanged, so the
  previous contrast figures stand.
- Weight: first load unchanged (HTML 36 KB, CSS 20 KB, JS 10 KB, fonts, hero 46 KB); the twelve lazy
  thumbnails total about 190 KB.

## Left open

- The nav/hero mark is still the hexagon glyph; the app's title bar now uses the bollard `BrandMark`.
  Porting that inline SVG to `site/index.html` and the 404 page is a ten-line change if wanted.
- The A4 Updates card and Network inspector (U2) exist in the app but the page lists updater and
  network tools as planned A4, as directed; flip the two `data-status` values when A4 ships.
- Statuses are still hand-copied from the README (no single source); re-check when the README
  table changes.
- `html-validate`'s stylistic findings could be silenced with a `.htmlvalidate.json` or by
  uppercasing the doctype and trimming the `<title>`; left as they were to keep the diff to content.
- The live GitHub API was not reachable from the sandbox; release and star rendering was checked
  with route mocks only, as in the first site handoff.

## Decision needed

- None. The orchestrator may want a row for this note in `docs/handoff/index.md`.
