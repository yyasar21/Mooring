# A5 · docs refresh: CHANGELOG, README, user guide, site and icon proposal for v0.2.0 (Harbor)

Worktree `/home/claude/nexus/.claude/worktrees/agent-a4ef83770412b0c94`, branch
`worktree-agent-a4ef83770412b0c94`, from `main` @ `faa242f` (Harbor W3 notes). Docs, site and
art only: nothing under `crates/`, `src-tauri/src`, `apps/desktop/src` or `src-tauri/icons`
changed, no cargo run, no manifest or lockfile change. Inputs: roadmap §A5, every
`a5-*.md` handoff, `docs/design/review-2026-11/README.md` §4 and §9 (decision 3), the
after-w1/w2/w3 captures, security review 9.

## Done

### CHANGELOG.md
- `[Unreleased]` (planned 0.2.0) in the existing Keep a Changelog shape: **Added** (jump hosts
  incl. web via SOCKS on Windows/Linux and Kubernetes, biometric unlock, backup export/import,
  dynamic Vault engines + SSH CA certificate role, 1Password Connect, Bitwarden `bws`, FIDO2 SSH
  keys, smart card / PIV, RD Gateway with NTLM channel binding, winget manifests, inert signing
  jobs, ADR-0028 Mooring Dev + Move to Applications + DMG layout, audit filters, Settings
  SSH / known RDG certs / import trust summary), **Changed** (Harbor redesign, Kubernetes IPC
  alignment and 15 s pod poll instead of the never-built watch, 20 credential kinds, `keyring`
  removal, signing secrets out of `build`), **Fixed**, **Security** (review 9 findings M-19,
  L-40, L-47..L-54, N-72..N-75, N-77; threat model; 66 fuzz targets).
- Fixed a pre-existing dead link (`0015-vsphere-sync.md` → `0015-vsphere-integration.md`).

### README.md
- Hero is a `<picture>` (light/dark) of the W3 SSH header + forwards screen; status block,
  "Why Mooring" (secret managers, hardware-backed sign-in, TOFU scope), feature table rebuilt
  for 0.2.0 with **New** markers (also fixes the dead `0011-rdp-vnc-sessions.md` link),
  comparison table gains jump hosts and RD Gateway rows, install table winget row, screenshot
  grid of four Harbor shots, ADR list, "About this project" copy. Badge colour cyan → `#1a5fb4`.
  No sci-fi wording left (grep for bridge/HUD/cyan/magenta/glow/deck: none).
- Images: 6 files in `docs/assets/screenshots/` (`hero-{light,dark}`, `credentials-light`,
  `audit-filters-dark`, `connection-gateway-light`, `smart-card-pin-dark`), 1280 px JPEG q82,
  **484 KiB total**. Removed `docs/assets/hero.png` and the six bridge-console PNGs (≈ 650 KiB).
  `docs/github-setup.md` §2 now points at `site/assets/og.png` for the social preview.

### docs/user-guide
- New: `jump-hosts.md`, `rd-gateway.md`, `security-keys-and-smart-cards.md`,
  `backup-and-restore.md`.
- Updated: `external-secrets.md` (provider table, dynamic engines + lease chip + SSH CA role,
  1Password Connect, Bitwarden `bws` with the four fixed paths and the pin rule, limits),
  `vault-and-security.md` (auto-lock as shipped, Backups → new page, Biometric unlock section:
  auto-disable triggers, signed-build gate, Linux not offered, refused with sync),
  `audit-log.md` (rail, filters, entry drawer, new event rows, syslog mirror exists, no export),
  `getting-started.md` (winget section with the "once listed" caveat and the inert marker,
  macOS Move to Applications, rail / New / side-sheet / ready page instead of the old icons),
  `updates.md` (winget and Mooring Dev rows), `ssh.md` (detach, session header, sk/PIV,
  certificates, forwards and SFTP no longer "in progress"), `connections-and-credentials.md`
  (protocols, jump hosts, newer kinds; dropped the pre-ADR-0009 "three kinds" and "(planned)"
  headings), `keyboard-shortcuts.md` (`mod 1`–`4`, detach), `faq.md` (stale 0.0.x answers),
  `README.md` index; `docs/README.md` index and ADR table (0010–0028).
- macOS web-via is documented as refused, with the SOCKS-forward workaround.

### site/
- Restyled to Harbor A: `css/site.css` rewritten on the shipped AA-tuned tokens (light/dark via
  `prefers-color-scheme`), IBM Plex Sans 400/500/600 + Plex Mono, sentence case, one blue
  accent, e1–e3 elevation; bezel brackets, grid background, glows, diamonds and the dock
  animation are gone. Chakra Petch (2 woff2 + licence) removed;
  `ibm-plex-sans-latin-500-normal.woff2` added from the repo's own `@fontsource/ibm-plex-sans`
  5.3.0 (same OFL licence file).
- `index.html` copy refreshed for 0.2.0 (status, pillars, features with a "New in 0.2" filter,
  20 kinds, winget, comparison rows, roadmap A5 / after A5, FAQ); the nav mark is the in-app
  BrandMark geometry. CSP unchanged; the only off-origin requests are the two GitHub API calls
  that already existed (checked with Playwright: `api.github.com/repos/…` and `/releases`).
- Images: `assets/hero-{light,dark}.webp` and 10 gallery screens × 2 themes × (1440, 720)
  WebP from after-w2/w3 (1.35 MiB); old 12-shot bridge gallery and `hero*.webp` removed. The
  gallery thumbnails use `<picture>` per theme and `js/site.js` opens the matching full image.
  `og.png`, `favicon.svg`, `favicon-32.png`, `apple-touch-icon.png` regenerated in the Harbor
  look (favicon = the icon proposal). `sitemap.xml` lastmod 2026-11-08.

### Icon proposal (`docs/design/review-2026-11/icon/`)
- `icon-harbor.svg` (recommended): flat bollard-and-line mark in `#1a5fb4` on a white plate
  with a `#c9ced4` hairline; same silhouette as `packaging/icon-mono.svg` / BrandMark, no
  gradients, filters, raster or fonts.
- `icon-harbor-blue-plate.svg` (alternative): white mark on a `#1a5fb4` plate.
- `icon-harbor-dev.svg`: the proposal plus the existing orange DEV ribbon (ADR-0028).
- `preview/`: 512 and 128 px PNGs of each, the dev 512 px, and `sheet.png` (128/64/32/16 on
  the light and dark canvases).

## Left open
- `src-tauri/icons`, `src-tauri/icons-dev`, `packaging/icon*.svg` and the in-app BrandMark are
  unchanged (see Decision needed). `packaging/macos/dmg-background.svg` is still navy/teal
  bridge styling; it should follow the icon decision (release-engineer).
- Screenshots come from the mock transport and show "Mooring dev" in the status bar; fine for
  docs, but a release-build capture would read better.
- `docs/developer-guide/*` and `docs/user-guide/troubleshooting.md` / `importing.md` were not
  reviewed for Harbor UI wording (out of the A5 feature list).
- The comparison table rows for jump hosts / RD Gateway reflect public vendor docs as
  understood on 2026-11-08; re-check before the public launch.
- `docs/handoff/index.md` row for this note: orchestrator-owned, not edited.

## Decision needed
1. **Apply the new icon** (owner decision 3 says the icon follows Harbor). Recommended:
   `icon-harbor.svg`. To apply, from the repository root:
   ```sh
   cp docs/design/review-2026-11/icon/icon-harbor.svg     packaging/icon.svg
   cp docs/design/review-2026-11/icon/icon-harbor-dev.svg packaging/icon-dev.svg
   pnpm tauri icon packaging/icon.svg --output src-tauri/icons
   pnpm tauri icon packaging/icon-dev.svg --output src-tauri/icons-dev
   rm -rf src-tauri/icons/android src-tauri/icons/ios
   rm -rf src-tauri/icons-dev/android src-tauri/icons-dev/ios
   ```
   (equivalently `scripts/release/gen-icons.sh all` after the two copies). Then check that the
   `merge-config.py check-identity` icon assertions still pass and update
   `packaging/icon-mono.svg` only if the silhouette changes (it does not in this proposal).
2. Blue plate instead of white plate? The white plate reads calmer next to other enterprise
   apps and matches §4.4 (accent used sparingly); the blue plate is stronger at 16 px.

## Test evidence
- Link check (scratch script: every relative Markdown link target, `src`/`href`/`srcset`, and
  `#anchor` into Markdown resolved against the tree) over README.md, CHANGELOG.md, docs/README.md,
  docs/github-setup.md, docs/user-guide/*.md, this note, site/index.html and site/404.html:
  **0 problems**.
- Bidi / zero-width scan over the same files: none. IPv4 scan: only `127.0.0.1`; host names are
  `example.test`.
- Prose line length ≤ 100 (`.markdownlint.jsonc` MD013) in every line I wrote.
- Site rendered with Playwright (Chromium, served over local HTTP) at 1440×900 and 390×844 in
  light and dark: no console errors, no horizontal overflow, lightbox opens the theme-matching
  image, external requests limited to the two existing GitHub API calls.
