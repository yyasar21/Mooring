# pub — ui-engineer handoff: product site on GitHub Pages

Target URL: <https://yyasar21.github.io/Mooring/>. Source: `site/` (plain HTML, CSS and
vanilla JS, no build step). Deploy: `.github/workflows/pages.yml`.

## Research summary: patterns adopted
I looked at RustDesk, Zed, Bruno, Termius, Ghostty (download page), Devolutions RDM, Royal TS and
Warp. The Tabby and Ghostty home pages and the Lapce site served only metadata or redirects to
the fetcher.
1. **Hero = promise + product shot.** All of them lead with one sentence and a real screenshot. Ours uses the keyword-rich sentence as the H1 and the hero in a console bezel.
2. **Two CTAs: download and source.** Zed has "Download now" and "Clone source"; RustDesk and Bruno have "Download" and "Docs". Ours: *Download for <OS>* and *View on GitHub*.
3. **OS detection is rarer than expected.** None of the fetched pages detect the OS on the hero. We do, but quietly: the CTA label, a "your system" tag, and the visitor's platform card sorted first. The other platforms are always visible.
4. **Per-OS download blocks with package-manager lines** (Ghostty: DMG plus "package manager"). Ours: one card per OS, real release assets, the Homebrew command, and winget marked as planned.
5. **Security as a named block, not marketing copy.** Bruno has "Secure & Local / your data never leaves your machine"; Termius has "E2E encryption". Ours is a ruled list of 7 pillars, each linking its ADR.
6. **Open-source proof near the top.** RustDesk and Bruno show star counts. Ours: a Star button with the live count in the nav, and a telemetry strip under the hero (release, stars, license, platforms, core).
7. **Feature grid grouped by area** (Devolutions uses tabs, Royal TS protocol tiles). Ours is grouped by area, with a status badge per line and a status filter, so planned work cannot pass as shipped.
8. **Comparison only where facts allow.** Most vendors avoid one; Devolutions blogs about mRemoteNG. We reuse the README table with its "vendor docs as of Nov 2026" caveat.
9. **Release cadence and timeline** (Devolutions shows versions). Ours is the A0–B roadmap with done, now and planned states.
10. **FAQ before the footer** (Bruno, Devolutions). Seven questions taken from `docs/user-guide/faq.md`.
11. **Closing honesty.** Bruno's "free, open source, no account". Ours is the AI-assisted transparency note.
12. **Footer = project hygiene links:** license, security policy, contributing, code of conduct, Discussions, docs.
13. Skipped on purpose: testimonials, logo walls, user counts, pricing, newsletter. A pre-release has none of these, and inventing them would be dishonest.
14. Skipped: a cookie banner and analytics. The site sets no cookies and has no tracking, which matches the product's "no telemetry".
15. Share cards and JSON-LD `SoftwareApplication`, as every one of these sites has.

## Structure
```
site/
  index.html     one page: nav, hero, Why Mooring (#security), Features, Screenshots (lightbox),
                 Credential kinds, Download (#download), Compare, Roadmap, FAQ, AI note, footer
  404.html       GitHub Pages fallback (absolute /Mooring/ paths)
  css/site.css   tokens copied from packages/ui (bridge console), dark default, light via
                 prefers-color-scheme
  js/site.js     OS detection, stars and releases from api.github.com (sessionStorage cache 10 min),
                 feature filter, <dialog> lightbox
  fonts/         Chakra Petch 500/600, IBM Plex Sans 400/600 (latin + latin-ext 400), Plex Mono 400;
                 woff2 copied from the @fontsource packages already in the lockfile, OFL texts alongside
  assets/        hero.webp, og.png (1280x640, generated from hero.png with Pillow),
                 shots/*.webp (+ -720 thumbnails), apple-touch-icon.png
  favicon.svg    = packaging/icon.svg; favicon-32.png rendered with rsvg-convert
  robots.txt, sitemap.xml, .nojekyll
```
- Design: one loud element (the bezelled hero screenshot with lit corner brackets and a single
  dock-in on load). Everything else uses hairline rules. Cyan means live, available or yours;
  magenta means in progress or pre-release, as in the app. Light mode deepens the accent to
  `#006d78` so accent text passes 4.5:1.
- Release logic: drafts are ignored. The newest non-pre-release is used, else the newest
  pre-release, which is labelled "(pre-release)" with a warning. Assets are matched by the names
  in `docs/release.md` (`.dmg`, `.pkg`, `-setup.exe`, `.msi`, `.deb`, `.rpm`, `.AppImage`),
  ordered by architecture, with their size. A kind missing from a release shows "not in this
  release". With no release, the page says "No release has been published yet. The first one
  will be v0.1.0." When the API fails, it links the Releases page.
- CSP via `<meta>`: `default-src 'self'`, `connect-src https://api.github.com`. There is no
  inline script or style apart from the JSON-LD data block. DOM writes use `textContent` and
  `createElement` only.
- No new package dependency. Fonts are copied files from packages already in the lockfile.

## What the owner must do (Settings)
1. Settings → Pages → Build and deployment → **Source: GitHub Actions**.
2. Merge, then run Actions → **pages** → *Run workflow* (or push any change under `site/`).
3. Settings → Environments → `github-pages`: keep the deployment branch rule at `main` only.
4. About → Website: `https://yyasar21.github.io/Mooring/`, and tick *Use your GitHub Pages website*.
5. Optionally upload `site/assets/og.png` as the repository social preview (Settings → General).
Details and a later custom-domain recipe: `docs/github-setup.md` §7.

## Left open
- **Live API not tested from here.** `api.github.com` returns 403 from this sandbox (the proxy
  does not allow the repository). The release and star fetch was tested with Playwright route
  mocks in four scenarios: stable release, pre-release, empty list and 403. All rendered as
  intended with no JS errors. The first real check happens on the deployed site.
- The comparison table repeats the README's vendor facts (Nov 2026). Re-check them when they
  are edited in the README; the two are not generated from one source.
- Feature statuses are hand-copied from README and roadmap. Update `site/index.html`
  (`data-status`, `data-phase`) when work lands; there is no single source.
- Lighthouse itself was not run (no Lighthouse CLI offline). A manual checklist was used instead (see below).
- `fetchpriority` and `<meta media>` on `theme-color` are flagged by the old vnu bundled with
  `html5validator`. The current vnu 26.11.3 accepts them.
- The light-theme hero swaps in the light screenshot through `<picture>`. The OG image is dark only.

## Decision needed
- Should `docs/handoff/index.md` get a line for this note? The orchestrator owns that file, so I did not edit it.
- Is the Discussions link fine before Discussions is enabled (github-setup §3)? Until then it 404s.

## Test evidence
- HTML: vnu 26.11.3 (`vnu-jar` from npm, run with `--also-check-css`) reports **0 errors** for
  `index.html`, `404.html` and `site.css`. It also prints informational CSP notices that come
  only from the `file://` origin; over HTTP Chrome logs no CSP or console errors.
- Contrast (WCAG, computed): dark body 16.7:1, muted 8.5:1, cyan link 13.2:1, magenta 6.0:1;
  light body 16.3:1, muted 7.0:1, link 6.1:1, accent text 5.6:1, white on accent 6.1:1.
- Manual Lighthouse checklist: one H1 and ordered headings; landmarks (header, nav ×4 labelled,
  main, footer); skip link; alt text on every image; visible focus rings; `aria-pressed` on
  filters; the lightbox is a native `<dialog>` with focus return and arrow keys; no horizontal
  scroll at 390 px (checked in Playwright); fonts are self-hosted woff2 with
  `font-display: swap` and the two critical faces preloaded; the hero image is preloaded with
  explicit width and height (no CLS); gallery images are lazy; first-load weight about 200 kB (HTML, CSS, JS, fonts, hero)
  plus 75 kB of thumbnails; `prefers-reduced-motion` removes the hero animation and smooth scroll.
- 404: an unknown path under `/Mooring/` returns 404 with the styled page (local server test).
- Text check: no Turkish text in the site. The author's name in the copyright and JSON-LD is the only non-ASCII text. No private hosts or addresses; screenshots are the repo's mock-data images.
- Screenshots (Playwright 1.63 with `/usr/bin/google-chrome`, mocked API), in `docs/handoff/img/site/`:
  `desktop-1440-release-top.png`, `desktop-1440-release-full.png`, `desktop-1440-release-lightbox.png`,
  `desktop-1440-prerelease-filter.png`, `desktop-1440-light-release-top.png`,
  `mobile-390-release-top.png`, `mobile-390-release-full.png`, `mobile-390-release-download.png`,
  `mobile-390-none-top.png`.
