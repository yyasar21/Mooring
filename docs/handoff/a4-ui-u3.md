# A4 · ui-engineer · U3: app icon and About/brand polish (ADR-0018 §5 "icons")

Worktree `agent-ab30f63cf44b1737e`, branch `worktree-agent-ab30f63cf44b1737e`, from `a4` @ `351e30c`.
Not merged. No cargo, no manifest or lockfile change, no capability change. `src-tauri/icons/*` are
generator output of `packaging/icon.svg` (release-engineer's script, run unchanged).

## Done

| Commit | What |
| --- | --- |
| `55fa1fb` | **Icon.** `packaging/icon.svg` (1024², 4.4 KB, flat vector: gradients + one clipPath, no filters, no raster, no fonts): a mooring bollard seen from the quay, the line made fast around its neck. The loop is the tokens' electric cyan (`#29e6f2`, `--accent`) with a brighter core and two soft halos, so the mark reads as "secured" and "connected" at once; the plate is the console ground (`#10212c → #03070a`) with a faint cyan haze and two range rings, rx 224 on a 960 inset (same framing as before). At 16 px the cap, post and the bright ring still read (see sheet). `packaging/icon-mono.svg` (1.4 KB): the same silhouette in one ink, no plate, the loop-over-post gap cut by a mask (never a painted white), ready as a macOS template / tray image. No `icon-maskable.svg`: `tauri icon` does not consume one and the Store logos it writes already keep the plate's transparent corners. `scripts/release/gen-icons.sh` run: `icon.icns` (258 KB), `icon.ico` (33 KB), `icon.png`, `32x32`, `64x64`, `128x128`, `128x128@2x`, the nine `Square*Logo.png` and `StoreLogo.png` regenerated; resvg (Tauri CLI) and librsvg render it identically. Contact sheet `docs/handoff/img/a4-ui/31-icon-sheet.png`: 512 / 128 / 32 / 16 (plus 4× and 8× pixel blow-ups) and the mono mark at 128 / 22 (4×), on `--bg` dark and light. |
| `1bcb5cd` | **BrandMark** (`packages/ui/src/BrandMark.tsx`, exported): the icon geometry as an inline two-ink glyph — post in `currentColor`, loop and line in `var(--accent)`, the crossing cut by an SVG mask with a `useId` id so it sits on any surface. `aria-hidden` unless a `title` is given (then `role="img"`). Replaces the placeholder hexagon in the title-bar wordmark (`Shell.tsx`; `.wordmark svg` ink is now `--text`, the loop carries the accent) and sits beside the airlock kicker (`VaultGate.tsx`, `.airlock-brand`, the one place it glows at rest). `apps/desktop/public/favicon.svg` = the master icon, linked from `index.html` (`<link rel="icon" type="image/svg+xml">`), so the dev/e2e browser and Linux WMs that read the page icon show it; the bundled window icon stays `src-tauri/icons`. |
| `7e6cd5d` | **Settings → About** (`settings/AboutCard.tsx`, last card): the icon (`/favicon.svg`, 72 px), the name from `app_info`, `versionLine(info)` = "Version 0.1.0 for macOS (aarch64)" (+", debug build"; "Version unknown" before boot), a one-line tagline, three links — Source code, Security policy, User guide (`ABOUT_LINKS`, all under `github.com/yyasar21/Mooring`) — each as text plus a **Copy** button (`navigator.clipboard.writeText`, "Copied" for 1.8 s, `role="status"` "Link copied."; a refused clipboard leaves the button at "Copy" and says nothing), then Licence (MIT), Telemetry ("None. … The only request it makes on its own is the update check, and only if you turn it on." — matches ADR-0018's updater opt-in) and Vault (Argon2id, XChaCha20-Poly1305, hash-chained audit). No `<a>` anywhere: the main window has no opener capability and Rust blocks off-origin navigation, so a real link would do nothing. |

Screenshots (`docs/handoff/img/a4-ui/`, 1440×860, `vite dev` + `e2e/boot.html`, system Chrome through
the `playwright` library): `32-airlock-{dark,light}`, `33-about-{dark,light}` (Settings scrolled to the
card), `34-about-card-{dark,light}` (element shots).

## Tests (5 new, 445 → 450)

`components/settings/about.test.tsx`: name + version from the mock `app_info` ("Version dev for browser
(mock), debug build"), icon `src`, MIT and no-telemetry lines; the three links in order, under the
repository, no `link` role rendered, Copy writes the exact URL and flips to "Copied" with the status
line; a rejecting clipboard stays quiet; About is the last `region` of `SettingsView`; `versionLine`
for null / macOS / Windows debug / unknown OS.

## Left open

- **Opening the About links in the browser** needs an audited `open_url` command (security review 2
  M-4 already asked for one for OSC 8 links; rust-core + security-reviewer, no opener plugin
  permission in the main capability). Until then the card copies the URL. `ABOUT_LINKS` is a
  constant; swapping Copy for an open action is a one-line change per row.
- The macOS template image (`icon-mono.svg`) is not wired anywhere yet (no tray in Phase A).
- The Store logos are the plate on transparent corners; if a Windows Store submission ever wants a
  full-bleed tile, run the generator on a variant with the plate at `rx="0"` and no inset.
- Playwright's own Chromium download is blocked in this sandbox; the screenshots used
  `/usr/bin/google-chrome` as `executablePath`. QA's `make e2e` is unaffected.

## Decision needed

- The icon is the first non-placeholder mark; say if the plate should be lighter (`--surface-raised`)
  for the light-theme Dock/taskbar, or if the line should enter from the right instead (RTL of the
  loop) — both are coordinate edits in `packaging/icon.svg` plus a rerun of `gen-icons.sh`.

## Test evidence

```
Linux x86_64, 2026-11-06, worktree agent-ab30f63cf44b1737e @ 7e6cd5d
pnpm typecheck ok (packages/ui, apps/desktop) · pnpm lint ok · pnpm test 60 files, 450 passed
pnpm build ok (index 328 kB, css 100.6 kB, favicon.svg in dist, no chunk warning)
scripts/release/gen-icons.sh ok (17 files in src-tauri/icons, android/ios removed)
packaging/icon.svg 4367 B · packaging/icon-mono.svg 1429 B
```
