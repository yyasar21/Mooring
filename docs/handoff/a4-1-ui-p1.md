# A4.1 · ui-engineer · P1: portable build badge (ADR-0021 §1–2, UI contract of `a4-1-rust-core-p1.md`)

Worktree `agent-ac6afef14a8b43af7`, branch `worktree-agent-ac6afef14a8b43af7`. Only
`apps/desktop/**` touched; no manifest, lockfile, `src-tauri/` or `packages/ui` change (the two
new CSS rules live in `apps/desktop/src/styles/tools.css` next to the About rules and use the
existing tokens only). `invoke()` is still called from `lib/ipc.ts` alone.

## Done

| Area | What |
| --- | --- |
| **DTOs** (`lib/ipc.types.ts`, `lib/ipc.types.update.ts`, `lib/ipc.decode.update.ts`) | `AppInfo.portableDataDir: string \| null` (all keys camelCase as before; `app_info` is passed through untouched by the Tauri transport). `UpdateManualReason` gains `"portable"`; the wire decoder accepts it (an unknown reason still drops to `undefined`). |
| **Mock** (`lib/ipc.mock.update.ts`, `lib/ipc.mock.ts`) | `MockTransport.portableDataDir` knob (default `null`), reported by `appInfo()`. `updateSettingsSet({ backgroundCheck: true })` in portable mode → `IpcError("update.manual_only", "portable build: download the new zip and replace the folder")`, audited `update.refused { code }`, nothing stored; `false` accepted; `updateCheck` unchanged. `PORTABLE_MANUAL_TEXT` exported so tests pin the UI text to the Rust message. |
| **`components/settings/PortableLine.tsx`** (new) | One line "Portable build — data in `<path>`": monospace path (`about-link-url`, selectable, `title` for the full path), Copy button (`aria-label="Copy portable data folder path"`, flips to "Copied" for 1.8 s, sr-only status "Path copied."), quiet when the clipboard is unavailable. Same pattern as the About links; no `<a>`, nothing opens a file manager. Exports `PORTABLE_UPDATE_TEXT`. |
| **About** (`AboutCard.tsx`) | Renders `PortableLine` under the head when `info.portableDataDir` is non-null; absent otherwise. |
| **Settings → Updates** (`UpdatesCard.tsx`) | Same line above the status/notice area when portable. The background toggle is disabled, shown unchecked, and its hint becomes `PORTABLE_UPDATE_TEXT`; the handler is therefore never reached (no `update_settings_set` round trip, no `update.refused` row). `MANUAL_REASON_TEXT.portable = PORTABLE_UPDATE_TEXT`, so a manual-mode offer with `manualReason: "portable"` shows that text plus the copyable release link. "Check for updates" stays enabled. |
| **Audit viewer** (`audit/AuditView.tsx`) | `EVENT_LABEL` gains `app.start` → "Application started" (the `portable: true` detail renders through the existing details column) and `portable.acl_unavailable` → "Portable data folder: owner-only ACL could not be applied (FAT/exFAT or policy)". |
| **Styles** (`styles/tools.css`) | `.portable-line` (grid `auto / 1fr / auto`, `--line-strong` border on `--bg-sunken`, `--row-h`) and `.portable-line-label`; dark and light themes use tokens only. |

## Left open

- **Screenshots**: no WebView/Playwright toolchain in this Linux container, so no screenshot of
  the two cards in portable mode is attached; the mock knob (`mock.portableDataDir = "<path>"`)
  makes it a one-line change in `make dev` with the mock transport if qa wants one.
- `stores/errors.ts` `FRIENDLY["update.manual_only"]` still says "managed by a package manager or
  Homebrew". The portable UI never reaches it (toggle disabled; manual offers use
  `MANUAL_REASON_TEXT`), so it was left alone to keep the change small; if Rust ever emits
  `update.manual_only` to a portable UI through another path the generic text would be wrong.
- The label text "portable build: download the new zip and replace the folder" is used verbatim
  (lower-case, as the Rust message); the other `MANUAL_REASON_TEXT` entries are full sentences.
  Kept verbatim on purpose so the helper, the manual-reason text and the Rust error match.

## Decision needed

- None.

## Test evidence

```
Linux x86_64, 2026-11-07, worktree agent-ac6afef14a8b43af7 (node_modules symlinked from the main checkout, no second install)

pnpm typecheck   → tsc -b --noEmit: Done (packages/ui, apps/desktop)
pnpm lint        → eslint src: Done, 0 problems
pnpm test        → Test Files 72 passed (72) · Tests 554 passed (554)   (was 71 / 549)
pnpm build       → tsc -b && vite build: ✓ built

New / extended tests (all pass):
  lib/ipc.update.test.ts
    decodeUpdateInfo accepts manualReason "portable", drops an unknown reason
    "ADR-0021: a portable build reports its data folder, refuses the background opt-in and still checks on demand"
  components/settings/about.test.tsx
    "shows the portable line with a copyable path only in a portable build" (absent → present, copy, Copied, status, no <a>)
  components/settings/updates.test.tsx
    manual-mode loop now includes "portable" (reason text + release link)
    "ADR-0021: a portable build shows the data folder, disables the background toggle with the zip hint and still checks"
    "not portable: no portable line and the toggle keeps its own hint"
  components/audit/audit.test.tsx (new)
    app.start → "Application started" + "portable: true"; portable.acl_unavailable → ACL label
  src/lint.n11.test.ts (existing) still asserts invoke() only in lib/ipc.ts
```
