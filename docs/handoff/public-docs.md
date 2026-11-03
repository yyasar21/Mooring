# Public docs — documentation / community handoff

Agent: documentation/community · 2026-11-03 · Worktree
`.claude/worktrees/agent-aad9eb324033ffa4b`, branch `worktree-agent-aad9eb324033ffa4b`, base
`b56d8cc`. Not merged.

## Done

| Commit | Files |
| --- | --- |
| `28c474e` | `README.md` (rewritten), `CONTRIBUTING.md`, `SECURITY.md` (policy), `CHANGELOG.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1, verbatim), `.markdownlint.jsonc`, `docs/assets/hero.png` + 6 screenshots |
| `34549ca` | `.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml`, `PULL_REQUEST_TEMPLATE.md`, `CODEOWNERS`, `dependabot.yml`, `FUNDING.yml` |
| `e2f37e7` | `docs/user-guide/` — README, getting-started, vault-and-security, connections-and-credentials (15 ADR-0009 kinds + matrix), ssh, keyboard-shortcuts, audit-log, troubleshooting, faq |
| `47779fa` | `docs/developer-guide/` — README, architecture (Mermaid), building (macOS/Windows/Linux, `age` pin), testing, coding-standards, adr-process, security-review, ai-assisted-workflow, release-process |
| `432ce5d` | `docs/roadmap.md`, `docs/README.md`, `docs/github-setup.md` |

- Status claims follow the handoffs: SSH, vault, tree, audit viewer ✅; forwarding and SFTP
  "core done, UI pending"; auto-lock, keyring, export 🚧; ADR-0009 typed credentials 🗓; RDP,
  VNC, web, K8s, vSphere 🗓 per roadmap.
- Shortcuts documented from `apps/desktop/src/lib/shortcuts.ts`, tree, palette and tab key
  handlers; UI labels checked against the components.
- Only placeholders (`example.test`, `<your-host>`, `<install-dir>`); grep for lab names, IP
  ranges and the old repo URL in my files is clean.
- markdownlint clean with the new `.markdownlint.jsonc` (line length 100, tables and code
  exempt, MD033 off). All files under 500 lines (README 246). YAML parses.

## Left open

- `docs/release.md` is linked from README, user guide, docs index and release-process; the
  release-engineer creates it. Install commands in README (`brew install --cask
  yyasar21/mooring/mooring`, file names `Mooring_<version>_…`) are assumptions — align with
  docs/release.md.
- README badges reference `ci.yml`, `security.yml`, `test-vectors.yml`; the release badge
  shows "no releases" until v0.1.0.
- Comparison table (Royal TS, RDM, mRemoteNG, Termius) is from general knowledge, dated
  "November 2026"; worth a spot check against vendor sites before launch.
- `CHANGELOG.md` will need an update when ADR-0009 or forwarding/SFTP IPC lands.
- Screenshots come from the mock backend (stated in the README). A real-app screenshot after
  `make dev` on macOS would be better for launch.
- `docs/assets/social-preview.png` (1280×640) not created — guidance in github-setup §2.

## Decision needed

- Out-of-scope edit for the orchestrator to accept: `SECURITY.md` is owned by
  security-reviewer; I kept all original content and added supported versions, reporting
  steps, timeline, scope and optional PGP. Security reviewer should sign off.
- `.markdownlint.jsonc` is a new root file (lint config for docs).
- Code of Conduct contact: email on the @yyasar21 profile. Owner should confirm a public
  contact email exists there, or replace with a dedicated address.
- Keep or delete `.github/FUNDING.yml`.

## Test evidence

```text
markdownlint README.md CONTRIBUTING.md SECURITY.md CHANGELOG.md CODE_OF_CONDUCT.md \
  .github/PULL_REQUEST_TEMPLATE.md docs/user-guide docs/developer-guide \
  docs/roadmap.md docs/README.md docs/github-setup.md            → no findings
python yaml.safe_load on .github/**/*.yml                         → all parse
relative-link check over the new docs                             → only docs/release.md missing (expected)
```
