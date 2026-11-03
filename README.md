# Mooring

Security-first remote-access manager for macOS, Windows and Linux. Encrypted vault,
connection tree, SSH / RDP / VNC / web / Kubernetes / vSphere sessions in one window.
Rust core (Tauri 2) + React UI.

Status: Phase A0 — skeleton, vault crypto, audit log, UI shell, quality gates, agent team.

```bash
make setup      # once: rust components, cargo tools, pnpm deps, hooks
make dev        # run the app
make check      # everything CI runs (fmt, clippy, tests, deny, audit, eslint, tsc, gitleaks)
```

Start a phase with Claude Code: `/phase A1` (see `.claude/commands/phase.md`, `docs/prompts/`).

Docs: `CLAUDE.md` (rules + team) · `docs/adr/` (decisions) · `docs/security/threat-model.md` ·
`docs/handoff/` (what each agent did).
