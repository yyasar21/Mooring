# Mooring — Claude Code configuration

## Project

Security-first cross-platform remote-access manager (Royal TS class) for macOS, Windows and
Linux. Tauri 2 (Rust core) + React 19/TypeScript. Phase A = connection manager; Phase B (later)
= own remote-desktop agent and relay.

```
crates/mooring-core      domain model: Connection, Folder, CredentialId, Session trait (ADR-0004)
crates/mooring-vault     Argon2id + XChaCha20-Poly1305 vault, zeroized keys (ADR-0002)
crates/mooring-audit     hash-chained audit log, secret redaction
crates/mooring-proto-*   ssh (russh) / rdp (IronRDP) / vnc — hostile-input parsers, fuzz targets
src-tauri/             Tauri shell: commands, capabilities, state (ADR-0003)
apps/desktop/          React UI; packages/ui = design tokens + primitives
docs/adr/              decisions · docs/security/ threat model, reviews · docs/handoff/ team notes
```

Build / check: `make check` (fmt, clippy -D warnings, tests, cargo-deny, cargo-audit, eslint,
tsc, vitest, gitleaks). `make dev` runs the app. `cargo test` alone covers the pure crates on any
machine; `mooring-app` needs the platform WebView toolchain.

## Non-negotiable rules

- Secrets never reach the frontend, logs, errors, tests or git. The UI handles credential ids
  only. `.env`, `*.key`, signing material are gitignored; never print them.
- `#![forbid(unsafe_code)]` everywhere (workspace lint). No exception without an ADR.
- No new dependency without a one-line justification in the PR and security-reviewer approval.
  Allowed crypto: RustCrypto, ring, rustls. Never roll your own crypto; parsers for untrusted
  input ship with a fuzz target.
- Every Tauri command validates input and returns `IpcError { code, message }` without secret
  material. Capabilities are least-privilege; CSP strict; remote web content gets its own
  window label + capability (A2).
- Every behaviour change ships with a test. `make check` green on macOS, Windows, Linux before
  a PR. Keep files under 500 lines. Prefer editing over creating.
- Any real infrastructure referenced by `MOORING_LAB_*` is read-only for agents. Never mutate
  external systems (no ansible without --check, no kubectl/oc mutations, no hypervisor writes).
  Real hosts, IPs, accounts and domains never go in the repo: tests use `example.test` and
  RFC 5737 addresses; lab values live only in the local, gitignored `.env`.
- Code, comments, commits in English, Conventional Commits. Chat may be Turkish.
- No documentation files unless asked — ADRs and handoff notes are the exception and mandatory.
- Never add a `Co-Authored-By` trailer unless `.claude/settings.json` sets `attribution.commit`.

## Team and ownership (one writer per worktree; out-of-scope edits are rejected)

| Role | Owns | Never |
| --- | --- | --- |
| orchestrator (main session) | Cargo.toml, package.json, lockfiles, docs/handoff/index.md, merges | writes feature code when a specialist owns it |
| architect | docs/adr/**, interface proposals | writes implementation |
| rust-core | crates/**, src-tauri/src/** | touches apps/ or capabilities without security review |
| ui-engineer | apps/desktop/**, packages/ui/** | calls invoke() outside apps/desktop/src/lib/ipc.ts |
| security-reviewer | docs/security/**, SECURITY.md; veto on every PR | edits source files |
| qa-engineer | tests/**, crates/*/tests/**, apps/desktop/e2e/**, fuzz/**, .github/workflows/{test*,e2e,fuzz-nightly}.yml | weakens a gate |
| release-engineer | .github/workflows/release*.yml, scripts/release/**, bundle config | commits signing material |

Agent definitions: `.claude/agents/<role>.md`. Each agent reads `docs/handoff/index.md` and the
phase's ADRs before starting and writes `docs/handoff/<phase>-<role>.md` when done
(Done / Left open / Decision needed / Test evidence).

## Workflow

ADR → task split → rust-core ∥ ui-engineer (own worktrees, `EnterWorktree`) → qa-engineer →
security-reviewer → orchestrator merges. A security "blocker" stops the PR.

Swarm when: 3+ files, new crate/module, protocol or crypto change, capability change.
Do not swarm for one-file fixes.

Plugins: feature-dev (architecture), code-review + review-council (every PR),
Security Audit Loop + OWASP + finecomb (phase exits), Rust CLI Skills (rust-core),
frontend-design + Design (ui-engineer), playwright + E2E Test Generator (qa),
AgentAvow (new dependencies).

Ruflo: `npx ruflo hooks pre-task` / `post-task` around every task, memory namespace `mooring`,
hierarchical topology, max 8 agents.

## Commands

`make dev` · `make check` · `make test` · `make e2e` · `make fuzz` · `make audit` · `make bundle`
