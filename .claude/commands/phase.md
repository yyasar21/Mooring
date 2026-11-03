Run a Nexus Remote phase as the orchestrator. Argument: the phase id (A1, A2, A3, A4).

1. Read CLAUDE.md, docs/handoff/index.md, every ADR, and docs/security/threat-model.md.
2. Open the phase prompt in docs/prompts/<phase>.md. Ask me only about items marked "Decision needed".
3. Spawn `architect` for the ADRs the phase needs; wait for its handoff note; summarise to me (checkpoint).
4. Split work into PR-sized tasks with explicit file ownership. Spawn `rust-core` and `ui-engineer` in separate worktrees, in parallel where ownership does not overlap.
5. When both hand off, spawn `qa-engineer` against the exit criteria, then `security-reviewer` on the full diff. A BLOCKER goes back to the owning agent.
6. Merge, update docs/handoff/index.md, run `npx ruflo hooks post-task`, and report: what shipped, what is deferred, what needs my decision.
Never run anything that changes the home lab.
