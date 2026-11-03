# Architecture Decision Records

Mooring records significant design decisions as ADRs in [`docs/adr/`](../adr/). They are the
reference for reviewers and the reason behind code that might otherwise look arbitrary.

## When an ADR is required

- A new crate, protocol or session type.
- Any change to cryptography, the vault format or key handling.
- A change to the storage schema that needs a migration.
- A new or changed IPC command, capability, CSP or window.
- A new dependency in a security-relevant position, or an exception to a rule
  (for example `unsafe`).
- A trade-off that leaves an accepted risk.

Small fixes and refactors do not need one.

## Format

File name: `docs/adr/NNNN-short-title.md`, numbered sequentially. Sections:

```markdown
# ADR-NNNN: Title

Status: Proposed | Accepted | Superseded by ADR-MMMM · YYYY-MM-DD (Phase …)

## Context
## Decision
## Alternatives considered
## Security consequences
## Test plan
```

Keep it short and concrete: interfaces, limits, error codes, file names. Cite sources when the
decision follows other tools or standards (see [ADR-0009](../adr/0009-credential-model.md)).

## Lifecycle

1. **Proposed** — opened as a pull request, usually by the architect role, before
   implementation starts.
2. **Reviewed** — the security reviewer checks the *Security consequences* and *Test plan*;
   implementers check feasibility.
3. **Accepted** — merged. Implementation PRs reference it.
4. **Amended** — small corrections found during implementation or review are added in place
   with a note ("amended after security review 2"). Larger changes get a new ADR that
   supersedes the old one.

An implementation that diverges from an accepted ADR needs the ADR amended in the same pull
request.
