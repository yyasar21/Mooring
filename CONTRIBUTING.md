# Contributing to Mooring

Thank you for your interest in Mooring. Bug reports, documentation fixes, tests and code are
all welcome. This guide explains how to propose a change and what reviewers look for.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- **Security issues** go through private reporting, never a public issue. See
  [SECURITY.md](SECURITY.md).
- **Bugs and feature requests**: open an issue with the matching template. Search existing
  issues first.
- **Questions and ideas**: use [GitHub Discussions](https://github.com/yyasar21/Mooring/discussions).
- **Larger changes** (a new protocol, a crypto or storage change, a new dependency, a change to
  the IPC surface): open an issue or discussion first. These usually need an
  [Architecture Decision Record](docs/developer-guide/adr-process.md) before code.

## Development setup

Follow the [build guide](docs/developer-guide/building.md) for your OS, then:

```bash
make setup   # once per machine
make dev     # run the app with hot reload
make check   # everything CI runs: fmt, clippy, tests, cargo-deny, cargo-audit, eslint, tsc, vitest, gitleaks
```

`cargo test --workspace --exclude mooring-app` runs the pure Rust crates on any machine without
the WebView toolchain. See [testing](docs/developer-guide/testing.md) for the full matrix.

## Ground rules

These are non-negotiable and enforced in review and CI. The full list is in
[coding standards](docs/developer-guide/coding-standards.md).

1. **Secrets never reach the UI, logs, errors, tests or git.** The frontend handles credential
   IDs only. Do not paste real hostnames, usernames or keys into issues, tests or fixtures; use
   `example.test` and generated test keys.
2. **No `unsafe`.** Every crate has `#![forbid(unsafe_code)]`. An exception needs an ADR.
3. **No new dependency without justification.** State in the PR why it is needed, its license
   and maintenance status. Crypto comes only from RustCrypto, `ring` or `rustls`. Never roll
   your own crypto.
4. **Untrusted input is capped and tested.** Parsers of data from servers or files need size
   limits, property tests and a fuzz target.
5. **Every behaviour change ships with a test.**
6. **Every Tauri command validates its input** and returns `IpcError { code, message }` with
   no secret material.
7. **Only `apps/desktop/src/lib/ipc.ts` calls `invoke()`.** CI enforces this.
8. **Files stay under 500 lines.** Prefer editing an existing file over adding a new one.
9. **English** for code, comments, commit messages and documentation.

## Branches, commits and pull requests

- Branch from `main`. Keep a pull request focused on one change.
- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat`, `fix`, `docs`,
  `refactor`, `test`, `chore`, `perf`, `build`, `ci`, `security`, with an optional scope:
  `fix(ssh): reject server-opened x11 channels`. A `commit-msg` hook checks the format.
- Fill in the pull request template, including test evidence and the security checklist.
- `make check` must be green. CI runs on macOS, Windows and Linux.
- Sign-off is not required. Do not add `Co-Authored-By` trailers for tools.

## Review

Every pull request gets a code review and a security review. The security review follows the
checklist in [security review process](docs/developer-guide/security-review.md): secret flow,
trust boundary, crypto, parsers, dependencies and whether tests prove the security property.
A security **blocker** stops the merge until it is resolved.

## Documentation

- User-facing behaviour: update the [user guide](docs/user-guide/README.md).
- Design decisions: add or amend an ADR in `docs/adr/`.
- Notable changes: add a line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).
- Markdown should pass `markdownlint`.

## Licensing

Mooring is MIT licensed. By submitting a contribution you agree that it is licensed under the
[MIT License](LICENSE).
