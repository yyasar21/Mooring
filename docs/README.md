# Mooring documentation

## For users

- [User guide](user-guide/README.md)
  - [Getting started](user-guide/getting-started.md)
  - [Vault and security model](user-guide/vault-and-security.md)
  - [Connections and credentials](user-guide/connections-and-credentials.md)
  - [SSH](user-guide/ssh.md)
  - [Keyboard shortcuts](user-guide/keyboard-shortcuts.md)
  - [Audit log](user-guide/audit-log.md)
  - [Troubleshooting](user-guide/troubleshooting.md)
  - [FAQ](user-guide/faq.md)
- [Roadmap](roadmap.md)
- [Changelog](../CHANGELOG.md)
- [Release and verification](release.md)

## For contributors

- [Contributing](../CONTRIBUTING.md) and [Code of Conduct](../CODE_OF_CONDUCT.md)
- [Developer guide](developer-guide/README.md)
  - [Architecture](developer-guide/architecture.md)
  - [Building](developer-guide/building.md)
  - [Testing](developer-guide/testing.md)
  - [Coding standards](developer-guide/coding-standards.md)
  - [ADR process](developer-guide/adr-process.md)
  - [Security review](developer-guide/security-review.md)
  - [AI-assisted workflow](developer-guide/ai-assisted-workflow.md)
  - [Release process](developer-guide/release-process.md)

## Security

- [Security policy and vulnerability reporting](../SECURITY.md)
- [Threat model](security/threat-model.md)
- Phase reviews: [A1 review 1](security/a1-review.md), [A1 review 2](security/a1-review-2.md)

## Architecture Decision Records

| ADR | Title |
| --- | --- |
| [0001](adr/0001-tauri-rust-react.md) | Tauri 2 + Rust core + React/TypeScript UI |
| [0002](adr/0002-vault-cryptography.md) | Vault cryptography |
| [0003](adr/0003-trust-boundaries.md) | Trust boundaries and the IPC contract |
| [0004](adr/0004-session-abstraction.md) | Session abstraction |
| [0005](adr/0005-storage.md) | Local storage — SQLite with sealed columns |
| [0006](adr/0006-vault-lifecycle.md) | Vault lifecycle — calibration, auto-lock, keyring wrap, export |
| [0007](adr/0007-ssh-trust-and-algorithms.md) | SSH client — trust, authentication, algorithms |
| [0008](adr/0008-a1-ipc-contract.md) | A1 IPC contract |
| [0009](adr/0009-credential-model.md) | Typed credential model |

## Project records

- [Handoff notes](handoff/index.md) — what each role did, per phase
- [Phase briefs](prompts/) — A1 to A4
- [GitHub repository setup](github-setup.md) — maintainer checklist
