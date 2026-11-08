# Mooring documentation

## For users

- [User guide](user-guide/README.md)
  - [Getting started](user-guide/getting-started.md)
  - [Vault and security model](user-guide/vault-and-security.md)
  - [Connections and credentials](user-guide/connections-and-credentials.md)
  - [SSH](user-guide/ssh.md)
  - [Security keys and smart cards](user-guide/security-keys-and-smart-cards.md)
  - [Jump hosts](user-guide/jump-hosts.md)
  - [RD Gateway](user-guide/rd-gateway.md)
  - [External secrets](user-guide/external-secrets.md)
  - [Backup and restore](user-guide/backup-and-restore.md)
  - [Importing connections](user-guide/importing.md)
  - [Updates](user-guide/updates.md)
  - [Network tools](user-guide/network-tools.md)
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
- Phase reviews: [all reviews](security/), from [A1 review 1](security/a1-review.md) to
  [A5 review 9](security/a5-review-9.md)

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
| [0010](adr/0010-a1-exit-ipc.md) | A1 exit — forwarding, SFTP, auto-lock and syslog over IPC |
| [0011](adr/0011-rdp-session.md) | RDP session, certificate trust and the shared frame path |
| [0012](adr/0012-vnc-session.md) | VNC session — own RFB 3.8 client, VeNCrypt and certificate TOFU |
| [0013](adr/0013-web-sessions.md) | Web sessions in isolated windows, and detaching a tab to a window |
| [0014](adr/0014-kubernetes-sessions.md) | Read-only Kubernetes sessions and the shared HTTP client |
| [0015](adr/0015-vsphere-integration.md) | vSphere inventory sync, power actions and VM consoles |
| [0016](adr/0016-external-secrets.md) | External secrets from HashiCorp Vault / OpenBao (KV v2) |
| [0017](adr/0017-vault-sync-and-signin.md) | Vault sync to S3-compatible storage |
| [0018](adr/0018-release-v0-1-0.md) | Release v0.1.0 — signing, updater, SBOM/provenance |
| [0019](adr/0019-importers-and-onboarding.md) | Importers and onboarding |
| [0020](adr/0020-network-tools.md) | Network tools |
| [0021](adr/0021-portable-mode.md) | Portable mode |
| [0022](adr/0022-biometric-unlock.md) | Biometric unlock — Touch ID and Windows Hello |
| [0023](adr/0023-vault-export-import-ui.md) | Vault export and import in the app |
| [0024](adr/0024-fido2-ssh-keys.md) | FIDO2 / hardware-key SSH authentication |
| [0025](adr/0025-jump-hosts.md) | Jump hosts and bastions |
| [0026](adr/0026-dynamic-secrets-1password-bitwarden.md) | Dynamic Vault engines, 1Password Connect and Bitwarden Secrets Manager |
| [0027](adr/0027-rd-gateway-and-smart-card.md) | RD Gateway and smart card / PIV |
| [0028](adr/0028-build-identity-and-macos-install-hygiene.md) | Build identity and macOS install hygiene |

## Project records

- [Handoff notes](handoff/index.md) — what each role did, per phase
- [Phase briefs](prompts/) — A1 to A4
- [GitHub repository setup](github-setup.md) — maintainer checklist
