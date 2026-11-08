# Frequently asked questions

## Is Mooring free?

Yes. Mooring is open source under the [MIT License](../../LICENSE). There is no paid tier, no
account and no telemetry.

## Is it ready for production use?

v0.1.0 was the first release (Phase A: vault, SSH, RDP, VNC, web sessions, Kubernetes,
vSphere, Vault / OpenBao references, sync, importers, updater). 0.2.0 adds jump hosts, RD
Gateway, security keys and smart cards, biometric unlock, backups, dynamic secrets, 1Password
and Bitwarden, and a new interface, after a ninth security review. Releases ship with
Sigstore-signed checksums and build provenance. It is still a 0.x: installers are not notarized
or Authenticode-signed yet, and the established tools do more. Keep your existing tool
alongside it until you trust it.

## Does Mooring send my data anywhere?

No. The vault, database, audit log and trusted host keys stay on your machine. Mooring makes
network connections only to the hosts and secret managers you configure, and to the GitHub
release page when you check for updates. Optional vault sync to S3-compatible storage you
choose encrypts on your device before uploading. There is no telemetry.

## What happens if I forget my master password?

Your secrets cannot be recovered — not by you, not by the developers. Inventory metadata
(names, hosts, tags) is readable in the database, so you can rebuild the tree, but the
passwords and keys are gone. Use a password manager or a written copy kept somewhere safe.

## Why Argon2id and XChaCha20-Poly1305?

Argon2id is the current recommendation for password hashing: it is slow and memory-hard, so
guessing on GPUs is expensive. XChaCha20-Poly1305 is a modern authenticated cipher whose long
random nonces remove the risk of nonce reuse. Both come from the audited RustCrypto project.
See [ADR-0002](../adr/0002-vault-cryptography.md).

## Why are hostnames not encrypted?

So the tree, search and credential inheritance work, and because encrypting the whole
database would duplicate the vault's per-field encryption with a second, C-based crypto stack.
The trade-off is documented as risk R-INV in the [threat model](../security/threat-model.md).
Use full-disk encryption on your device.

## Can I use my existing `~/.ssh` keys and `known_hosts`?

Keys: paste the private key into an SSH key credential, or rely on your ssh-agent; FIDO2
security keys and PIV smart cards work through the agent too
([guide](security-keys-and-smart-cards.md)). The `~/.ssh/config` importer brings your hosts
and, from your own `~/.ssh`, their key files. `known_hosts`: Mooring reads the OpenSSH format,
so you can copy entries into its own `known_hosts` file while it is closed.

## Can I import from Royal TS, mRemoteNG, Termius or PuTTY?

Yes, and from Remote Desktop Manager, `~/.ssh/config` and LDAPS directories. See
[Importing connections](importing.md).

## Can I reach hosts behind a bastion or an RD Gateway?

Yes. Any connection can go through up to three SSH [jump hosts](jump-hosts.md), and RDP
connections can use an [RD Gateway](rd-gateway.md).

## Does Mooring support teams or shared vaults?

Mooring is a single-user, local-first tool. Encrypted vault sync lets several devices share one
vault, and [external secret references](external-secrets.md) (HashiCorp Vault, OpenBao,
1Password Connect, Bitwarden Secrets Manager) let a team keep shared secrets in its own secret
manager.

## Why is the app built with AI agents?

Mooring is developed with AI coding agents under human direction, with every change gated by
tests, security scanning and a written security review. See
[AI-assisted development workflow](../developer-guide/ai-assisted-workflow.md).

## How do I report a security problem?

Privately, via GitHub Security Advisories. See [SECURITY.md](../../SECURITY.md).
