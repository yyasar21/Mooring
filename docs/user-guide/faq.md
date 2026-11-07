# Frequently asked questions

## Is Mooring free?

Yes. Mooring is open source under the [MIT License](../../LICENSE). There is no paid tier, no
account and no telemetry.

## Is it ready for production use?

v0.1.0 is the first release: everything in Phase A (vault, SSH, RDP, VNC, web sessions,
Kubernetes, vSphere, Vault / OpenBao references, sync, importers, updater) has passed seven
security reviews and ships with Sigstore-signed checksums and build provenance. It is still a
0.x: installers are not notarized or Authenticode-signed yet, and the established tools do
more. Keep your existing tool alongside it until you trust it.

## Does Mooring send my data anywhere?

No. The vault, database, audit log and trusted host keys stay on your machine. Mooring makes
network connections only to the hosts you connect to. Optional encrypted sync to storage you
choose is planned for Phase A3; it will encrypt on your device before uploading.

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

Keys: paste the private key into an SSH key credential, or rely on your ssh-agent. Importing
from `~/.ssh` with a file picker is planned. `known_hosts`: Mooring reads the OpenSSH format,
so you can copy entries into its own `known_hosts` file while it is closed.

## Can I import from Royal TS, mRemoteNG, Termius or PuTTY?

Importers are planned for v0.1.0 (Phase A4).

## When will RDP, VNC, Kubernetes and vSphere work?

RDP, VNC and web sessions are Phase A2; vSphere and Kubernetes are Phase A3. See the
[roadmap](../roadmap.md).

## Does Mooring support teams or shared vaults?

Not yet. Mooring is a single-user, local-first tool today. Sync and external secret
references (HashiCorp Vault, OpenBao, 1Password, Bitwarden) are planned.

## Why is the app built with AI agents?

Mooring is developed with AI coding agents under human direction, with every change gated by
tests, security scanning and a written security review. See
[AI-assisted development workflow](../developer-guide/ai-assisted-workflow.md).

## How do I report a security problem?

Privately, via GitHub Security Advisories. See [SECURITY.md](../../SECURITY.md).
