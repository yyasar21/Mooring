# Mooring user guide

Mooring is a secure remote-access manager: an encrypted vault for your credentials, a tree of
connections, and sessions in tabs. This guide describes 0.2.0 (Phase A5: jump hosts, RD
Gateway, security keys and smart cards, biometric unlock, backups, dynamic secrets, 1Password
and Bitwarden, and the Harbor interface). Features marked *planned* are on the
[roadmap](../roadmap.md).

1. [Getting started](getting-started.md) — install or build, create the vault, first SSH
   connection.
2. [Vault and security model](vault-and-security.md) — what is encrypted, how locking works,
   biometric unlock, what Mooring protects against and what it does not.
3. [Connections and credentials](connections-and-credentials.md) — folders, inheritance,
   overrides, search, credential kinds and which protocol accepts which credential.
4. [SSH](ssh.md) — host-key verification (TOFU), authentication, ssh-agent, port forwarding,
   SFTP, supported algorithms.
5. [Security keys and smart cards](security-keys-and-smart-cards.md) — FIDO2 `sk-*` keys and
   PIV cards through ssh-agent, touch prompt, PIN dialog.
6. [Jump hosts](jump-hosts.md) — reach hosts through up to three SSH bastions, for SSH, RDP,
   VNC, Kubernetes and (on Windows and Linux) web sessions.
7. [RD Gateway](rd-gateway.md) — RDP through a Remote Desktop Gateway, certificate trust,
   NTLM and Basic.
8. [External secrets](external-secrets.md) — HashiCorp Vault / OpenBao (KV v2 and dynamic
   engines), 1Password Connect and Bitwarden Secrets Manager, fetched at connect time.
9. [Backup and restore](backup-and-restore.md) — encrypted export, merge or replace import.
10. [Importing connections](importing.md) — bring your tree from Royal TS, Remote Desktop
    Manager, Termius, mRemoteNG, PuTTY or `~/.ssh/config`, or from an LDAPS directory.
11. [Updates](updates.md) — checking for new versions, what is installed in-app and what by
    hand, the signature trust chain, downgrade protection.
12. [Network tools](network-tools.md) — port check, ping, traceroute and WireGuard status from
    the inspector, without raw sockets or elevation.
13. [Keyboard shortcuts](keyboard-shortcuts.md)
14. [Audit log](audit-log.md) — what is recorded, filters, and how to verify the chain.
15. [Troubleshooting](troubleshooting.md)
16. [FAQ](faq.md)

Examples in this guide use placeholder hosts such as `web01.example.test`. Replace them with
your own.
