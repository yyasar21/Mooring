# Mooring user guide

Mooring is a secure remote-access manager: an encrypted vault for your credentials, a tree of
connections, and sessions in tabs. This guide describes v0.1.0
(Phase A complete). Features marked *planned* are on the [roadmap](../roadmap.md).

1. [Getting started](getting-started.md) — install or build, create the vault, first SSH
   connection.
2. [Vault and security model](vault-and-security.md) — what is encrypted, how locking works,
   what Mooring protects against and what it does not.
3. [Connections and credentials](connections-and-credentials.md) — folders, inheritance,
   overrides, search, credential kinds and which protocol accepts which credential.
4. [SSH](ssh.md) — host-key verification (TOFU), authentication, ssh-agent, port forwarding,
   SFTP, supported algorithms.
5. [External secrets: HashiCorp Vault and OpenBao](external-secrets.md) — keep passwords and
   keys in your own secret manager and let Mooring fetch them at connect time.
6. [Importing connections](importing.md) — bring your tree from Royal TS, Remote Desktop
   Manager, Termius, mRemoteNG, PuTTY or `~/.ssh/config`, or from an LDAPS directory.
7. [Updates](updates.md) — checking for new versions, what is installed in-app and what by
   hand, the signature trust chain, downgrade protection.
8. [Network tools](network-tools.md) — port check, ping, traceroute and WireGuard status from
   the inspector, without raw sockets or elevation.
9. [Keyboard shortcuts](keyboard-shortcuts.md)
10. [Audit log](audit-log.md) — what is recorded and how to verify the chain.
11. [Troubleshooting](troubleshooting.md)
12. [FAQ](faq.md)

Examples in this guide use placeholder hosts such as `web01.example.test`. Replace them with
your own.
