# Mooring user guide

Mooring is a secure remote-access manager: an encrypted vault for your credentials, a tree of
connections, and sessions in tabs. This guide describes what works in the current pre-release
(Phases A1–A3). Features marked *planned* are on the [roadmap](../roadmap.md).

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
6. [Keyboard shortcuts](keyboard-shortcuts.md)
7. [Audit log](audit-log.md) — what is recorded and how to verify the chain.
8. [Troubleshooting](troubleshooting.md)
9. [FAQ](faq.md)

Examples in this guide use placeholder hosts such as `web01.example.test`. Replace them with
your own.
