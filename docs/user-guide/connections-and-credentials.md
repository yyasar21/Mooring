# Connections and credentials

## Connections

A connection is a named target: protocol, host, optional port, folder, optional credential
and up to 50 tags. Names are limited to 120 characters and hosts to 2048. Names, hosts and
tags refuse control characters and invisible or right-to-left override characters, which
could otherwise disguise one host as another.

Protocols you can store today: SSH, RDP, VNC, web. Only **SSH** sessions open in the current
version; the others return "sessions are not available in this version" until their phase
lands (see the [roadmap](../roadmap.md)).

## Folders and inheritance

Folders organise connections and carry an optional **default credential**. When you open a
connection, Mooring resolves the credential in this order:

1. the credential set on the connection itself (an **override**);
2. otherwise the default credential of the nearest folder above it;
3. otherwise none (the SSH client may still try your ssh-agent).

Example:

```text
All connections
└── Production              default credential: "ops on-call" (SSH key)
    ├── Web tier
    │   ├── web01           inherits "ops on-call"
    │   └── web02           override: "web deploy" (password)
    └── Databases
        └── pg-primary      inherits "ops on-call"
```

The inspector on the right shows which credential a connection uses and where it comes from
("folder Production"). It never shows the secret itself.

## Search

The command palette (`Ctrl+K` / `⌘K`) searches connection names, hosts and tags with a
full-text index. Type a few letters of any of them.

## Credentials today

The current version stores three kinds of credential:

| Kind | Fields | Secrets |
| --- | --- | --- |
| Password | username | password |
| SSH key | username | private key, optional passphrase |
| Certificate | username | certificate, private key |

Secrets are write-only in the interface: you can set or replace them, never read them back.
For password credentials, **Copy password** in the inspector places the password on the
clipboard for 30 seconds (see [Vault and security](vault-and-security.md#clipboard)).

## Typed credentials (planned)

[ADR-0009](../adr/0009-credential-model.md) replaces the three kinds with **15 typed kinds**,
so Mooring can express domains, agents, tokens and cluster credentials precisely. Existing
credentials migrate automatically (password → user/password, SSH key → SSH key,
certificate → X.509).

| Kind | What it stores | Typical use |
| --- | --- | --- |
| User and password | username, optional domain; password | SSH, RDP, web, vSphere |
| Domain user | `DOMAIN\user` or `user@domain`; password | Windows / Active Directory, RDP with NLA |
| SSH key | username, public key, optional SSH certificate; private key, passphrase | SSH |
| SSH agent | username, optionally one pinned agent key | SSH with keys held by an agent |
| X.509 client certificate | certificate; private key, passphrase | Web mutual TLS, Kubernetes |
| API token | header name and scheme (default `Authorization: Bearer`); token | Web APIs |
| OAuth client | token URL, client id, scope; client secret, refresh token | Web APIs |
| kubeconfig | context names; the whole kubeconfig (sealed) | Kubernetes |
| Kubernetes token | display subject; token | Kubernetes |
| vSphere user | `user@domain`; password | vSphere web client and console |
| VNC password | password (up to 8 bytes, the protocol's limit) | VNC |
| VNC user and password | username; password | Apple Remote Desktop, VeNCrypt |
| Prompt on connect | optional username and domain; nothing stored | Any protocol where you type the password each time |
| External reference | provider and reference (HashiCorp Vault/OpenBao, 1Password, Bitwarden) | Secrets that stay in another manager (resolved from Phase A3) |
| Privilege escalation (`sudo`/`su`/`doas`) | method, target user; optional password | Secondary role on SSH |

**One-time passwords**: a TOTP seed can be attached to the interactive kinds (user/password,
domain user, SSH key, vSphere user). Storing the second factor beside the password means
"whoever opens the vault has both"; Mooring will warn you when you do it.

**Overrides without copying secrets**: a connection can override just the username or
domain of an inherited credential. One shared domain password can then serve different admin
accounts per server.

**Safety rules for imported kubeconfigs**: Mooring refuses kubeconfigs that run commands
(`exec`, `auth-provider`) or point to files on disk, because opening such a file would let it
run code or read files on your machine.

## Which credential works with which protocol (planned)

✓ = valid as the main credential · R = valid in a secondary role · — = rejected

| Kind | SSH | RDP | VNC | Web | Kubernetes | vSphere console |
| --- | --- | --- | --- | --- | --- | --- |
| User and password | ✓ | ✓, R (gateway) | — | ✓ | — | ✓ |
| Domain user | ✓ | ✓, R (gateway) | — | ✓ | — | ✓ |
| SSH key | ✓ | — | — | — | — | — |
| SSH agent | ✓ | — | — | — | — | — |
| X.509 client certificate | — | — | — | ✓ (mTLS) | ✓ | — |
| API token | — | — | — | ✓ | — | — |
| OAuth client | — | — | — | ✓ | — | — |
| kubeconfig | — | — | — | — | ✓ | — |
| Kubernetes token | — | — | — | — | ✓ | — |
| vSphere user | — | — | — | ✓ | — | ✓ |
| VNC password | — | — | ✓ | — | — | — |
| VNC user and password | — | — | ✓ | — | — | — |
| Prompt on connect | ✓ | ✓, R (gateway) | ✓ | ✓ | — | ✓ |
| External reference | depends on the referenced kind | | | | | |
| Privilege escalation | R (become) | — | — | — | — | — |

Secondary roles are set per connection: **gateway** is the RD Gateway credential for RDP
(often "same as the session"), **become** is the `sudo`/`su`/`doas` credential used after an
SSH login. A credential that does not fit the protocol is refused with a clear message, also
when it is inherited from a folder; the tree marks such connections.

Jump hosts are not a credential: they will be modelled as a separate connection that another
connection goes *through*.
