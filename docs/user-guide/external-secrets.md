# External secrets: Vault, OpenBao, 1Password and Bitwarden

Mooring can read a connection's password, key or token from your own secret manager at the
moment you connect, instead of storing it in the Mooring vault. The secret never touches disk,
never reaches the user interface and is dropped from memory as soon as the session handshake is
done. The decision records are [ADR-0016](../adr/0016-external-secrets.md) and
[ADR-0026](../adr/0026-dynamic-secrets-1password-bitwarden.md).

Supported providers:

| Provider | How Mooring reaches it | Values |
| --- | --- | --- |
| HashiCorp Vault / OpenBao | HTTPS API; token, AppRole or OIDC sign-in | KV v2, plus the dynamic `database`, `ssh` (sign, OTP) and `pki` engines ([below](#dynamic-vault-engines)) |
| 1Password | Your **1Password Connect** server, with a Connect token ([below](#1password-connect)) | Item fields |
| Bitwarden Secrets Manager | The official **`bws`** CLI, with a machine-account access token ([below](#bitwarden-secrets-manager)) | Secrets |

Vault and OpenBao speak the same API (KV version 2 and the `token`, `approle` and `oidc` auth
methods), so steps 1 to 3 apply to either. Examples use `https://vault.example.test:8200`.

## How it fits together

1. A **secret source** describes one Vault/OpenBao server and how Mooring signs in to it
   (Settings → *Secret sources*).
2. A credential of kind **Secret manager reference** points at a source and a KV path, and
   says which kind of credential the secret becomes (a user/password, an SSH key, a
   kubeconfig…).
3. Connections use that credential like any other. On connect, Mooring signs in (or reuses its
   in-memory token), reads the KV secret, validates it with the target kind's own rules and
   hands it to the protocol. Reconnects read it again; nothing is cached.

## Step 1 — prepare Vault / OpenBao

Create a KV v2 secret with keys named after the credential fields Mooring expects. The default
key names are the field names of the target kind:

| Target kind | Required keys | Optional keys |
| --- | --- | --- |
| User / password | `username`, `password` | — |
| Domain user (RDP) | `username`, `password` | `domain` |
| SSH key | `private_key` (PEM) | `passphrase`, `username` |
| API token / Kubernetes token | `token` | — |
| Kubeconfig | `kubeconfig` (the file's text) | — |
| vSphere user | `username`, `password` | — |
| VNC password | `password` | — |

```sh
vault kv put secret/servers/web01 username=deploy password='…'
```

Give the Vault identity that Mooring will use a policy with **read** on that path only:

```hcl
path "secret/data/servers/*"     { capabilities = ["read"] }
path "secret/metadata/servers/*" { capabilities = ["read"] }
```

Pick one sign-in method:

- **Token** — any non-root token with the policy above. Root tokens are refused by Mooring.
- **AppRole** — `vault write auth/approle/role/mooring token_policies=mooring token_ttl=1h
  token_max_ttl=24h`, then read its `role_id` and generate a `secret_id`.
- **OIDC** — an OIDC role whose allowed redirect URIs include
  `http://localhost:8250/oidc/callback`, for example
  `vault write auth/oidc/role/mooring allowed_redirect_uris="http://localhost:8250/oidc/callback"
  user_claim=email token_policies=mooring`.

## Step 2 — add the secret source in Mooring

Settings → **Secret sources** → **Add source…**, provider **Vault / OpenBao**

| Field | What to enter |
| --- | --- |
| Name | A label, e.g. `Prod Vault` |
| Address | `https://vault.example.test:8200` (plain `http://` is only accepted for `127.0.0.1`/`[::1]` with the *Allow http:// (loopback only)* switch, and is audited) |
| Namespace | Vault Enterprise namespace, if any (sent as `X-Vault-Namespace`) |
| Auth method | *Token*, *AppRole* or *OIDC* |
| Credential | Token → an **API token** credential holding the Vault token. AppRole → a **Vault AppRole** credential holding `role_id` and `secret_id`. OIDC → none |
| OIDC role | The Vault role name (OIDC only) |
| Auth mount | Only when the auth method is mounted somewhere other than `approle` / `oidc` |
| CA certificate (PEM) | Your private CA, if the server's certificate is not publicly trusted. Otherwise Mooring pins the certificate on first use (TOFU) and asks you to confirm its fingerprint |
| Allowed origins | OIDC only: extra origins the sign-in window may load (your identity provider's login page is allowed automatically) |

Press **Test**. Mooring signs in and shows the auth method, the token TTL, whether it is
renewable and how many policies it carries — never the token itself. For OIDC, **Sign in…**
opens an isolated window with no access to Mooring; finish the login there, the window closes
by itself and the test completes. A sign-in that takes longer than five minutes is abandoned.

## Step 3 — create the reference credential

Credentials → **New credential** → kind **Secret manager reference**, provider Vault, engine
**KV v2**:

| Field | What to enter |
| --- | --- |
| Source | The secret source from step 2 |
| Reference | `<mount>/<path>`, e.g. `secret/servers/web01` (no `..`, no empty segments) |
| Version | Leave empty for the latest KV version, or pin one |
| Target kind | What the secret becomes, e.g. *User / password* or *SSH key* |
| Field map | Only if your KV keys are named differently: `password ← pw`, `private_key ← key` |

Press **Test**: Mooring reads the secret and reports which required keys are **present**,
**missing** or **extra** — names only, never values.

Attach the credential to a connection (or to a folder, so every connection below inherits it)
and connect as usual.

## Dynamic Vault engines

Instead of a stored KV value, a Secret manager reference can ask Vault to **issue** a
credential at connect time. Choose the **Vault engine** in the reference form; the reference
field becomes **Role** (`<mount>/<role>`, for example `database/reporting`), and the target kind
is fixed by the engine:

| Engine | Becomes | Extra fields | Notes |
| --- | --- | --- | --- |
| Database (`database/creds`) | Username and password | — | A lease: renewed at two thirds of its TTL while the session is open, revoked when it closes, on reconnect, on lock and on quit |
| SSH sign (`ssh/sign`) | A certificate for your SSH key | Principals (up to 16), TTL | Only the public key is sent to Vault. Pick the reference as the connection's **Certificate (Vault SSH CA)**, see below |
| SSH OTP (`ssh/creds`) | Username and one-time password | Login (required) | Used once; Mooring sends the target's IP address |
| PKI (`pki/issue`) | X.509 certificate and key | Common name (required), alt names, TTL | Can be tested; no protocol uses X.509 for sign-in yet |

TTLs are 1 second to 24 hours; leave them empty for the role's default. Dynamic engines take no
version and no field map.

**SSH certificates from a Vault SSH CA.** On an SSH connection, set **Certificate (Vault SSH
CA)** to an SSH sign reference. At each connect Mooring sends the public half of the
connection's SSH key (or SSH security key) to Vault, checks that the certificate it gets back
is a user certificate for that key and valid now, and offers it to the server before the plain
key.

**Lease chip.** A session that holds a lease shows a chip on its tab, for example "Lease ·
renews in 23 min". A failed renewal turns it into a warning ("renewal failed, expires in …");
the session goes on until the lease expires. If Vault issues database credentials without a
lease, Mooring does not use them and does not connect. Lease ids are never shown.

**Test reference** issues a credential once, checks that it has every field the target kind
needs, and revokes it at once.

## 1Password Connect

Mooring reads 1Password items through a **1Password Connect** server that you run; it does not
use the `op` CLI or a 1Password account sign-in.

1. Settings → **Secret sources** → **Add source…** → provider **1Password Connect**.
2. **Address**: your Connect server, for example `https://connect.example.test:8080`.
3. **Connect token credential**: an **API token** credential holding the Connect token.
4. Optional **CA certificate (PEM)** for a private CA; otherwise the server certificate is
   pinned on first use, as for Vault.
5. **Test** reports how many vaults the token can see.

In the reference credential choose provider **1Password** and enter an `op://` reference:

- `op://vault/item/field` or `op://vault/item/section/field` for a single value;
- `op://vault/item` with a **field map** to fill a kind with several values (for example
  `username ← login`, `password ← password`).

Vaults and items are matched by name or id and must match exactly one. A field at the top level
of the item wins over one in a section; two candidates at the same level are refused. Fields of
type one-time password supply `otp_seed`.

## Bitwarden Secrets Manager

Mooring runs the official **`bws`** CLI for Bitwarden Secrets Manager. Install it in one of the
fixed places Mooring looks; it never searches `PATH`:

| OS | Locations |
| --- | --- |
| macOS, Linux | `/usr/local/bin/bws`, `/opt/homebrew/bin/bws` |
| Windows | `%LOCALAPPDATA%\Programs\bws\bws.exe`, `%ProgramFiles%\bws\bws.exe` |

1. Create a machine account in Bitwarden and an access token for it.
2. In Mooring, create a **Bitwarden access token** credential holding the token.
3. Settings → **Secret sources** → **Add source…** → provider **Bitwarden**: the **server URL**,
   the access token credential, and **bws location** (*First one found* or one of the paths
   above).
4. **Test** runs `bws` and reports how many projects the token can see. The first successful
   test also records the `bws` binary's SHA-256 checksum.

References are a secret id (`<secret uuid>`) or `<project uuid>/<key>`. A secret whose value is a
JSON object of strings can fill a kind with several values, with a field map.

How `bws` is run: with a cleared environment (only the token and server URL are passed), no
input, fixed arguments, a 30-second deadline and capped output. If the `bws` file changes (for
example after an update), Mooring refuses to run it until you **Test** the source again. `bws`
makes its own TLS connections, so Mooring's certificate pinning does not apply and there is no
CA field.

## What happens on lock, errors and renewal

- Tokens live only in memory. AppRole and OIDC tokens are renewed before they expire and are
  **revoked** when you lock the vault or quit; a stored token-method token is only forgotten
  (it is yours, Mooring does not revoke it). **Revoke** (AppRole, OIDC) or **Forget** (token) on the source does the same on demand.
- There is **no fallback**: if Vault is unreachable, the token has expired, the policy denies
  the path or the secret has the wrong shape, the connection fails with a clear reason
  (`credential.external_unavailable` plus a category such as `network`, `auth_failed`,
  `forbidden`, `not_found` or `shape`). Mooring never keeps an old value to try instead.
- A secret that was deleted or destroyed in KV counts as not found.
- Secret sources are **not** included in [vault sync](vault-and-security.md): each device adds
  its own sources and signs in on its own.
- Every sign-in, read, refusal and configuration change is recorded in the
  [audit log](audit-log.md) — by name and path, never by value.

## Limits

- One OIDC sign-in at a time per source; the callback port `8250` must be free on your
  machine.
- A [jump host](jump-hosts.md) cannot use a Secret manager reference credential yet.
- PKI certificates are not used for sign-in by any protocol yet, and are not revoked when a
  session closes.
- 1Password only through Connect; Bitwarden only through `bws` (its TLS is its own).
