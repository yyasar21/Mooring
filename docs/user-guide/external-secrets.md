# External secrets: HashiCorp Vault and OpenBao

Mooring can read a connection's password, key or token from **HashiCorp Vault** or **OpenBao**
at the moment you connect, instead of storing it in the Mooring vault. The secret never
touches disk, never reaches the user interface and is dropped from memory as soon as the
session handshake is done. The decision record is [ADR-0016](../adr/0016-external-secrets.md).

Both servers speak the same API (KV version 2 and the `token`, `approle` and `oidc` auth
methods), so everything below applies to either. Examples use `https://vault.example.test:8200`.

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

Settings → **Secret sources** → **Add source…**

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

Credentials → **New** → kind **Secret manager reference**:

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

- KV v2 only. Dynamic engines (database, SSH OTP, PKI) are planned for a later release.
- One OIDC sign-in at a time per source; the callback port `8250` must be free on your
  machine.
- 1Password and Bitwarden are not supported yet (ADR-0016 §5).
