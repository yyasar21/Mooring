# Security keys and smart cards

Mooring can sign in to SSH servers with keys that never leave a hardware device: FIDO2
security keys (`sk-*` keys, for example on a YubiKey) and PIV smart cards. In both cases the
device does the signing through your **ssh-agent**; Mooring never sees a private key and never
falls back to a password. The decision records are
[ADR-0024](../adr/0024-fido2-ssh-keys.md) and [ADR-0027](../adr/0027-rd-gateway-and-smart-card.md).

## Which ssh-agent

Mooring looks for the agent in `SSH_AUTH_SOCK` on macOS and Linux, and at the OpenSSH agent
pipe on Windows. Pageant is not used for these keys because it does not support `sk-*` keys.
**Settings → SSH** shows the same information.

## SSH security keys (FIDO2)

### Prepare the key

Create the key with OpenSSH as usual, then load it into your agent:

```sh
ssh-keygen -t ed25519-sk            # or: ssh-keygen -t ecdsa-sk
ssh-add ~/.ssh/id_ed25519_sk        # a key handle file on disk
ssh-add -K                          # or: load resident keys from the device
```

### Add the credential

Credentials → **New credential** → **SSH security key (FIDO2)**:

| Field | What to enter |
| --- | --- |
| Username | The account on the server |
| Public key | The `sk-ssh-ed25519@openssh.com …` or `sk-ecdsa-sha2-nistp256@openssh.com …` line. Paste it or use **Open .pub file…** |
| Signing | **Through your ssh-agent** (the only option in this release) |
| Resident key | Tick it for a key created with `-O resident` |
| OpenSSH certificate | Optional: a certificate for this key |
| Key handle file and passphrase | Optional; only needed for direct signing, which is not available yet |

While you type, the form shows the key type, the FIDO application (`ssh:` by default) and the
`SHA256:` fingerprint. Pasting an `sk-*` key into an ordinary **SSH key** credential is refused
with a button that creates the right credential instead. SSH key credentials from 0.1.x that
hold a security key are converted automatically after the next unlock (written to the audit
log).

### Connect

1. Mooring checks that your agent holds the key **before** it contacts the server. If it does
   not, the tab says "Security key not in ssh-agent" and shows the `ssh-add` commands above.
2. When the server asks for a signature, a banner over the terminal says **Touch your security
   key to continue**, with the key's fingerprint and a 30-second countdown. Touch the key.
3. If nobody touches it in time, Mooring stops with "No touch within 30 seconds" and does not
   try a password. **Retry** starts again.

Mooring checks the signature the agent returns (user presence flag set, signed by this key)
before sending it to the server. A security key can also be used on a
[jump host](jump-hosts.md); the banner then names the hop.

## Smart cards (PIV)

### Add the credential

Credentials → **New credential** → **Smart card / PIV**:

| Field | What to enter |
| --- | --- |
| Username, domain | The account on the server (domain is optional) |
| Reader | Optional hint, for example the reader's name |
| Public key | The card key's OpenSSH line, for example from `ssh-keygen -D <module>` |
| PKCS#11 module | **OpenSC**, **YubiKey (ykcs11)** or **Windows smart card (no module)** |

There is no secret field: **the PIN is asked at connect and never stored.** Smart cards work
for SSH only; RDP smart-card logon needs Kerberos PKINIT, which is planned.

### Connect

- If the card's key is already in your agent (for example after `ssh-add -s <module>`),
  Mooring signs with it directly.
- Otherwise the **Smart card PIN** dialog opens. Mooring hands the PIN to your ssh-agent once,
  which loads the card **for 60 minutes**; a reconnect within that hour does not ask again.
  After that the agent forgets the card and the next sign-in asks for the PIN.
- **Cancel** or `Esc` stops the sign-in. Too many wrong PINs can lock the card.
- The PIN is never written to disk, the audit log or the interface's memory. The audit log
  records only that a PIN was asked and the outcome.
- If the key is not in the agent and no module is installed, the tab says "Smart card key not
  in ssh-agent" and shows the `ssh-add -s` step.

## Limits

- Signing directly with `ssh-sk-helper` (without an agent) is not available yet.
- No direct PKCS#11 access: the card is always used through ssh-agent.
- No RDP smart-card logon yet.
