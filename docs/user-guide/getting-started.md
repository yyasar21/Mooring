# Getting started

## 1. Install Mooring

Signed installers are published from v0.1.0 on the
[releases page](https://github.com/yyasar21/Mooring/releases); see
[docs/release.md](../release.md) for verification.

| OS | Recommended | Alternatives |
| --- | --- | --- |
| macOS 12 or later | `brew install --cask yyasar21/mooring/mooring` | `.dmg` or `.pkg` (universal) |
| Windows 10/11 | `.exe` installer | `.msi`; winget after v0.1.0 |
| Debian, Ubuntu | `.deb` | AppImage |
| Fedora, RHEL | `.rpm` | AppImage |

Until the first release, build from source with the
[build guide](../developer-guide/building.md):

```bash
git clone https://github.com/yyasar21/Mooring.git
cd Mooring
make setup
make dev
```

## 2. Create your vault

On first start Mooring shows the unlock screen in *create* mode.

1. Choose a **master password** of at least 12 characters. Length matters more than symbols;
   a passphrase of four or five random words is a good choice.
2. Confirm it and select **Create vault**.
3. Mooring measures your machine and picks an Argon2id memory cost that takes about half a
   second. This runs once at creation and again when you change the password.

> **There is no password recovery.** The master password is never stored anywhere. If you
> forget it, the secrets in the vault cannot be recovered by you or anyone else.

## 3. Build your tree

The left pane is the **connection tree**. *All connections* is the root folder.

- **New folder**: folder icon above the tree. Folders nest without limit.
- **New connection**: plus icon above the tree. Pick the protocol, host, port, folder,
  credential and tags.
- **Rename**: select a row and press `F2`.
- **Move**: drag a row onto a folder.

## 4. Add a credential

Select the key icon above the tree to open **Credentials**, then add one:

- **Password** — username and password.
- **SSH key** — username, private key (OpenSSH format) and optional passphrase.
- **Certificate** — certificate and private key (stored for later protocols).

Secrets are write-only: after saving, Mooring never displays them again. You can replace them.

Attach the credential either to a **folder** (as its default, inherited by everything inside)
or to a single **connection**. See [Connections and credentials](connections-and-credentials.md).

## 5. Connect

1. Press `Ctrl+K` (`⌘K` on macOS) and type part of the name, host or a tag.
2. Press `Enter` to open the connection in a tab, `Ctrl+Enter` / `⌘Enter` for a new tab.
3. The first time you connect to a host, Mooring shows its key fingerprint. Compare it with
   the fingerprint your administrator gave you, for example from
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server, then select
   **Trust and connect**. See [SSH](ssh.md#host-key-verification-tofu).

## 6. Lock

Select **Lock** in the top bar or press `Ctrl+Shift+L` (`⌘⇧L`). Locking:

- removes the decryption key from memory,
- clears a password you copied to the clipboard,
- keeps already open sessions running,
- requires the master password for new sessions and credential actions.

## Next steps

- Read the plain-language [security model](vault-and-security.md).
- Learn the [keyboard shortcuts](keyboard-shortcuts.md).
- Review activity in the [audit log](audit-log.md).
