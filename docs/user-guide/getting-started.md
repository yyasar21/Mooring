# Getting started

## 1. Install Mooring

Installers are on the
[releases page](https://github.com/yyasar21/Mooring/releases); every file is listed in a
`SHA256SUMS` that the release pipeline signs with Sigstore. [docs/release.md](../release.md)
has the per-OS install steps and the verification commands.

| OS | Recommended | Alternatives |
| --- | --- | --- |
| macOS 11 or later | `brew install --cask yyasar21/mooring/mooring` | `.dmg` or `.pkg` (universal) |
| Windows 10/11 | `.exe` installer | `.msi`; winget after v0.1.0 |
| Debian, Ubuntu | `.deb` | AppImage |
| Fedora, RHEL | `.rpm` | AppImage |

### Installing an unsigned build

v0.1.0 ships without an Apple Developer ID or a Windows code-signing certificate: macOS builds
are ad-hoc signed and not notarized, Windows builds are unsigned. Gatekeeper and SmartScreen
will therefore warn. Treat the warning as a prompt to **verify the download first**, then
override it:

1. Verify: `cosign verify-blob` on `SHA256SUMS` and `sha256sum --check` on your file
   ([commands](../release.md#verify-a-download)), or
   `scripts/release/verify-release.sh v<version>` from a checkout.
2. macOS: System Settings → Privacy & Security → "Mooring was blocked" → **Open Anyway**
   (or Control-click → Open on macOS 14 and earlier).
3. Windows: SmartScreen "Windows protected your PC" → **More info** → **Run anyway**.
4. Linux: no OS gate; the checksum verification is the only check, so do not skip it.

Later releases with certificates need no override and no change on your side.

To build from source instead, follow the
[build guide](../developer-guide/building.md):

```bash
git clone https://github.com/yyasar21/Mooring.git
cd Mooring
make setup
make dev
```

### Portable build (no installer, no admin)

For a machine where you cannot install software, download `Mooring_<version>_x64_portable.zip`
(Windows) or `Mooring_<version>_universal_portable.zip` (macOS), verify it against `SHA256SUMS`,
and unzip it anywhere you can write — your Desktop, `~/Applications`, a USB stick, a network
share. The folder holds the app, an empty file named `portable` and a `README.txt`:

- Keep `portable` next to `Mooring.exe` / `Mooring.app`. That file is what switches Mooring to
  portable mode; without it the app uses the normal per-user data folders.
- Everything Mooring writes — vault, database, audit log, trusted host keys, cache — goes to
  `Mooring Data/` in the same folder (owner-only permissions; on NTFS Mooring also applies an
  owner-only ACL, on FAT/exFAT it cannot and says so in the audit log). Back that folder up;
  move the whole folder and the data follows.
- If the folder is read-only, Mooring refuses to start and tells you which folder — it never
  silently falls back to a hidden location.
- Windows needs the Evergreen WebView2 runtime, present on Windows 10/11 with Edge; if it is
  missing Mooring says so and `README.txt` links Microsoft's per-user bootstrapper (no admin).
- Gatekeeper / SmartScreen ask once, as for the installers (section above).
- Updates are manual: download the new zip and replace everything except `Mooring Data/`. The
  in-app updater only checks; it does not install in portable mode. On macOS, persistent web
  sessions behave as ephemeral in portable mode because WebKit keeps site data under
  `~/Library/WebKit`, which cannot be redirected.

## 2. Create your vault

On first start Mooring shows the unlock screen in *create* mode.

1. Choose a **master password** of at least 12 characters. Length matters more than symbols;
   a passphrase of four or five random words is a good choice.
2. Confirm it and select **Create vault**.
3. Mooring measures your machine and picks an Argon2id memory cost that takes about half a
   second. This runs once at creation and again when you change the password.

> **There is no password recovery.** The master password is never stored anywhere. If you
> forget it, the secrets in the vault cannot be recovered by you or anyone else.

### First run

An empty vault shows the **First run** card, "Nothing is moored here yet", with three paths:
**Start from scratch** opens the new-connection dialog in the root folder; **Import from
another tool** opens the import wizard for Royal TS, Remote Desktop Manager, Termius,
mRemoteNG, PuTTY, an ssh config or an LDAPS directory (see [Importing connections](importing.md));
**Read the user guide** copies this guide's address for your browser. **Not now** hides the
card for this vault; it never comes back once the tree has a connection, and the same wizard
stays available under Settings → **Import**.

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
- Keep Mooring current with Settings → [Updates](updates.md).
