# Getting started

## 1. Install Mooring

Installers are on the
[releases page](https://github.com/yyasar21/Mooring/releases); every file is listed in a
`SHA256SUMS` that the release pipeline signs with Sigstore. [docs/release.md](../release.md)
has the per-OS install steps and the verification commands.

| OS | Recommended | Alternatives |
| --- | --- | --- |
| macOS 11 or later | `brew install --cask yyasar21/mooring/mooring` | `.dmg` or `.pkg` (universal) |
| Windows 10/11 | `.exe` installer | `.msi`; [winget](#windows-winget) once listed |
| Debian, Ubuntu | `.deb` | AppImage |
| Fedora, RHEL | `.rpm` | AppImage |

### Windows: winget

From 0.2.0 every stable release comes with validated winget manifests for the package
`yyasar21.Mooring`. They are submitted to the community repository (`winget-pkgs`) only once
the Windows installers are Authenticode-signed, so check whether the package is listed before
you rely on it:

```powershell
winget search yyasar21.Mooring
winget install --id yyasar21.Mooring --scope user      # per-user installer (.exe)
winget install --id yyasar21.Mooring --scope machine   # per-machine MSI (needs admin)
winget upgrade yyasar21.Mooring
```

Mooring is prepared to recognise a winget install and then show "Installed with winget — update
with winget upgrade yyasar21.Mooring" in Settings → Updates instead of installing in-app. The
installer change that marks such an install is not in 0.2.0 yet, so for now a winget install
behaves like the matching `.exe` or `.msi` install (see
[Updates](updates.md#in-app-or-manual-per-install)).

### Installing an unsigned build

v0.1.x and 0.2.0 ship without an Apple Developer ID or a Windows code-signing certificate:
macOS builds are ad-hoc signed and not notarized, Windows builds are unsigned. Gatekeeper and SmartScreen
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

### macOS: Move to Applications

When you start a release of Mooring straight from the disk image or from your Downloads folder,
it offers to **move itself to Applications** (or to `~/Applications` if you cannot write to
`/Applications`), restarts from there and ejects the disk image. **Not now** remembers your
answer for this version. Mooring never asks for an administrator password and never removes
the quarantine flag. Builds you make yourself are called **Mooring Dev**, keep their own data
and never offer this.

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
  move the whole folder and the data follows. The vault is encrypted at rest: a lost USB stick
  is a lost vault unless you remember the master password, and whoever finds it holds only
  the encrypted vault, protected by that password alone.
- The OS still keeps its usual per-app state outside the folder — macOS: `~/Library/WebKit`
  site data, saved window state and preferences; Windows: the SmartScreen decision. None of it
  holds a secret.
- Keep the folder out of cloud-synced locations (OneDrive, Dropbox, iCloud Drive, a
  OneDrive-redirected Desktop). Their "files on demand" placeholders are links, which Mooring
  refuses (`portable.marker_invalid`), and a synced vault is a copy outside this device. If you
  must, mark the folder "Always keep on this device".
- If the folder is read-only, Mooring refuses to start and tells you which folder — it never
  silently falls back to a hidden location.
- Windows needs the Evergreen WebView2 runtime, present on Windows 10/11 with Edge; if it is
  missing Mooring says so and `README.txt` links Microsoft's per-user bootstrapper (no admin).
- First launch on macOS: after unzipping, drag `Mooring.app` out of the folder and back in with
  Finder once. Otherwise macOS runs it from a temporary read-only copy (App Translocation) that
  cannot see `portable`; Mooring then reports a translocation copy (`portable.translocated`)
  and exits rather than starting with a second, empty vault. Do not use `xattr`.
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

The **navigation rail** on the far left switches between **Hosts**, **Credentials**, **Audit**
and **Settings** (`mod 1` to `mod 4`). In Hosts, the **Connections** pane shows your tree;
*All connections* is the root folder.

- **New folder**: the folder icon next to **New**. Folders nest without limit.
- **New connection**: **New**. Pick the protocol, then fill in name, host, port, folder,
  sign-in and tags; the dialog's section list jumps between General, Sign-in, Gateway and the
  protocol's options, and marks sections with errors. **Create and connect** saves and opens
  the session.
- **Rename**: select a row and press `F2`.
- **Move**: drag a row onto a folder.

## 4. Add a credential

Select **Credentials** in the rail, then **New credential** and a kind, for example:

- **Username and password**.
- **SSH key** — username, private key (OpenSSH format) and optional passphrase.
- **SSH security key (FIDO2)** or **Smart card / PIV** — see
  [Security keys and smart cards](security-keys-and-smart-cards.md).

The editor opens as a side sheet. After saving, the credential's detail page shows what it is,
which connections use it (**Used by**) and its **Audit** entries.

Secrets are write-only: after saving, Mooring never displays them again. You can replace them.

Attach the credential either to a **folder** (as its default, inherited by everything inside)
or to a single **connection**. See [Connections and credentials](connections-and-credentials.md).

## 5. Connect

1. Select a connection in the tree: the middle pane shows a **ready to connect** page with its
   host, folder, sign-in and route. Press **Connect**. Or:
2. Press `Ctrl+K` (`⌘K` on macOS), type part of the name, host or a tag and press `Enter`
   (`Ctrl+Enter` / `⌘Enter` for a new tab). The palette also lists recent connections, actions
   and settings pages.
3. The first time you connect to a host, Mooring shows its key fingerprint. Compare it with
   the fingerprint your administrator gave you, for example from
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server, then select
   **Trust and connect**. See [SSH](ssh.md#host-key-verification-tofu).

## 6. Lock

Select **Lock** in the title bar or press `Ctrl+Shift+L` (`⌘⇧L`). Locking:

- removes the decryption key from memory,
- clears a password you copied to the clipboard,
- keeps already open sessions running,
- requires the master password for new sessions and credential actions.

## Next steps

- Read the plain-language [security model](vault-and-security.md).
- Learn the [keyboard shortcuts](keyboard-shortcuts.md).
- Review activity in the [audit log](audit-log.md).
- Keep Mooring current with Settings → [Updates](updates.md).
