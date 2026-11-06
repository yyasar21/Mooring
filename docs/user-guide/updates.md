# Updates

Mooring checks for a new version **only when you ask**, or once a day if you opt in. A
background check only shows a notice; nothing is ever downloaded or installed until you press
**Install and restart**, and Mooring never asks for an administrator password to do it. The
decision record is [ADR-0018 §3](../adr/0018-release-v0-1-0.md); the release side
(what is published, how it is signed) is in [docs/release.md](../release.md).

## How it fits together

1. The check reads one small file, `latest.json`, from the project's GitHub releases over
   HTTPS. The request carries only Mooring's version and your platform. Drafts and pre-releases
   are never "latest", so a release candidate sees no update.
2. The file names the newest version, its release notes and, per platform, a download URL and a
   **signature**. Mooring verifies that signature against a public key compiled into the app
   before a single byte is written — independently of TLS, so a tampered download or a
   tampered manifest is refused with `update.signature`.
3. Where the installed copy can be replaced without elevation, Mooring downloads, verifies,
   replaces itself and restarts. Everywhere else it shows the new version and points you to
   the release page or your package manager.

## Settings → Updates

| Element | What it shows or does |
| --- | --- |
| Installed version | The running version; **Last checked** underneath |
| **Check for updates** | A manual check ("Checking…"). Result: "Mooring is up to date." or the **Update available** block |
| Update available | Version, date and size, the release notes as plain text (no links, no formatting — markup in the notes is shown literally), and either **Install and restart** or a manual-install note |
| **Check for updates in the background (daily)** | Opt-in. "One request a day to the release server carrying only the version and platform. It only shows a notice in the title bar; nothing is downloaded or installed until you ask." |
| Last verified update | Appears once an update has been verified: "Older versions are refused from now on." (see *Downgrade protection*) |

A background check runs at the earliest 60 seconds after start, only while the vault is
unlocked and only when the last check is more than 24 hours old. When it finds something newer,
a small **Update \<version\>** chip appears in the title bar; selecting it opens this card.

## What "Install and restart" does

Pressing it opens a confirmation, **Install \<version\> and restart?**: "Mooring downloads the
update, verifies its signature, replaces itself and restarts." If sessions are open, the dialog
says how many will be closed first and that port forwards and web windows end with the
restart; the button then reads **Close sessions, install and restart**. Then:

1. Mooring re-runs the check and refuses unless the offered version is exactly the one you
   confirmed (`update.none` otherwise — "Check again").
2. The download URL must be under `https://github.com/yyasar21/Mooring/releases/download/`;
   anything else is refused as `update.manifest`. The download is capped at 256 MiB and ten
   minutes.
3. The signature is verified. Only then is `update.install { from, to }` audited, the bundle
   written and the app restarted. A write failure after verification is `update.install_failed`
   — nothing has changed.

While this runs the card shows "Downloading and verifying the update… Mooring restarts when it
is installed." There is no progress bar.

## In-app or manual, per install

| Your install | Mode | Why |
| --- | --- | --- |
| macOS `.app` in a folder **you** can write to (e.g. `~/Applications`) | in-app | The bundle is replaced in place |
| macOS `.app` in a root-owned `/Applications` | manual (*not writable*) | Replacing it would need an administrator password; Mooring never asks for one |
| macOS, installed with Homebrew (`brew install --cask yyasar21/mooring/mooring`) | manual (*Homebrew*) | Run `brew upgrade` |
| Windows `.exe` installer, **per-user** install | in-app | The NSIS installer re-runs silently and relaunches |
| Windows `.exe` per-machine install, or `.msi` | manual | Per-machine installs need elevation; MSI is a package manager |
| Linux AppImage in a writable directory | in-app | The file is replaced in place |
| Linux `.deb`, `.rpm` | manual (*package manager*) | Update with `apt` / `dnf`, or download the new package |
| A build you made yourself | manual (*not bundled*), or *unconfigured* | There is nothing packaged to replace |

The manual note shows the release page, `github.com/yyasar21/Mooring/releases/latest`, with a
**Copy** button (Mooring's main window opens no external links). Never install an update from
anywhere else: verify the download as described in
[docs/release.md → Verify a download](../release.md#verify-a-download) and in
[Getting started](getting-started.md#installing-an-unsigned-build).

## The trust chain, in plain words

- The **public key** is built into the Mooring binary at release time. The matching private key
  exists only in the maintainer's secret store; it is never in the repository.
- Each release carries, per platform, an updater bundle and its **signature** made with that
  private key. `latest.json` lists both.
- TLS protects the transport, but Mooring does not rely on it: a bundle whose signature does not
  verify against the built-in key is dropped before anything is written, whatever server it
  came from. A `latest.json` with a URL outside the release tree is refused too.
- Whoever controls the private key can ship code to in-app installs. That is why the key is a
  separate trust root from the `SHA256SUMS` signature described in `docs/release.md`, and why a
  build without the key has no update channel at all (below).

## Downgrade protection

A version that is not newer than the running one is never offered (`update.none`). On top of
that, once an update has been **verified** on this install, its version becomes a floor: a
later manifest offering anything older is refused with `update.downgrade` ("The offered
version is older than an update this install already verified, so Mooring refused it. Nothing
was installed; check again later."). The floor only ever rises; the card shows it as
**Last verified update**. This stops a replayed or stale manifest from walking you back to a
version with known problems.

## Rate limits and errors

| Code | What it means |
| --- | --- |
| `update.rate_limited` | A manual check less than a minute after the previous one ("You checked a moment ago. Wait a minute before checking again."); also an install attempt within a minute of the previous one |
| `update.busy` | A check or install is already running |
| `update.network`, `update.manifest` | The release server did not answer, or `latest.json` could not be read (also: over 64 KiB, or a download URL outside the release tree) |
| `update.signature` | The signature did not verify; nothing was installed |
| `update.manual_only`, `update.not_writable` | This install is updated manually (see the table above) |
| `update.sessions_open` | Sessions are still open and you did not confirm closing them |
| `update.unconfigured` | This build has no update key (below) |

Every completed check (`update.check`), install (`update.install`), refusal
(`update.refused { code }`) and change of the background switch (`update.settings_changed`)
is recorded in the [audit log](audit-log.md). No URL, signature or download ever is.

## The "unconfigured" state

A Mooring you built yourself from source (`make dev`, `make bundle`) carries no update public
key. The card then says "Updates are not configured in this build. There is no update key, so
Mooring never checks for or installs anything; install new versions the way this one was
installed." **Check for updates** is disabled and the background switch is hidden. The
updater plugin is not even loaded in such a build, and no window has permission to reach it
directly in any build — the four commands behind this card are the only way in, and all of
them need an unlocked vault.
