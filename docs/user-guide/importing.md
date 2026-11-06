# Importing connections

Mooring can read the export of another remote-access tool, or the computer objects of an
LDAP directory, into **a new folder** of your vault. Nothing you already have is merged or
overwritten, no password of another tool is ever decrypted, and nothing about an import leaves
your computer. The decision record is [ADR-0019](../adr/0019-importers-and-onboarding.md).

## How it fits together

1. Settings → **Import** shows one tile per source. On a fresh vault the **First run** card
   offers the same wizard under **Import from another tool**.
2. The wizard has three steps: **File** (or **Directory** for LDAPS) → **Preview** → **Apply**.
   The file is opened by Mooring's Rust core, read once and kept as a *plan* in memory for ten
   minutes; it is never changed or copied, and the user interface never sees its bytes.
3. **Preview** is a dry run: you untick what you do not want, decide about duplicates and the
   plaintext-secret opt-ins, and see what was skipped and why.
4. **Import n items** writes everything in one transaction under a folder named
   *Imported from \<tool\> (\<date\>)*. If anything fails, nothing is written. A mistaken
   import is one folder delete away.

Importing needs an unlocked vault. Locking the vault drops every held plan.

## The file importers

| Tile | What to import | How to get it | Imported | Never imported |
| --- | --- | --- | --- | --- |
| **Royal TS** | A document saved as `.rtsx` or `.rtsz` | The document file itself (File → Save As). A password-protected document is refused — save a copy without the document password | Folders; RDP, SSH/terminal, VNC and web connections; credential objects (as *ask at connect*) | Passwords (`import.encrypted` for a protected document) |
| **Remote Desktop Manager** | An `.rdm` or XML export | File → Export → connections (unencrypted) | `Group` paths → folders; RDP, SSH, VNC, web; host, port, user | Passwords (`SafePassword` is encrypted; warning `secret_encrypted`) |
| **Termius** | A CSV or JSON export | Termius desktop → Settings → Export | Groups → folders; label, address, port, username, tags | Plaintext passwords and keys **unless** you opt in (below) |
| **mRemoteNG** | The `confCons.xml` file | `%APPDATA%\mRemoteNG\confCons.xml`, or File → Export without encryption | `Container` → folders; RDP, SSH2, VNC, HTTP(S); username and domain | **Passwords, always.** A fully encrypted file (`FullFileEncryption="true"`) is refused |
| **PuTTY** | A `.reg` export of the sessions | Windows: `reg export HKCU\Software\SimonTatham\PuTTY\Sessions putty.reg`. Linux/macOS: **Import from ~/.putty/sessions** reads the folder directly | SSH sessions: host (`user@host` is split), port, user name | `Default Settings`; Telnet, rlogin, raw, serial, SSH-1 (skipped as `unsupported`); `.ppk` key files (warning `ppk_key`, convert them to OpenSSH format) |
| **OpenSSH config** | Host entries of an ssh config file | **Import from ~/.ssh/config** reads your own config; or choose any config file | Literal `Host` aliases with `HostName`, `User`, `Port`, `IdentityFile` (as an *SSH agent* credential), `ProxyJump` (as a `jump:` tag) | Wildcard or negated `Host` patterns, `Match` blocks, `Include` files (warnings); `%` tokens are kept literally |

Every item passes Mooring's own validation for names, hosts, ports and tags; an item that
fails is listed under **Skipped** with its reason, it never stops the import. A ZIP archive is
refused (`import.unsupported_container`): unpack it and import the file inside.

## Step 1 — File

Choose a tile, then **Choose file**. The native dialog filters by the tool's extensions
(`.rtsx`/`.rtsz`, `.rdm`/`.xml`, `.csv`/`.json`, `.xml`, `.reg`). The dock shows the chosen
name and size; **Preview** reads and checks the file ("Reading and checking the file…").

PuTTY and OpenSSH config have a shortcut, **Import from ~/.putty/sessions** and
**Import from ~/.ssh/config**, that skips the dialog and previews at once. If there is nothing
there, you get `import.not_found`: "Nothing to import at that location on this computer."

## Step 2 — Preview

- Six counters: **folders**, **connections**, **credentials**, **secrets**, **skipped**,
  **warnings** (the last two light up when non-zero).
- A tree with a checkbox per folder and connection (protocol, `user@host:port`), **All** /
  **None**, and "*n* of *m* items selected". Unticking a folder lifts its contents one level;
  unticking a credential unlinks it from its connections.
- **Skip duplicates** (on by default): a connection with the same protocol, host, port and user
  as one already in the vault carries a **Duplicate, skipped** badge and is left out. Off, it is
  imported as a second copy.
- The credential list with each kind and a **has secret** mark; the skipped list with reasons
  in plain words; warnings grouped by code with the items they refer to.

### Plaintext secrets: opt-in only

By default no secret is imported at all. A credential that had a password in the source
becomes one that **asks at connect** (warning `password_dropped`): you enter the password
once, Mooring seals it, and from then on it is in your vault. Two sources can do more:

| Switch | Shown for | What it does |
| --- | --- | --- |
| **Import plaintext passwords and keys** | Termius exports | The export stores secrets in clear text. On, they are sealed into the vault once and the preview runs again (a file source asks the dialog again, because a pick is single use). Off, each credential asks at connect. **The export file stays on disk either way — delete it when you are done.** |
| **Import private keys from ~/.ssh** | Only the **Import from ~/.ssh/config** shortcut | Reads each `IdentityFile` that is a regular file under `~/.ssh`, at most 16 KB and in OpenSSH format, and seals it into an **SSH key** credential. Anything else is skipped as `key_unreadable` and the connection keeps using your SSH agent. A *chosen* config file never reads keys (warning `key_files_only_for_known_location`). |

mRemoteNG has no switch: its preview shows the banner "mRemoteNG passwords are never
imported. Every credential below asks for its password at connect; re-enter them once and
Mooring seals them." Encrypted or obfuscated values of any tool are never decrypted.

## Step 3 — Apply

**Import n items** writes the plan. The report lists folders, connections, credentials,
secrets and skipped; **Open folder** selects the new root in the tree, **Close** leaves you
in Settings. Cancel or Escape at any earlier step discards the plan.

## The Directory (LDAPS) importer

The **Directory (LDAPS)** tile reads computer objects from Active Directory or OpenLDAP. It
is **read-only** by construction: Mooring can only bind, search, abandon and unbind. Nothing
is written to the directory, and the directory never hands a credential back.

| Field | What to enter |
| --- | --- |
| Server | `ldaps://dc01.example.test:636`. Only `ldaps://` is accepted; plain `ldap://` and StartTLS are refused (`ldap.insecure`). Port 636 unless given |
| Base DN | Where the search starts, e.g. `DC=corp,DC=example,DC=test`. Use an OU to import one part of the directory |
| Scope | **Subtree** or **One level** |
| Directory kind | **Active Directory**: reads `objectClass=computer`, the DNS host name and the operating system; Windows becomes an **RDP** connection, anything else **SSH**. **OpenLDAP**: reads `ipHost` and `device` objects; the first `ipHostNumber`, else the name, is the host; every connection is SSH |
| Name filter (optional) | Keeps the computers whose name or DNS host name contains this text. Matched as plain text: `*`, `( )`, `\` and the like are escaped, never interpreted |
| Bind credential | A **Windows domain** or **user and password** credential that may read the directory (**New credential…** creates one). The password is read from the vault for the bind and dropped |
| CA certificates (PEM) | Your private CA, if the server's certificate is not publicly trusted. Otherwise Mooring pins the certificate on first contact (TOFU) in a native **Mooring · Directory certificate** dialog |
| Size limit | 1–5 000 entries per run (default 5 000), and 30 seconds. A search that matches more stops with `ldap.size_limit` instead of importing a part |

**Test bind** connects, binds and disconnects without searching; the dock then shows
`host:port` and "Bound as *name*, then disconnected. Nothing was searched."

**The sign-in confirmation.** The first bind to a server with a given credential opens a
native dialog, **Mooring · Directory sign-in**, with the button **Sign in to host:port**. It
names the credential and the host; the password is sent only after you confirm. Cancelling
sends nothing (`ldap.bind_declined`). The confirmation is remembered for that credential and
server until the vault locks. Order on first contact: certificate dialog, then sign-in dialog,
then the bind.

**Preview** lands on the same step as a file import: each OU between the base DN and the
computer becomes a folder (eight levels at most, deeper paths are cut with the warning
`path_truncated`), computers without a DNS host name are skipped as `invalid`, and every
connection shares one credential, *Directory account (\<domain\>)*, that asks at connect. No
credential, port or tag comes from the directory. The root folder is *Imported from LDAP
directory (\<date\>)*.

## What happens on lock and errors

- Plans live in memory only, at most eight at a time, ten minutes each, single use. Locking the
  vault drops them and zeroizes any opted-in secret; afterwards **Import** answers
  `import.plan_expired` ("The preview expired or was already used. Preview the file again.").
- Parser refusals name a reason, never file content: `import.format` (not that tool's export),
  `import.encrypted` ("Export it unencrypted from the source tool, then import it again."),
  `import.doctype` (XML with a `<!DOCTYPE`, refused on purpose), `import.too_large` (over
  16 MiB), `import.limits`.
- Directory errors: `ldap.bind` (sign-in refused — check user, domain and password),
  `ldap.dn_invalid`, `ldap.unavailable`, `ldap.timeout` (30 s), `ldap.response` (a reply
  Mooring could not read; it stops rather than guess), `http.trust_rejected` (you rejected the
  certificate), `credential.incompatible` (not a domain or user/password credential).
- The [audit log](audit-log.md) records `import_previewed { format }`, `import_applied`
  (format and counts), `import_refused { code }`, `ldap_bind { host, success }`,
  `cert_decision` and `confirm_refused` — never a file name, host list, DN, bind name or secret.

## Limits

- One file ≤ 16 MiB; decompressed `.rtsz` ≤ 64 MiB and ≤ 20:1; XML ≤ 64 levels deep and
  ≤ 200 000 elements; ≤ 20 000 connections, 5 000 folders, 2 000 credentials per import.
- PuTTY on Windows is read from a `.reg` export only, never from the registry.
- `ProxyJump` becomes a `jump:<host>` tag; Mooring has no jump-host setting yet.
- No connection options (RDP resolution, VNC view-only…) are carried over yet.
- The directory import is one-shot: there is no saved directory source or scheduled refresh.
