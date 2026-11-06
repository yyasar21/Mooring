# Security policy

Mooring stores credentials and opens sessions to systems you administer. Security is a
release criterion, not a feature.

## Supported versions

Until v1.0, only the latest minor line receives security fixes. Fixes ship as a new patch
release of that line, never as a change to an existing release.

| Version | Supported |
| --- | --- |
| `main` (unreleased) | ✅ fixes land here first |
| `0.1.x` | ✅ current line, from the publication of v0.1.0 |
| pre-releases (`0.1.0-rc.*`) | ❌ dry runs; install v0.1.0 or later |
| older `0.x` lines (once `0.2` exists) | ❌ upgrade to the latest release |

## Reporting a vulnerability

**Please do not open public issues, discussions or pull requests for vulnerabilities.**

Report privately through GitHub Security Advisories:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**
   (direct link: <https://github.com/yyasar21/Mooring/security/advisories/new>).
3. Describe the issue, the affected version or commit, the impact and steps to reproduce.
   A proof of concept helps; redact any real hostnames, usernames or secrets.

If you cannot use GitHub, contact the maintainer through the email address on the
[@yyasar21](https://github.com/yyasar21) profile and ask for a private channel. Do not send
vulnerability details in the first message.

### PGP (optional)

Encrypted reports are not required: GitHub Security Advisories are private. If you prefer
PGP, ask for a key in your first message and the maintainer will publish its fingerprint in
this file before you send details.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledgement of your report | within 72 hours |
| Initial assessment and severity (CVSS) | within 7 days |
| Fix for critical and high severity | within 30 days where feasible |
| Fix for medium and low severity | next scheduled release |
| Public disclosure | coordinated, by default 90 days after the report or when a fix ships, whichever is first |

If a fix needs more time, we will tell you why and agree an extended date with you; we will
not ask for an extension beyond 120 days without a concrete reason. If a vulnerability is
being exploited in the wild, we may publish an advisory with mitigations before a fix exists.

We will keep you informed, credit you in the advisory and the changelog unless you prefer to
stay anonymous, and request a CVE through GitHub where appropriate. We ask that you give us
reasonable time to fix the issue before disclosing it, and that you do not access data that
is not yours or degrade other people's systems while testing.

## Scope

In scope:

- The Mooring desktop application and the crates in this repository.
- The vault format, its cryptography and the `age` export.
- The IPC boundary between the WebView and the Rust core, capabilities and CSP.
- Protocol parsers (SSH; RDP through IronRDP and our TLS/CredSSP layer; our VNC/RFB client;
  others as they land), the certificate trust stores and the frame path to the UI.
- Release artefacts, signatures, SBOMs and provenance, the release workflows
  (`.github/workflows/release*.yml`, `scripts/release/`) and the update channel (from v0.1.0).
- Credential import parsers (kubeconfig, PEM, OpenSSH keys and certificates, TOTP seeds), the
  connection importers (Royal TS, RDM, Termius, mRemoteNG, PuTTY, OpenSSH) and the LDAPS
  directory reader.
- The in-app updater (manifest handling, signature check, install modes) and the network tools
  (`ping` / `traceroute` / `wg show` runners, TCP check).
- The HTTPS API clients and their trust stores: Kubernetes (the read-only request guard,
  exec, logs, port-forward), vCenter (inventory sync, power actions, consoles), Vault /
  OpenBao secret sources (token, AppRole, OIDC sign-in window), and vault sync to
  S3-compatible storage (the MSY1 blob format, rollback and fork detection).

Out of scope:

- Attacks requiring root or administrator rights on the user's machine, or physical access to
  an unlocked session.
- Risks documented as accepted in the [threat model](docs/security/threat-model.md)
  (for example plaintext inventory metadata at rest, R-INV), unless you show a new impact.
- Vulnerabilities in third-party servers you connect to (Kubernetes, vCenter, Vault, S3). A
  bypass of Mooring's Kubernetes read-only guard, a power action without the native
  confirmation, or a sync blob accepted after tampering, rollback or a fork **is** in scope.
- Findings from automated scanners without a demonstrated impact.

## What we promise

- Vault format and cryptography are documented in
  [ADR-0002](docs/adr/0002-vault-cryptography.md) and
  [ADR-0006](docs/adr/0006-vault-lifecycle.md).
- The threat model in [docs/security/threat-model.md](docs/security/threat-model.md) is
  updated every phase. Phase reviews are committed under [docs/security/](docs/security/).
- Every change is reviewed by the security-reviewer role. `cargo deny`, `cargo audit`,
  `pnpm audit`, `gitleaks` and Semgrep run on every pull request.

<!-- Maintainer: GitHub private vulnerability reporting must be enabled
     (Settings → Code security → Private vulnerability reporting) or the link above 404s. -->

- Releases are drafts until a maintainer publishes them by hand. Known medium-severity findings
  at release time are listed in the release notes and in this file.

## Verifying a download

Every release from v0.1.0 ships:
- `SHA256SUMS`, signed with Sigstore cosign (keyless). The signature is bound to this
  repository's `release.yml` workflow and logged in Rekor (`SHA256SUMS.sigstore.json`).
- SLSA build provenance for every file, and CycloneDX SBOMs (Rust and source).
- For the in-app updater, `latest.json` and one `.sig` per updater artifact. Both are listed
  in `SHA256SUMS`.

**v0.1.0 installers are not platform-signed.** The macOS build is ad-hoc signed and not
notarized. The Windows `.exe` / `.msi` carry no Authenticode signature. Linux packages carry no
GPG signature unless the release notes say so. Gatekeeper and SmartScreen will warn. **Verify
before you override the warning:**

```sh
scripts/release/verify-release.sh v0.1.0            # needs gh, cosign >= 3, python3; minisign optional
```

The script fails closed. It checks, in order:
1. the cosign signature (identity
   `https://github.com/yyasar21/Mooring/.github/workflows/release.yml@refs/tags/v0.1.0`, or
   `@refs/heads/main` for a maintainer re-run; issuer
   `https://token.actions.githubusercontent.com`);
2. every hash;
3. that no file on the release is missing from `SHA256SUMS`;
4. the provenance of each file;
5. that `latest.json` points only at this release's own files, and, with `minisign`
   installed, every updater signature against the public key below.

Without the script:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/yyasar21/Mooring/\.github/workflows/release\.yml@refs/tags/v0\.1\.0$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing SHA256SUMS        # macOS: shasum -a 256 -c
```

Platform signing (Developer ID + notarization, Authenticode, RPM GPG) is added without a code
change once certificates exist; until then the cosign-signed checksums are the authority.

## In-app updates and their trust

- **Off by default and never automatic.** Mooring checks for an update only when you press
  "Check for updates", or once a day if you turn on the background check. The background check
  only shows a badge. Nothing is downloaded or installed until you confirm. A check sends one
  HTTPS request to `github.com`, which redirects it to GitHub's download host. The app version
  is in the user agent. There is no telemetry.
- **What is trusted.** The manifest (`latest.json`, from this repository's latest published
  release) is not signed. It can only name a version and a file. The file must carry a
  minisign signature from the Mooring updater key, whose public half is compiled into the app:
  `plugins.updater.pubkey`, key id `9F4EDAC489D4B86D`. The signature is checked before
  anything is written. Only a strictly newer version is offered; pre-releases and downgrades
  never are.
- **No elevation, ever.** In-app install is offered only where your user can replace the app
  without administrator rights: an AppImage, a `.app` in a folder you can write, or a per-user
  Windows (NSIS) install. Packages (`.deb`, `.rpm`, `.msi`), Homebrew and root-owned installs
  show "update manually" with the release link. Mooring never asks for a sudo, UAC or macOS
  administrator password to update.
- **Second trust root.** Whoever holds the updater private key, and can also make the
  manifest point at their file, can ship code to in-app installs. The key lives only in the
  repository's release secrets and the maintainer's password manager. Rotating it needs a new
  release. Open hardening before the key is created: [review 7](docs/security/a4-review-7.md)
  M-17, L-39, L-40.

## Importers, directory import and network tools (A4)

- **Import files** are parsed locally under size, depth and count caps; XML with a `DOCTYPE` is
  refused. Nothing is merged into existing folders. Plaintext passwords or keys are imported
  only from Termius, and only when you tick the option. Passwords stored in mRemoteNG files are
  never read. The source file stays on disk: delete it yourself if it holds secrets.
- **LDAPS directory import** uses `ldaps://` only. It binds with a vault credential after the
  server certificate is trusted (CA, pin, or a native dialog on first use), runs one read-only
  search and never follows referrals.
- **Network tools** run the operating system's own `ping`, `traceroute` and `wg show` from
  fixed paths, and a TCP connect check. They never use elevated rights.

## Security-relevant design summary

A plain-language overview is in
[Vault and security model](docs/user-guide/vault-and-security.md).

## Server certificates for RDP and VNC

RDP (TLS + NLA) and VNC (VeNCrypt X509) check the server certificate the way SSH checks host
keys: trust on first use.
- A certificate that validates against the operating system's roots, or the connection's own
  CA (`caPem`), is accepted and not pinned, so a routine reissue does not stop a connection.
- Any other certificate is shown to you before anything is sent (subject, issuer, validity,
  SHA-256, problems). Accepting it pins its SHA-256 for that `host:port` in
  `known_rdp_certs` / `known_vnc_certs` in the app data directory. Pins are hashed and mode
  0600, but they are **not** in the vault.
- A pinned host that presents a different certificate is a hard stop
  ("CERTIFICATE CHANGED"). There is no "connect anyway". To accept a new certificate you remove
  the pin explicitly, and both steps are recorded in the audit log.
- A pin never replaces the TLS signature check.
- For VNC, a pinned host must use TLS from then on: a server or network that suddenly offers no
  TLS is refused ("TLS EXPECTED").
- VNC connections default to `prefer_tls`, which falls back to an unencrypted session when the
  server has no usable TLS. Such a session carries an "Unencrypted" badge and is audited. With
  VNC authentication, the password response can then be recorded and cracked offline. Use
  `require_tls` wherever the server supports it.

- For VNC, a host that has once used VeNCrypt with a certificate that validated against the
  system roots or `caPem` is also marked as TLS-required (a host-only marker, no
  fingerprint), so stripping TLS later is refused the same way.
- "Trust once" accepts the certificate for the next connect only, without pinning it. It is
  recorded in the audit log.

Open hardening items for these protocols are tracked in
[review 5](docs/security/a2-review-5.md).

## Web sessions and detached windows

Web consoles (vCenter, Grafana, firewalls and the like) never load inside the main Mooring
window.
- **Own window, no bridge rights.** Each web connection opens in its own window
  (`web-<connectionId>`). That window's capability is empty and has no remote grant. Tauri's
  app ACL manifest requires an explicit grant for every Mooring command, and the Rust core
  refuses every command from a web window again before it runs. A malicious or compromised
  page therefore cannot call any Mooring command, read the vault or reach other sessions, even
  though Tauri injects its IPC script into every window.
- **Navigation.** A web window navigates only to its start origin and the origins you list
  for the connection (exact `scheme://host:port`, IDN shown as punycode). The Mooring app
  origin, `file:`, `data:`, `javascript:`, `blob:`, `about:` and URLs with `user:pass@` are
  always refused, and refusals are audited.
- **Denied natively.** New windows, downloads and camera, microphone, location, notification
  and clipboard-read requests are denied. Developer tools are off. The window title always
  shows the real origin.
- **Storage.** It is ephemeral by default. "Keep me signed in" (`persistent`) is a
  per-connection opt-in: it stores that connection's cookies in its own folder, in plain text
  and outside the vault. It is audited, and it is wiped by "Clear site data" and when the
  connection is deleted.
- **TLS and credentials.** TLS uses the operating system's trust store. Mooring adds no
  certificate and offers no "proceed anyway". Credentials are never auto-filled into a
  page: copy them from the connection, and the clipboard is cleared after 30 s.
- **Locked vault.** While the vault is locked, every web and detached window is hidden.
- **Detached windows.** A session tab detached to its own window runs the bundled Mooring UI.
  It may call only the six commands one session view needs, and only for its own session.

Known gaps before the A2 tag are listed in the
[review 5 re-review](docs/security/a2-review-5.md#re-review-fix-round-6--r5u2u3):
- on Windows, ephemeral web windows that are open at the same time share one private session
  (L-29);
- deleting a folder does not yet wipe the persistent web stores of its connections (L-30);
- whether page-raised dialogs (`alert`, HTTP authentication, print) appear while the vault is
  locked has not been verified (L-31).

Engine bugs in the operating system's WebView are outside Mooring's control: keep the OS
WebView (WebView2, Safari/WebKit, WebKitGTK) updated.

## Kubernetes, vSphere, secret sources and vault sync

- **Kubernetes is read-only through Mooring.** Every API request passes a local allow-list
  (namespaces, pods, logs, the self-review APIs, exec and port-forward) before it leaves the
  process; anything else, including impersonation and `dryRun`, is refused and audited. An exec
  shell runs what you type inside the pod: that is the one deliberate exception. kubeconfig
  `exec` plugins, auth-providers and proxies are never run or used.
- **vSphere power actions** are off by default per vCenter and, when enabled, each one needs a
  confirmation in a native dialog that names the VM and the vCenter. VMRC hand-off is also
  opt-in; its single-use ticket is passed to the OS URL handler and is visible to other local
  users in the process list for a few seconds (R-VMRC-ARGV).
- **Secret sources (Vault / OpenBao).** Tokens stay in memory, root tokens are refused, and
  tokens Mooring obtained are revoked when the vault locks or the app exits. OIDC sign-in runs
  in its own window that cannot call Mooring; the code from the redirect is exchanged by the
  Rust core.
- **Vault sync.** The storage sees only encrypted, authenticated blobs and the password-wrapped
  vault header — with that header, the storage operator can try to guess your master password
  offline, so use a strong one. Rolled-back or forked data stops sync until you choose. Server
  certificates you trust on one device are trusted on all devices of the vault.

Known gaps before the A3 tag are listed in [review 6](docs/security/a3-review-6.md#conditions-before-the-a3-tag).
Conditions before the v0.1.0 tag are listed in
[review 7](docs/security/a4-review-7.md#conditions-before-the-v010-tag).

## Syslog mirror

The optional syslog mirror is the only copy of the audit log that a local attacker running as
the same user cannot rewrite, and its configuration is stored in plain text, so silence from a
Mooring client must be treated as an alert. Every app start with a stored configuration writes
`audit_syslog_started` (sent to the collector when the mirror is on, recorded locally with
`"enabled":false` when it is off), a redirect writes `audit_syslog_changed` to the old collector
and then to the new one, and a running mirror sends `audit_heartbeat { seq }` every hour.
Collectors should alert when a host that has sent `audit_syslog_started` misses two
consecutive heartbeats. Messages are RFC 5424 with `APP-NAME` `mooring` and the structured-data
element `[mooring@32473 seq="…" hash="…"]` (32473 is the RFC 5612 documentation enterprise
number, used until Mooring's own IANA number is assigned); `trunc="1"` or `redacted="1"` marks a
line whose MSG no longer matches its `hash`, so verify those against the local log.
