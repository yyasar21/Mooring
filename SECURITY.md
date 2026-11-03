# Security policy

Mooring stores credentials and opens sessions to systems you administer. Security is a
release criterion, not a feature.

## Supported versions

Mooring is pre-release. Until v1.0, only the latest release line receives security fixes.

| Version | Supported |
| --- | --- |
| `main` (unreleased) | ✅ fixes land here first |
| latest `0.x` release | ✅ once v0.1.0 is published |
| older `0.x` releases | ❌ upgrade to the latest release |

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
- Protocol parsers (SSH today; RDP, VNC and others as they land).
- Release artefacts, signatures, SBOMs and provenance, the release workflows
  (`.github/workflows/release*.yml`, `scripts/release/`) and the update channel (from v0.1.0).
- Credential import parsers (kubeconfig, PEM, OpenSSH keys and certificates, TOTP seeds).

Out of scope:

- Attacks requiring root or administrator rights on the user's machine, or physical access to
  an unlocked session.
- Risks documented as accepted in the [threat model](docs/security/threat-model.md)
  (for example plaintext inventory metadata at rest, R-INV), unless you show a new impact.
- Vulnerabilities in third-party servers you connect to.
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

- From v0.1.0, every release ships a `SHA256SUMS` signed with Sigstore cosign (keyless, bound to
  this repository's `release.yml` and logged in Rekor), SLSA build provenance for each file and
  CycloneDX SBOMs. Verify a download with
  [`scripts/release/verify-release.sh`](scripts/release/verify-release.sh) before installing.
  Platform signing (macOS Developer ID + notarization, Windows Authenticode, RPM GPG) applies
  where the release notes say so. Until then, macOS builds are ad-hoc signed and Windows builds
  are unsigned; the checksum signature is the authority.
- Releases are drafts until a maintainer publishes them by hand. Known medium-severity findings
  at release time are listed in the release notes and in this file.

## Security-relevant design summary

A plain-language overview is in
[Vault and security model](docs/user-guide/vault-and-security.md).
