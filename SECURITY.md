# Security policy

Nexus Remote stores credentials and opens sessions to systems you administer. Security is a
release criterion, not a feature.

## Reporting a vulnerability
Use GitHub's private vulnerability reporting on this repository ("Security" tab → "Report a
vulnerability"). Expect an acknowledgement within 72 hours. Please do not open public issues
for vulnerabilities.

## What we promise
- Vault format and cryptography are documented in `docs/adr/0002-vault-cryptography.md`.
- The threat model in `docs/security/threat-model.md` is updated every phase.
- Every change is reviewed by the security-reviewer role; `cargo deny`, `cargo audit`,
  `gitleaks` and Semgrep run on every PR.
- Releases are signed (macOS notarized, Windows Authenticode, Linux minisign) and ship with a
  CycloneDX SBOM and provenance (from v0.1.0).

## Out of scope
Attacks requiring root/administrator on the user's machine, or physical access to an unlocked
session.
