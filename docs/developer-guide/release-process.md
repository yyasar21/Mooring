# Release process

The authoritative release documentation — workflows, signing, notarization, checksums,
verification and package channels — is [docs/release.md](../release.md), maintained by the
release-engineer role.

## Summary

- Releases are cut from tags `v*` on `main` and built by GitHub Actions only. Signing material
  never lives in the repository.
- Version numbers follow [Semantic Versioning](https://semver.org/); the workspace version is
  in `Cargo.toml` and `package.json`.
- [CHANGELOG.md](../../CHANGELOG.md) is updated from Conventional Commits: move the
  `Unreleased` entries under the new version with its date.

## Artefacts (from v0.1.0)

| Platform | Artefacts | Channel |
| --- | --- | --- |
| macOS | universal `.dmg`, `.pkg`, notarized | GitHub Releases, Homebrew tap `yyasar21/homebrew-mooring` |
| Windows | `.exe` (NSIS), `.msi`, Authenticode-signed | GitHub Releases, winget (later) |
| Linux | `.deb`, `.rpm`, `.AppImage`, minisign-signed `SHA256SUMS` | GitHub Releases |

Each release also carries CycloneDX SBOMs (cargo and npm) and build provenance, and the
in-app updater uses signed manifests.

## Release checklist (maintainer)

1. Phase exit criteria met; security review signed off with no open blocker or high finding.
2. `CHANGELOG.md` updated; known medium findings listed in the release notes.
3. Tag `vX.Y.Z` on `main`; watch the release workflow.
4. Verify signatures and checksums on clean macOS, Windows and Linux machines.
5. Publish the draft release; update the Homebrew tap (and winget when available).
