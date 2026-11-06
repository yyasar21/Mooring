# Release process

How a Mooring release is cut, what the pipeline produces and how it is verified. Decisions:
[ADR-0018](../adr/0018-release-v0-1-0.md). User-facing install and verification notes:
[docs/release.md](../release.md). Pipeline: `.github/workflows/release.yml`,
`release-repro.yml`, `release-homebrew.yml`; scripts in `scripts/release/`.

## Principles

- Releases are built by GitHub Actions only, from a `v*` tag on `main`, into a **draft**
  release that a human reviews and publishes. No build artefact is ever produced on a laptop
  and uploaded by hand.
- Signing material exists only as GitHub secrets. The repository holds public keys only
  (`plugins.updater.pubkey` in `src-tauri/tauri.conf.json`). Every signing step is opt-in per
  secret, so a fork without secrets still builds (unsigned).
- Jobs are split by privilege: third-party code (npm/cargo build scripts, tauri-action, the SBOM
  tools) only runs with `contents: read` and **never next to the updater key**; the job that
  holds the Sigstore identity (`id-token: write`) has no checkout and runs pinned actions plus
  the project's own `updater-manifest.sh`, handed over as a workflow artifact from the tag's
  checkout. The updater key lives in the `release` environment and is read by one job
  (`sign-updater`) that runs no project code (security review 7, M-17).
- Every GitHub Action is pinned by commit SHA. `tauri-apps/tauri-action` stays on the v1 line
  (`1deb371b…` = v1.0.0); Dependabot bumps it like any other action. The Rust toolchain is
  pinned (`RUST_TOOLCHAIN`, the same value in `release.yml` and `release-repro.yml`; N-57).
- Every run starts from the tag ref (`refs/tags/v*`): a tag push, or `workflow_dispatch` run
  *from the tag*. `create-release` refuses anything else, and the cosign identity the verify
  script accepts is `release.yml@refs/tags/<tag>` only (N-58).

## Versions and tags

Versions follow SemVer 2.0.0 and live in `Cargo.toml` (`[workspace.package]`), the internal
path-dependency pins, `src-tauri/tauri.conf.json` and every `package.json`.
`scripts/release/bump-version.sh x.y.z` (or `make bump VERSION=x.y.z`) rewrites them all,
refreshes `Cargo.lock` and rolls `CHANGELOG.md` (`Unreleased` → `[x.y.z] - date`). `make
release VERSION=x.y.z` does the bump, commits `chore(release): vx.y.z` and tags on a clean
`main`.

`release.yml` refuses a tag whose version differs from `Cargo.toml` or `tauri.conf.json`, so
the tag can never claim a version the binaries do not carry.

**Pre-release tags** (`v0.1.0-rc.2`) are for pipeline dry runs:

- the draft is marked *pre-release*; GitHub never serves it as `releases/latest`, so the in-app
  updater (which reads `releases/latest/download/latest.json`) never sees it;
- Linux ships the `.deb` only: the rpm and AppImage bundlers reject `-` in a version, and Tauri
  rejects `~`. rpm and AppImage are first built at the stable version;
- the MSI carries the numeric part (`0.1.0`) as its ProductVersion (CI config overlay);
- Homebrew is skipped (`release-homebrew.yml` runs on published stable releases only).

## What a release carries

| File | Produced by |
| --- | --- |
| `Mooring_<v>_{aarch64,x64,universal}.dmg`, `.pkg` | tauri-action + `scripts/release/macos-pkg.sh` (macos-14) |
| `Mooring_<v>_x64-setup.exe` (NSIS, per-user), `Mooring_<v>_x64_en-US.msi` | tauri-action (windows-2022) |
| `Mooring_<v>_{amd64,arm64}.deb`, `Mooring-<v>-1.{x86_64,aarch64}.rpm`, `Mooring_<v>_{amd64,aarch64}.AppImage` | tauri-action (ubuntu-22.04, ubuntu-22.04-arm) |
| `Mooring_universal.app.tar.gz` | `build` (macos-universal): `tar -czf` of the signed `.app` |
| `Mooring_universal.app.tar.gz.sig`, `*-setup.exe.sig`, `*.AppImage.sig` | `sign-updater`, only when the `release` environment holds `TAURI_SIGNING_PRIVATE_KEY` |
| `latest.json` | `finalize`, from the `.sig` files (`scripts/release/updater-manifest.sh`) |
| `mooring-<v>-cargo.cdx.json`, `mooring-<v>-source.cdx.json` | CycloneDX 1.5 SBOMs: `cargo-cyclonedx =0.5.9` (Rust tree), syft (source tree incl. npm) |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | `finalize`: hashes of every file above, cosign keyless signature (Rekor-logged) |
| build-provenance attestations (not files) | `actions/attest-build-provenance` over `SHA256SUMS`, one per file |

`SHA256SUMS` is written **after** `latest.json`, so the manifest is hashed, signed and attested
with everything else. The last step of `finalize` fails if the draft holds any file that
`SHA256SUMS` does not cover (stale files from an earlier run must be deleted by hand).

## Signing

| What | How | Secret |
| --- | --- | --- |
| `SHA256SUMS` | cosign keyless (Sigstore): identity `…/.github/workflows/release.yml@refs/tags/<tag>`, issuer GitHub OIDC. No long-lived key. | none (`id-token: write`) |
| Updater artifacts (`.sig`) | Tauri's updater signature (minisign key pair), made by the `sign-updater` job (below); the app verifies against the compiled-in `plugins.updater.pubkey` before anything is written. **A second trust root** (R-UPD): whoever holds the private key can ship code to in-app installs. | **environment** secret `TAURI_SIGNING_PRIVATE_KEY` (+ `_PASSWORD`, may be empty) of environment `release` |
| macOS | Developer ID + notarization when the `APPLE_*` secrets exist; otherwise ad-hoc (`-`), hardened runtime, not notarized | `APPLE_*` (optional) |
| Windows | Azure Artifact Signing (`AZURE_*` + `artifact-signing-cli =0.12.0`) or a PFX; otherwise unsigned | `AZURE_*` / `WINDOWS_CERTIFICATE*` (optional) |
| `.rpm` | GPG when `TAURI_SIGNING_RPM_KEY` exists | optional |

### Updater signing (`sign-updater`)

The build jobs never hold the updater key (M-17): with the key in the job environment every
npm devDependency, cargo build script and proc macro of the app could read it. Instead:

- The CI config overlay forces `createUpdaterArtifacts: false`. That is what makes the Tauri
  CLI demand `TAURI_SIGNING_PRIVATE_KEY` (it only does so when updater artifacts are on), and
  it has no other effect: `plugins.updater.pubkey` is still compiled in from the merged config
  (checked in `tauri-cli` 2.12.4 `interface/rust.rs` and `bundle.rs`). The repository default
  stays `true` so a local `pnpm tauri build` without `--no-sign` still fails loudly.
- The macOS universal job creates `Mooring_universal.app.tar.gz` itself after tauri-action
  (`COPYFILE_DISABLE=1 tar -czf … -C bundle/macos Mooring.app`): the signed, notarized bundle
  as the archive's single top-level entry, the layout `tauri-plugin-updater` extracts (it strips
  the first path component). The NSIS `-setup.exe` and the AppImage are their own updater
  artifacts in the v2 format, so nothing else is made. A `.sig` among the build outputs fails
  the job. No throwaway build-time key is involved.
- `sign-updater` (`needs: build`, `contents: read`, `environment: release`, **no checkout**)
  downloads the `bundles-*` artifacts, fetches `@tauri-apps/cli` 2.12.4 and its
  `cli-linux-x64-gnu` binding as npm tarballs from `registry.npmjs.org`, checks each SHA-512
  against the value pinned in the workflow (`TAURI_CLI_SHA512`, `TAURI_CLI_LINUX_X64_SHA512` =
  the `integrity` values in `pnpm-lock.yaml`), unpacks them with `tar` (no `npm install`, no
  lifecycle scripts) and runs `tauri signer sign --app-version <version>` for every
  `*.app.tar.gz`, `*-setup.exe` and `*.AppImage`. The key is in the environment of that one
  step only; the signer's stdout (it echoes the public signature) is discarded. The `.sig`
  files go up as the `updater-signatures` artifact. Without the secret the job reports
  `signed=false` and the release has no in-app update channel.
- `--app-version` writes `version:<v>` into the signed trusted comment, as `tauri build`
  would; clients with `requireSignedVersion` refuse a manifest that announces another version.
- `finalize` merges the signatures with the installers, writes `latest.json`, hashes, signs
  and attests everything and uploads the `.sig` files with the manifest.
- `scripts/release/lint-workflows.sh` runs in `create-release`: `secrets.TAURI_SIGNING_PRIVATE_KEY`
  may be referenced by the `sign-updater` job of `release.yml` only (any other job or workflow
  file fails the run), and `RUST_TOOLCHAIN` must match `release-repro.yml`.

Bumping the Tauri CLI used by `sign-updater`: take the new `integrity` values from
`pnpm-lock.yaml` after `pnpm update @tauri-apps/cli` and update `TAURI_CLI_VERSION` and the two
SHA-512 values together; the job also asserts `tauri-cli <version>` from `--version`.

Local unsigned bundles use `pnpm tauri build --no-sign` (that flag also skips platform code
signing, which is why CI does not use it).

## Updater channel

`plugins.updater` in `tauri.conf.json`: the public key, the endpoint
`https://github.com/yyasar21/Mooring/releases/latest/download/latest.json` and
`windows.installMode: "passive"` (progress bar, no prompts; the NSIS installer is per-user, so
no elevation). `latest.json` lists, per platform key: `darwin-{aarch64,x86_64}` → the universal
`.app.tar.gz`; `windows-x86_64` → the NSIS installer (the MSI is per-machine and never offered);
`linux-{x86_64,aarch64}` → the AppImage. Platforms without a signed artifact are absent. The
Rust side (plugin registration gated on the pubkey, `update_*` commands, install-mode matrix) is
task U0; nothing in any capability grants `updater:*` to the WebView.

## Reproducible-build check

`release-repro.yml` builds the Rust workspace crates (`default-members`, everything but
`mooring-app`) twice on `ubuntu-22.04` from two different checkout paths with a pinned
toolchain (`RUST_TOOLCHAIN` in the workflow), `--release --locked`, `SOURCE_DATE_EPOCH` = commit
time, `--remap-path-prefix` for the source tree and a separate `CARGO_HOME` per build, then
compares `sha256sum` over `target/…/release/deps/libmooring_*.{rlib,rmeta}`. A difference fails
the job and uploads a diffoscope report. Runs weekly, on `v*` tags and on dispatch. The Tauri
bundles are out of scope (installer tools embed timestamps and host data; provenance covers them).

## Cutting a release

1. Gate (ADR-0018 §6): QA per OS, green nightly fuzz, `security.yml` and `make check` green on
   three OSes, fresh-install smoke, security review with zero critical/high.
2. `CHANGELOG.md` has an `## [Unreleased]` section describing the release.
3. `make release VERSION=x.y.z` on a clean `main`, then `git push origin main vx.y.z`.
4. Watch `release.yml` (about 30–40 minutes). The `sign-updater` job waits for the owner's
   approval of the `release` environment (Actions → the run → *Review deployments*); `publish`
   and `finalize` follow. Review the draft: notes, asset list, job summaries (`signed:
   true/false`, `updater artifact: true/false`).
5. `scripts/release/verify-release.sh vx.y.z` (needs `gh` authenticated for the draft, `cosign`
   3.x; `minisign` optional for the updater signatures). It checks the cosign signature
   (identity `release.yml@refs/tags/vx.y.z`, printing the signing run's workflow and source
   commits), every hash, that no asset is unlisted, provenance per file and, when present,
   `latest.json` against the `.sig` files and the public key.
6. Install on at least one machine per OS, then **Publish release**. That triggers
   `release-homebrew.yml`, which re-verifies `SHA256SUMS` and pushes the Cask to the tap.

A failed job is re-run from the Actions page (same run, same tag ref) or with
`workflow_dispatch` started **from the tag** (*Use workflow from* → Tags → `vx.y.z`, `tag`
input = the same tag; uploads into the same draft with `--clobber`). A dispatch from `main` is
refused by `create-release`: the signature identity must be the tag ref. A published release is
never rebuilt: cut a patch version.

### GitHub settings the pipeline relies on (owner)

- Environment **`release`**: required reviewer = the owner; *Deployment branches and tags* →
  *Selected* with the tag rule `v*` (nothing else). Secrets `TAURI_SIGNING_PRIVATE_KEY` and
  `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` are **environment** secrets of `release`. **Do not create
  them as repository secrets**: a repository secret can be read by any workflow a writer starts
  on any branch, and `lint-workflows.sh` cannot see where a secret is defined.
- Tag ruleset for `v*`: creation, update and deletion restricted to the owner (a moved tag
  would also trip the source-commit warning of `verify-release.sh`).
- Branch ruleset for `main`: pull request + review required, no force push, no deletion.

## Tests

`scripts/release/tests/run.sh` runs the bash tests (`verify-release.test.sh`,
`updater-manifest.test.sh`, `lint-workflows.test.sh`) against fake release directories and
workflow fixtures with stub `gh`, `cosign` and `minisign`; no network. Workflows: `actionlint`
when installed, else `yaml.safe_load`.
