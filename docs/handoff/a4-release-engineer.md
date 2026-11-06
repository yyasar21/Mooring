# A4 R1 — release-engineer handoff

Date: 2026-11-06 · Worktree from `a4` @ `351e30c` · ADR-0018 (R1 row in `a4-architect.md`)

## Done

- **Updater manifest in `finalize`**: `scripts/release/updater-manifest.sh <dist> <tag> [repo]`
  writes `latest.json` (tauri-plugin-updater dynamic format) from the `.sig` files: universal
  `.app.tar.gz` → `darwin-aarch64` + `darwin-x86_64` (an arch-specific archive wins), NSIS
  `-setup.exe` → `windows-<arch>` (the MSI is never offered: per-machine), AppImage →
  `linux-<arch>`; missing platforms are absent; no `.sig` at all → notice, no file, exit 0.
  `pub_date` = the tagged commit's time (stable across re-runs). Written **before**
  `SHA256SUMS`, so it is hashed, cosign-signed and attested with the rest.
- **`release.yml`**: `create-release` uploads `scripts/release/*.sh` as the `release-scripts`
  artifact; `finalize` (still no checkout) downloads it, `bundles-*` and `sbom`, runs the
  manifest script, then SHA256SUMS + cosign + provenance + upload (incl. `latest.json`). The CI
  config overlay now sets `createUpdaterArtifacts` = presence of `TAURI_SIGNING_PRIVATE_KEY`
  (repo default is `true`; the per-arch macOS jobs and forks get `false`). tauri-action stays
  at `1deb371b…` (v1.0.0). Pre-release behaviour documented in the header.
- **`tauri.conf.json`**: `bundle.createUpdaterArtifacts: true`; `plugins.updater` =
  `{ pubkey: <owner's public key>, endpoints: [releases/latest/download/latest.json],
  windows.installMode: "passive" }` (progress bar, no prompt; NSIS per-user needs no
  elevation). No `dangerousInsecureTransportProtocol`. `cargo check -p mooring-app` passes
  (tauri-build parses the config).
- **`release-repro.yml`** (ADR-0018 §4): `default-members` built twice on `ubuntu-22.04` from
  `build-a/src` and `build-b/deeper/path/src`, Rust **1.97.0** pinned (`RUST_TOOLCHAIN`; the
  local dev toolchain, above the `rust-version = 1.95` floor), `--release --locked`,
  `SOURCE_DATE_EPOCH` = commit time, `--remap-path-prefix` for source and a separate
  `CARGO_HOME` per build, `codegen-units=1`; `sha256sum` over
  `deps/libmooring_*.{rlib,rmeta}`; mismatch → diffoscope HTML report artifact + failure.
  Weekly (Mon 04:17 UTC), on `v*` tags, on dispatch with a `ref`.
- **`verify-release.sh`**: new step 5 — when `latest.json` is on the release, every platform
  entry must point at `https://github.com/<repo>/releases/download/<tag>/`, name an asset of
  the release, equal its `.sig`, and both must be in `SHA256SUMS`; with `minisign` installed,
  each updater artifact is verified against the public key (`MOORING_UPDATER_PUBKEY`
  overrides the compiled-in default). `python3` is now required (JSON parsing with `-I`).
- **Tests** moved to `scripts/release/tests/` (`run.sh`, `verify-release.test.sh` 16 cases,
  `updater-manifest.test.sh` 20 cases), stub `gh`/`cosign`/`minisign`, no network.
- **Version** bumped to `0.1.0-rc.2` with `bump-version.sh` (Cargo.toml, 10 crate pins,
  Cargo.lock, tauri.conf.json, 3 package.json). `CHANGELOG.md` deliberately **not** rolled:
  the rc is a dry run; `make release VERSION=0.1.0` rolls it once.
- **Docs**: `docs/developer-guide/release-process.md` rewritten for the ADR flow (no
  minisign wording); `docs/release.md` assets table, verification, Updates section (on
  demand, no elevation, pre-releases invisible), secrets note, local build `--no-sign`;
  `docs/user-guide/getting-started.md` "Installing an unsigned build" (verify before the
  Gatekeeper/SmartScreen override, macOS 11 minimum per `tauri.conf.json`).

## Dry run (orchestrator)

After merging the worktree branch into `a4` (or `main`):

```sh
git tag -a v0.1.0-rc.2 -m "Mooring 0.1.0-rc.2 (pipeline dry run)" <merge commit>
git push origin v0.1.0-rc.2
```

Expected: a **draft pre-release** with macOS dmg/pkg ×3, Windows exe + msi, Linux `.deb` ×2
(no rpm/AppImage: `-` in the version), two SBOMs, `SHA256SUMS` + `.sigstore.json`, and, only
if `TAURI_SIGNING_PRIVATE_KEY` exists, `.sig` files + `latest.json` (platforms: darwin ×2,
windows-x86_64; no linux). `release-repro.yml` runs on the same tag. Then
`scripts/release/verify-release.sh v0.1.0-rc.2` (needs `gh auth`, cosign 3.x; `minisign`
optional). The draft stays a draft; delete it and the tag after the run, or keep it for the
Fedora smoke (rpm/AppImage must be built locally from the rc commit with a numeric version
override: `pnpm tauri build --no-sign --bundles rpm,appimage --config '{"version":"0.1.0"}'`).

Re-runs: `workflow_dispatch` with `tag: v0.1.0-rc.2` uploads into the same draft; stale assets
must be deleted by hand, or `finalize` fails its last step.

## Owner actions (secrets never in the repo or a chat)

1. **Updater key** (ADR-0018 §7 step 2): the public key is already in `tauri.conf.json`.
   Create the secrets `TAURI_SIGNING_PRIVATE_KEY` (file content of
   `~/.tauri/mooring-updater.key`) and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` (**empty value**
   for a key without a password; the workflow passes it through as-is). The Tauri CLI fails the
   build if the private key does not match the configured public key.
2. **Actions settings**: allow GitHub Actions; `GITHUB_TOKEN` may stay read-only (jobs request
   `contents: write`, `id-token: write`, `attestations: write` individually). The repo must be
   public for `ubuntu-22.04-arm`, Sigstore keyless and the attestation API on the free plan.
3. **Homebrew tap**: public repo `yyasar21/homebrew-mooring` with `Casks/`; fine-grained PAT
   (that repo only, Contents read/write) → secret `HOMEBREW_TAP_TOKEN`.
4. Optional, no code change: `TAURI_SIGNING_RPM_KEY` / `_PASSPHRASE`; Apple Developer ID
   (`APPLE_*`), Azure Artifact Signing (`AZURE_*` secrets + `AZURE_SIGNING_*` variables) or a
   PFX (`WINDOWS_CERTIFICATE*`) — table in `docs/release.md`.
5. Keep the updater private key in the password manager only; rotation = new key pair, new
   `pubkey` in `tauri.conf.json`, new release (R-UPD).

## For the orchestrator

- Out of my scope, still saying **minisign** for `SHA256SUMS`: `README.md:148` and
  `docs/roadmap.md:68` (A4 bullet). Replace with "Sigstore (cosign keyless) signed
  `SHA256SUMS`". `.claude/agents/release-engineer.md` already says cosign (checked);
  `docs/handoff/public-release.md`, `a1-security-reviewer-3.md` and `a4-architect.md` mention
  minisign only historically — leave them.
- `Makefile` `bundle` target: `cargo tauri build` now fails locally without the updater key
  (`createUpdaterArtifacts: true`). Change it to `cargo tauri build --no-sign`
  (`README.md:161` and `docs/developer-guide/building.md:103` describe it as unsigned, which
  stays true).
- `docs/handoff/index.md` row for this note.
- U0 (rust-core) registers `tauri-plugin-updater` gated on `plugins.updater.pubkey`; the
  config is in place, so an empty pubkey can no longer be the "unconfigured" path in this repo
  — U0's `update.unconfigured` applies to forks that blank the key.

## Left open

- Neither workflow has run yet; the rc.2 tag is the first execution of the manifest step, the
  script hand-off artifact and `release-repro.yml`. Riskiest: `--remap-path-prefix` alone may
  not make every rlib byte-identical (build-script outputs, `env!` paths); the diffoscope report
  shows what to fix.
- `actionlint` is not installed here (no network for `go install`); workflows were validated
  with `yaml.safe_load` only. Run `actionlint` on the Mac before merging if available.
- `shellcheck` not installed here either; `bash -n` + the tests only.
- The updater manifest uses plain `<os>-<arch>` keys; if U0 sets a custom `target` in the
  plugin builder, the keys must follow.
- Windows ARM64 is not built, so `windows-aarch64` never appears in `latest.json`.

## Test evidence

- `scripts/release/tests/run.sh`: 36 passed, 0 failed (verify 16, manifest 20).
- `bash -n` on every `scripts/release/**/*.sh`; `yaml.safe_load` on `release.yml`,
  `release-repro.yml`, `release-homebrew.yml`.
- `CARGO_TARGET_DIR=/home/claude/nexus/target cargo check -p mooring-app --offline`:
  finished (3m50s), config with `plugins.updater` accepted by tauri-build.
- `bump-version.sh 0.1.0-rc.2`: 17 files changed, CHANGELOG reverted on purpose.
- Tauri CLI 2.12.4 binary strings confirm: `--no-sign` skips updater signing; without a key
  and with `createUpdaterArtifacts` on, the bundler errors "A public key has been found, but
  no private key"; a key/pubkey mismatch is rejected.
