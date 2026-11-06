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

---

# A4 R2 — release-engineer handoff (security review 7: M-17, N-57, N-58, N-8, L-14)

Date: 2026-11-06 · Worktree from `a4` @ `756484b` · Owner decisions, no acceptance route.

## Done

- **M-17 — the updater key never reaches the build tree** (`release.yml`):
  - `build` jobs do not reference `TAURI_SIGNING_PRIVATE_KEY*` at all. The CI config overlay
    forces `createUpdaterArtifacts: false`; that is the only thing that makes the Tauri CLI
    demand a key (`tauri-cli` 2.12.4 `interface/rust.rs` builds `UpdaterSettings` only when
    it is on; `bundle.rs::sign_updaters` returns early without them), and `plugins.updater.pubkey`
    is still compiled in. **No throwaway build-time key**: the macOS universal job makes
    `Mooring_universal.app.tar.gz` itself after tauri-action (`COPYFILE_DISABLE=1 tar -czf …
    -C bundle/macos Mooring.app`; `tauri-plugin-updater` 2.14.1 strips the first path
    component, so one top-level `Mooring.app` entry is the required layout, verified in the
    step). The NSIS `-setup.exe` and the AppImage are their own v2 updater artifacts. A `.sig`
    among the build outputs fails the job.
  - New job **`sign-updater`**: `needs: [create-release, build]`, `permissions: contents:
    read`, `environment: release`, **no checkout**, no `npm`/`cargo` install. Downloads
    `bundles-*`; fetches `@tauri-apps/cli@2.12.4` and `@tauri-apps/cli-linux-x64-gnu@2.12.4`
    as npm tarballs from `registry.npmjs.org`, checks SHA-512 against the values pinned in the
    workflow env (`TAURI_CLI_SHA512`, `TAURI_CLI_LINUX_X64_SHA512`; they equal the `integrity`
    in `pnpm-lock.yaml` and the hashes I computed from the registry downloads in this session),
    unpacks with `tar` (no lifecycle scripts), asserts `tauri-cli 2.12.4`, then runs
    `tauri signer sign --app-version <version> <file>` for `*.app.tar.gz`, `*-setup.exe`,
    `*.AppImage`. The key and password are in that step's `env:` only; signer stdout (public
    signature) is dropped; each `.sig` is checked to be one base64 line. Output `signed`;
    artifact `updater-signatures`. Without the secret: notice, `signed=false`, no `.sig`.
  - `finalize` needs `sign-updater`, downloads `updater-signatures` when `signed == 'true'`,
    flattens them next to the installers, and uploads `*.sig` with `latest.json`.
  - `create-release` runs **`scripts/release/lint-workflows.sh`** (M-17 (4)):
    `secrets.TAURI_SIGNING_PRIVATE_KEY*` may appear in the `sign-updater` job of `release.yml`
    only (every other job and every other `.github/workflows/*.yml` fails the run); the
    `sign-updater` job must exist; `RUST_TOOLCHAIN` must be equal in `release.yml` and
    `release-repro.yml` and no `toolchain: stable` may remain. Tests:
    `scripts/release/tests/lint-workflows.test.sh` (8 cases incl. the real workflows).
  - `create-release` refuses a run whose `GITHUB_REF` is not `refs/tags/<tag>` (N-58 below and
    the environment's tag-only policy make a branch dispatch pointless).
  - Local dry run of the signer path with a throwaway key: `signer generate --ci`, `signer sign
    --app-version 0.1.0` from the unpacked tarball layout; the `.sig` decodes to a minisign
    signature with trusted comment `timestamp:…\tfile:…\tversion:0.1.0`.
- **N-57**: `release.yml` top-level `RUST_TOOLCHAIN: "1.97.0"`, used by the build matrix and
  the SBOM job (`dtolnay/rust-toolchain` SHA pin unchanged). `lint-workflows.sh` keeps it
  equal to `release-repro.yml`.
- **N-58**: `verify-release.sh` accepts the identity
  `…/release.yml@refs/tags/<tag>` only (no `refs/heads/main`); `release-homebrew.yml` uses the
  same regexp. The script prints the signing run from the Fulcio extensions of the bundle's
  certificate (`identity`, `workflow-commit`, `source-commit`, `run`; `python3 -I`, byte search
  by OID, informational) and warns when the source commit differs from what the tag points at
  (`gh api`, best effort). Tests: identity regexp passed to cosign, no `heads/main`, issuer
  pin, signer summary from a synthetic certificate (22 cases now).
- **N-8**: `release-homebrew.yml` clones the public tap anonymously and pushes with a
  `GIT_ASKPASS` script that answers `x-access-token` / the token from the step environment;
  `credential.helper=` and `GIT_TERMINAL_PROMPT=0`; the step fails if `x-access-token` shows
  up in `tap/.git/config`. No token in any URL.
- **L-14**: Docker Hub (`registry-1.docker.io`, `hub.docker.com`) is 403 through the session
  proxy, so the digest could not be resolved here. `security.yml` keeps the `# TODO(L-14):
  digest` marker with the exact commands (below).
- Docs: `docs/developer-guide/release-process.md` (sign-updater section, run-from-tag rule,
  GitHub settings), `docs/release.md` (assets, verification identity, flow with approval gate,
  environment secrets).

## Owner actions (R2)

1. **Environment `release`** (Settings → Environments → New): required reviewers = the owner;
   *Deployment branches and tags* → *Selected branches and tags* → add tag rule **`v*`** and
   nothing else. Then add the **environment secrets** `TAURI_SIGNING_PRIVATE_KEY` (content of
   `~/.tauri/mooring-updater.key`) and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` (empty value for a
   key without a password). **Do not create the key secret as a plain repository secret**; if
   one exists from R1 instructions, delete it. Repository-level `TAURI_SIGNING_*` secrets would
   be readable by any workflow a writer dispatches on any branch, and the lint cannot see where
   a secret is defined.
2. **Tag ruleset** (Settings → Rules → Rulesets → New tag ruleset): target `v*`; restrict
   creations, updates and deletions to the repository owner (bypass list = owner only).
3. **Branch ruleset on `main`**: require a pull request with one review, block force pushes
   and deletion; the owner may be on the bypass list for the `chore(release)` commit, or that
   commit goes through a PR.
4. The platform secrets (`APPLE_*`, `AZURE_*`, `WINDOWS_*`, `TAURI_SIGNING_RPM_KEY*`) stay
   repository secrets for now (the build jobs need them and run third-party code; R-REL accepts
   that). Moving them to `release` would require `environment: release` on the build matrix
   (six approvals per release, or one if the reviewer approves all jobs at once); say so if
   wanted.
5. **L-14 digest**, on a machine with Docker Hub access:
   `docker manifest inspect --verbose semgrep/semgrep:latest | jq -r '.[0].Descriptor.digest // .Descriptor.digest'`
   (or `docker buildx imagetools inspect semgrep/semgrep:latest --format '{{.Manifest.Digest}}'`),
   note the version `docker run --rm semgrep/semgrep:latest semgrep --version` prints, and
   replace the `image:` line in `security.yml` with `semgrep/semgrep:<version>@sha256:<digest>`.
6. Re-runs: `workflow_dispatch` must be started **from the tag** ("Use workflow from" → Tags);
   a run from `main` fails in `create-release` by design.

## Left open

- Neither workflow has run with these changes. First real exercise: the rc tag. Riskiest
  points: `environment: release` on a job whose secret may not exist yet (the job then
  reports `signed=false`, which is the intended fork behaviour); the hand-made `.app.tar.gz`
  on a real macOS runner (layout is asserted in the step); `download-artifact` of
  `updater-signatures` is skipped via the job output, so no "artifact not found" path exists.
- `actionlint` and `shellcheck` are not installed here and the binary download was denied by
  the sandbox; workflows were validated with `yaml.safe_load`, scripts with `bash -n` and the
  test suite. Run `actionlint` on the Mac before merging.
- `tauri.conf.json` keeps `createUpdaterArtifacts: true` (CI overrides it to `false`). It now
  only serves to make a local `pnpm tauri build` without `--no-sign` fail loudly; flipping the
  repository default to `false` would be equally valid and remove the `--no-sign` requirement
  from `make bundle` — orchestrator's call (bundle config is my scope, but ADR-0018 states the
  current value).
- `sign-updater` does not check that the private key matches the compiled-in public key (the
  CLI's `signer sign` cannot); a mismatch surfaces in `verify-release.sh` (minisign) before
  publication and in the app at update time. Could be added with a `minisign` download pinned
  by SHA in the job if wanted.
- Windows ARM64 still not built; Linux updater artifacts absent on pre-releases (no AppImage).

## Test evidence

- `scripts/release/tests/run.sh`: 50 passed, 0 failed (verify 22, manifest 20, lint 8).
- `bash -n` on every `scripts/release/**/*.sh`; `python3 yaml.safe_load` on `release.yml`,
  `release-homebrew.yml`, `release-repro.yml`, `security.yml`; the heredoc inside the homebrew
  `run:` block checked to de-indent to a column-0 terminator.
- Tarball hashes: `cli-2.12.4.tgz` and `cli-linux-x64-gnu-2.12.4.tgz` downloaded from
  `registry.npmjs.org` in this session; `openssl dgst -sha512` equals the `pnpm-lock.yaml`
  integrity for both; the registry metadata (`dist.integrity`) agrees.
- Signer dry run with a throwaway key (never printed, deleted with the scratchpad): see M-17.
