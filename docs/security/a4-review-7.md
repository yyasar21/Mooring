# A4 security review 7 — release v0.1.0: pipeline, updater, importers, LDAPS, network tools (ADR-0018..0020)

Reviewer: security-reviewer · 2026-11-06 · Range `git diff fc41747..HEAD` (`a4` @ `cfca0ff`,
480 files, +27 594 / −414). Focus: `.github/workflows/release{,-repro}.yml`,
`scripts/release/{updater-manifest,verify-release}.sh`, `src-tauri/tauri.conf.json`,
`src-tauri/src/updater/*`, `src-tauri/src/commands/{update,import,import_source,import_dto,
ldap_import,net}.rs`, `src-tauri/src/import_plans.rs`, `crates/mooring-import` (all importers,
`ldap/*`), `crates/mooring-http/src/{tls,connect}.rs`, `crates/mooring-net`,
`crates/mooring-store/src/import.rs`, the guard table, the capability tests, `apps/desktop`
(import wizard, LDAPS form, Updates card, Network card, About, onboarding) and `site/`.
`crates/mooring-testsrv` was read as test scope only. A small rust-core fix round for Q1's gaps
ran concurrently and is not in this range.

Inputs:
- [ADR-0018](../adr/0018-release-v0-1-0.md), [ADR-0019](../adr/0019-importers-and-onboarding.md)
  with its I2 amendment, [ADR-0020](../adr/0020-network-tools.md).
- Handoffs `a4-architect.md`, `a4-release-engineer.md`, `a4-rust-core-{u0,i1,i2,n1}.md`,
  `a4-ui-{u1..u4,site}.md`, `a4-qa-q1.md`.
- [Review 6](a3-review-6.md) (6b, 6c) with its carried tag conditions; the "before the first
  public release" items of [review 3](a1-review-3.md) and [review 4](a1-review-4.md) (L-11,
  L-12..L-14, N-8, N-9, G-1; M-12, L-19); the [threat model](threat-model.md).

Evidence gathered here (Linux x86_64, no build, no test run — the orchestrator runs the gate):
- `cargo deny --offline check`: advisories ok, bans ok, licenses ok, sources ok.
- `cargo audit --no-fetch --db <local copy, 1409 advisories, 847 crates>`: one vulnerability,
  RUSTSEC-2023-0071 (`rsa`, R-RSA, ignored in `deny.toml`). Unmaintained warnings:
  `atomic-polyfill`, `basic-toml`, `proc-macro-error`, `zbus_names`, `zvariant*` (all pre-A4),
  and `pin-utils` (RUSTSEC-2026-0441, via `sspi` → `async-dnssd`, R-RDP-FFI tree, pre-A4 edge).
  None reaches an A4 crate.
- `cargo tree --workspace --target all -i` for every package added to `Cargo.lock` (table in §6).
- Registry sources read: `tauri-plugin-updater` 2.14.1 (`src/updater.rs` check / download /
  verify / `verify_signed_version`, the AppImage, deb/rpm and macOS install paths, `config.rs`),
  `reqwest` 0.13.5 (`https_only` on redirects, `redirect.rs:324`).
- **Not run:** builds, tests, `cargo geiger` (not installed), `gitleaks`, `semgrep`,
  `pnpm audit`, cargo-fuzz, `actionlint`, any workflow, any per-OS check.

## Verdict: `APPROVE WITH NITS` (merge) — the `v0.1.0` tag stays conditional

No blocker. The three new surfaces each hold their ADR's central property:

- **Release.** M-7 is closed: third-party code runs only in `contents: read` jobs;
  `finalize` (the only job with `id-token: write`) has no checkout and runs only pinned
  cosign-installer, attest-build-provenance and our own scripts from the tag. It hashes the
  workflow artifacts, not the draft, and then fails if the draft holds anything unsigned.
  Every action is SHA-pinned. `latest.json` is built from the `.sig` files and is itself in
  `SHA256SUMS`. `verify-release.sh` now fails closed (L-12) and cross-checks the manifest.
- **Updater.** Rust-only. The plugin is registered only with a pubkey. No capability or
  permission set names `updater:` (a test pins it). The four `update_*` commands are main-only
  and vault-gated. The install-mode matrix refuses deb, rpm, MSI, Homebrew, unwritable and
  unbundled installs before the plugin is called. The minisign signature is checked against
  the compiled-in key before any byte is written. Redirects stay `https` (reqwest enforces
  `https_only` on every hop). Downgrades are refused twice. Release notes are plain text,
  sanitised and capped.
- **Importers / LDAPS / net.** Every parser is capped before allocation, refuses `DOCTYPE`,
  is fuzzed and never echoes input in an error. Plans stay in Rust: 128-bit id, single use,
  10 min TTL, cleared on lock, secrets `Zeroizing`. Plaintext secrets are read only with the
  opt-in and only from Termius. mRemoteNG passwords are never read. The apply is one
  transaction into a new root folder. The LDAP reader was rewritten so that no hostile BER
  reaches a recursive parser: an iterative scan (256 KiB, depth 32) runs first. It sends only
  bind, search, abandon and unbind. The bind password is sent only after a trusted handshake,
  and TOFU goes through the B-6 three-slot Gate. Network tools run fixed absolute paths with a
  cleared environment, no shell, a `Target` that can never start with `-` or `/`, the read-only
  `WgQuery` set, output caps and kill-on-deadline. Nothing elevates.

There is **one Medium**, M-17. The updater private key reaches the environment of every npm and
cargo build script in the `build` jobs. No GitHub Environment fences the key off from workflows
on other refs. Whoever holds the key plus a way to serve `latest.json` ships code to every
in-app install. The key is not set yet (ADR-0018 §7 step 2), so **M-17 is a condition before
the secret is created**, not a merge stop.

## Findings

Numbering continues from review 6 (last used: B-6, M-16, L-38, N-50).

| ID | Sev | Where | Finding | Exact fix |
| --- | --- | --- | --- | --- |
| **M-17** | Medium (condition before `TAURI_SIGNING_PRIVATE_KEY` is created) | `.github/workflows/release.yml:184`, `:204-208` (`put TAURI_SIGNING_PRIVATE_KEY` into `$GITHUB_ENV`), `:284-289` (tauri-action → `pnpm tauri build` → `beforeBuildCommand` + every cargo build script and proc macro); `:38-43` (`workflow_dispatch`), no `environment:` on any job | **The updater key is exposed to the whole build tree.** The key is a second release trust root (R-UPD): the app installs whatever it signs, with no human gate on the client. It is written to the job environment *before* tauri-action runs, so every npm devDependency used by the Vite build and every crate build script or proc macro of the app (≈ 850 crates) can read and exfiltrate it (T6). R-REL accepted that for the platform certificates, but those still need notarization or SmartScreen reputation. This key needs neither, never expires and can only be rotated by shipping a release. Second, the secret is a repository secret: any workflow run that a writer starts on any branch (a modified `release.yml` dispatched from a branch, or any `on: push` workflow) can read it. **Exploit chain:** stolen key + control of the manifest response (repo write, or a TLS MITM on `github.com` with a CA the OS trusts, e.g. a corporate proxy — the plugin uses the platform verifier) → `latest.json` with a higher version and a URL to a signed payload → code execution on every AppImage, user-writable `.app` and NSIS install that clicks "Install". The client checks nothing else (L-40) | **release-engineer.** (1) Build **without** the key: `createUpdaterArtifacts: false` in every build job; create the updater archives yourself in the build job (`tar -czf Mooring_<arch>.app.tar.gz -C …/macos Mooring.app` on macOS; the NSIS `-setup.exe` and the `.AppImage` are their own updater artifacts in the v2 format). (2) New job `sign-updater`: `needs: build`, `contents: read`, no checkout, `environment: release`. It downloads `bundles-*`, installs one pinned, checksum-verified signer and runs `tauri signer sign` per artifact. Candidates: `@tauri-apps/cli@2.12.4` with `--ignore-scripts` from the lockfile's integrity hash, or a prebuilt `tauri-cli` release binary with its SHA-256 in the workflow. It uploads the `.sig` files as an artifact that `finalize` merges. No project code and no other third-party code runs there. (3) Move `TAURI_SIGNING_PRIVATE_KEY{,_PASSWORD}` (and the Apple/Azure/RPM secrets when they arrive) to **environment secrets** of `release`: deployment policy "tags matching `v*`", required reviewer = owner. Add a tag ruleset (`v*`: create/update/delete restricted to the owner) and a branch ruleset on `main` (PR + review, no force push). (4) Test: a workflow lint step that fails if `TAURI_SIGNING_PRIVATE_KEY` is referenced outside `sign-updater`. If the owner prefers to keep signing in the build job, record that as an explicit acceptance under R-UPD; (3) is required either way |
| L-39 | Low (before `0.1.1`; recommended for `0.1.0`) | `src-tauri/tauri.conf.json:82-86` (no `requireSignedVersion`); `src-tauri/src/updater/source.rs:351` (`MissingSignedVersion` not mapped) | `latest.json` is unsigned. With `require_signed_version` off (the plugin default, `config.rs:125-135`), a signature without a version in its trusted comment is accepted for **any** announced version (`updater.rs:1930-1938`). Whoever controls the manifest can therefore pair "0.9.9" with an older, validly signed package that has a known bug (a downgrade disguised as an upgrade), as soon as two releases exist. Signatures that *do* carry a version are already bound | Set `"requireSignedVersion": true` in `plugins.updater` now: no older release exists, so no user can be stranded. In the rc.2 dry run, confirm that Tauri CLI 2.12.4 writes the version: `minisign -V` prints the trusted comment, and `verify-release.sh` step 5 should assert `version:<v>` in it. Map `E::MissingSignedVersion` to `SourceError::Signature`. Test: `map_err` table test. QA: a manifest that names a higher version over the rc.2 package → `update.signature` |
| L-40 | Low | `src-tauri/src/updater/source.rs:318-332`, `:380-387`; plugin `updater.rs:623` (`res.json()`), `:875-888` (`buffer.extend` with no cap) | **What `latest.json` can do to the client.** The manifest body and the download are read into memory without a size cap. The download URL may name any `https` host. A hostile manifest (same sources as M-17) can make the client fetch from an attacker host and buffer an unbounded body for up to 30 s (an OOM on a fast link), and it reveals the user's IP to that host. The signature still stops installation. The plugin also honours the OS/env proxy (`system-proxy`), unlike `mooring-http`. Availability side: the 30 s `timeout` covers the **whole** download, so an 80 MB AppImage fails on a slow link | Before `download`, require `update.download_url` to start with `https://github.com/yyasar21/Mooring/releases/download/v<version>/` (the repo and version from the build, the asset name `[A-Za-z0-9._-]+`), else `update.manifest`. Download with a capped client instead of `Update::download`: `mooring-http`, or reqwest with `https_only`, a 256 MiB cap from `Content-Length` and a running count, and a 10 min overall deadline with a 30 s idle timeout. Then call `update.install(bytes)`, which verifies the signature itself (`updater.rs:921-925`). For the manifest, a 64 KiB cap needs the same own fetch plus `restore_update(raw_json)`, which forces `require_signed_version` (`:681-688`). Record `system-proxy` under R-UPD. Tests: a URL outside the prefix → `update.manifest`; an oversize body → `update.network` |
| L-41 | Low | `src-tauri/src/commands/import.rs:113` (`import_key_files && format == Openssh`), `:81-84` (picked file) | The `IdentityFile` opt-in also applies to a **picked** `ssh_config`, i.e. a file from someone else (T4). A hostile "connection pack" can name `~/.ssh/id_ed25519` under `Host build.attacker.example`. With the box ticked, the user's real private key is copied into the vault as an `ssh_key` credential, named by the attacker and bound to the attacker's host. From then on that key is offered to that server, which confirms the key and links identities. The `~/.ssh` confinement holds (`import_source.rs:173-177`), but the *mapping* is attacker-chosen | Honour `importKeyFiles` only for `source.known == "openssh"`. With a `pickId`, refuse `importKeyFiles: true` (`import.invalid`), or ignore it and warn `key_files_ignored`. UI: show the key toggle only on the known-location tile. Test: a picked config + `importKeyFiles` → no `ssh_key` credential |
| L-42 | Low (docs; before the tag) | `site/index.html:217-218`, `:357-358`, `:375`; `README.md:149` | Public claims the release does not back: "In-app updater with signed manifests" / "minisign-signed manifests" / "a minisign-signed updater manifest" (the manifest is **not** signed; the artifacts are, see L-39); "Code-signed and notarized installers" listed for A4 (ADR-0018 §2: v0.1.0 ships ad-hoc / unsigned); "Mooring connects only to the hosts and services you open" (the update check contacts `github.com` on demand or when opted in) | Say "updater artifacts signed with the Mooring updater key; the manifest is unsigned and bound by the signed version" (after L-39). Move "code-signed and notarized installers" to "later, when certificates exist" and say "v0.1.0 installers are unsigned (macOS ad-hoc); verify `SHA256SUMS` first". Add "and `github.com` when you check for updates". Flip the updater / network rows to available when A4 ships (U-site Left open) |
| L-43 | Low | `src-tauri/src/commands/ldap_import.rs:61-63` (`caPem` per call), `:107-117`, `:216-224` (`ldap_import_test`) | **T5 can send any vault password to a host of its choice, in one call, without a dialog.** `ldap_import_test({ url: "ldaps://x.attacker.example", credentialId, caPem })` binds with the password of any `user_password` / `domain_user` credential. With a public-CA certificate, or with the attacker's own CA passed as `caPem`, the chain validates, so the native TOFU dialog never appears. The only trace is `ldap_bind { host, success }`. A T5 could already reach the same result through SSH (create a connection, answer TOFU itself, connect). This path is quieter: no connection in the tree, no session | Either (a) on the first bind of a (credential, `host:port`) pair, ask in the native Gate (three-slot rule): "Send the password of <credential name> to <host>?". Remember the pair in the store (audited), or (b) accept explicitly under R-LDAP-STR / the T5 TOFU entry. Recommended (a). Also audit `ca_pem` use by fingerprint (as L-22 / N-42). Test: a T5-style call against the mock with a `caPem` root → a dialog is requested before the bind frame |
| N-51 | Nit | `src-tauri/src/commands/update.rs:208-250` | `update_install` has no rate limit and is not tied to the last check. A T5 that loops it with `version: "99.0.0"` causes one GitHub request and one `update.refused` row per call (N-43/N-47 class) | Refuse before any network unless `version == rt.last_available()?.version` (`update.none`, audited within the N-47 budget). Apply `MIN_CHECK_GAP` to installs that fail before the download |
| N-52 | Nit | `src-tauri/src/commands/net.rs:187`, `:207`, `:223`, `:233` | Every `net_*` call writes one hash-chained row. `net_port_check` at 1/s is also a slow port scanner of the LAN and of `127.0.0.1` from a T5 (open / closed only, no bytes): R-NET-PROBE | The N-47 budget per command (16 rows/h, then `…_suppressed { count }`). Keep 1/s. Record R-NET-PROBE (done here) |
| N-53 | Nit | `src-tauri/src/import_plans.rs:69` | Expired plans, which may carry plaintext secrets, are pruned only by the next `insert`. Without another preview and without a lock (auto-lock off) they stay in memory past the 10 min TTL | Prune in `with()` (every access) and from the existing 60 s scheduler tick |
| N-54 | Nit | `src-tauri/src/commands/ldap_import.rs:112-115` | An empty stored password makes a simple bind with a name and no password. That is an *unauthenticated* bind (RFC 4513 §5.1.2), which many servers answer with success. The UI then reports "bound as alice" for an anonymous session | Refuse an empty password (`credential.secret_missing`) before connecting (RFC 4513 §6.3.1) |
| N-55 | Nit | `src-tauri/src/updater/install_mode.rs:104-112` | Homebrew casks **move** `Mooring.app` into `/Applications` (an `app` stanza is not a symlink), so `under_homebrew` never matches a cask install. Such an install updates in-app and the cask's recorded version drifts. No elevation results | Detect `…/Caskroom/mooring/` existence (`/opt/homebrew`, `/usr/local`) instead of the bundle path. Fix the comment |
| N-56 | Nit | `src-tauri/src/updater/notes.rs:212-223` | The notes sanitiser removes C0/C1, the bidi controls and a few invisibles, but keeps other `Cf` characters (U+2060..U+2064, tag characters U+E0001..U+E007F) and U+2028/U+2029 | Use the same `Cf`/bidi predicate as the mooring-core name validators (drop every `Cf`), and map U+2028/U+2029 to `\n` |
| N-57 | Nit | `.github/workflows/release.yml:142-145`, `:363-365` (`toolchain: stable`) vs `release-repro.yml:36` (`1.97.0`) | The reproducibility check pins 1.97.0, but releases build with whatever `stable` is that day, so the check says nothing about the shipped compiler | Use one `RUST_TOOLCHAIN` for both workflows (and `cargo-cyclonedx`) |
| N-58 | Nit | `scripts/release/verify-release.sh:184-194`; `release-homebrew.yml` (same identity) | `@refs/heads/main` is accepted for **every** tag: anything merged to `main` later can re-sign an older tag's `SHA256SUMS` through a `workflow_dispatch` re-run. Correct by design (re-runs), but it makes branch protection on `main` part of R-REL | Keep it, and make the `main` ruleset of M-17 (3) an owner action. Print the matched identity and the workflow SHA in the script's summary, so a reviewer sees which run signed |
| N-59 | Nit | `src-tauri/src/commands/import.rs:82-83` | An undetected file (`import.format` from `detect`) writes no `import_refused` row (Q1 Decision 1; the ignored test pins it) | Audit that branch; un-ignore `a4_import::undetected_format_is_audited_as_a_refusal` |
| N-60 | Nit | `src-tauri/src/commands/import.rs:355`, `:367` (sync commands) | `import_preview` (a 16 MiB parse plus a duplicate scan of every connection) and `import_apply` (up to 2 000 seals) are synchronous commands and run on the main thread, so a large hostile file freezes the UI (L-10 class) | `async` + `spawn_blocking`, as L-10 / L-3 did |

### Closure of carried items

| ID | Status in A4 | Evidence / what remains |
| --- | --- | --- |
| M-7 (review 3) | **fixed** | `release.yml` job split as asked: `build` / `sbom` `contents: read`; `publish` no checkout; `finalize` no checkout, no `cargo install`, signs the workflow artifacts, fails on unsigned draft assets (`:499-510`). Updater key: M-17 |
| L-12 | **fixed** | `verify-release.sh:207-214` (unlisted → exit 1, `--allow-unlisted`), `:224` (provenance failure → exit 1). Without `gh attestation` it only warns, which is acceptable for old `gh` |
| L-13 | **open, not triggered** | `release.yml:229-237`: `artifact-signing-cli =0.12.0` still runs only when `AZURE_CLIENT_ID` is set. v0.1.0 has no Azure secrets, so it is a condition **before the Azure secrets are created**, not before this tag |
| L-14 | **partial** | `security.yml`, `ci.yml`, `test-vectors.yml`: every `uses:` is SHA-pinned (grep). `security.yml:45` `semgrep/semgrep` container is still a floating tag (TODO in the file). Pin by digest before the tag |
| N-8 | **open** | `release-homebrew.yml:89` still embeds `TAP_TOKEN` in the clone URL (persisted in `tap/.git/config`). Use `git -c http.extraHeader=…` or `gh repo clone` |
| N-9 | **fixed** | `.gitleaks.toml:20-45`: no test-path exemption; only lockfiles and the literal `10.0.0.1`; CGNAT / ULA rule added |
| G-1 | **owner action** | ADR-0018 §7 step 1: fresh public repository with one squashed commit; never flip the existing repo. Not verifiable from the code |
| L-11 (review 3) | **fixed** | `src-tauri/src/commands/vault.rs:102`, `:116-119` (`reseal_legacy` after the unlock bind, non-fatal) |
| M-12 (review 4) | **fixed** | `crates/mooring-core/src/credential/kubeconfig/mod.rs:165` (non-ASCII mapping keys refused) |
| L-19 (review 4) | **fixed** | `crates/mooring-proto-ssh/src/sftp_upload.rs:37-39`, `:117-128` (target mode read, part file created and re-set with it) |
| L-28 (review 5) | **partial** | `cut_text`, `framebuffer_ops` added (`fuzz-nightly.yml`). Still owed: `rdp_reactivation` (needs a rust-core entry point, Q1 Decision 2), the upstream IronRDP targets, and **one green nightly run** (never run on nightly so far) |
| B-6 per-OS run | **manual** | `docs/qa/native-dialogs.md` on macOS, Windows 11, Fedora — now also covers the `ldap_trust` dialog (same builder) |
| L-31 | **manual** | per-OS page-raised dialog check; R-WEB-UI stays open |
| ADR-0013 E2E per OS | **manual** | unchanged |
| ADR-0016 §4 OIDC interception per OS | **manual** | unchanged |
| Windows L-29 E2E | **manual** | unchanged |
| L-36 VMRC help text | **open (UI)** | `VsphereOptions.tsx:59` hint does not say the ticket is visible to other local users on shared machines |
| N-50 | **open (with F1)** | `secret_source_trust` not built. The LDAP Gate already prompts on `TrustPrompt` only (`ldap_import.rs:186`), the pattern N-50 asks for |

## Rulings

### 1. Release pipeline (ADR-0018 §1, §2, §4)
1. **Pins and permissions: approved.** Top-level `contents: read`. Per job: `create-release` /
   `publish` / `finalize` write the release; only `finalize` has `id-token` + `attestations`.
   All 18 `uses:` references are full SHAs. cosign is `v3.1.4` via the installer's own checksum
   check, syft is `v1.55.0`, `cargo-cyclonedx =0.5.9 --locked`. No cache.
   `persist-credentials: false` everywhere.
2. **Script injection: none found.** `${{ }}` expressions in `run:` blocks are limited to
   matrix constants and step outputs we write. The dispatch `tag` input reaches shell only
   through `env` (`TAG`) and is regex-checked (`:77`).
3. **`latest.json` generation: approved** (`updater-manifest.sh`). It reads only `.sig` files.
   Asset names must match `[A-Za-z0-9._-]+`; signatures must be base64 of ≥ 64 characters. The
   MSI is never offered; two artifacts for one platform are an error. JSON is written by
   `python3 -I` (no hand escaping); `pub_date` = the tag's commit time; the notes are a fixed
   link. The file is written before `SHA256SUMS`, so it is hashed, cosign-signed and attested.
4. **Trust chain: consistent.** `tauri.conf.json` `plugins.updater.pubkey` is byte-equal to
   `verify-release.sh`'s default. It decodes to a minisign public key, id `9F4EDAC489D4B86D`.
   The Tauri CLI refuses a private key that does not match the configured pubkey (R1 handoff).
   The client verifies each artifact against the compiled-in key. `latest.json` itself is
   unsigned; only the signed version (L-39) binds it to an artifact.
5. **`verify-release.sh`: approved.** The cosign identity is
   `release.yml@refs/(tags/<tag>|heads/main)` with the GitHub issuer (N-58). It checks every
   hash, fails on unlisted files and on missing provenance, and step 5 checks the manifest:
   prefix, assets, `.sig` equality, membership in `SHA256SUMS`, and minisign against the
   pubkey when `minisign` is present. Untrusted JSON is parsed with `python3 -I`.
6. **`release-repro.yml`: approved** (`contents: read`, nothing published, two checkouts, two
   `CARGO_HOME`s). Scope and exclusions as ADR-0018 §4; N-57.
7. **Pre-releases:** a `-` version creates a draft **pre-release**. GitHub never serves it as
   `releases/latest`, so rc builds are invisible to the updater: confirmed by construction.
   A maintainer can still mark any release "latest". The comparator then refuses a lower
   version, so this cannot be used to downgrade.
8. **`--no-sign` local bundle (`Makefile` `bundle`): approved.** It skips only the updater
   signature. Nothing local ever holds the key.
9. **Attacker analysis.**
   - *Repo write:* can tag, dispatch and publish a draft, so can ship a release (R-REL; human
     publication is a process control, not a technical one). With the key as a repository
     secret, a writer can also exfiltrate it from any branch (M-17 (3)).
   - *Compromised build runner or dependency (T6):* can alter its own platform's bundles
     before they are hashed. The SBOM, provenance and checksums then faithfully describe the
     bad build. It can also read the platform secrets and, today, the updater key (M-17 (1)).
     It cannot sign `SHA256SUMS` or write the release.
   - *Compromised `GITHUB_TOKEN` of `finalize`:* can upload and sign arbitrary files for the
     run's identity. Mitigated by `finalize` running only pinned code.
   - *Stolen updater key alone:* not enough. The attacker must also control the
     `releases/latest/download/latest.json` response: repo write, or a TLS MITM with a trusted
     CA. With both: M-17 / L-40.

### 2. Updater (ADR-0018 §3)
10. **Registration and ACL: approved.** `lib.rs:97-104`: `.plugin(updater)` only when
    `configured_pubkey` is non-empty. `capability_tests.rs:134-147`: no capability and no
    `mooring-main.toml` entry contains `updater`. The four commands are `Scope::Main` and
    refused from `detached-*` / `web-*`. The plugin's own JS commands need a permission that
    nothing grants.
11. **Install-mode matrix: approved.** It covers deb / rpm / MSI → package manager; unbundled →
    manual; `.app`, AppImage and NSIS need the install **and** its parent to be writable,
    proven by creating a probe file. **The elevation paths of `tauri-plugin-updater` 2.14.1
    are unreachable in practice:** deb / rpm (`pkexec` → zenity/kdialog sudo → `sudo`,
    `updater.rs:1382-1410`) are never called because the matrix refuses them first. macOS
    AppleScript "with administrator privileges" (`:1581-1600`) runs only when the bundle swap
    fails with `PermissionDenied`, which the probe rules out. The residual is a TOCTOU (a
    permission change between the probe and the swap). It would show the genuine macOS
    authorisation dialog, which the user can cancel, and is accepted under R-UPD. The AppImage
    path never elevates. Windows NSIS `currentUser` + `passive` runs the per-user installer
    via `ShellExecuteW`. N-55 (Homebrew detection).
12. **Version comparison: approved.** Plugin comparator `release.version > current` (semver: a
    pre-release of the same version is lower), re-checked in Rust (`is_newer`) for both check
    and install. `update_install` re-runs the check and installs only when the offered version
    equals the confirmed one, so the renderer never supplies a URL or bytes. N-51.
13. **Rate limit / single flight: approved.** One check or install at a time (`update.busy`),
    60 s between manual checks. The background check is opt-in, starts 60 s after launch, runs
    at most every 24 h (measured from the stored `lastCheck`) while unlocked, and never
    downloads.
14. **`https_only`: approved.** `configure_client(|c| c.https_only(true))` applies to the
    manifest request and the download, and reqwest re-checks it on every redirect hop
    (`reqwest/src/redirect.rs:324`). No `dangerous*` option is set. Caps and host: L-40.
15. **Audit / errors: approved.** Rows `update_check { current, available }`,
    `update_install { from, to }` (written after verification, before the write),
    `update_refused { code }`, `update_settings_changed`. `update.install_failed` is a new
    code with a static message. The plugin error (which can contain a URL) goes only to
    `tracing`. **The `update.install_failed` code is approved** (U0 decision); fold
    `MissingSignedVersion` into `update.signature` (L-39).
16. **U0 decisions:** the ADR names were implemented (`update.manual_only`, `update.check` /
    `install` / `refused`): **correct**. A 4 KiB notes cap is accepted (stricter). On Windows
    the plugin exits the process right after launching NSIS: acceptable. Sessions were closed
    first (`closeSessions`); keys die with the process.

### 3. Importers (ADR-0019 §1–§3, §5)
17. **Caps: approved** (`limits.rs`, checked before allocation): input 16 MiB (metadata
    before read, re-checked at read), gzip ≤ 64 MiB and ≤ 20:1 while streaming (`gzip.rs:84-99`;
    the 8 MiB-zeros hostile fixture is refused), ZIP refused. XML: depth 64, 200 000 elements,
    attribute and text values ≤ 4 KiB (the attribute length is checked before unescaping).
    Plans: ≤ 20 000 connections, 5 000 folders, 2 000 credentials. PuTTY directory: ≤ 2 000
    files and ≤ 16 MiB in total.
18. **XML: approved** (`xml.rs`): any `DocType` → `import.doctype`. Only the five predefined
    entities and numeric references resolve; any other entity → `import.format`. No DTD,
    no XInclude. Errors carry a byte offset and a fixed reason, never content
    (`error.rs`).
19. **Secrets: approved.** `SecretBundle` is `Zeroizing`, never `Serialize`, and its `Debug`
    shows names only. Only Termius produces secrets, and only with
    `include_plaintext_secrets` (`termius.rs:96-113`). mRemoteNG `Password` is dropped with a
    warning (`mremoteng.rs:74`). Royal TS / RDM passwords and `SafePassword` are never read.
    The fuzz oracle asserts "no secret without the opt-in" (`fuzz.rs:53`). Copies in the
    parse buffers (the file bytes, `serde_json::Value`, quick-xml strings) are not zeroized:
    R-IMPORT-SECRET.
20. **Key-file opt-in: approved with L-41.** `read_identity`: canonical path under the
    canonical `~/.ssh`, regular file, ≤ 16 KiB, parses as an OpenSSH private key, read into
    `Zeroizing`.
21. **Plan store: approved with N-53** (`import_plans.rs`): random 128-bit id, strict hex
    check, single use, 10 min TTL, ≤ 8 plans, `clear()` on lock (`commands/vault.rs:141`), and
    secrets zeroized on drop.
22. **`LocalPicker::pick_filtered` + the `"import"` pick session: approved** (I1 Decision 3).
    Same `Picks` store, mode `File`, TTL, epoch and app-data refusal (`dialog_dir`) as the SFTP
    picks. A pick is bound to the literal session `"import"`, and SFTP session ids are random,
    so neither side can consume the other's pick. **`import_pick` returning `{ pickId,
    fileName, size }` without the bytes is approved** (I1 deviation; the ADR line must
    follow).
23. **Audit: approved** — `import_previewed { format }`, `import_applied { format, counts }`,
    `import_refused { code }`, no names, hosts or file names. N-59.
24. **`Store::import_apply`: approved** — one `unchecked_transaction`, a new root folder,
    every item re-validated in the store, secrets sealed inside the transaction, first
    failure rolls back (`mooring-store/src/import.rs:159-205`).
25. **`csv`: not used.** Termius CSV goes through our own RFC 4180 reader under
    `import_termius_csv`, so no new crate. **Approved** (architect Decision 2).

### 4. LDAPS (ADR-0019 §4 + amendment)
26. **Own LDAP v3 reader instead of `ldap3`: approved** (I2 Decision 1; owner decision 18
    becomes "ldap3 dev-only"). I confirm the reason: `lber::parse_tag` recurses per nesting
    level and `ldap3`'s transport cannot be fronted. In the product, `lber` encodes our four
    requests and parses only frames that passed `frame::scan`, which is iterative,
    definite-length only, ≤ 4 length octets, ≤ 4 tag octets, depth ≤ 32, ≤ 256 KiB
    (`frame.rs`). Decoding returns errors and never panics. The run is spawned and under a
    deadline, and `panic = "unwind"` (root `Cargo.toml:130`) keeps any residual `lber` panic
    inside the task.
27. **Operations: approved.** `wire.rs` can express only bind (v3, simple), search (with
    `neverDerefAliases`, a size limit, a time limit and the paged-results control), abandon
    and unbind. Referrals and intermediates are counted and ignored, never followed. Caps:
    5 000 entries, 12 pages, 1 024 unrelated frames, 64 malformed entries, 30 s; DN and values
    ≤ 1 KiB, ≤ 16 values, ≤ 64 attributes.
28. **Filter / DN: approved.** Values travel as BER octet strings, so nothing can break out of
    the filter on the wire. The RFC 4515 text form (`escape_value`: `* ( ) \ NUL` and controls)
    is used for display and audit only, checked against `ldap3`'s parser as an oracle. The base
    DN is parsed per RFC 4514 and re-encoded.
29. **TLS and TOFU: approved.** `mooring-http::tls::client_config` uses the same verifier
    (pin before CA, pins reloaded per connect and failing closed, resumption off, no ALPN),
    so the `TlsClient` exposure to a non-HTTP caller is approved (I2 Decision 5). Only
    `TrustPrompt` prompts (N-50 pattern). The dialog is the shared `Prompt` / `ConfirmGate`,
    so the **B-6 three-slot rule, single flight and the cool-down apply** (`ldap_trust`,
    `destructive: true`). `known_ldap_certs` is in `CertProtocol::ALL`, so it is synced and
    the L-35 conflict rule applies. The bind frame is sent only after a trusted handshake.
    Issues: L-43 (`caPem` / CA-valid host without a dialog), N-54.
30. **Bind password: approved under R-LDAP-STR.** `BindCredential.password` is `Zeroizing`
    and its `Debug` shows the name only. The password is copied once into an unzeroized
    `lber` `Vec` / `BytesMut` (`wire.rs:63-70`). Errors carry a result code, never server
    diagnostic text or a DN.
31. **Hostile server (Q1 suite): approved.** Deep nesting (100 000), huge lengths, empty,
    garbage, extra elements, oversized values, a slow bind and floods all end in
    `ldap.response` / `ldap.timeout`, with no panic and no hang.

### 5. Network tools (ADR-0020)
32. **Approved.** Paths are fixed per OS (`tools.rs` `for_os`); there is no `PATH` lookup.
    On Windows they come from `%SystemRoot%` / `%ProgramFiles%` (same-user environment: T2
    baseline). macOS `wg` sits under Homebrew prefixes the user can write, which is also only
    T2. argv: the target is always one last element, with `--` before it where the tool
    accepts it (Linux/macOS ping and traceroute), and `Target` (ASCII, no whitespace, no `%`,
    never starts with `-` or `/`) holds everywhere, including Windows and `tracepath`.
    `run.rs`: `env_clear` + `LC_ALL=C` / `SystemRoot`, stdin null, `kill_on_drop`, kill at the
    cap or the deadline, `CREATE_NO_WINDOW` (compiled; Windows run still owed). `WgQuery`
    cannot express `dump`, `showconf`, `private-key`, `set`; interface names are validated.
    Parsers are capped and fuzzed. `TargetArg`: connection hosts go through the same check;
    kube / vSphere connections are refused. Two processes at a time, one port check per
    second, vault-gated, no elevation, permission errors surfaced verbatim. Audit and probe
    budget: N-52 / R-NET-PROBE.

### 6. UI
33. **No secret in DTO, state or fixture: confirmed.** The wizard sends
    `includePlaintextSecrets` / `importKeyFiles` flags and receives names, `hasSecret` and
    counts. The LDAPS form sends a `credentialId` and receives `{ host, port, boundAs }`. The
    mocks hold no secret values. `invoke()` appears only in `apps/desktop/src/lib/ipc.ts`
    (grep).
34. **About links are copy-only: confirmed** (`AboutCard.tsx`: text + Copy, no `<a>`, no
    opener capability; `about.test.tsx:37`).
35. **Onboarding storage: approved.** A list of dismissed vault ids in `localStorage`
    (device-local; the vault id is not secret).
36. **Site: L-42.**

### 7. Dependencies
| Crate | Version | License | Reached from | `unsafe` / notes | Ruling |
| --- | --- | --- | --- | --- | --- |
| `tauri-plugin-updater` (`rustls-tls`, `system-proxy`; no `zip`) | =2.14.1 | MIT OR Apache-2.0 | mooring-app | 5 blocks (Windows `ShellExecuteW`, macOS `renamex_np`, `statfs`) | **Approved**; M-17, L-39, L-40 |
| `minisign-verify` | 0.3.0 | MIT | updater | `forbid(unsafe_code)` | **Approved** |
| `tar` → `filetime`, `xattr` | 0.4.46 / 0.2.29 / 1.7.0 | MIT OR Apache-2.0 | updater (unpacks only signed archives) | small FFI | **Approved** |
| `osakit` → `objc2-osa-kit` | 0.3.1 | MIT | updater, macOS | objc FFI | **Maintenance exception approved** (last release 2025-03): its only caller is the AppleScript elevation path, which the matrix keeps unreachable (ruling 11). Revisit when the plugin bumps |
| `rustls-platform-verifier` (+ `-android`, `jni` Android-only), `webpki-root-certs`, `hyper-rustls`, `system-configuration` 0.7, `core-foundation` 0.9 (duplicate) | 0.7.1 / … | MIT OR Apache-2.0 | reqwest 0.13.5 (tauri, updater) | platform FFI | **Approved**. The duplicate `core-foundation` costs build time only. `jni` is not compiled for desktop targets |
| `lber` | =0.5.1 | MIT | mooring-import (product), testsrv | none | **Approved**, frames pre-scanned (ruling 26) |
| `ldap3` (`tls-rustls-ring`) | =0.12.1 | MIT OR Apache-2.0 | **dev-dependency only** (escaping oracle) | none | **Approved as dev-only**; maintenance exception moot for the product |
| `tokio-stream` | 0.1.19 | MIT | ldap3 (dev) | — | **Approved**, dev only |
| `simd_cesu8` | — | MIT OR Apache-2.0 | `jni` (Android) | — | Not compiled for desktop |
| tokio `process` feature | 1.x | MIT | mooring-net | — | **Approved** (`signal-hook-registry` already locked) |
| fuzz `[patch.crates-io] age` | rage `b5b68c4f…` | — | fuzz workspace | — | **Approved**: the same commit as the root patch (the one allowed git source); `fuzz/Cargo.lock` pins the full SHA |

`cargo deny`: licenses ok (only "allowance not encountered" warnings); no new ban; no
`aws-lc-*`, `openssl-sys` or `native-tls` edge.

## Conditions before the `v0.1.0` tag
1. **M-17 (1)–(3)** before `TAURI_SIGNING_PRIVATE_KEY` is created. If the owner publishes
   v0.1.0 without the key (no in-app updates, `latest.json` absent), M-17 moves to "before the
   first release with an updater key". (3) (environment, tag and `main` rulesets) is wanted
   for v0.1.0 regardless, because of the cosign identity (N-58).
2. L-39 (`requireSignedVersion` + mapping), L-41, L-42 (docs), L-14 remainder (semgrep
   digest), N-8. L-40 and L-43 land before the tag or are accepted in writing under R-UPD /
   R-LDAP-STR.
3. Per-OS manual runs (carried): `docs/qa/native-dialogs.md` on macOS, Windows 11 and Fedora,
   including the LDAPS trust dialog; L-31; the ADR-0013 E2E plan; the ADR-0016 §4 OIDC
   interception; the Windows L-29 E2E; the Q1 Decision 3 updater leg (wrong signature, lower
   version, bogus platform, then a real in-app install per bundle type and the manual reason
   on deb / rpm / MSI / Homebrew); a Windows run of the net tools (`CREATE_NO_WINDOW`,
   `PING.EXE` / `TRACERT.EXE`).
4. L-28: one green nightly fuzz run including the 14 A4 targets; `rdp_reactivation` after
   rust-core adds the entry point.
5. L-36 VMRC help text (UI). G-1 fresh squashed repository (owner).
6. ADR-0018 §6 gates unchanged: `security.yml` green on the release commit; `make check` green
   on three OSes; fresh-install smoke on clean VMs; `verify-release.sh` green on the rc.2 draft
   (and check the trusted comment, L-39); a human publishes.
7. Nits as scheduled (N-51..N-60); L-13 before any Azure secret; N-50 with F1.

## Test evidence
```
Linux x86_64, 2026-11-06, a4 @ cfca0ff, no build, no test run (orchestrator gate)
cargo deny --offline check          advisories ok, bans ok, licenses ok, sources ok
cargo audit --no-fetch --db ~/.cargo/advisory-db/advisory-db-3157b0e258782691
                                    1409 advisories, 847 crates: RUSTSEC-2023-0071 (rsa, R-RSA, ignored);
                                    unmaintained: atomic-polyfill, basic-toml, pin-utils (sspi→async-dnssd),
                                    proc-macro-error, zbus_names, zvariant, zvariant_derive — none from A4
cargo tree --workspace --target all -i  tar|osakit|minisign-verify|xattr|filetime <- tauri-plugin-updater
                                    rustls-platform-verifier|hyper-rustls|webpki-root-certs <- reqwest 0.13.5
                                    lber <- mooring-import, mooring-testsrv; ldap3, tokio-stream: dev only
registry sources read               tauri-plugin-updater 2.14.1 src/updater.rs:533-700 (check), :815-925
                                    (download/verify/install), :1213-1320 (AppImage), :1382-1410 (pkexec/sudo),
                                    :1486-1600 (macOS swap / AppleScript), :1893-1945 (signed version);
                                    src/config.rs:107-140; reqwest 0.13.5 src/redirect.rs:324 (https_only)
grep updater: capabilities/ permissions/   none
grep invoke( apps/desktop/src (non-test)    lib/ipc.ts only
diff pubkey tauri.conf.json vs verify-release.sh   identical (minisign key id 9F4EDAC489D4B86D)
grep uses: without @<40-hex> in security/ci/test-vectors.yml   none; semgrep container unpinned
```
Not run: builds, tests, cargo-geiger (not installed), gitleaks, semgrep, pnpm audit, cargo-fuzz,
actionlint, the workflows, the per-OS checks.
