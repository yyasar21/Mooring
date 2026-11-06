# A4 — architect handoff

Date: 2026-11-06 · Branch: worktree from `a4` @ `15c0b92` (main `fc41747` + icons) · docs only

## Done
- **ADR-0018** Release v0.1.0: cosign keyless `SHA256SUMS` (minisign wording to be removed),
  `tauri-action` v1.0.0 pinned by SHA (`1deb371`, re-resolved 2026-11-06), `tauri-plugin-updater`
  `=2.14.1` without default features, Rust-side only (no `updater:*` permission), check on demand
  by default, opt-in background check, never auto-installs, in-app install only where no
  elevation is needed (macOS user-writable `.app`, Windows NSIS per-user, AppImage); `latest.json`
  built in `finalize`; reproducible check for the Rust workspace crates on Linux (Tauri bundle
  excluded, with reasons); release gate; unsigned matrix (ad-hoc macOS, unsigned Windows);
  owner-action list. Owner decisions 13–15.
- **ADR-0019** Importers and onboarding: `mooring-import` crate (`Importer` trait, dry-run
  `ImportPlan`, `planId`), six file formats + LDAPS (`ldap3` `=0.12.1`, `tls-rustls-ring`,
  read-only `DirectoryReader`, `known_ldap_certs`), caps and hostile-input rules, one fuzz target
  per parser, IPC + codes, wizard + onboarding card, audit, no-telemetry statement. Owner
  decisions 16–18.
- **ADR-0020** Network tools: `mooring-net` crate, own TCP connect check, `ping`/`traceroute`/
  `tracert` from fixed absolute paths with fixed argv and no shell, sanitised and capped output,
  `wg show` read-only through an allow-list that cannot reach `dump`/`showconf`, no raw sockets
  or elevation, inspector "Network" card, IPC, audit. Owner decision 19.
- Dependency checks (licence / maintenance / `unsafe` / overlap) are in each ADR. Sources were
  read for `tauri-plugin-updater` 2.14.1, `ldap3` 0.12.1, `lber` 0.5.1, `quick-xml` 0.42.0,
  `minisign-verify` 0.3.0 and `csv` 1.4.0.

## Proposed A4 task split
| Task | Owner | Scope | Depends on |
| --- | --- | --- | --- |
| **R1** | release-engineer | `v0.1.0-rc.2` pipeline dry run → draft release, `verify-release.sh`; `scripts/release/updater-manifest.sh` + `latest.json` in `finalize`; `plugins.updater` config (pubkey from the owner, endpoint, `createUpdaterArtifacts: true`); `release-repro.yml`; minisign wording in README, release-process.md, roadmap, agent definition (with the docs owner) | owner action 2 (updater key) for the pubkey |
| **U0** | rust-core | updater wiring in `mooring-app`: plugin registration gated on pubkey, `update_check` / `update_install` / `update_settings_get/set`, install-mode matrix, background check, codes, audit; `AppManifest` + capability test | ADR-0018; security review of the capability change |
| **I1** | rust-core | `mooring-import` crate + Royal TS, RDM, Termius, mRemoteNG, PuTTY, OpenSSH importers; `import_*` commands, `planId`, transactional apply, key-file opt-in | owner sample exports (scrubbed) |
| **I2** | rust-core | LDAPS directory importer (feature `directory`), `known_ldap_certs` + TOFU prompt, `ldap_import_*`; LDAP mock in `mooring-testsrv` | I1 (plan/apply), `ldap3` approval |
| **N1** | rust-core | `mooring-net` crate + `net_*` commands, tokio `process` feature | orchestrator `Cargo.toml` edit |
| **U1** | ui-engineer | import wizard (Settings → Import) + first-run onboarding card | I1 IPC (mock first) |
| **U2** | ui-engineer | Settings → "Updates" card; inspector "Network" card | U0, N1 IPC (mock first) |
| **U3** | ui-engineer | proper app icon design (replaces the placeholder `packaging/icon.svg`, then `make icons`), About dialog and brand polish | — |
| **Q1** | qa-engineer | fuzz targets: 8 importer + `ldap_ber_response` + `ldap_filter_escape` + 3 `net_*`; hostile fixtures (DOCTYPE, gzip/depth bombs, bidi, UTF-16 `.reg`); E2E import flow, Updates card, Network card; L-28 remainder; first green nightly | I1, I2, N1 |
| **Review 7** | security-reviewer | A4 range + the "before first public release" items (L-19, L-11, M-12, L-12..L-14, N-8, N-9, G-1); `ldap3`/`osakit`/`csv` approvals; R-UPD, R-IMPORT-SECRET, R-LDAP-STR, R-NET-PROBE in the threat model | all of the above |
| **Mac-side manual gates** | owner (+ qa) | per-OS `docs/qa/native-dialogs.md` (macOS, Windows 11, Fedora GTK), L-31, ADR-0013 E2E per OS, OIDC interception per OS, Windows L-29 E2E, fresh-install smoke on clean VMs, Gatekeeper/SmartScreen notes checked | R1 draft artifacts |

Waves: R1 ∥ U0 ∥ I1 ∥ N1 ∥ U3 → I2 ∥ U1 ∥ U2 → Q1 → review 7 → manual gates → `v0.1.0`.

## Left open
- SSH jump hosts: `ProxyJump` is imported as a tag + warning; Mooring has no jump-host model
  (needs an ADR-0007 follow-up).
- LDAPS import is one-shot; a saved, scheduled directory source (like vSphere) is not designed.
- Royal TS / RDM XML element names and the `.rtsz` container (gzip vs ZIP) are unconfirmed until
  I1 has scrubbed sample exports; ZIP would need a dependency decision.
- rpm and AppImage are not built for pre-releases (bundlers reject `-`), so the AppImage
  updater path is first exercised at `0.1.0`; R1 builds both once locally for the Fedora smoke.
- Offline/air-gapped Windows installs (`offlineInstaller`), winget/Scoop, notarization and
  Authenticode wait for certificates.
- Not reproducible: the Tauri bundles (ADR-0018 §4).
- Docs outside `docs/adr/` that still say minisign: `README.md:148`,
  `docs/developer-guide/release-process.md:22`, `docs/roadmap.md` A4, `.claude/agents/release-engineer.md`.

## Decision needed
1. Confirm the `ldap3` maintenance exception (last release 2025-09-18) and the `osakit`
   exception (macOS, 2025-03-01, pulled in by the updater, path never taken) — review 7 and owner.
2. Termius CSV: `csv` 1.4.0 (new crate, 4 `unsafe` blocks) or a small in-house RFC 4180 reader
   under the same fuzz target. ADR-0019 picks `csv`; review 7 may flip it.
3. Owner: supply scrubbed sample exports (Royal TS `.rtsx`/`.rtsz`, RDM `.rdm`, Termius CSV +
   JSON, mRemoteNG `confCons.xml`, PuTTY `.reg`) using `example.test` / RFC 5737 only.
4. Owner: generate the updater key (ADR-0018 §7 step 2) before R1 can set the pubkey; without
   it, U0 ships `update.unconfigured` and v0.1.0 has no in-app updates.

## Test evidence
- Docs only; no code changed. Each ADR ≤ 150 lines (`wc -l`: 150 / 150 / 124).
- crates.io API and crate sources read on 2026-11-06: `tauri-plugin-updater` 2.14.1 (features,
  5 `unsafe` blocks, `pkexec`/zenity/`sudo` and AppleScript install paths), `ldap3` 0.12.1 and
  `lber` 0.5.1 (no `unsafe`; `set_config`, `set_starttls`, `set_no_tls_verify` APIs), `quick-xml`
  0.42.0 (`forbid(unsafe_code)`), `minisign-verify` 0.3.0 (`forbid(unsafe_code)`), `csv` 1.4.0.
- Lockfile overlap checked: `quick-xml` (via `plist`), `reqwest` 0.13 (via `tauri`), `flate2`,
  `x509-parser`, `tokio-rustls`, `rustls-native-certs`, `nom` 7, `infer`, `semver`, `dirs`,
  `signal-hook-registry` are present; `lber`, `tokio-stream`, `minisign-verify`, `tar`, `osakit`,
  `csv` are new.
- `git ls-remote tauri-apps/tauri-action`: `v1`, `v1.0`, `v1.0.0` → `1deb371b0cd8…`, matching
  `release.yml`.
