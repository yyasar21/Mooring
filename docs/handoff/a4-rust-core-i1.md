# A4 — rust-core I1: `mooring-import` crate, six importers, `import_*` commands

Branch: worktree `agent-a0acccc76daed97e6`, started from `a4` @ `351e30c`. Not merged. Ten
commits (`5b978bb`..`1331fb0`), one per importer plus crate / fuzz / store / app. ADR-0019
with the owner decisions given to I1: Termius CSV through a small in-house RFC 4180 reader
(no `csv` crate), Royal TS `.rtsz` = gzip first then plain XML, ZIP refused with
`import.unsupported_container` (no zip dependency), mRemoteNG passwords never imported,
`ProxyJump` → tag + warning.

## Done

- **Crate `crates/mooring-import`** (`#![forbid(unsafe_code)]`, no I/O): `Importer` trait,
  `ImportFormat` (`royal_ts | rdm | termius | mremoteng | putty | openssh`), `ImportSource`
  (`File` / `Dir`), `ImportOptions { include_plaintext_secrets, limits }`, `detect(bytes,
  filename)` (extension / known name first, then each importer's `sniff` on the first 4 KiB),
  `parse(format, src, opts)`. `ImportPlan` = folders, connections, credentials, skipped (with
  reasons), warnings (with codes) + overflow counters; `PlanBuilder` runs the core validators
  (`validate_name` / `validate_host` / `validate_tag`, bidi/`Cf`, ports 1..=65535, ≤ 50 tags,
  username ≤ 256 / domain ≤ 253 bytes) and the caps (≤ 20 000 connections, ≤ 5 000 folders,
  ≤ 2 000 credentials → `import.limits`; notes capped at 20 000 with a `notes_truncated`
  warning), de-duplicates folders by `(parent, name)` and credentials by `(kind, fields,
  secrets, key file)`. `SecretBundle` is `Zeroizing`, zeroized on drop, never `Serialize`,
  `Debug` prints names only; it is `Some` only for a plaintext field **and** the opt-in.
- **Guards** (`xml.rs`, `gzip.rs`, `csv.rs`, `text.rs`): quick-xml 0.42 with `<!DOCTYPE` →
  `import.doctype` wherever it appears, depth ≤ 64, ≤ 200 000 elements, attribute / text
  ≤ 4 KiB, only the five predefined and numeric references (any other entity →
  `import.format`), indentation dropped; gzip inflate streamed under 64 MiB and 20:1
  (`import.limits`), ZIP magic refused; CSV fields ≤ 4 KiB, ≤ 64 columns, malformed quoting
  → `import.format` with the record number; UTF-8 (BOM optional) and UTF-16 LE/BE with BOM
  only. Input ≤ 16 MiB (`import.too_large`) per file and per directory. Errors carry an
  offset or line and a fixed reason, never input.
- **Credential mapping** (`creds.rs`, ADR-0009 kinds): username without a usable secret →
  `prompt` (username / domain pre-filled, one per `(user, domain)`); Termius plaintext
  password + opt-in → `user_password`; Termius private key + opt-in → `ssh_key`; OpenSSH
  `IdentityFile` → `ssh_agent` per `(user, key file)` (the path is kept on the plan, read only
  by the src-tauri opt-in), OpenSSH `User` without a key → `prompt`. Encrypted / obfuscated
  values are never decrypted (`secret_encrypted` / `password_dropped` warnings).
- **Importers** (one commit each, fixtures under `crates/mooring-import/tests/fixtures/`,
  `example.test` / RFC 5737 only): Royal TS (`.rtsx`, gzip `.rtsz`; flat or nested `Royal*`
  objects linked by `ID` / `ParentID`, RDS / SSH / terminal(SSH) / VNC / web, credential
  objects, folder cycles land at the root, protected document → `import.encrypted`); RDM
  (`ArrayOfConnection`, `Group` paths, RDP* / SSHShell / VNC / WebBrowser, per-type host /
  port / user sub-elements, `SafePassword` left encrypted); Termius CSV (header-driven column
  aliases) and JSON (`hosts` + `groups` by id, or a bare array); mRemoteNG (`Container` →
  folders, RDP / SSH2 / VNC / HTTP(S), `FullFileEncryption="true"` → `import.encrypted`,
  `Password` dropped with a warning — never imported); PuTTY (`.reg` UTF-16LE / UTF-8,
  `~/.putty/sessions/*`, %-decoded names, `user@host` split, `Default Settings` and non-SSH
  protocols skipped, PPK → warning); OpenSSH (literal `Host` aliases, first obtained value
  wins, `Host *` defaults, wildcard / negated patterns and `Match` → warnings, `Include` not
  followed, `%` tokens literal, `ProxyJump` → `jump:<value>` tag + warning).
- **Fuzz** (`fuzz/entries/import_*.rs`, `fuzz/fuzz_targets/`, seeds in `fuzz/corpus/` added
  with `-f`, `fuzz/regressions/<target>/.gitkeep`): `import_royalts`, `import_rdm`,
  `import_termius_csv`, `import_termius_json`, `import_mremoteng`, `import_putty_reg`,
  `import_putty_session`, `import_ssh_config`, `import_detect`. Entries live in
  `mooring_import::fuzz` with the oracle (caps, validators re-run, key consistency, no secret
  without the opt-in / outside Termius + OpenSSH). Replayed on stable by
  `crates/mooring-import/tests/fuzz_corpus.rs` (also pins that every `fixture-plain` seed
  parses and is detected). `fuzz/Cargo.toml` (+ dep, 9 bins), `fuzz/Cargo.lock` (resolved
  offline: `mooring-import`, `quick-xml 0.42.0`), `.github/workflows/fuzz-nightly.yml` rows
  + the `import_*` malloc-limit rule, `docs/qa/fuzzing.md` "A4 targets" — QA to review.
- **Store** (`crates/mooring-store/src/import.rs`): `Store::import_apply(vault, &ImportBatch)`
  writes a new subfolder of the root, its folders, credentials (secrets sealed in the same
  transaction) and connections in **one** `unchecked_transaction`; every item is re-validated
  (names, hosts, tags, credential fields and secrets, `check_compatible` for the primary
  role); any failure rolls everything back (tests inject failures mid-batch). Never merges.
- **App** (`src-tauri`): `import_plans.rs` (plan held under a random 128-bit `planId`, single
  use, 10 min TTL, ≤ 8 plans, cleared by `vault_lock` → secrets zeroized),
  `commands/import.rs` + `import_dto.rs` + `import_source.rs`: `import_formats`,
  `import_pick` (Rust-side dialog with an extension filter, `LocalPicker::pick_filtered`
  default-delegating; the path is kept in `Picks` under the `"import"` pick session, B-4),
  `import_preview`, `import_apply`, `import_discard`. All five rows in `guard::COMMANDS`
  (`Scope::Main`), `permissions/mooring-main.toml`, autogenerated permission files, goldens
  re-blessed (`ipc-manifest.json` +5 commands, `ipc-codes.json` + `import.doctype`,
  `import.encrypted`, `import.format`, `import.limits`, `import.not_found`,
  `import.plan_expired`, `import.too_large`, `import.unsupported_container`;
  `ipc-passive.json` unchanged). Vault gate first in every command (`with_ready`); L-38 matrix:
  `import_pick` / `import_preview` / `import_apply` / `import_discard` in
  `vault_gated_codes_a4` (all `vault.locked`), `import_formats` in `NOT_GATED` (static).
  Audit (`mooring-audit`): `import_previewed { format }`, `import_applied { format, folders,
  connections, credentials, secrets, skipped }`, `import_refused { code }` — no file name,
  host or secret (tested).
- Known locations: `~/.ssh/config` and `~/.putty/sessions/` (unix layout; `HOME` /
  `USERPROFILE`). OpenSSH key opt-in (`importKeyFiles`): `~`-expanded, canonical path under
  canonical `~/.ssh/`, regular file, ≤ 16 KiB, `ssh_private_key` with a fingerprint (OpenSSH
  format) → the `ssh_agent` credential becomes `ssh_key` with the key as its secret; anything
  else → `skipped(key_unreadable)` and the `ssh_agent` credential stays.
- Duplicates at preview: `(protocol, host lower-cased, effective port, user)` against the
  store, user = `username_override` else the effective credential's `username`; flagged as
  `duplicateOf`, skipped by default, `duplicates: "import"` writes them anyway.

## UI contract (for the ui-engineer, `apps/desktop/src/lib/ipc.ts`)

```
import_formats() -> [{ format, label, extensions: string[], knownLocation: "openssh" | "putty" | null, secretsPossible }]
import_pick({ format }) -> { pickId, fileName, size } | null          # dialog; null = cancelled
import_preview({ source: { pickId } | { known: "openssh" | "putty" },
                 includePlaintextSecrets: boolean, importKeyFiles: boolean }) -> ImportPreview
import_apply({ planId, exclude: string[], duplicates?: "skip" | "import" }) -> ImportReport
import_discard({ planId }) -> void
ImportPreview = { planId, format, rootName, counts: { folders, connections, credentials, secrets, skipped, warnings },
                  items: [{ key, parent: key | null, kind: "folder" | "connection", name,
                            protocol?, host?, port?, username?, credentialKey?, duplicateOf? }],
                  credentials: [{ key, name, kind, hasSecret }],
                  skipped: [{ sourceRef, reason: unsupported | invalid | encrypted | key_unreadable | duplicate | limit }],
                  warnings: [{ code, sourceRef }] }
warning codes: host_pattern, match_block, include_ignored, proxy_jump, ppk_key, password_dropped,
               secret_encrypted, tags_truncated, port_ignored, user_ignored, notes_truncated
ImportReport  = { rootFolderId, folders, connections, credentials, secrets, skipped }
codes: import.too_large, import.format, import.encrypted, import.doctype, import.limits,
       import.unsupported_container, import.plan_expired, import.not_found, input.invalid, vault.locked
```
Exclusions: an excluded folder lifts its subtree to the nearest kept ancestor (or the import
root); an excluded credential unlinks its connections; an unreferenced `prompt` / `ssh_agent`
credential is not written. The mRemoteNG banner: every credential is `prompt` with
`hasSecret: false` (re-enter passwords after the import).

## Left open

- **Deviation from ADR §3**: `import_pick` returns `{ pickId, fileName, size }` — not the file
  bytes; the bytes never reach the `WebView` (nothing in the UI needs them, and a plaintext
  export may hold secrets). Architect to confirm or amend the ADR line.
- **Royal TS / RDM element names are unconfirmed** (owner decision needed #3: scrubbed sample
  exports). The parsers are tolerant (`URI` / `Uri` / `Host`, `UserName` / `Username`, nested or
  flat objects, `RoyalTerminalConnection` + `TerminalConnectionType`, RDM per-type
  sub-elements); the fixtures encode I1's reading of the schemas. A sample may still rename a
  field: one-line fixes expected, no structural change.
- Royal TS "password protected" is detected on `RoyalTSDocument` children `Encrypted` /
  `IsEncrypted` / `PasswordProtected` / `IsPasswordProtected` = `true` — to be confirmed on a
  sample; an undetected protected document simply yields `skipped` / empty items.
- Connection options (`PlanConnection.options` in the ADR sketch) are not emitted: no importer
  produces per-protocol options yet (RDP console / resolution, VNC view-only would be next).
- PuTTY on Windows reads no registry (no `winreg` dependency): the user exports a `.reg`;
  `knownLocation: "putty"` only finds `~/.putty/sessions/` (unix).
- The gzip ratio cap (20:1, ADR §3) is tight for very repetitive XML; a real large `.rtsz`
  may hit `import.limits` — raise to 50:1 in the ADR if an owner sample does.
- Termius export column / field names are matched by alias; the exact set in the current
  Termius build is unverified (no sample).
- `ProxyJump` stays a tag (`jump:<value>`) + warning until a jump-host model exists (ADR-0007
  follow-up, as the ADR says).
- Telemetry: nothing about an import leaves the device (no network code in the crate; the
  commands only read local files).

## Decision needed

1. `import_pick` without bytes in the reply (above).
2. Owner samples (Royal TS `.rtsx` / `.rtsz`, RDM `.rdm`, Termius CSV + JSON, mRemoteNG
   `confCons.xml`, PuTTY `.reg`) to confirm element and column names.
3. Review 7: the `LocalPicker::pick_filtered` default method and the new `"import"` pick
   session (`Picks` is shared with the SFTP picks; mode `File`, same TTL / refusal rules).

## Manifests touched (orchestrator-owned, flagged)

- `Cargo.toml`: `crates/mooring-import` added to `members` and `default-members` (comment).
- `Cargo.lock`: `+ [[package]] mooring-import` (deps `flate2`, `mooring-core`, `proptest`,
  `quick-xml`, `serde`, `serde_json`, `thiserror 2.0.21`, `tracing`, `zeroize`) and
  `mooring-import` under `mooring-app`'s dependency list. No new third-party crate: `quick-xml
  0.42.0` and `flate2 1.1.10` were already locked.
- `src-tauri/Cargo.toml`: `mooring-import` dependency line (workspace crate).
- `fuzz/Cargo.toml` + `fuzz/Cargo.lock`: the dependency and nine `[[bin]]`s; the lock gains
  `mooring-import` and `quick-xml 0.42.0` (resolved with `cargo metadata --offline`, not built:
  libFuzzer needs nightly).
- `.github/workflows/fuzz-nightly.yml`, `docs/qa/fuzzing.md` (QA-owned; rows for the nine
  targets, the `import_*` malloc rule, an "A4 targets" section) — for QA to confirm.

## Test evidence (Linux, rustc 1.97.0)

- `cargo fmt --all -- --check`: clean.
- `cargo clippy -p mooring-import -p mooring-app -p mooring-store -p mooring-audit
  --all-targets -- -D warnings`: clean (the pre-existing `unknown_lints` note on
  `clippy::unused_async_trait_impl` only).
- `cargo test -p mooring-import`: 43 unit + 2 replay (`corpora_replay`,
  `fixture_seeds_are_accepted`; 40 corpus files) — all pass.
- `cargo test -p mooring-store`: 49 lib (+3 new: apply, mid-transaction rollback ×6 cases,
  two applies never merge) + integration suites — all pass.
- `cargo test -p mooring-audit`: pass (3 new variants).
- `cargo test -p mooring-app`: 282 lib (+9: plan store; formats; preview → apply → tree +
  audit rows without host / secret; exclusions, duplicates, discard; locked vault refuses and
  drops plans; known OpenSSH source + key-file opt-in with a generated ed25519 key, junk key
  and a key outside `~/.ssh` refused; PuTTY sessions dir + `import_refused` audit; parser
  code catalogue) + 21 `e2e_flow` (gate matrix with the four gated rows) — all pass.
- `MOORING_BLESS=1 cargo test -p mooring-app golden`: `ipc-manifest.json`, `ipc-codes.json`
  rewritten as listed; `ipc-passive.json` unchanged; `cargo metadata --locked`: ok.
- Every file ≤ 500 lines (`plan.rs` 448, `import.rs` 383 after the DTO split). `target/`
  removed before the report.
