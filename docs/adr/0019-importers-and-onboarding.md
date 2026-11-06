# ADR-0019: Importers and onboarding (files + LDAPS directory)

Status: Accepted (owner decisions inline) · 2026-11-06 (Phase A4; extends ADR-0005, ADR-0009,
ADR-0010 picks, ADR-0017 §6 directory lookup)

## Context
The roadmap promises onboarding with importers and no telemetry; ADR-0017 §6 moved the LDAPS
lookup here. Every import file is untrusted (T3: a colleague's export, a downloaded "pack"), so
each parser gets a fuzz target. No local path crosses IPC (review 4 B-4): Rust picks files.

## Decision

### 1. Crate `mooring-import` (pure; I/O only in src-tauri)
```rust
pub enum ImportSource<'a> { File { name: &'a str, bytes: &'a [u8] }, Dir(&'a [(String, Vec<u8>)]) }
pub trait Importer: Send + Sync {
    fn format(&self) -> ImportFormat;            // royal_ts | rdm | termius | mremoteng | putty | openssh
    fn sniff(&self, head: &[u8]) -> bool;        // first 4 KiB; only a hint for the picker
    fn parse(&self, src: ImportSource<'_>, opts: &ImportOptions) -> Result<ImportPlan, ImportError>;
}
pub struct ImportOptions { pub include_plaintext_secrets: bool, pub limits: Limits }
pub struct ImportPlan {                          // a dry run: nothing touches the store
    pub folders: Vec<PlanFolder>,                // { key, parent: Option<PlanKey>, name }
    pub connections: Vec<PlanConnection>,        // { key, folder, name, protocol, host, port, user, domain, credential, tags, options }
    pub credentials: Vec<PlanCredential>,        // { key, name, kind, fields, secrets: Option<SecretBundle> }
    pub skipped: Vec<Skipped>,                   // { source_ref, reason }
    pub warnings: Vec<Warning>,                  // { code, source_ref }
}
```
- `SecretBundle` is `Zeroizing`, never `Serialize`. It is `Some` only when the source holds the
  secret **in plaintext** (format-documented field) **and** `include_plaintext_secrets` is set
  (owner decision 16). Encrypted or obfuscated values are never decrypted.
- Every item passes the mooring-core validators (names, hosts, bidi/`Cf`, tags, ports); an
  invalid item becomes `skipped`, not an error.
- Deps: `quick-xml` 0.42 (MIT, 2026-08-22, `forbid(unsafe_code)`, already in the tree via
  `plist`), `flate2` (in the tree), `serde_json`, `csv` 1.4.0 (Unlicense/MIT, 2025-10-17, new;
  4 `unsafe` blocks, UTF-8-unchecked after validation; alternative: a 150-line RFC 4180 reader
  under the same fuzz target if review 7 prefers no new crate). Feature `directory` (§4) adds `ldap3`.

### 2. Formats
| Format | Input | Maps | Secrets |
| --- | --- | --- | --- |
| Royal TS | `.rtsx` (XML), `.rtsz` (compressed `.rtsx`) | folders; RDS/SSH-terminal/VNC/Web connections; credential objects (no secret) | never; a password-protected document → `import.encrypted` |
| Remote Desktop Manager | `.rdm` XML export | `Group` path `A\B` → folders; `ConnectionType` RDP/SSH/VNC/web | never (`SafePassword` is encrypted) |
| Termius | CSV or JSON export | groups → folders; label, address, port, username, tags | plaintext password/key column, opt-in |
| mRemoteNG | `confCons.xml` | `Container` → folders; RDP/SSH2/VNC/HTTP(S); username, domain | **never** (owner decision 17); `FullFileEncryption="true"` → `import.encrypted` |
| PuTTY | `.reg` export (UTF-16LE BOM or UTF-8), `~/.putty/sessions/*` | `Sessions\<%-encoded>` → SSH; HostName (`user@host` split), PortNumber, UserName | none exist |
| OpenSSH | `~/.ssh/config` | literal `Host` aliases: HostName, User, Port, IdentityFile, ProxyJump | key files only by §3 opt-in |
- Telnet, rlogin, raw, serial, ICA, SSH1 and PuTTY "Default Settings" → `skipped(unsupported)`.
  mRemoteNG `Password` is dropped at parse. `PublicKeyFile` (PPK) → warning, not read.
- OpenSSH: wildcard/negated `Host` patterns and `Match` blocks → warning; **`Include` is not
  followed**; `%` tokens left literal. `IdentityFile` → one `ssh_agent` credential per
  (user, key) by default. `ProxyJump` → tag `jump:<value>` + warning (Mooring has no jump-host
  model yet; Left open).
- Royal TS / RDM element names are confirmed on scrubbed owner samples; `.rtsz` via `flate2`
  (a ZIP container → I1 stops for a dependency decision).

### 3. Sources, plans and apply (src-tauri)
- `import_pick({ format })` opens the native dialog in Rust (ADR-0010 `pickId`, extension
  filter) and returns `{ pickId, fileName, bytes } | null`. Known locations (`~/.ssh/config`,
  `~/.putty/sessions/`) are read by Rust; the UI names a format, never a path.
- §2 opt-in key import (OpenSSH): Rust reads an `IdentityFile` only if its canonical path is a
  regular file under `~/.ssh/`, ≤ 16 KiB, and parses as an OpenSSH private key (`ssh-key`); it
  becomes an `ssh_key` credential. Anything else → `skipped(key_unreadable)`.
- `import_preview` parses and keeps the plan in Rust under a random 128-bit `planId`
  (single use, 10 min TTL, dropped on lock). The DTO shows `hasSecret`, never a secret.
- `import_apply` is one SQLite transaction into a **new root folder** "Imported from <format>
  (<date>)"; it never merges or overwrites. Duplicates (protocol + host + port + user) are flagged
  for skip/import. Secrets are sealed in the same transaction. Needs an unlocked vault.
- Limits: input ≤ 16 MiB; decompressed ≤ 64 MiB and ratio ≤ 20:1; XML depth ≤ 64, elements
  ≤ 200 000, attribute/text ≤ 4 KiB; ≤ 20 000 connections, ≤ 5 000 folders, ≤ 2 000 credentials.
  Over a cap → `import.limits` (streamed check, before allocation).
- XML: any `<!DOCTYPE` → `import.doctype` (no DTD or custom entities; only the five predefined
  and numeric references; no XInclude). Errors give an offset or line, **never file content**.

### 4. LDAPS directory importer (feature `directory`)
- Input: `{ url: "ldaps://host[:636]", baseDn, credentialId, preset, nameContains?, ouFolders,
  protocolRule: by_os | rdp | ssh }`. Presets only (`computers`, `computers_enabled`,
  `windows_computers`): no free-form filter. `nameContains` is RFC 4515-escaped; `baseDn` is
  parsed per RFC 4514; RDN values become folder names through the core validators.
- Transport: `ldaps://` only; `ldap://` and StartTLS → `ldap.insecure`. rustls `ClientConfig`
  from `mooring-http`'s verifier (`set_config`), new trust store `known_ldap_certs` with the
  vSphere TOFU prompt (B-6 slot rule); `set_no_tls_verify` never called. Simple bind only, with
  a `domain_user` (UPN/NetBIOS) or `user_password` credential from the vault; no anonymous,
  SASL, GSSAPI or NTLM (features off).
- Read-only: a `DirectoryReader` wrapper exposes only bind, paged search (500/page), abandon,
  unbind; a test greps for `modify`/`add`/`delete`/`modifydn`/`extended`. Attributes `cn,
  dNSHostName, operatingSystem, userAccountControl`; ≤ 10 000 entries, value ≤ 1 KiB, server
  limit 30 s, client deadline 60 s; referrals not followed.
- Plan: computers → connections (`dNSHostName`, else skipped), OUs → folders; no credentials; one-shot.
- Dependency: `ldap3 = { version = "=0.12.1", default-features = false, features =
  ["tls-rustls-ring"] }`. Licence MIT/Apache-2.0. **Maintenance exception** (owner decision 18):
  last release 2025-09-18, 14 months. `unsafe`: none in `ldap3` or `lber` 0.5.1 (source read).
  Overlap: `rustls`, `tokio-rustls`, `rustls-native-certs`, `x509-parser`, `nom` 7 are in the
  tree; new are `lber` (MIT) and `tokio-stream` (tokio project). Mitigation: exact pin,
  `ldap_ber_response` fuzz target, cargo-deny advisories; on a RUSTSEC, fork or replace.
- The bind password is handed to `ldap3` as `&str` (R-LDAP-STR, like R-RDP-STR).

### 5. IPC
```
import_formats() -> [{ format, label, extensions, knownLocation, secretsPossible }]
import_pick({ format }) -> { pickId, fileName, bytes } | null
import_preview({ source: { pickId } | { known: "openssh" | "putty" }, includePlaintextSecrets,
                 importKeyFiles }) -> ImportPreview
import_apply({ planId, exclude: [key], duplicates: "skip" | "import" }) -> ImportReport
import_discard({ planId }) -> void
ldap_import_preview({ url, baseDn, credentialId, preset, nameContains, ouFolders, protocolRule })
  -> ImportPreview
ldap_import_apply({ planId, exclude, duplicates }) -> ImportReport
ImportPreview = { planId, format, rootName, counts, items: [{ key, parent, kind, name, protocol?,
  host?, port?, username?, credentialKey?, duplicateOf? }], credentials: [{ key, name, kind,
  hasSecret }], skipped: [{ sourceRef, reason }], warnings: [{ code, sourceRef }] }  # ≤ 20 000 items
ImportReport  = { rootFolderId, folders, connections, credentials, secrets, skipped }
```
Codes: `import.too_large`, `import.format`, `import.encrypted`, `import.doctype`,
`import.limits`, `import.plan_expired`, `import.not_found`; `ldap.insecure`, `ldap.trust`,
`ldap.bind`, `ldap.dn_invalid`, `ldap.size_limit`, `ldap.timeout`, `ldap.unavailable`.

### 6. UI, audit, telemetry
- Onboarding card on an empty tree after `vault_create` (format tiles + "Start empty"); the same
  wizard in Settings → Import: Source → Options (plaintext-secret toggle only if `secretsPossible`,
  off) → Preview (checkboxes, duplicates, skipped) → Apply → Report; mRemoteNG "re-enter passwords" banner.
- Audit: `import.apply { format, folders, connections, credentials, secrets, skipped }`,
  `ldap.search { host, entries }`, `ldap.bind_failed { host }`, `import.refused { code }`.
  No host lists or file names in the audit.
- **No telemetry**: parsing is local; the only network traffic is LDAPS to the server the user
  types. Nothing about an import (format, counts, errors) leaves the device.

## Alternatives considered
- Merge into existing folders: silent-overwrite risk; one new root folder is reversible. Rejected.
- Decrypt mRemoteNG's default-key passwords: normalises reading "protected" data. Rejected (owner).
- `roxmltree` / `xml-rs`: DOM memory or speed, and new; `quick-xml` is in the tree. Rejected.
- Free-form LDAP filter: injection and DoS surface for no v0.1.0 need. Rejected.

## Security consequences
- New T3 surface: eight parsers on hostile files; bounded by caps, `DOCTYPE` refusal, fuzzing.
- R-IMPORT-SECRET (new): opted-in plaintext secrets pass the import buffer once; the source file
  stays on disk (the wizard says so).
- LDAPS: TOFU trust store, bind over TLS only, read-only wrapper; `ldap3` maintenance risk.

## Test plan
- Unit per importer: golden plans from scrubbed fixtures; caps max/max+1; DOCTYPE, gzip and depth
  bombs, bidi names, `user@host`, UTF-16 `.reg`; no secret without opt-in, none ever for mRemoteNG.
- Fuzz (one each): `import_royalts`, `import_rdm`, `import_termius_csv`, `import_termius_json`,
  `import_mremoteng`, `import_putty_reg`, `import_putty_session`, `import_ssh_config`,
  `ldap_ber_response`, `ldap_filter_escape` (oracle: escaped filter re-parses to one literal).
  Oracle for importers: no panic, caps hold, every item validates.
- Integration: apply is all-or-nothing (inject a failure mid-transaction); `planId` single use
  and dropped on lock; an LDAP mock in `mooring-testsrv` (LDAPS, paging, size limit, referral).
- E2E: onboarding → Termius CSV → preview → apply → tree; mRemoteNG banner.

## Amendment (2026-11-06, I2)

`ldap3` 0.12.1 is **not** in the product binary: its BER decoder (`lber::parse_tag`) recurses per
nesting level and `expect()`s on malformed frames, so a hostile LDAPS server could abort the
process. `mooring-import::ldap` speaks LDAP v3 itself (bind, paged search, abandon, unbind — the
only four operations the reader can emit) over tokio-rustls with `mooring-http`'s verifier,
encodes with `lber` and decodes only frames that passed an iterative bounds scan. `ldap3` stays a
dev-dependency as the RFC 4515 escaping oracle; the feature set is `tls-rustls-ring` (plain
`tls-rustls` does not compile). Filter shape: selectable object class (`ad` | `openldap`) plus an
escaped `cn`/`dNSHostName` substring; caps 5 000 entries / 30 s. Owner accepted.

