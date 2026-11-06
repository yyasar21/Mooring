# A4 — rust-core I2: LDAPS directory importer, `known_ldap_certs`, `ldap_import_*`, LDAP mock

Branch: worktree `agent-a245a94ee0c517afa`, started from `a4` @ `0c219aa` (I1, N1, U0 merged).
Not merged. Four commits (`4a47c3c`, `7bf9969`, `37286b4`, `16d109d`): http `TlsClient` +
`CertProtocol::Ldap`; `mooring-import::ldap` (feature `directory`); own bounded transport +
testsrv mock + fuzz targets; app commands. ADR-0019 §4 with the owner decisions given to I2:
LDAPS only (StartTLS refused), selectable AD / `OpenLDAP` object classes, optional name
substring filter with RFC 4515 escaping, ≤ 5 000 entries and 30 s, Windows OS hint → RDP else
SSH, no credential from the directory (`prompt`).

## Done

- **`mooring-http::tls`** (`crates/mooring-http/src/tls.rs`): `TlsTarget { protocol, host,
  port, known_certs_path, extra_ca_pem, trusted_once }` → `client_config()` →
  `TlsClient { config: Arc<ClientConfig>, .. }` carrying **our** `HttpVerifier` (pin before CA,
  `known_<protocol>_certs` reloaded per connect and failing closed, `extra_ca_pem`,
  `trusted_once`; resumption off, no ALPN). `TlsClient::trust_error()` maps a failed handshake
  to the same `http.trust_prompt` / `trust_mismatch` / `trust_rejected` / `trust_conflict`
  errors (with the `TrustDecision`) the HTTPS clients raise. The connector's chain builder,
  pin-store loader and decision→error mapping were factored into shared functions; the HTTP
  path is unchanged (153 http tests pass). `CertProtocol::Ldap` → `known_ldap_certs`, name
  `ldap`, no connection protocol, TLS always.
- **`mooring-import::ldap`** (feature `directory`, on in src-tauri, fuzz and the crate's own
  tests):
  - `filter.rs`: `escape_value` (RFC 4515 §3: `* ( ) \`, NUL and every control char →
    `\XX`), `search_filter(kind, name_contains)` → `(objectClass=computer)` or
    `(|(objectClass=ipHost)(objectClass=device))`, AND-ed with
    `(|(cn=*v*)(dNSHostName=*v*))` (value ≤ 256 bytes, no control chars); `Dn::parse`
    (RFC 4514: unescaped `,` / `+` splitting, `\XX` and `\<special>` escapes, `#hex` opaque,
    types `descr` or OID, ≤ 1 024 bytes, ≤ 64 RDNs, root DSE refused), `relative_to(base)`
    (case-insensitive suffix match), `domain()` (`dc` → `corp.example.test`), `to_wire()`;
    `LdapTarget::parse`: `ldaps://host[:port][/]` only — `ldap://` and `ldapi://` →
    `ldap.insecure`, user info / path / query / bad host → `ldap.invalid`; IPv6 bracketed.
  - `wire.rs`: the **only four request encoders** (`bind_request`, `search_request` with the
    RFC 2696 control, `abandon_request`, `unbind_request`; `write_ops_are_absent_from_the_reader`
    pins it), the BER filter builder (`filter_tag`: values travel as octet strings, so the
    escaping above is the text / audit / recorder form, not a wire concern), and panic-free
    decoders for `LDAPMessage`, `LDAPResult.resultCode` and the paged cookie.
  - `frame.rs`: `scan()` — an **iterative** TLV walk (definite lengths only, ≤ 4 length
    octets, ≤ 4 tag octets, depth ≤ 32, ≤ 256 KiB) that every server frame must pass before
    the recursive `lber` parser sees it. Why: see *Decision needed* 1.
  - `entry.rs`: `extract()` walks `[APPLICATION 4] { dn, attributes }` with caps (DN ≤ 1 KiB,
    value ≤ 1 KiB, ≤ 16 values, ≤ 64 attributes looked at), keeps only `cn`, `dNSHostName`,
    `operatingSystem`, `description`, `distinguishedName`, `ipHostNumber`, drops binary or
    over-cap values (counted), errors on any other shape.
  - `client.rs`: `DirectoryReader` — tokio-rustls connect with the `TlsClient` (10 s), simple
    bind (rc ≠ 0 → `ldap.bind` with the code, unbind, no diagnostic text kept), paged search
    (page 500, ≤ 12 pages, server `sizeLimit` = cap, `timeLimit` = 30 s; one entry over the
    cap → `AbandonRequest` + `ldap.size_limit`; rc 4 → `ldap.size_limit`, rc 3 →
    `ldap.timeout`, rc 32 → `ldap.dn_invalid`; referrals / intermediates ignored, never
    followed; > 64 malformed entries → `ldap.response`), unbind + read-to-EOF (500 ms grace),
    the whole run in one `tokio::spawn` under the 30 s deadline (a panic below becomes
    `ldap.response`, never the process). `fetch` / `bind_only` / `preview` entry points.
  - `plan.rs`: entries → `ImportPlan` through `PlanBuilder` (I1 validators and caps): the OUs
    between the entry and the base DN become folders (`ou` value, else the first AVA), depth
    cap 8 with `WarningCode::PathTruncated` (new), name = `cn` else the entry RDN; host =
    `dNSHostName` (AD; missing → `skipped(invalid)`), `OpenLDAP` falls back to `ipHostNumber`
    then `cn`; entries outside the base or with an unparsable DN → `skipped(invalid)`
    (`source_ref` = `entry <n>`, never a DN); `operatingSystem` containing `windows` → RDP,
    else SSH; **one shared `prompt` credential** "Directory account (corp.example.test)" with
    the `dc` domain pre-filled (AD) / "Directory account" (`OpenLDAP`); no tags, no port.
  - `LdapQuery { url, base_dn, scope, kind, name_contains, size_limit }` → `prepare()` →
    `Prepared` (parsed target, DN, text filter, clamped cap); `LdapLimits::DEFAULT`;
    `BindCredential` (`Zeroizing` password, `Debug` prints the name only); `LdapError` with
    codes `ldap.insecure | invalid | dn_invalid | bind | size_limit | timeout | unavailable |
    response`, TLS failures as `LdapError::Tls(HttpError)` → `http.*` codes.
  - `ImportFormat::Ldap` (name `ldap`, label "LDAP directory", no extensions, no secrets);
    `ImportFormat::FILES` (six) vs `ALL` (seven); `importer()` now returns `Option`;
    `parse(Ldap, …)` → `import.format`. `import_formats()` keeps listing `FILES`.
- **Fuzz** (`fuzz/entries/ldap_filter_escape.rs`, `ldap_ber_response.rs`, targets, bins,
  seeds under `fuzz/corpus/` added with `-f`, `fuzz/regressions/*/.gitkeep`, nightly rows +
  the `ldap_*` malloc rule, `docs/qa/fuzzing.md` section, stable replay in
  `crates/mooring-import/tests/fuzz_corpus.rs`): entries in `mooring_import::ldap::fuzz`.
  `ldap_filter_escape` oracle: no raw `( ) * \` / control byte in the output, unescapes back
  to the input, the built filter is one balanced expression no deeper than the fixed shape, a
  parsed DN round-trips through `to_wire`, URL parser never panics. `ldap_ber_response`:
  `scan` → `lber::parse_tag` (a scan-accepted frame must parse to exactly that length) →
  message / result / cookie / entry decoders → `build_plan` under the I1 plan oracle.
  `fuzz/Cargo.lock` gains `lber 0.5.1` only (resolved offline).
- **Mock** (`crates/mooring-testsrv/src/ldap/`, `ldap-testsrv` bin): loopback TLS, one bind
  account, five AD-style fixture entries (`DC=corp,DC=example,DC=test`: `OU=Servers`,
  `OU=Web`, `OU=Workstations`, `OU=People`), filter evaluation (and / or / not / eq /
  substrings / present), scope base / one / sub, RFC 2696 paging with a decimal-offset cookie,
  request `sizeLimit` honoured (rc 4), knobs `size_limit_after`, `referral`, `ignore_paging`,
  `ignore_size_limit`, `never_answer_search`, `bind_delay`, `hostile: EmptyMessage |
  DeepNesting(n) | HugeLength | Garbage | OversizedValue(n) | ExtraElement`. `LdapRecorder`
  (`ops()`, `searches()` with the filter rendered back to RFC 4515 text, base, scope, limits,
  paged cookie; the bind password is never recorded) and `assert_no_violations()`: a
  violation is any operation other than bind / search / abandon / unbind, a search before a
  successful bind, a SASL bind, a malformed frame or a frame over 64 KiB.
- **App** (`src-tauri/src/commands/ldap_import.rs`): `ldap_import_preview` and
  `ldap_import_test` (async, `Scope::Main`, `permissions/mooring-main.toml`, autogenerated
  permission files, guard rows, goldens re-blessed: `ipc-manifest.json` +2,
  `ipc-codes.json` +8 `ldap.*`, `ipc-passive.json` unchanged; gate matrix rows in
  `vault_gated_codes_a4_import`). Vault gate first; the credential (`domain_user` → UPN or
  `DOMAIN\user` by `form`, `user_password` → username or `user@domain`; anything else →
  `credential.incompatible`) is read from the vault for the call and dropped; `caPem`
  ≤ 64 KiB. Trust: `known_ldap_certs`, `caPem`, and on `http.trust_prompt` the Rust-native
  Gate (`Scope { kind: "ldap_trust" }`, "Trust" pins through `KnownCerts::add_and_save`, a
  store write failure → `trusted_once` for this run; refused → `http.trust_rejected`; no
  prompt (tests) → `http.trust_prompt`). The plan goes through I1's `finish_preview`
  (duplicates against the store, plan store, `import_previewed { format: "ldap" }`) and is
  applied with `import_apply` / `import_discard`. Audit (`mooring-audit`): new `ldap_bind
  { host, success }`; `import_refused { code }` on every refusal; `cert_decision` with
  protocol `ldap`. Nothing about the bind name, DN, entries or password is audited (tested).

## UI contract (for the ui-engineer, `apps/desktop/src/lib/ipc.ts`)

```
ldap_import_test({ url, baseDn, kind, credentialId, caPem? }) -> { host, port, boundAs }
ldap_import_preview({ url, baseDn, scope?, kind, filter?, credentialId, caPem?, sizeLimit? }) -> ImportPreview
  url:          "ldaps://host[:636]"            (ldap:// → ldap.insecure)
  baseDn:       "DC=corp,DC=example,DC=test"    (RFC 4514; ldap.dn_invalid)
  scope:        "base" | "one" | "sub"           (default "sub")
  kind:         "ad" | "openldap"
  filter:       substring the cn / dNSHostName must contain (≤ 256 chars; escaped by Rust)
  credentialId: a domain_user or user_password credential (credential.incompatible otherwise)
  caPem:        extra PEM roots (≤ 64 KiB)
  sizeLimit:    1..=5000 (clamped; 0 → ldap.invalid)
ImportPreview as in I1, with format: "ldap", rootName "Imported from LDAP directory (<date>)",
  items: folders mirror the OU path (≤ 8 deep), connections rdp | ssh with host = dNSHostName,
  no port / username; credentials: one { kind: "prompt", hasSecret: false };
  skipped reasons: invalid (no dNSHostName, bad or foreign DN); warnings: path_truncated (new code)
then import_apply({ planId, exclude, duplicates }) / import_discard({ planId }) as in I1
codes: ldap.insecure, ldap.invalid, ldap.dn_invalid, ldap.bind, ldap.size_limit, ldap.timeout,
       ldap.unavailable, ldap.response, http.trust_prompt (only when the dialog could not be
       shown), http.trust_rejected, http.trust_mismatch, http.trust_conflict, http.trust_store,
       http.tls, http.invalid, credential.incompatible, credential.not_found, input.invalid,
       vault.locked, import.plan_expired
```
The certificate prompt is a Rust-native dialog (like vCenter): the UI only sees the result.
`ldap_import_test` runs bind + unbind and never searches; `boundAs` is the name used.

## Decision needed

1. **`ldap3`'s transport is not used (owner decision 18 reconsidered).** The crate is pinned
   and in the lockfile as the ADR asked, but only as a **dev-dependency** of `mooring-import`
   (its RFC 4515 parser is the independent oracle of the escaping tests). Reason, found
   while writing the hostile-response tests: `lber::parse_tag` recurses once per BER nesting
   level and `ldap3`'s decoder and control parsers `expect()` on malformed frames. With
   `ldap3 0.12.1` driving the connection, the mock's `DeepNesting(2_000)` reply (≈ 6 KiB)
   **overflowed the stack and aborted the test process** — a T3 server could crash the whole
   app with a few KiB; a `30 00` frame panicked the driver task. No stack size fixes a
   linear-in-bytes recursion, and `ldap3` owns the socket after `set_config`, so nothing can
   be put in front of its parser. The reader now speaks LDAP v3 itself (RFC 4511: four
   requests, bind / search / abandon / unbind) over tokio-rustls, uses `lber` only to encode
   requests and to parse frames that passed the iterative scan, and the same mock replies
   (`DeepNesting(100_000)`, `HugeLength`, `EmptyMessage`, `Garbage`, `ExtraElement`,
   `OversizedValue`) now end in `ldap.response` within milliseconds, nothing panics. Product
   tree: `lber 0.5.1` (MIT, no `unsafe`, ldap3's own codec, ≈ 1 100 lines) + crates already
   present (`tokio-rustls`, `rustls`, `bytes`, `tokio`); **no `ldap3` code runs in the
   product**. If the owner still wants `ldap3` on the wire, the only safe route I see is a
   patched `lber` (depth cap inside `parse_tag`) via `[patch.crates-io]` plus wrapping every
   `ldap3` call in a task — still leaving the `expect()`s and the unbounded `BytesMut`
   growth in `ldap3::conn`. Review 7 should take this decision; the ADR §4 dependency line
   needs the architect's update either way (`ldap3` dev-only, `lber` product).
2. **Filter shape vs ADR §4 presets.** The orchestrator's I2 brief (selectable object class,
   optional name filter with RFC 4515 escaping, ≤ 5 000 / 30 s) was implemented; the ADR text
   still says presets `computers | computers_enabled | windows_computers`, `nameContains`,
   `ouFolders`, `protocolRule`, ≤ 10 000 / 60 s, and `ldap_import_apply`. The IPC above is the
   brief's; `ouFolders` is always on, `protocolRule` is always `by_os`; apply reuses
   `import_apply`. Architect to align §4 / §5.
3. `description` is requested but not mapped: `PlanConnection` has no notes field (I1 left
   `options` / notes out too). Drop it from the attribute list, or add notes to the plan.
4. Client deadline = server `timeLimit` = 30 s (the brief's one number). A slow directory
   answers `timeLimitExceeded` and the client's own deadline race at the same moment; both
   are `ldap.timeout`. If the ADR's 30 s server / 60 s client split is preferred, change
   `LdapLimits::DEFAULT.deadline` and add a `server_time_limit` field.
5. Review 7 items to look at: `TlsClient` exposes `HttpVerifier` indirectly to a non-HTTP
   caller (same pins file semantics, no plaintext path); the `ldap_trust` dialog kind in the
   `ConfirmGate`; the `prompt` credential with an empty username (allowed by `PromptFields`).

## Left open

- `OpenLDAP` mapping is untested against a real server (no sample): `ipHost` / `device`
  objects, `ipHostNumber` first value as the host. AD attribute names are the documented
  ones (`dNSHostName`, `operatingSystem`); `userAccountControl` (disabled computers) is not
  read — a `computers_enabled` preset would add `(!(userAccountControl:1.2.840.113556.1.4.803:=2))`.
- One run per preview; no saved directory source, no scheduled refresh (ADR Left open).
- Paging assumes a server that returns a cookie; a server that ignores the control returns
  everything in one page (tested with `ignore_paging`). Servers that cap the page size
  themselves (AD `MaxPageSize` 1 000) are fine: the client follows the cookie.
- The TOFU dialog names `host:port`, subject, issuer and fingerprint like the vCenter one; no
  SAN list (the `CertificateInfo` is available if the UI wants more).
- `ldap_import_test` uses the credential but no search; it does not check the base DN exists
  (`ldap.dn_invalid` surfaces at preview from rc 32).
- Telemetry: the only network traffic is the LDAPS session to the typed host; the local
  known-certs file is the only write outside the store.

## Dependency notes for review 7 (`ldap3` / `lber`)

- `lber 0.5.1` (MIT, Ivan Nejgebauer; last release with `ldap3 0.12.x`): **product
  dependency** of `mooring-import` (feature `directory`) and `mooring-testsrv`. Source read:
  no `unsafe`; recursive `parse_tag` (hence the scan in front), `nom 7` (in the tree),
  `bytes` (in the tree). Exact pin `=0.5.1`.
- `ldap3 0.12.1` (MIT/Apache-2.0, 2025-09-18): **dev-dependency only** (escaping oracle);
  features `default-features = false, features = ["tls-rustls-ring"]` — the feature named in
  the brief, `tls-rustls`, does **not** compile alone (`compile_error!`: a provider feature is
  mandatory), so `tls-rustls-ring` (= `tls-rustls` + `rustls/ring` + `rustls-provider`) is
  the right set, as the ADR says. No `unsafe` in its source. Its tree adds `tokio-stream
  0.1.19` (tokio project, MIT) to the lockfile; `tokio-util`, `url`, `percent-encoding`,
  `futures`, `nom 7`, `x509-parser 0.18`, `rustls-native-certs` were already present. Not in
  any product binary (`cargo tree -e normal -p mooring-app` shows `lber` only).
- `cargo deny check`: advisories ok, bans ok, licenses ok (MIT), sources ok.
- Root `Cargo.lock` diff vs `0c219aa`: `+ lber 0.5.1`, `+ ldap3 0.12.1`, `+ tokio-stream
  0.1.19`; no version changes. `fuzz/Cargo.lock`: `+ lber 0.5.1`.

## Manifests and QA-owned files touched (flagged for the orchestrator / QA)

- `Cargo.toml`: workspace deps `ldap3`, `lber` with the justification comment.
- `crates/mooring-import/Cargo.toml`: feature `directory`, optional deps, dev-deps
  (`mooring-import` self with the feature, `ldap3`, `mooring-testsrv`, `tempfile`, `tokio`).
- `crates/mooring-testsrv/Cargo.toml`: `lber`. `src-tauri/Cargo.toml`: `features =
  ["directory"]` on `mooring-import`. `fuzz/Cargo.toml` + `fuzz/Cargo.lock`: the feature and
  two bins. `.github/workflows/fuzz-nightly.yml`, `docs/qa/fuzzing.md`: two rows + section.
- `src-tauri/tests/e2e_flow/support.rs`: two gate matrix rows (as I1 did).

## Test evidence (Linux, rustc 1.97.0)

- `cargo fmt --all -- --check`: clean.
- `cargo clippy -p mooring-app -p mooring-audit -p mooring-import -p mooring-testsrv
  -p mooring-http -p mooring-core --all-targets -- -D warnings`: clean (the pre-existing
  `unknown_lints` note only).
- `cargo test -p mooring-import`: 65 unit (+22: filter / DN / URL / entry / plan / query /
  reader-ops grep / error codes, 2 frame scans incl. 100 000-level nesting, 9 mock-driven:
  fixture mapping with recorder assertions, paging cookies + page / entry caps, client-side
  abandon, escaped injection on the wire, bind failure + bind-only, trust prompt, referral +
  unpaged server, hostile frames fail fast without panics, slow bind → timeout) + 2 replay
  (now 11 targets) — all pass.
- `cargo test -p mooring-testsrv`: 16 — pass. `cargo test -p mooring-http`: 153 (+2) — pass.
  `cargo test -p mooring-core`, `-p mooring-audit` (36), `-p mooring-store`, `-p
  mooring-sync`, `-p mooring-secrets`: pass.
- `cargo test -p mooring-app`: 329 lib (+6: prompt once → pin → preview → apply → second run
  without prompt and duplicates flagged, audit rows without names; refused / absent prompt
  never reaches the server; bad inputs, wrong credential kind, wrong password; test bind +
  locked vault; server size limit; code catalogue) + 21 `e2e_flow` (gate matrix with the two
  new rows) — all pass.
- `MOORING_BLESS=1 cargo test -p mooring-app golden`: `ipc-manifest.json`, `ipc-codes.json`
  rewritten as listed; `ipc-passive.json` unchanged; `cargo metadata --locked`: ok.
- `cargo deny check`: ok. Every file ≤ 500 lines (largest: `mooring-testsrv/src/ldap/mod.rs`
  466, `ldap/tests.rs` 436). `target/` removed before the report.
