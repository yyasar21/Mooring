# A5 · qa-engineer · W4: fuzz targets, E2E flows, seed-count check

Worktree `agent-acb4ddced7e3aa83b`, branch `worktree-agent-acb4ddced7e3aa83b`, from `73ec34a`
(R1–R6, U1–U6, release A5 merged). Only qa-owned paths touched: `fuzz/**`,
`crates/*/tests/**`, `apps/desktop/e2e/**`, `src-tauri/tests/e2e_flow/**`,
`.github/workflows/fuzz-nightly.yml`, plus `docs/qa/fuzzing.md` (the fuzz inventory qa keeps)
and this note. No product code, no new dependency. Linux x86_64, `CARGO_INCREMENTAL=0`,
`CARGO_TARGET_DIR=/home/claude/nexus/target` reused, `node_modules` symlinked from the main
checkout (not committed).

## Done

### 1. Fuzz targets (12 new, 66 in all)

Every A5 entry point the handoffs name is wired with the exact `fuzz_*` function: an entry in
`fuzz/entries/`, a 3-line wrapper in `fuzz/fuzz_targets/`, a `[[bin]]` in `fuzz/Cargo.toml`, a
nightly matrix row (with the 1 GiB `-malloc_limit_mb` like every other wire parser), seeds in
`fuzz/corpus/<t>/` (force-added: `fuzz/corpus/` is gitignored, as for the earlier seeds), an
empty `fuzz/regressions/<t>/` and a stable replay in the crate's `tests/fuzz_corpus*.rs`.

| Target | Crate entry | Seeds | Stable replay + seed pins |
| --- | --- | --- | --- |
| `export_document_json` | `mooring_sync::fuzz::fuzz_export_document_json` | 6: a valid v2 document of a throwaway `KdfParams::TEST` vault; folder cycle, version 3, vault-id mismatch, dangling credential, duplicate JSON key | `mooring-sync/tests/fuzz_corpus.rs`: the v2 seed parses (2 folders, 1 connection, 1 credential); each hostile seed is refused with its own `ExportError` |
| `vault_db_creds` | `mooring_secrets::fuzz::fuzz_vault_db_creds` | 5: `database/creds`, `ssh/creds` OTP, `sys/leases/renew`, bad lease id, no data (shapes copied from `mooring-testsrv` dynamic Vault) | `mooring-secrets/tests/fuzz_corpus.rs` |
| `vault_ssh_sign` | `…::fuzz_vault_ssh_sign` | 2: `testdata::SSH_CA_CERT` (fits the entry's fixed subject key), a truncated cert | same; the cert seed passes `check_signed_certificate` |
| `vault_pki_issue` | `…::fuzz_vault_pki_issue` | 2: `testdata::CERT_PEM` with a placeholder key, a bad serial + non-list chain | same |
| `connect_item_json` | `…::fuzz_connect_item_json` | 4: LOGIN item with a section, API item, vault list, item list (Connect mock shapes) | same |
| `bws_secret_json` | `…::fuzz_bws_secret_json` | 5: `secret get` (full CLI object), `secret list`, duplicate key, `project list`, `bws 1.0.0` | same; no A5 secrets seed holds a `PRIVATE KEY` block (asserted) |
| `op_reference_parse` | `mooring_core::credential::fuzz_op_reference` | 6: `op://` item / field / section+field, `?attribute=otp` (refused), bws id, bws project/key | `mooring-core/tests/fuzz_corpus_a5.rs` (new): each grammar's shapes parse, the query form is refused |
| `sk_key_parse` | `mooring_core::credential::fuzz_sk_key_parse` | 6: Ed25519-sk and ECDSA-sk lines and blobs, a non-`ssh:` application, a plain Ed25519 line | same: both lines parse with `ssh:`; plain line and foreign application refused; the `id_*_sk` handle is built at test time from `testdata::sk_key_handle_pem` and parsed through the entry (never committed: it is PEM-armoured like a private key) |
| `agent_identities` | `mooring_proto_ssh::fuzz_agent_identities` | 8: identities answer (sk + plain), empty answer, FAILURE, sign response, sk signatures (Ed25519, ECDSA, no presence), a 2³²−1 count | `mooring-proto-ssh/tests/fuzz_corpus.rs`; the answer seed carries the same blob as `sk_key_parse/ed25519-sk-blob` |
| `sk_helper_reply` | `mooring_proto_ssh::fuzz_sk_helper_reply` | 4: sign reply, error reply, version 4, length mismatch | same |
| `rdg_pdu` | `mooring_proto_rdp::gateway::fuzz_rdg_pdu` | 7: whole server flow (8 packets, built with `pdu::server`), client flow, masked and unmasked WebSocket frames, ping+close, a 4 GiB length, a hostile `CHANNEL_CREATE` | `mooring-proto-rdp/tests/fuzz_corpus.rs`: the server flow decodes to 8 packets, the masked frame unwraps to the client flow, the hostile length is refused |
| `rdg_http_response` | `mooring_proto_rdp::gateway::fuzz_rdg_http_response` | 5: 101 upgrade, NTLM 401 (+ Negotiate), Basic 401 with body, chunked 404, bad NTLM base64 | same: 101 has the upgrade token, the challenge sets match, the bad token is refused |

New inventory gate: `mooring-core/tests/fuzz_corpus_a5.rs::every_fuzz_target_runs_nightly_with_seeds`
fails when any `[[bin]]` of `fuzz/Cargo.toml` is missing from the nightly matrix, has no seed or
no regressions directory (66 targets today).

`fuzz/Cargo.lock`: one line, `mooring-proto-rdp` now depends on `sha1` (already in the lock; R5's
WebSocket accept). No new package.

Seeds are ASCII or binary wire bytes; none holds a bidi control character, a real host (only
`*.example.test`, RFC 5737), or key material (no `PRIVATE KEY` PEM anywhere in the new corpora).

### 2. E2E (`apps/desktop/e2e/a5.e2e.mjs`, 7 → 9 flows)

- **RD Gateway** (U6 suggestion 1): open the seeded "finance-desk" → "RD Gateway certificate"
  dialog names `gw01.example.test:443` and explains Trust once → Trust once → "Verify server
  certificate" without a Trust once button → Trust and remember → `connected`; the first
  gateway/prompt event is `gateway_status`; the toolbar shows "via RD Gateway gw01.example.test"
  and NLA; audit `trust_decision { protocol: rdg, decision: trusted_once }` and
  `session.rdp.gateway { outcome: ok }`; no `rdg|gw01.example.test:443` pin stored.
- **Smart card PIN** (U6 suggestion 2): web01 is pointed at "piv badge" in the editor → host
  key → "Smart card PIN" dialog (reader named, `type=password`, Unlock disabled while empty) →
  answer → `connected`; `credential.pin_prompted { entered }`, `session.auth_sk { backend: piv,
  ok }`; the PIN is in no audit row and not in the DOM. Close, reopen → the PIN is asked again
  first → Escape → dialog gone, `pin_prompted { cancelled }`, `closed` after the prompt, never a
  second `connected`, "smart card PIN cancelled" shown.
- **Security-key touch banner** (U5): already added by U5; kept as is and confirmed (it runs in
  `make e2e`).
- **Web via spinner**: not added; the mock has no `via` for web windows (`ipc.mock.web.ts`
  opens a window at once, no hop or proxy step), so there is no spinner to drive. See Left open.

### 3. `InstallFacts { winget: false }` in `src-tauri/tests/e2e_flow` (taken over from R6)

Both literals are right: `a4_1_portable.rs` is an AppImage and `a4_update.rs` rows are
Deb / MacApp / Unknown / AppImage; `OsProbe` reads the winget marker for NSIS only
(`install_mode.rs`: `winget = bundle == Nsis && winget_marker(..)`), so `false` is exactly
what a real probe reports. Added coverage: `probe_winget(..)` and a fifth manual-mode row in
`offer_in_manual_mode_is_shown_but_install_is_refused_before_the_source` — a **writable** NSIS
install with the marker → `install_mode: manual`, `manual_reason: "winget"`,
`update.manual_only`, the offer still shown, install refused before the source (refused / check
audit counts 4 → 5 because of the new row).

### 4. Seed-count changes in vitest (U5 / U6) — confirmed intentional

- `backup.test.tsx`: `12/15 → 13/16` (U5: `c-yubi` + `cr-yubi`) → `14/17` (U6: `c-rdg` +
  `cr-piv`). The seed has exactly 14 `c("c-…")` and 17 `m("cr-…")` rows; folders stay 6. The
  assertion is still the exact sentence (regex on the full text), not loosened.
- `credentials.test.tsx`: "domain admin" `2used → 3used` — `cr-ad` is the Desktops folder
  default, dc01's gateway credential and now finance-desk's sign-in. Exact count kept.
- Both files pass (38 tests). No gate weakened.

## Left open

- **Web via E2E**: needs a mock `via` path for web windows (hop status + a "connecting via"
  state) from ui-engineer; then one flow in `a5.e2e.mjs`.
- **RDG over a jump chain** (R5 Left open): no app-level test through `ViaSession` + the mock
  gateway yet; the gateway mock still lives in `crates/mooring-proto-rdp/tests/rdg_mock/` and
  was not lifted into `mooring-testsrv` this round.
- Nightly toolchain is not installed here; the targets were built and run with stable +
  `RUSTC_BOOTSTRAP=1` (see Test evidence). CI uses real nightly.

## Decision needed

- **`parse_hdiutil_info`** (`src-tauri/src/install_location.rs`, a5-rust-core-0028): there is no
  `fuzz_*` entry and the function lives in `mooring-app`; the fuzz crate cannot depend on it
  without Tauri and the WebView toolchain. Options: rust-core moves it (pure, no Tauri) into a
  small module of an existing pure crate (e.g. `mooring-core::install`) with a
  `fuzz_hdiutil_info` entry, and qa wires `hdiutil_info`; or accept the in-crate proptest/junk
  test (`install_location_tests::hdiutil_info_lists_image_mounts_only`) as enough. Not edited.
- **Smart card / PIV**: no PIV-specific parser is exposed (`piv_auth` only resolves module
  paths; agent replies go through `agent_wire`, already fuzzed by `agent_identities`). Nothing
  to wire unless rust-core adds one.
- Target name: the secrets doc comment calls it `op_reference_parse` (the brief said
  `op_reference`); I used `op_reference_parse` to match `external_ref_parse` and the crate docs.

## Test evidence

Linux x86_64, 2026-11-08, `CARGO_INCREMENTAL=0`, one package at a time.

```
cargo test -p mooring-sync --test fuzz_corpus                 6 passed  (export_document_json 2 new)
cargo test -p mooring-secrets --test fuzz_corpus              10 passed (6 new)
cargo test -p mooring-core --test fuzz_corpus --test fuzz_corpus_a5   17 + 6 passed (6 new, incl. inventory gate: 66 targets)
cargo test -p mooring-proto-ssh --test fuzz_corpus            6 passed  (3 new)
cargo test -p mooring-proto-rdp --test fuzz_corpus            12 passed (4 new)
cargo test -p mooring-app --test e2e_flow                     55 passed (winget row in a4_update)
cargo clippy -p mooring-{core,sync,secrets,proto-ssh,proto-rdp} --all-targets -D warnings   clean*
cargo clippy -p mooring-app --test e2e_flow -D warnings       clean*
cargo fmt --check (touched packages)                          clean
fuzz/: cargo check --locked --bins                            ok (all 66 bins)
fuzz/: RUSTC_BOOTSTRAP=1 cargo fuzz build <t> + run 20 s each (seed corpus copied to a temp dir,
       -malloc_limit_mb=1024 -rss_limit_mb=3072), no crash, no OOM:
  export_document_json  540 567 execs   vault_db_creds     611 439   vault_ssh_sign   1 064 694
  vault_pki_issue       600 767         connect_item_json  470 125   bws_secret_json    455 734
  op_reference_parse  2 669 285         sk_key_parse     1 360 777   agent_identities 1 887 022
  sk_helper_reply     6 210 738         rdg_pdu          2 357 729   rdg_http_response 1 841 419
make e2e (MOORING_E2E_BROWSER=/usr/bin/google-chrome)
  flows 5/5 · kube 6/6 · vsphere 4/4 · secrets-sync 7/7 · a4 11/11 · a5 9/9 — 42 passed, 0 failed
pnpm lint                                                     ok
vitest backup.test.tsx + credentials.test.tsx                 38 passed
```

\* the only clippy output is the pre-existing `unknown lint: clippy::unused_async_trait_impl`
warning from the root `Cargo.toml` (toolchain older than the lint name); not from this change.

Not run here: real nightly (none installed; CI's `fuzz-nightly` uses it), semgrep registry rules
(the proxy refuses `semgrep.dev`), gitleaks. The new seeds were grepped for `PRIVATE KEY`,
bidi controls and RFC 1918 addresses: none.
