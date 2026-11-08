# Fuzzing

Every parser of untrusted input ships with a fuzz target (CLAUDE.md, ADR-0010 §Consequences).
The targets live in their own cargo workspace under `fuzz/`, so `cargo test --workspace` never
builds libFuzzer.

| Target | Entry (`fuzz/entries/`) | Parser | Hostile source |
| --- | --- | --- | --- |
| `known_hosts_parse` | `known_hosts.rs` | `KnownHosts::parse_bytes` | `~/.ssh/known_hosts` written by other tools |
| `kubeconfig_parse` | `kubeconfig.rs` | `credential::kubeconfig::parse` | pasted / imported kubeconfig |
| `vault_header_from_bytes` | `vault_header.rs` | `Header::from_bytes` | vault file read before any key exists |
| `import_age` | `import_age.rs` | `import_age` | backup file chosen by the user |
| `socks5_handshake` | `socks5.rs` | `socks::parse_request` | local app on the dynamic-forward port |

Each entry is a plain `pub fn run(data: &[u8])` that must never panic and asserts a few
invariants (round trips, documented caps, determinism). The same file is compiled twice:

- by `fuzz/fuzz_targets/<target>.rs` through `libfuzzer_sys::fuzz_target!` (nightly);
- by `crates/<crate>/tests/fuzz_corpus.rs` through `#[path]`, which replays every file in
  `fuzz/corpus/<target>/` and `fuzz/regressions/<target>/` on stable as part of the normal test
  suite. A regression therefore fails `cargo test` in ordinary CI without nightly.

`kubeconfig_parse` also checks the parser's security property (review 3 M-5, review 4 M-11).
After a successful parse, `violations` re-scans the input with `saphyr-parser`, the parser's own
YAML event layer at the locked version, through separate code. It panics on any of these:

- a `<<` or `!!merge` key anywhere in the file;
- a key under `users[]` (any depth) that matches `exec`, `auth-provider`, `tokenFile`,
  `client-certificate` or `client-key`, compared ASCII case-insensitively;
- a key under `clusters[]` that matches `certificate-authority`;
- under either section, a key the oracle cannot name: a tagged key, an alias, or a complex
  (`? …`) key.

The section names `users` / `clusters` are matched case-insensitively too, because a lenient
consumer folds them. The forbidden list is a separate copy of the parser's list. It does not
contain `token-file`: that is not a kubeconfig field. client-go's field is `tokenFile`, and
case folding does not remove a hyphen. The stable test `oracle_flags_each_construct` pins the
oracle itself, so a weakened oracle fails CI.

## Owed targets

CLAUDE.md requires a fuzz target for every parser of untrusted input. Review 4 ("Carried
forward") lists these as still owed. None is a target yet, and each has only unit and proptest
coverage in its crate:

| Planned target | Function | Hostile source | Invariants to assert | Blocker |
| --- | --- | --- | --- | --- |
| `fingerprint_ssh_public_key` | `credential::fingerprint::ssh_public_key(&str)` | pasted public key / `authorized_keys` line | no panic; `Ok` starts with `SHA256:`; deterministic | none (`pub`) |
| `fingerprint_ssh_certificate` | `fingerprint::ssh_certificate(&str)` | pasted OpenSSH certificate | as above; a plain public key is refused | none |
| `fingerprint_ssh_private_key` | `fingerprint::ssh_private_key(&[u8])` | imported private key (PEM / OpenSSH) | no panic; never decrypts (bounded time whatever the KDF rounds); legacy PEM yields no fingerprint | none |
| `fingerprint_x509_pem` | `fingerprint::x509_pem(&str)` | pasted certificate PEM | no panic; deterministic; any non-`CERTIFICATE` PEM block refused | none |
| `otp_decode_seed` | `credential::otp::decode_seed(&[u8])` | pasted TOTP seed / `otpauth://` secret | no panic; `Ok` holds at least `MIN_SEED_BYTES`; input over `MAX_SEED_TEXT` refused; case, space, hyphen and padding variants decode equal | none |
| `parse_account` | `credential::parse_account(&str)` | typed `DOMAIN\user` / UPN | no panic; `parse_account(a.render()) == a` for every `Ok` (round trip) | none |
| `export_json` | post-decryption check of `mooring_vault::export::import_age` (`serde_json` into `ExportDocument` + `header.check()`) | decrypted backup payload | no panic; caps (`MAX_EXPORT_BYTES`, record count) honoured; header re-accepted | not reachable without scrypt + AEAD: needs `ExportDocument::from_json(&[u8])` from rust-core (A1 exit QA, decision 4) |

Each one is an `entries/<name>.rs` with `pub fn run(&[u8])`, a seed corpus and a stable replay in
the owning crate's `tests/fuzz_corpus.rs`, as for the targets above. The fingerprint, OTP and
account targets go in `mooring-core` and can land without any API change.

## A2 targets

The `r1` / `r3` / `r4` gates are gone (A2 integration): every target below fuzzes the real
parser and is replayed on stable by the owning crate's `tests/fuzz_corpus.rs`.

| Target | Entry | Parser | Name in the ADR | Stable replay |
| --- | --- | --- | --- | --- |
| `mfr1_decode` | `mfr1.rs` | `mooring_core::frame::decode_mfr1` | (MFR1 frame path) | mooring-core |
| `known_certs_parse` | `known_certs.rs` | `mooring_core::known_certs::KnownCerts::parse_bytes` | `known_certs_parse` | mooring-core |
| `rfb_server_msg` | `rfb_server_msg.rs` | `mooring_proto_vnc::fuzz::server_messages` | `rfb_server_message` | mooring-proto-vnc |
| `vnc_zrle` | `vnc_zrle.rs` | `mooring_proto_vnc::fuzz::zrle` (`decode_zrle`) | `zrle_decode` | mooring-proto-vnc |
| `vnc_tight` | `vnc_tight.rs` | `mooring_proto_vnc::fuzz::tight` (`decode_tight`) | `tight_decode` | mooring-proto-vnc |
| `rdp_fastpath` | `rdp_fastpath.rs` | `mooring_proto_rdp::fuzz::active_stage` | `rdp_active_stage` | mooring-proto-rdp |
| `rdp_certificate_info` | `rdp_certificate_info.rs` | `mooring_proto_rdp::fuzz::certificate_info` | `certificate_info` | mooring-proto-rdp |
| `rdp_cliprdr_text` | `rdp_cliprdr_text.rs` | `mooring_proto_rdp::fuzz::cliprdr_text` | `cliprdr_text` | mooring-proto-rdp |
| `rdp_input` | `rdp_input.rs` | `mooring_proto_rdp::fuzz::input_sequence` | (input mapping) | mooring-proto-rdp |

Seeds are in `fuzz/corpus/<target>/` (synthetic, fake hosts only); the RFB test server
(`mooring-testsrv`, docs/qa/test-servers.md) can record more RFB seeds for every encoding.

### Review 5 L-28 (pre-TLS RFB, reassembly, cut text, framebuffer)

| Target | Entry (`fuzz/entries/`) | Parser | Stable replay |
| --- | --- | --- | --- |
| `rfb_handshake` | `rfb_handshake.rs` | `mooring_proto_vnc::fuzz::handshake` (version, security list, `SecurityResult`, `ServerInit`) | mooring-proto-vnc |
| `vencrypt_negotiation` | `vencrypt_negotiation.rs` | `mooring_proto_vnc::fuzz::vencrypt` | mooring-proto-vnc |
| `rdp_reassembly` | `rdp_reassembly.rs` | `mooring_proto_rdp::fuzz::reassembly` (M-14 caps) | mooring-proto-rdp |
| `cut_text` | `cut_text.rs` | `mooring_proto_vnc::{parse_server_message, messages::latin1_to_string / string_to_latin1}` | mooring-proto-vnc |
| `framebuffer_ops` | `framebuffer_ops.rs` | `mooring_core::frame::Framebuffer` (resize / blit / copy / fill / cursor / `take_update` → `encode_update` → `decode_mfr1`) | mooring-core |
| `rdp_reactivation` | `rdp_reactivation.rs` | `mooring_proto_rdp::fuzz::reactivation` (`ConnectionActivationSequence` → `check_desktop` → `ActiveStage::reactivate`) | mooring-proto-rdp |

`cut_text` (A4 Q1): byte 0 even frames the rest as a `ServerCutText` with the real length (or,
for `sel % 4 == 2`, a tripled claim, so `Need` and `CutTextTooLong` are reached); the oracle
is "no control character except tab / newline survives, the text re-encodes to the filtered
input, a claim over 1 MiB is reported without reading the body". `framebuffer_ops` (A4 Q1):
bytes 0–1 pick the size, then 8-byte ops whose rectangles are never clamped by the harness;
the oracle is "a rectangle is refused exactly when it lies outside the framebuffer, the pixel
buffer stays `w·h·4`, the dirty area never exceeds the framebuffer, an invalid sprite never
reaches an update, every update's `MFR1` encoding decodes back". `raw_copyrect_bounds` is
covered by `rfb_server_msg` (every encoding through `parse_rect` + `FrameSink`), so it is not
a separate target.

`rdp_reactivation` (A4 F1, the last L-28 item): each `[len16, bytes]` frame is one hostile
server PDU stepped through a fresh `ConnectionActivationSequence` built from the product
connector config (same ids as the other RDP entries), with `step_no_input` on the client's
own turns exactly as `single_sequence_step_read` does; a finalized sequence then goes through
`check_desktop` and `ActiveStage::reactivate` like `active::reactivate` after a server
`DeactivateAll`. The oracle is "never panics, a desktop outside `MAX_DIM` is refused before
`DecodedImage` allocates for it". Seeds: the full sequence (Demand Active → Synchronize →
Control ×2 → Font Map) at 1024×768, the same behind a leading `DeactivateAll` at 1280×800,
a 60000×60000 desktop, a truncated Demand Active and an error-info disconnect;
`rdp_reactivation_seeds_reach_the_reactivation_branch` pins that the two full sequences
still finalize (so the fuzzer starts past the refusal branches) and the other three do not.
The
pinned upstream IronRDP targets (`pdu_decoding`, `rle_decompression`, `bitmap_stream`,
`cliprdr_format`, `channel_processing`) are run by the IronRDP project on the locked
versions; they are not duplicated here.

## A3 targets (ADR-0014..0017)

The A3 gates are gone for every parser the crates expose (Q2). Each target below fuzzes the
real code, has a seed corpus in `fuzz/corpus/<target>/` and an (empty) regression directory,
and is replayed on stable by the owning crate's `tests/fuzz_corpus.rs`, which also pins that
the accepting seeds keep being accepted (so the fuzzer never loses its path past the refusal
branch).

| Target | Entry (`fuzz/entries/`) | Parser | ADR | Stable replay |
| --- | --- | --- | --- | --- |
| `kubeconfig_resolve` | `kubeconfig_resolve.rs` | `mooring_core::credential::kubeconfig::resolve` | 0014 §3 | mooring-core |
| `external_ref_parse` | `external_ref_parse.rs` | `mooring_core::credential::{fuzz_external_ref, parse_vault_reference}` | 0016 §2 | mooring-core |
| `kube_exec_frames` | `kube_exec_frames.rs` | `mooring_proto_kube::{decode_exec, fuzz::fuzz_exec_frame}` | 0014 §5 | mooring-proto-kube |
| `kube_log_sanitize` | `kube_log_sanitize.rs` | `mooring_proto_kube::{sanitize_line, fuzz::fuzz_log_line}` | 0014 §5 | mooring-proto-kube |
| `kube_portforward_frames` | `kube_portforward_frames.rs` | `mooring_proto_kube::{PfDecoder, fuzz::fuzz_portforward_frame}` | 0014 §5 | mooring-proto-kube |
| `kube_guard_path` | `kube_guard_path.rs` | `mooring_proto_kube::fuzz::fuzz_guard_path` (request guard) | 0014 §4 | mooring-proto-kube |
| `vsphere_inventory_json` | `vsphere_inventory_json.rs` | `mooring_vsphere::fuzz::fuzz_inventory_json` (`[selector, body]`) | 0015 §1–2 | mooring-vsphere |
| `vsphere_session_token` | `vsphere_session_token.rs` | `mooring_vsphere::parse_session_token` | 0015 §1 | mooring-vsphere |
| `vsphere_ticket_url` | `vsphere_ticket_url.rs` | `mooring_vsphere::fuzz::fuzz_ticket_url` (`parse_vmrc_ticket`) | 0015 §4 | mooring-vsphere |
| `vault_kv_response` | `vault_kv_response.rs` | `mooring_secrets::fuzz::fuzz_kv_response` | 0016 §3 | mooring-secrets |
| `vault_login_response` | `vault_login_response.rs` | `mooring_secrets::fuzz::fuzz_login_response` | 0016 §3 | mooring-secrets |
| `oidc_callback_url` | `oidc_callback_url.rs` | `mooring_secrets::{parse_callback, fuzz::fuzz_oidc_callback_url}` | 0016 §4 | mooring-secrets |
| `sync_blob_parse` | `sync_blob_parse.rs` | `mooring_sync::{decode_msy1, fuzz::fuzz_msy1}` | 0017 §2 | mooring-sync |
| `sync_snapshot_json` | `sync_snapshot_json.rs` | `mooring_sync::fuzz::fuzz_snapshot_json` (`Snapshot::decode`) | 0017 §1 | mooring-sync |
| `http_certificate_info` | `http_certificate_info.rs` | `mooring_http::fuzz::fuzz_certificate_info` | 0011 / 0014 §3 | mooring-http |
| `http_response_headers` | `http_response_headers.rs` | `mooring_http::fuzz::fuzz_response_headers` (`[selector, value]`) | 0014 §4 | mooring-http |
| `http_json_body` | `http_json_body.rs` | `mooring_http::fuzz::fuzz_json_body` (`decode_json`) | 0014 §4 | mooring-http |
| `jwt_exp_peek` | `jwt_exp_peek.rs` | `mooring_core::credential::kubeconfig::peek_exp` | 0014 §3 | mooring-core |
| `kube_pod_list_json` | `kube_pod_list_json.rs` | `mooring_proto_kube::fuzz::fuzz_pod_list_json` | 0014 §5 | mooring-proto-kube |

Selector-prefixed targets take the first byte as the model / header selector and the rest as
the body (see the crate's `fuzz.rs`); their seeds carry that byte. `sync_blob_parse` seeds
include the committed `test-vectors/blob-v1.hex` blob so the fuzzer starts past the header
checks. The seed under `http_certificate_info` is a throwaway self-signed EC certificate for
`k.example.test` (no key is committed; kubeconfig seeds use token auth for the same reason).

### Still gated (no-op stub)

One target remains a compiling no-op behind a fuzz-crate feature; the nightly "Stub notice"
step flags it.

| Target | Gate | Blocker |
| --- | --- | --- |
| `s3_error_xml` | `s1` | `mooring-sync` parses no XML (presigned PUT/GET/HEAD/DELETE only, errors from status + `ETag`). Keep gated until a listing / error-body parser exists, or drop the target in the ADR. |

To activate one: run `cargo check --bins --features <gate>` in `fuzz/`, fix the call, add the
stable replay to the owning crate's `tests/fuzz_corpus.rs`, delete the gate and the `PENDING`
marker in the wrapper.

The nightly job runs these families with `-malloc_limit_mb=1024`, as it does the RDP/VNC
targets: an API body, frame or blob parser must not allocate before it checks the size.
`ASan` on `kubeconfig_parse` (the R-YAML-DEQ gate, ADR-0014 test plan) is not run: the hostile
kubeconfig cases are plain `cargo test`s in `crates/mooring-core/tests/hostile_kubeconfig.rs`.

## A4 targets (ADR-0020 network tools, N1)

| Target | Entry (`fuzz/entries/`) | Parser | ADR | Stable replay |
| --- | --- | --- | --- | --- |
| `net_ping_output` | `net_ping_output.rs` | `mooring_net::fuzz::fuzz_ping_output` (`parse_ping`) | 0020 §3 | mooring-net |
| `net_traceroute_output` | `net_traceroute_output.rs` | `mooring_net::fuzz::fuzz_traceroute_output` (`parse_traceroute`) | 0020 §3 | mooring-net |
| `net_wg_output` | `net_wg_output.rs` | `mooring_net::fuzz::fuzz_wg_output` (`[query selector, body]`, `parse_wg`) | 0020 §4 | mooring-net |

Oracle for all three: no panic, the caps hold (64 KiB in, 200 lines × 512 bytes out, ≤ 64
replies / hop rows, ≤ 32 interfaces, ≤ 256 peers), every produced line is free of control,
ANSI, bidi and other `Cf` characters, numbers are finite and `received ≤ sent`. Seeds cover
iputils, BSD, Windows en-US and tr-TR `ping`, Linux `traceroute`, `tracepath`, `tracert`
and each `wg show` subcommand plus a hostile sample (ANSI, bidi, overlong numbers);
`crates/mooring-net/tests/fuzz_corpus.rs` pins that the well-formed seeds keep parsing.

## A4 targets (ADR-0019, I1)

Every import file is hostile (T3). Each importer in `crates/mooring-import` has one target;
the entries live in `mooring_import::fuzz` and are replayed on stable by
`crates/mooring-import/tests/fuzz_corpus.rs`, which also pins that every `fixture-plain` seed
still parses (≥ 2 connections) and that `detect` names its format. The first byte of every
input is the plaintext-secret opt-in flag (odd = on); the oracle asserts the item caps, that
every emitted item re-passes the `mooring-core` validators, that folder / credential keys
resolve, and that no plan carries a secret unless the flag is set **and** the format can hold
plaintext secrets (Termius, OpenSSH) — never for mRemoteNG, PuTTY, Royal TS or RDM.

| Target | Entry (`fuzz/entries/`) | Parser | ADR | Stable replay |
| --- | --- | --- | --- | --- |
| `import_royalts` | `import_royalts.rs` | `mooring_import::fuzz::fuzz_royalts` (`.rtsx`, gzip `.rtsz`; ZIP refused) | 0019 §2 | mooring-import |
| `import_rdm` | `import_rdm.rs` | `mooring_import::fuzz::fuzz_rdm` | 0019 §2 | mooring-import |
| `import_termius_csv` | `import_termius_csv.rs` | `mooring_import::fuzz::fuzz_termius_csv` (in-house RFC 4180 reader) | 0019 §2 | mooring-import |
| `import_termius_json` | `import_termius_json.rs` | `mooring_import::fuzz::fuzz_termius_json` | 0019 §2 | mooring-import |
| `import_mremoteng` | `import_mremoteng.rs` | `mooring_import::fuzz::fuzz_mremoteng` | 0019 §2 | mooring-import |
| `import_putty_reg` | `import_putty_reg.rs` | `mooring_import::fuzz::fuzz_putty_reg` (UTF-16LE / UTF-8) | 0019 §2 | mooring-import |
| `import_putty_session` | `import_putty_session.rs` | `mooring_import::fuzz::fuzz_putty_session` (`name NUL content NUL …`) | 0019 §2 | mooring-import |
| `import_ssh_config` | `import_ssh_config.rs` | `mooring_import::fuzz::fuzz_ssh_config` | 0019 §2 | mooring-import |
| `import_detect` | `import_detect.rs` | `mooring_import::fuzz::fuzz_detect` (`[name selector, file]`, then the detected parser) | 0019 §1 | mooring-import |

The XML targets share `mooring_import::xml` (quick-xml 0.42 under the ADR caps: `<!DOCTYPE`
refused, depth ≤ 64, ≤ 200 000 elements, attribute / text ≤ 4 KiB, five predefined and
numeric references only). The fuzz-time caps lower the input to 1 MiB and the decompressed
size to 8 MiB (`FUZZ_LIMITS`) so a run stays fast.

## A4 targets (ADR-0019 §4, I2: LDAPS directory importer)

| Target | Entry (`fuzz/entries/`) | Parser | ADR | Stable replay |
| --- | --- | --- | --- | --- |
| `ldap_filter_escape` | `ldap_filter_escape.rs` | `mooring_import::ldap::fuzz::fuzz_filter_escape` (`escape_value`, `search_filter`, `Dn::parse`, `LdapTarget::parse`) | 0019 §4 | mooring-import |
| `ldap_ber_response` | `ldap_ber_response.rs` | `mooring_import::ldap::fuzz::fuzz_ber_response` (`frame::scan` → `lber::parse_tag` → `wire::decode_message` / `result_code` / `paging_cookie` → `entry::extract` → `build_plan`) | 0019 §4 | mooring-import |

Oracles: the escaped value holds no raw `( ) * \` or control byte and unescapes back to the
input; a filter built from it is one balanced expression no deeper than the fixed shape; a
parsed DN round-trips through its wire form. For responses: every frame the iterative scan
accepts (≤ 256 KiB, depth ≤ 32, definite lengths) is parsed by `lber` to exactly that length,
nothing below panics, and a plan built from a decoded entry passes the importer oracle. Seeds:
a bind response, an entry, a result with a paged-results control, `30 00`, a 4 GiB length
claim, 40 nested SEQUENCEs, a referral and a `sizeLimitExceeded` result (`fuzz/corpus/ldap_ber_response/`).

## A5 targets (ADR-0023 / 0024 / 0026 / 0027, W4)

| Target | Entry (`fuzz/entries/`) | Parser | ADR | Stable replay |
| --- | --- | --- | --- | --- |
| `export_document_json` | `export_document_json.rs` | `mooring_sync::fuzz::fuzz_export_document_json` (`parse_document_json` + `validate`, round trip) | 0023 §1 | mooring-sync |
| `vault_db_creds` | `vault_db_creds.rs` | `mooring_secrets::fuzz::fuzz_vault_db_creds` (`database/creds`, `ssh/creds` OTP, `sys/leases/renew`) | 0026 §2 | mooring-secrets |
| `vault_ssh_sign` | `vault_ssh_sign.rs` | `mooring_secrets::fuzz::fuzz_vault_ssh_sign` (`ssh/sign` → `check_signed_certificate`) | 0026 §2 | mooring-secrets |
| `vault_pki_issue` | `vault_pki_issue.rs` | `mooring_secrets::fuzz::fuzz_vault_pki_issue` (`pki/issue` → serial, `x509` mapping) | 0026 §2 | mooring-secrets |
| `connect_item_json` | `connect_item_json.rs` | `mooring_secrets::fuzz::fuzz_connect_item_json` (1Password Connect item / lists → `item_values`) | 0026 §3 | mooring-secrets |
| `bws_secret_json` | `bws_secret_json.rs` | `mooring_secrets::fuzz::fuzz_bws_secret_json` (`bws` get / list / projects / version) | 0026 §4 | mooring-secrets |
| `op_reference_parse` | `op_reference_parse.rs` | `mooring_core::credential::fuzz_op_reference` (`op://` round trip, Bitwarden grammar) | 0026 §1 | mooring-core (`fuzz_corpus_a5.rs`) |
| `sk_key_parse` | `sk_key_parse.rs` | `mooring_core::credential::fuzz_sk_key_parse` (`sk-*` blob / line / certificate, key handle, helper key blob) | 0024 §1 | mooring-core (`fuzz_corpus_a5.rs`) |
| `agent_identities` | `agent_identities.rs` | `mooring_proto_ssh::fuzz_agent_identities` (identities, sign response, `sk-*` signature) | 0024 §2, 0027 (PIV via agent) | mooring-proto-ssh |
| `sk_helper_reply` | `sk_helper_reply.rs` | `mooring_proto_ssh::fuzz_sk_helper_reply` | 0024 §3 | mooring-proto-ssh |
| `rdg_pdu` | `rdg_pdu.rs` | `mooring_proto_rdp::gateway::fuzz_rdg_pdu` (MS-TSGU packets + WebSocket frames, both roles) | 0027 §1 | mooring-proto-rdp |
| `rdg_http_response` | `rdg_http_response.rs` | `mooring_proto_rdp::gateway::fuzz_rdg_http_response` (head, body length, challenges, base64) | 0027 §1 | mooring-proto-rdp |

`export_document_json` replaces the owed `export_json` row above for v2 backups (the v1
`mooring_vault` path is still reached only through `import_age`). Its seeds are one valid
document of a throwaway `KdfParams::TEST` vault and five copies that each break one rule
(folder cycle, version 3, vault-id mismatch, dangling credential, duplicate JSON key).

No committed seed holds a private-key PEM block (secret scanning): the `pki/issue` seed carries
a placeholder in `private_key`, and the `id_*_sk` key-handle file is built at test time from
`testdata::sk_key_handle_pem` (`sk_key_handle_built_at_test_time_parses_through_the_entry`).
To seed a local nightly run with it, write that output into `fuzz/corpus/sk_key_parse/` by
hand and do not commit it.

`crates/mooring-core/tests/fuzz_corpus_a5.rs::every_fuzz_target_runs_nightly_with_seeds` is the
inventory gate: every `[[bin]]` of `fuzz/Cargo.toml` must be in the nightly matrix and have a
non-empty seed corpus and a regressions directory.

Not a target yet: `parse_hdiutil_info` (`src-tauri/src/install_location.rs`) has no `fuzz_*`
entry and lives in `mooring-app`, which the fuzz crate does not build (it would pull in Tauri
and the WebView toolchain). PIV parsing has no parser of its own: the agent replies go through
`agent_identities`.

## Layout

```
fuzz/
  Cargo.toml          own [workspace]; libfuzzer-sys only here; mirrors the root age patch
  Cargo.lock          committed (seeded from the root lockfile)
  entries/            target logic + replay.rs (shared with the stable tests)
  fuzz_targets/       one 3-line libFuzzer wrapper per target
  corpus/<target>/    small, hand-made seeds (fake hosts only); committed
  regressions/<target>/  minimised crash inputs, one file per fixed bug; committed
  artifacts/, target/, coverage/   local only (gitignored)
```

`import_age` uses the public test-vector passphrase, so the committed `export.age` vector seeds
the fuzzer past decryption. Inputs that keep a valid scrypt stanza cost one scrypt run (the
vector is `N = 2^16`, the import cap `2^20`), so this target is slow by design: expect tens of
executions per second, not thousands.

`socks5_handshake` drives the pure request parser. The async greeting state machine
(`socks::handshake`) is `pub(crate)` and so not reachable from the fuzz crate (see the A1 exit
QA handoff, "Decision needed").

## Running locally

Needs a nightly toolchain and cargo-fuzz (CI pins the version in
`.github/workflows/fuzz-nightly.yml`):

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked

cargo +nightly fuzz list
cargo +nightly fuzz run known_hosts_parse fuzz/corpus/known_hosts_parse fuzz/regressions/known_hosts_parse \
  -- -max_total_time=120 -timeout=60 -rss_limit_mb=3072
make fuzz            # every target for 60 s
```

Run from the repository root. libFuzzer writes newly found corpus entries into the first corpus
directory. The root `.gitignore` ignores `fuzz/corpus/`, so that growth never shows up in
`git status`; the committed seeds were added with `git add -f` and stay tracked. To add a seed,
minimise first (`cargo +nightly fuzz cmin <target>`) and `git add -f` only a handful of small,
readable files. `fuzz/.gitattributes` keeps every input byte-exact (no CRLF normalisation).

Without nightly, the stable side still works and is what CI runs on every push:

```sh
cargo test -p mooring-proto-ssh -p mooring-core -p mooring-vault -p mooring-proto-rdp \
  -p mooring-proto-vnc -p mooring-http -p mooring-proto-kube -p mooring-vsphere \
  -p mooring-secrets -p mooring-sync -p mooring-net -p mooring-import --test fuzz_corpus
cd fuzz && cargo check --bins     # the targets compile on stable; only running them needs nightly
```

## Nightly job

`.github/workflows/fuzz-nightly.yml` runs at 02:17 UTC and on demand (`workflow_dispatch`,
optional `seconds` per target). One job per target, 120 s each by default, read-only token. A
crash fails that job and uploads `fuzz/artifacts/<target>/` as `fuzz-artifacts-<target>`
(30 days). Nothing is opened, pushed or commented automatically.

## Triaging a crash

1. Download the `fuzz-artifacts-<target>` artifact from the failed run. The file name tells the
   kind: `crash-*` (panic / assertion / sanitizer), `timeout-*`, `oom-*`, `slow-unit-*`.
2. Treat the input as potentially sensitive only if it came from a real file; nightly inputs
   are synthetic. Never attach real `known_hosts`, kubeconfigs or vaults to an issue.
3. Reproduce: `cargo +nightly fuzz run <target> path/to/crash-…` (runs that one input), or
   with a backtrace: `RUST_BACKTRACE=1 cargo +nightly fuzz run <target> path/to/crash-…`.
4. Minimise: `cargo +nightly fuzz tmin <target> path/to/crash-…`.
5. Classify:
   - a panic inside the parser (index, slice, overflow, `expect`) is a bug in the crate: hand it
     to rust-core with the minimised input;
   - an assertion in `fuzz/entries/*.rs` is either a parser bug or a wrong invariant: decide
     which before changing anything, and never relax an invariant just to get green;
   - `timeout-*` / `oom-*` on any target except a scrypt-bound `import_age` input is a
     resource-bound bug (caps are part of the threat model);
   - anything that looks like a security issue (trust bypass, key confusion, unbounded memory
     from small input) goes to security-reviewer first (SECURITY.md), not a public issue.
6. Fix in the crate, then copy the minimised input to
   `fuzz/regressions/<target>/<short-description>` in the same PR. The stable replay test now
   guards it on every OS in `ci.yml`.
