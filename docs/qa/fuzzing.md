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
Still Q1: `framebuffer_ops`, `rfb_handshake`, `raw_copyrect_bounds`, `vencrypt_negotiation`,
`cut_text` as separate targets, and the pinned upstream IronRDP targets.

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
the body (see the crate's `fuzz.rs`); their seeds carry that byte.

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
`crates/mooring-net/tests/fuzz_corpus.rs` pins that the well-formed seeds keep parsing. `sync_blob_parse` seeds
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
size to 8 MiB (`FUZZ_LIMITS`) so a run stays fast. `ldap_ber_response` and
`ldap_filter_escape` belong to I2 and are not here yet.

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
  -p mooring-secrets -p mooring-sync --test fuzz_corpus
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
