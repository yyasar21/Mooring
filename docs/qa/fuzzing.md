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

## A3 targets (scaffolding, ADR-0014..0017)

The parsers of A3 are still being written (K2, K3, V1, E1, S1). Each target below is already in
`fuzz/Cargo.toml`, in the nightly matrix, and has seeds plus an empty regression directory. Each
entry is gated behind a fuzz-crate feature, as the A2 targets were before R1–R4 landed. Without
the feature, `run` is a compiling no-op, and the wrapper's `PENDING` marker makes the nightly
"Stub notice" step print a warning. The gated branch names the function that the ADR and the
task split imply. Nobody has compiled it against a real signature yet.

| Target | Gate | Expected parser | ADR |
| --- | --- | --- | --- |
| `kubeconfig_resolve` | `k2` | `mooring_core::credential::kubeconfig::resolve` | 0014 §3 |
| `jwt_exp_peek` | `k2` | `mooring_core::credential::kubeconfig::jwt_exp_peek` | 0014 §3 |
| `kube_pod_list_json` | `k3` | `mooring_proto_kube::fuzz::pod_list_json` | 0014 §5 |
| `kube_exec_frames` | `k3` | `mooring_proto_kube::fuzz::exec_frames` (channel demux + status JSON) | 0014 §5 |
| `kube_log_sanitize` | `k3` | `mooring_proto_kube::fuzz::log_sanitize` | 0014 §5 |
| `vsphere_inventory_json` | `v1` | `mooring_vsphere::fuzz::inventory_json` | 0015 §1–2 |
| `vsphere_session_token` | `v1` | `mooring_vsphere::fuzz::session_token` | 0015 §1 |
| `vsphere_ticket_url` | `v1` | `mooring_vsphere::fuzz::ticket_url` | 0015 §4 |
| `vault_kv_response` | `e1` | `mooring_secrets::fuzz::kv_response` | 0016 §3 |
| `vault_login_response` | `e1` | `mooring_secrets::fuzz::login_response` | 0016 §3 |
| `external_ref_parse` | `e1` | `mooring_core::credential::fuzz::external_ref` | 0016 §2 |
| `oidc_callback_url` | `e1` | `mooring_secrets::fuzz::oidc_callback_url` | 0016 §4 |
| `sync_blob_parse` | `s1` | `mooring_sync::fuzz::blob_parse` (`MSY1`) | 0017 §2 |
| `sync_snapshot_json` | `s1` | `mooring_sync::fuzz::snapshot_json` | 0017 §1 |
| `s3_error_xml` | `s1` | `mooring_sync::fuzz::s3_error_xml` (`quick-xml` path) | 0017 §4 |

To activate a gate when its crate lands:

1. Add the crate to `fuzz/Cargo.toml` `[dependencies]` (path dependency).
2. Run `cargo check --bins --features <gate>` and fix the call to the real signature.
3. Turn the invariants in the entry's doc comment into assertions.
4. Add the stable replay to the owning crate's `tests/fuzz_corpus.rs`.
5. Delete the gate and the `PENDING` marker.

The nightly job runs these families with `-malloc_limit_mb=1024`, as it does the RDP/VNC
targets: an API body, frame or blob parser must not allocate before it checks the size.
`ASan` on `kubeconfig_parse` (the R-YAML-DEQ gate, ADR-0014 test plan) is Q2.

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
cargo test -p mooring-proto-ssh -p mooring-core -p mooring-vault --test fuzz_corpus
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
