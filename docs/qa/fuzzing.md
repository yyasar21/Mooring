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
