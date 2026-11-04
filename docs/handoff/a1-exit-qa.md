# A1 exit — qa-engineer

Scope: ADR-0010 §Consequences (fuzz targets + nightly job), ADR-0007 §Tests (`known_hosts_parse`),
a1-orchestrator "Left open" (cargo-fuzz targets and nightly job, Playwright/tauri-driver E2E).
Branch `worktree-agent-aba505445833965d6`, not merged.

## Done

- **`fuzz/`** — own cargo workspace (`[workspace]` in `fuzz/Cargo.toml`, root manifest untouched),
  `libfuzzer-sys 0.4.13` only there, root `age` patch mirrored, lockfile seeded from the root one.
  Five targets: `known_hosts_parse`, `kubeconfig_parse`, `vault_header_from_bytes`, `import_age`,
  `socks5_handshake`. Logic in `fuzz/entries/*.rs` (`forbid(unsafe_code)`), each a
  `pub fn run(&[u8])` asserting invariants beyond "no panic": write/parse round trips
  (known_hosts, header), documented caps (kubeconfig contexts / names, header and export size,
  SOCKS request length), determinism, SOCKS re-encode idempotence, imported header re-accepted.
- **Seed corpora** `fuzz/corpus/<target>/` (fake hosts only; age/header seeds are the existing
  public test vectors) and `fuzz/regressions/<target>/`. Force-added because the root
  `.gitignore` ignores `fuzz/corpus/` (fuzzer growth stays ignored); `fuzz/.gitattributes`
  keeps inputs byte-exact (the repo-wide `text=auto eol=lf` would rewrite CRLF seeds).
- **Stable replay** `crates/{mooring-core,mooring-proto-ssh,mooring-vault}/tests/fuzz_corpus.rs`
  — `#[path]`-include the same entries and replay corpus + regressions inside
  `cargo test --workspace` (all three OSes in `ci.yml`, no nightly). Fails on missing/empty
  corpus; checks that the valid seeds stay accepted so the fuzzer keeps its deep paths.
- **`.github/workflows/fuzz-nightly.yml`** — cron 02:17 UTC + `workflow_dispatch` (`seconds`,
  validated numeric, default 120), one job per target, nightly via the pinned
  `dtolnay/rust-toolchain`, `cargo-fuzz 0.13.2 --locked`, `-timeout=60 -rss_limit_mb=3072`,
  crash artifacts uploaded on failure (30 days), `permissions: contents: read`,
  `persist-credentials: false`, ci.yml's SHA pins. Opens/pushes nothing.
- **`docs/qa/fuzzing.md`** — layout, local runs, corpus hygiene, crash triage.
- **E2E** `apps/desktop/e2e/` — Playwright (library) + `node:test` against the Vite dev server
  with the mock transport; `e2e/boot.html` boots the real app with a fresh
  `MockTransport({ vault: "missing" })` and a probe of mock state (dev server only; `vite build`
  still bundles `index.html` alone). Flows: (1) create vault, weak/mismatched passwords refused;
  (2) create → add connection → TOFU trust → echo shell → lock drops sessions, tabs, terminal;
  (3) TOFU reject never connects and is audited; (4) lock → unlock keeps the connection and the
  trusted host (no second prompt); (5) `mod+Shift+L` locks. Accessible names only. Failure
  screenshots to `e2e/results/` (gitignored). `e2e/tsconfig.json` type-checks `boot.ts` against
  the mock so API drift breaks CI, not the flows.
- **`.github/workflows/e2e.yml`** — ubuntu-24.04, 10 min cap, path-filtered, read-only, pinned
  Playwright 1.63.0 + `playwright install --with-deps chromium` (official step), screenshots on
  failure.
- **E2E choice.** Playwright against `vite dev` + mock: runs headless on Linux with no display
  server, ~15–25 s, exercises the real React UI and stores. `tauri-driver` + WebdriverIO was not
  taken now: it needs a full `mooring-app` build per run (minutes), `WebKitWebDriver` +
  `xvfb-run` on Linux, has no macOS driver, and adds a WebdriverIO dependency tree. The Rust
  side of the same flows is already `cargo test -p mooring-app --test e2e_flow`. Revisit for A2
  when the native window behaviour (detach, OS lock signals) needs coverage.

### Finding QA-F1 (low) — `KnownHosts` loses a trailing CR per save

Found by `known_hosts_parse` within seconds. `parse_bytes` strips one `\r` per line and keeps
the rest in `lines`; `to_file_string` writes them back, so `"host key\r\r\n"` becomes
`"host key\r\n"` after one save and `"host key\n"` after the next; a `"\r"`-only last line
becomes empty and is then trimmed. Entry count and trust decisions are unchanged (a probe test
confirmed the CR-suffixed entry already matches), so this is file-fidelity, not trust. The
invariant compares written forms modulo trailing CRs until fixed; the two crash inputs are in
`fuzz/regressions/known_hosts_parse/qa-f1-*`. Owner: rust-core (`known_hosts.rs`), then tighten
the assertion in `fuzz/entries/known_hosts.rs` to plain equality.

## Left open

- The nightly and e2e workflows have not run on GitHub yet (first run after push). `actionlint`
  was not available (no binary, Go proxy unreachable); reviewed by eye and YAML-parsed.
- Real nightly was not installable here (rustup blocked by the proxy). The local fuzz evidence
  below used stable 1.97 with `RUSTC_BOOTSTRAP=1` and `-s none` (no ASan); CI uses real nightly
  with cargo-fuzz's default AddressSanitizer.
- `import_age` is scrypt-bound (~10 exec/s locally): almost every mutant of the vector keeps a
  valid stanza and pays `N = 2^16`. Coverage of the post-decryption JSON / header checks is thin.
- `Makefile`: `e2e` still points at `playwright test tests/e2e` (should be
  `node --test --test-concurrency=1 apps/desktop/e2e/flows.e2e.mjs`), `fuzz` calls `cargo fuzz`
  without `+nightly`. Not mine to edit.
- E2E covers the mock transport only; forwarding / SFTP / auto-lock / syslog panels (ADR-0010)
  get flows once ui-engineer lands them (same harness; add steps to `harness.mjs`).

## Decision needed

1. **orchestrator** — add `playwright` (exact `1.63.0`) as a devDependency of
   `@mooring/desktop` and a `test:e2e` script, then drop the global install from `e2e.yml`.
   Until then CI installs a pinned global copy (exact version, but no lockfile integrity).
2. **orchestrator** — workflow names: CLAUDE.md gives QA `.github/workflows/test*.yml`; the brief
   asked for `e2e.yml` / `fuzz-nightly.yml`. Keep (and amend the ownership table) or rename to
   `test-e2e.yml` / `test-fuzz-nightly.yml`.
3. **rust-core + security** — make `socks::handshake` reachable from the fuzz crate
   (`pub` or `#[doc(hidden)] pub`) so `socks5_handshake` can drive the greeting + request state
   machine over `tokio::io::duplex` instead of only `parse_request`.
4. **rust-core + security** — expose the post-decryption export check (e.g.
   `ExportDocument::from_json(&[u8])`) so a cheap `export_json` target can fuzz what
   `import_age` reaches only after scrypt + AEAD.
5. **rust-core** — fix QA-F1 (strip all trailing CRs on parse, or write lines as read).

## Test evidence (2026-11-04, Linux x86_64, stable 1.97.0, Node 22.23.4)

- `cargo test --workspace` (incl. `mooring-app`): **399 passed, 0 failed, 3 ignored**; the new
  `fuzz_corpus` binaries: core 2, proto-ssh 3, vault 3 tests, all green.
- `cargo clippy -p mooring-core -p mooring-proto-ssh -p mooring-vault --all-targets -- -D warnings`
  clean; `cargo fmt --all -- --check` clean; `fuzz/`: `cargo check --bins` and
  `cargo clippy --bins -- -D warnings` clean on stable.
- Local fuzzing (`cargo-fuzz 0.13.2`, `RUSTC_BOOTSTRAP=1`, `-s none`, 60 s each unless noted):
  `kubeconfig_parse` 1.84 M execs, cov 2183, clean · `vault_header_from_bytes` 7.64 M, cov
  1329, clean · `socks5_handshake` 52.7 M, cov 102, clean · `import_age` 579 execs, cov 1011,
  clean · `known_hosts_parse` crashed twice (QA-F1), then 180 s / 1.37 M execs clean with the
  adjusted invariant. Peak RSS ≤ 101 MB.
- E2E: `node --test --test-concurrency=1 apps/desktop/e2e/flows.e2e.mjs` **5/5 pass**, 14.3 s
  (22.7 s with fuzzers running alongside), pre-installed Chromium. Negative check: a flipped
  expectation fails with an assertion diff and writes a screenshot.
  `pnpm exec tsc -p e2e/tsconfig.json` clean; `vitest run` still 109/109 (e2e files are not
  picked up: `*.e2e.mjs`).

## Fix round 4 (review 4 M-11)

Branch `worktree-agent-ae55b8a763ed5b36e` (from `a1-exit` @ 0077e40), not merged. Scope was
`fuzz/**`, `crates/*/tests/**`, `docs/qa/**` and this file. The parser is unchanged.

- **M-11 met on the QA side.** `fuzz/entries/kubeconfig.rs::run` now checks the security
  property, not only caps and determinism. After a successful parse, `violations` re-scans the
  input with `saphyr-parser` 0.3.3 (the parser's own event layer, pinned `=` to the root lock)
  through code that does not share the parser's lookups. It panics on any of these:
  - a `<<` or `!!merge` key anywhere;
  - a key under `users[]` (any depth) that matches `exec`, `auth-provider`, `tokenFile`,
    `client-certificate` or `client-key`, compared ASCII case-insensitively;
  - a key under `clusters[]` that matches `certificate-authority`;
  - under either section, a tagged, aliased or complex key, which the oracle cannot name.

  The section names are also matched case-insensitively, and every document in the stream is
  scanned. `token-file` is not in the list: it is not a kubeconfig field (client-go's field is
  `tokenFile`, and case folding does not remove a hyphen).
- **Seeds** (force-added under `fuzz/corpus/kubeconfig_parse/`):
  - review 4: `users-merge-inline`, `users-Exec`, `users-AUTH-PROVIDER`, `complex-key-exec`
    (`? exec` / `: {command: x}`), `quoted-exec` (`"ex\x65c"`);
  - M-5: `m5-merge-toplevel-inline`, `m5-users-item-level-exec`, `m5-users-nested-TOKENFILE`,
    `m5-users-path-keys-mixed-case`;
  - probes: `probe-clusters-ca-path`, `probe-tagged-merge-key`, `probe-binary-tagged-key`
    (`!!binary ZXhlYw==`), `probe-quoted-merge-key`.

  Each seed is otherwise a valid kubeconfig.
- **Stable replay** (`crates/mooring-core/tests/fuzz_corpus.rs`):
  - `kubeconfig_forbidden_seeds_are_seen_and_refused` checks three things for every seed: the
    oracle flags it, `parse` refuses it with the expected reason (not an unrelated one), and
    `run` passes.
  - `oracle_flags_each_construct` pins the oracle itself, including negatives: the same names
    outside `users[]` / `clusters[]` are not flagged.
  - `kubeconfig_valid_seed_is_accepted` also checks that the oracle reports no false positive.
  - `replay_except` skips a named regression only when the file exists, so a stale exception
    fails the test.

### Finding QA-F2 (medium, latent) — `Users:` / `Clusters:` bypass the forbidden-key check

- **Reproducer:** `fuzz/regressions/kubeconfig_parse/qa-f2-section-key-case`.
- **How it was found:** the new oracle crashed during the first fuzz run of this
  round (`fuzz/artifacts/kubeconfig_parse/crash-5edab2f…`, local only). The crash input is a
  one-byte mutation of the seed `m5-users-nested-TOKENFILE`, with `users` changed to `Users`.
  The reproducer is a hand-minimised version that covers both sections.
- **What slips through:** `kubeconfig::parse` finds the sections with
  `root.get("users")` / `root.get("clusters")`, and `Node::get` compares keys exactly
  (`kubeconfig.rs:53-58`, `:219-225`). A top-level `Users:` (or `USERS:`, `uSers:` …) is
  therefore never checked. The same holds for `Clusters:`. `parse` accepts the reproducer,
  which has:
  - `Users: [{name: ops, user: {exec: {command: /bin/sh}}}]`;
  - `Clusters: [{…, certificate-authority: /tmp/ca}]`.

  The duplicate-key check is also exact, so a clean `users:` and a hostile `Users:` can sit
  side by side.
- **Impact:** the same threat model and reach as M-5. Review 3 asked for ASCII
  case-insensitive matching because lenient decoders fold JSON field names. Go's
  `encoding/json` does that by default, for example `sigs.k8s.io/yaml.Unmarshal` into the
  client-go `v1.Config` types. Such a consumer reads `Users` as `users`, which means:
  - it runs `exec` (code execution) from a kubeconfig that Mooring labelled "self-contained";
  - it reads the file named by `certificate-authority` (disclosure).

  Whether current kubectl, which decodes through apimachinery's case-sensitive serializer,
  folds the name was **not verified here**. It is latent today: there is no Kubernetes or
  kubeconfig consumer yet, and review 3 gates any consumer on M-5 / M-11.
- **Fix (rust-core, not done here):** check every top-level key that matches `users` /
  `clusters` ASCII case-insensitively, or refuse such a key unless it is the exact lower-case
  spelling. Make duplicate detection case-insensitive at every level, since a folding decoder
  merges `exec` and `Exec` as well.
- **Guard:** `kubeconfig_qa_f2_regression` runs the reproducer through the unchanged `run`. It
  is `#[ignore = "QA-F2: …"]`, and the corpus replay excludes only this one file
  (`replay_except(…, &[QA_F2])`). `cargo test -p mooring-core --test fuzz_corpus -- --ignored`
  fails today with `forbidden key 'exec'`. When the parser is fixed:
  1. remove the `#[ignore]` and the `QA_F2` exception;
  2. leave the file in `regressions/`.
- **For security-reviewer:** the M-11 gate should stay shut until QA-F2 is fixed. The fuzz
  target now asserts the property, but the parser does not yet satisfy it.

### Left open (round 4)

- `cargo fuzz run` uses `fuzz/corpus/<target>` only, so the nightly job does not replay
  `regressions/`. That is fine for QA-F2, because the stable test is the guard, and the fuzzer
  rediscovers the bypass by mutation. Running the ignored test in CI would need a
  `--include-ignored` job, which is not added (out of scope: workflows).
- The four owed targets are listed in `docs/qa/fuzzing.md` "Owed targets". The fingerprint,
  OTP and account targets need no API change. `export_json` still needs decision 4 above.

### Test evidence (round 4, 2026-11-04, Linux x86_64, stable 1.97.0)

- `cargo test --workspace` (incl. `mooring-app`): **458 passed, 0 failed, 4 ignored**. The
  fourth ignored test is `kubeconfig_qa_f2_regression`. `mooring-core` `fuzz_corpus`: 4 passed,
  1 ignored. With `-- --ignored` it fails as expected:
  `kubeconfig::parse accepted a forbidden construct: forbidden key 'exec' (matches 'exec')`.
- `cargo clippy -p mooring-core --tests -- -D warnings` is clean. In `fuzz/`,
  `cargo clippy --locked --bins -- -D warnings` is clean, and `rustfmt --check` is clean on the
  three changed files.
- `RUSTC_BOOTSTRAP=1 cargo fuzz run kubeconfig_parse -s none -- -max_total_time=120 -timeout=60
  -rss_limit_mb=3072` (cargo-fuzz 0.13.2, installed `--locked` here; no ASan) finished clean:
  4.25 M execs in 121 s, cov 3259 (up from 2183 in round 1), corpus 3697, rss 78 MB. That
  120 s run did not hit QA-F2 again (libFuzzer is random). The earlier run of this round that
  found it left `crash-5edab2f…`.
