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
