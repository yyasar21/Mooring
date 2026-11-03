# Public-release privacy scrub

Goal: before `yyasar21/Mooring` goes public, the tree must not identify the maintainer's
private infrastructure. This note does **not** repeat the removed values; it names them by
category so that it does not publish them again.

## Inventory (before)

The inventory grep, extended with host-name, IP, account, domain and path patterns, found
**89 hits in 34 files**, plus about 50 more `okd`/hostname fixture hits that the base pattern
missed.

| Category | Where |
| --- | --- |
| Private /16 network and host IPs | `CLAUDE.md`; core/store/src-tauri unit tests; store integration tests; proto-ssh `exposure.rs`, `tests/forward.rs`, `socks.rs` test; one handoff table |
| Private DNS zone and lab host names (SSH host, monitoring host, syslog host, domain controllers, vCenter, S3 endpoint, K8s API) | `.env.example`, `CLAUDE.md`, `tests/lab.rs`, store search tests, ADR-0004/0007, prompts A1–A3, handoffs, threat model |
| Lab service account and AD UPN | `.env.example` |
| Bundle id / keyring service using the private domain | `tauri.conf.json`, `keyring_store.rs`, ADR-0006, threat model, review 2, vault handoff |
| Specific lab product inventory (K8s distributions, firewall, S3 server, etc.) | prompts A2/A3, ADR-0003 |
| Maintainer's first name in a test string and a prompt | `mooring-audit` redact test, prompt A4 |
| Absolute build-host paths | handoff ssh-b, review 2 |
| Stale placeholder GitHub repo name | a1-orchestrator handoff |

Checked and clean:
- **UI mock** (`apps/desktop/src/lib/ipc.seed.ts`, `ipc.mock.ts`, tests): only `*.example.test`.
- **Screenshots** (`docs/handoff/img/**`, 26 PNGs): visually checked. They show the mock tree
  (`web01.example.test`, `pg01.example.test`, `dc01.example.test`, `EXAMPLE\admin`) only.
  There are no tEXt/iTXt/zTXt/eXIf chunks. The `src-tauri/icons` PNGs have no metadata either.
- **Fixtures**: `crates/mooring-vault/tests/vectors/` hold only public test values.
- **Commit authors**: the maintainer's public name and email, and `Claude <noreply@anthropic.com>`.
  We keep these on purpose.

## Replacements

| Was | Now |
| --- | --- |
| Lab hosts in tests | `web01` / `mon01` / `kube-cp`, `*.example.test` (RFC 2606/6761) |
| Lab IPs in tests | RFC 5737 `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| `tests/lab.rs` hard-coded host + `MOORING_LAB=1` | Reads `MOORING_LAB_HOST` / `MOORING_LAB_PORT` (default 22) / `MOORING_LAB_USER`. It prints a skip reason and returns when they are unset. Still `#[ignore]`d. |
| `.env.example` real hosts/accounts | `ssh.lab.example.test`, `mooring-test`, plus a line saying that real hosts never go in the repo |
| `CLAUDE.md` home-lab rule | "Any real infrastructure referenced by `MOORING_LAB_*` is read-only for agents. Never mutate external systems." |
| Syslog mirror target host | "a syslog server" |
| Hosts in ADRs, prompts, handoffs | `<lab-host>` or a generic role (domain controller, S3-compatible store) |
| Bundle id / keyring service | `io.github.yyasar21.mooring` |
| Absolute build paths | `<repo>/target` |

Guard: `.gitleaks.toml` has a new generic rule, `private-ipv4-outside-tests`. It flags RFC 1918
IPv4 addresses in any file outside `tests/`, `*_test(s).rs`, `*.test.ts(x)` and lockfiles. It
names no private patterns. Its regex was checked against the whole tree with Python and gave
0 hits. The `gitleaks` binary itself was not available in this environment.

## Inventory (after)

The same grep now returns only `Cargo.toml` `authors` and `LICENSE` (the public author name),
the generic word "vCenter" in prompt A3 (a product name, not a host), and a false positive in
a `pnpm-lock.yaml` integrity hash. Generic "Home lab" folder labels remain in store tests.
They identify nothing.

## Left open / decision needed

1. **Git history still contains every removed value.** This scrub does not rewrite history.
   Before you make the repo public, choose one:
   (a) Publish a fresh repo with a single squashed initial commit.
   (b) Run `git filter-repo --replace-text` over the history, then force-push.
   (c) Accept the exposure.
   Option (a) is the simplest and the most complete. Commit messages and old handoff revisions
   carry these values too.
2. **Identifier change moves the app data directory and the keyring service.** Any local dev
   vault created under the old identifier will not be found. This is fine before v0.1.0, but
   nothing migrates it.
3. `gitleaks detect` with the new rule should run once in CI (`security.yml`) to confirm that
   gitleaks accepts the rule. The TOML parses and the regex is RE2-compatible.

## Test evidence

```
cargo fmt --all -- --check                                   ok
cargo clippy --workspace --all-targets -- -D warnings        ok
cargo test --workspace                                       exit 0 (lab test ignored)
cargo test -p mooring-proto-ssh --test lab -- --ignored      ok, prints skip reason (vars unset)
pnpm test                                                    46 passed (11 files)
```
