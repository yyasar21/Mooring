# Testing

Every behaviour change ships with a test. A test for a security property must fail without
the fix (tamper detection, rejection of bad input), not only exercise the happy path.

## The gate: `make check`

`make check` runs exactly what CI runs:

| Stage | Commands |
| --- | --- |
| `lint` | `cargo fmt --check`, `cargo clippy --workspace --exclude mooring-app --all-targets -D warnings`, `pnpm lint` (ESLint strict-type-checked), `pnpm typecheck`, check that `invoke(` appears only in `apps/desktop/src/lib/ipc.ts` |
| `test` | `cargo test --workspace --exclude mooring-app`, `pnpm test` (Vitest) |
| `audit` | `cargo deny check`, `cargo audit`, `pnpm audit --audit-level=high`, `gitleaks detect` |

CI (`.github/workflows/ci.yml`) runs the full workspace including `mooring-app` on
macOS, Windows and Linux. Locally, with the WebView toolchain installed:

```bash
make app-check     # clippy + tests for the whole workspace, including the Tauri crate
```

## Test suites

| Where | What |
| --- | --- |
| `crates/mooring-core` | Model validation, tree inheritance and cycles, forbidden characters, serde shapes |
| `crates/mooring-vault` | Round trips, tamper detection (proptest bit flips), KDF floor/ceiling, calibration, auto-lock table, keyring wrap with a mock, export/import, vectors |
| `crates/mooring-store` | Migrations, CRUD, inheritance, FTS search, sealed columns bound to row and column, cascades |
| `crates/mooring-audit` | Chain verification, tamper detection, redaction |
| `crates/mooring-proto-ssh/tests` | In-process russh server: auth methods, TOFU and mismatch, algorithms, shell, forwarding, SFTP, hostile limits |
| `src-tauri` (unit) | Every command: validation, error codes, no secret in outputs, clipboard, sessions |
| `src-tauri/tests/e2e_flow.rs` | End-to-end IPC flow and ~3 000 hostile inputs (see below) |
| `apps/desktop` (Vitest) | Stores, IPC decoding, components, shortcuts, prompt dialogs |

Run a single crate: `cargo test -p mooring-vault`. Run UI tests in watch mode:
`pnpm --filter @mooring/desktop exec vitest`.

## End-to-end IPC flow

```bash
make e2e-ipc       # cargo test -p mooring-app --test e2e_flow
```

Drives the command layer like the UI does: create vault → folder → credential as folder
default → SSH connection that inherits it → search → open a session against an in-process SSH
server → accept the host key → run a command → close → lock → verify that every vault-gated
command refuses → unlock → verify the audit chain and that no secret was logged.

The hostile-input suite feeds every string argument a fixed corpus (control characters, bidi
overrides, traversal, SQL/FTS syntax, huge strings) plus seeded random strings. Reproduce a
failure with `MOORING_HOSTILE_SEED=<seed> MOORING_HOSTILE_ROUNDS=<n>`.

The `test-util` feature of `mooring-app` exposes the command layer to this test; it is enabled
automatically for the package's own tests.

## Vault test vectors

```bash
make test-vectors  # needs the `age` CLI and Python 3
```

`crates/mooring-vault/tests/vectors/` pins the vault format (header, sealed fields, an `age`
export). `tests/vectors/verify_age_export.py` decrypts the export with the reference `age`
CLI, compares the contents and checks that a tampered file is rejected. The
`test-vectors` workflow runs this in CI. The vectors use a fixed test password and test KDF
parameters; they contain no real secrets and are allow-listed for gitleaks.

## Fuzzing

```bash
make fuzz          # every cargo-fuzz target for 60 s (needs nightly + cargo-fuzz)
```

Fuzz targets for the vault header, `age` import, `known_hosts` and the SOCKS parser are owed
for A1 exit; property tests cover them today. New parsers of untrusted input must add a
target.

## Lab tests

Integration tests against real servers are behind `MOORING_LAB=1` and skipped by default.
Copy `.env.example` to `.env` (gitignored) and point the variables at your own test hosts.
Passwords are never stored in files: lab tests read them from the OS keychain. Lab tests are
read-only by design.

## UI end-to-end

`make e2e` (Playwright through `tauri-driver`) is planned; until then the IPC-level flow above
covers the same path.
