# Coding standards

## Non-negotiable rules

These come from the project's `CLAUDE.md` and apply to every contributor, human or AI.

1. **Secrets never reach the frontend, logs, errors, tests or git.** The UI handles credential
   ids only. `.env`, `*.key` and signing material are gitignored; never print them.
2. **`#![forbid(unsafe_code)]` everywhere** (workspace lint, checked in CI). No exception
   without an ADR.
3. **No new dependency without a one-line justification** in the PR and security-reviewer
   approval. Allowed crypto: RustCrypto, `ring`, `rustls`. Never roll your own crypto.
4. **Parsers for untrusted input** have size caps and ship with a fuzz target.
5. **Every Tauri command** validates its input and returns `IpcError { code, message }`
   without secret material. Capabilities stay least-privilege; CSP strict. Remote web
   content gets its own window label and capability.
6. **Every behaviour change ships with a test.** `make check` is green on macOS, Windows and
   Linux before a PR.
7. **Files stay under 500 lines.** Prefer editing an existing file over creating a new one.
8. **English** for code, comments, commit messages and documentation; Conventional Commits.
9. **Test environments are read-only for automation.** Never run anything against shared
   infrastructure that changes it (no Ansible without `--check`, no cluster mutations, no
   hypervisor writes).

## Rust

- Edition 2021, MSRV 1.89, `rustfmt` with 100 columns (`rustfmt.toml`).
- Clippy: `all = deny`, `pedantic = warn` with a documented allow-list in `Cargo.toml`.
  `unwrap()` is denied; library code also avoids `expect()`. `dbg!`, `todo!`, `println!` and
  `eprintln!` are denied — log through `tracing`.
- Secrets live in `zeroize::Zeroizing` or `secrecy::SecretString`. Types holding secrets get
  a hand-written, redacting `Debug` and no `Display` or `Serialize`.
- Error variants carry fixed strings, never values from the input or a secret.
- Validate at the edge with `mooring-core` constructors before data reaches SQL or a protocol.
  SQL is parameterised; sizes are capped.
- Protocol crates never receive the vault; the Tauri layer resolves credentials and hands
  over a `ConnectSecret` that is dropped after the handshake.

## TypeScript and React

- TypeScript `strict`, ESLint `strictTypeChecked`.
- Only `apps/desktop/src/lib/ipc.ts` calls `invoke()`; components use the typed `Ipc`
  interface. A `MockTransport` implements the same interface for `vite dev` and tests.
- No `innerHTML` / `dangerouslySetInnerHTML`. Secret inputs are write-only.
- Design tokens and primitives live in `packages/ui`. Two semantic hues: cyan for
  live/selection/focus, magenta for danger and "waiting for you". Respect
  `prefers-reduced-motion`.
- Accessible names and roles are part of the contract; tests select by them.

## Commits

Conventional Commits, checked by a `commit-msg` hook:

```text
<type>(<optional scope>)!: <summary up to 72 characters>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `build`, `ci`, `security`.
Do not add `Co-Authored-By` trailers for tools.

## Placeholders in examples

Use `example.test`, `<your-host>`, RFC 5737 documentation addresses (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`), `alice` and generated test keys in code, tests, docs and
issues. Never commit real hostnames, IP ranges, accounts, domains or keys; lab values live only
in the local, gitignored `.env`.
