# A0 — orchestrator handoff

## Done
- Cargo workspace: `mooring-core` (model, tree with inheritance + cycle checks, Session trait),
  `mooring-vault` (Argon2id + XChaCha20-Poly1305, authenticated header, KDF floor, password change,
  proptest bit-flip detection), `mooring-audit` (hash-chained JSONL, verify, redaction),
  `mooring-proto-{ssh,rdp,vnc}` stubs implementing `Session`.
- Tauri 2 shell: `app_info`, `vault_status/create/unlock/lock` commands; header persisted to
  `$APP_DATA/vault.header.json`, audit to `$APP_DATA/audit.jsonl`; capability `main` =
  `core:default` only; strict CSP; `freezePrototype`.
- UI: tokens (`packages/ui`), three-pane shell, command palette (mod+K), onboarding/unlock
  screens, sample lab tree; Vitest covers boot → palette → tab → lock.
- Gates: `make check`, lefthook, deny.toml, CI matrix + security workflow, release stub.
- Team: `.claude/agents/*` (6 roles), CLAUDE.md, ADR-0001..0004, threat model v0.

## Left open
- `mooring-app` was not compiled in the cloud workspace (no WebView toolchain there). First
  `cargo tauri dev` on the Mac may surface small API mismatches in `src-tauri/src/*` — fix inline.
- Icons are placeholders; run `pnpm tauri icon <512px png>` once a logo exists.
- Argon2 defaults not yet calibrated; A1.
- Ruflo not initialised in this repo yet (`npx ruflo init` on the Mac; copy hook conventions
  from HomeInfraAsCode/.claude/helpers).

## Decision needed
- GitHub repository name/visibility (CI assumes GitHub Actions).
- Light theme: keep as opt-in (current) or auto-follow OS?

## Test evidence (cloud workspace, 2026-11-03)
- `cargo clippy --all-targets -- -D warnings` → clean (pure crates)
- `cargo test` → 13 test binaries, 0 failures (core 7, vault 8 + proptest 2, audit 6, …)
- `pnpm typecheck && pnpm lint && pnpm test && pnpm build` → clean, 2 UI tests pass
