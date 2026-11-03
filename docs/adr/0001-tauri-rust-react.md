# ADR-0001: Tauri 2 + Rust core + React/TypeScript UI

Status: Accepted · 2026-11-03

## Context
Nexus Remote must run natively on macOS, Windows and Linux, embed terminal and remote-desktop
renderers, and hold credentials. The UI layer must be fast to iterate on; the security-critical
layer must be memory-safe and auditable.

## Decision
- Shell: Tauri 2. One Rust binary per OS, system WebView, capability-based IPC permissions,
  built-in bundler/updater/signing hooks.
- Core: Rust workspace (`crates/*`). All crypto, protocol parsing, vault logic and session
  state live here. `#![forbid(unsafe_code)]` is a workspace lint.
- UI: React 19 + TypeScript strict + Vite + Tailwind 4; design tokens in `packages/ui`.
  The UI is treated as untrusted (ADR-0003).

## Alternatives considered
- Electron: 150+ MB binaries, Chromium attack surface, secrets would live next to Node. Rejected.
- Avalonia / .NET MAUI: MAUI has no Linux target; RDP/SSH crates are more mature in Rust. Rejected.
- Flutter: no mature desktop terminal/RDP rendering packages. Rejected.
- Pure Rust GUI (egui/iced/slint): slower UI iteration, weaker text/accessibility. Deferred.

## Security consequences
Secret material never leaves Rust. WebView is sandboxed by Tauri capabilities + CSP. The
dependency tree is split: `cargo deny` governs Rust, lockfile + `pnpm audit` govern npm.

## Tooling
clippy `all=deny`, `pedantic=warn` with the allow-list in `Cargo.toml`; rustfmt 100 cols;
ESLint `strictTypeChecked`; `make check` is the single gate.

## Test plan
`make check` on three OSes in CI (A0). `nexus-app` compiles only where a WebView toolchain exists;
the pure crates are tested everywhere.
