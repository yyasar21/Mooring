# ADR-0003: Trust boundaries and the IPC contract

Status: Accepted · 2026-11-03

## Context
The WebView runs JavaScript from our bundle today and, in A2, renders remote web pages
(hypervisor consoles, dashboards...). Any of it may be compromised by a malicious page, an XSS in a dependency
or a supply-chain change.

## Decision
- The WebView is untrusted. Every `#[tauri::command]` validates its input, caps sizes, and
  returns `IpcError { code, message }` with no secret or internal detail.
- Secrets never cross IPC outward. The UI receives credential *ids*; connect/reveal/copy are
  Rust commands that audit (`mooring-audit`).
- Capabilities: `main` window has `core:default` only. No `shell`, `fs`, `http`, `opener`
  permissions. Remote web content (A2) opens in a window with its own label and a separate,
  narrower capability; `withGlobalTauri` stays off.
- CSP: `default-src 'self'`, `script-src 'self'`, `connect-src ipc: http://ipc.localhost`,
  `object-src 'none'`, `frame-ancestors 'none'`. `style-src 'unsafe-inline'` is accepted for
  Tailwind/Vite injection (no script execution vector); revisit when Vite emits nonces.
- `freezePrototype: true`. Devtools off in release.
- The only file that calls `invoke()` is `apps/desktop/src/lib/ipc.ts`.

## Alternatives considered
- Trusting the WebView and caching decrypted credentials in the store: simpler, rejected.
- Separate process for the vault (like a keyring daemon): stronger isolation, larger scope;
  revisit for Phase B when an agent process exists anyway.

## Security consequences
A compromised UI can open sessions the user could open, but cannot read secrets or escape the
capability set. The audit log records what it did.

## Test plan
Every command has input-validation tests (A1). CI greps that `invoke(` appears only in `ipc.ts`.
