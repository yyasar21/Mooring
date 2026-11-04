# A2 — orchestrator handoff

## Done
- ADR-0011 (RDP + frame path), 0012 (VNC), 0013 (web sessions + detach) accepted with seven
  owner decisions (panic=unwind, R-RDP-FFI accepted, no x509/Kerberos/RD Gateway, VNC
  prefer_tls + no JPEG, web OS-trust only, ephemeral web storage by default).
- Waves: R1 core (frame/MFR1, known_certs, options, migration 0005) → R2 Tauri (session task,
  FramePump, reconnect, IPC) ∥ R3 IronRDP ∥ R4 own RFB 3.8 ∥ U1 WebGL canvas ∥ Q2 RFB/RDP test
  servers → integration (clipboard/audit unification, factory wiring, loopback + IPC E2E, fuzz
  gates, screenshot) → review 5 ∥ R5 web windows/ACL/detach ∥ U2 forms/TOFU dialog/known certs
  → U3 web tab + detached route → fix round 6 → re-review.
- Security review 5: BLOCKER B-5 (desktop size allocated before validation) + M-13..M-15,
  L-20..L-28, N-23..N-29 → fixed in round 6; re-review APPROVE WITH NITS (L-29..L-32 fixed only
  L-32 so far; N-30..N-38 open). R5 capability change approved.
- Gate (cloud Linux, fresh build): 842 Rust tests / 0 failed / 6 ignored; clippy + fmt clean;
  cargo-deny clean; vitest 305; build clean; E2E 5/5; frame_bench 29 fps / p95 19.6 ms at 1080p
  25 % dirty (Rust side).

## Left open
- L-29 (Windows shared ephemeral session), L-30 (orphaned web stores on folder delete), L-31
  (native page dialogs while hidden — per-OS QA), N-30..N-38 (incl. N-33 UI drops host/port
  from known_certs_list, N-35 drop russh flate2 feature, N-28c mock in production bundle).
- L-28 partial: fuzz targets `cut_text`, `framebuffer_ops`, `rdp_reactivation`, upstream IronRDP
  targets; first green nightly run owed.
- M-14 upstream IronRDP issue (fragment caps) to be filed.
- Manual checks owed on macOS/Windows: real RDP/VNC hosts, web windows (dialogs while hidden,
  persistent store wipe on macOS), detach across monitors.
- Multi-window Playwright E2E (web tab, detach) — QA.

## Decision needed
- None blocking. A3 owner questions are answered in the A3 ADRs' "Owner decisions".

## Test evidence
- `cargo test --workspace` → 842 passed, 0 failed, 6 ignored (after `rm -rf target`).
- `pnpm lint && pnpm typecheck && pnpm test && pnpm build` → 305 vitest, clean.
- `node --test apps/desktop/e2e/flows.e2e.mjs` → 5/5.
