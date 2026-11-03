# A1 · security-reviewer · review 2 (SSH, forwarding, SFTP, Tauri commands, UI, rename)

Worktree `.claude/worktrees/agent-ac9df847a40ab8dd8`. Reviewed range `1e76c3a..2003ec8`.
Full report: [docs/security/a1-review-2.md](../security/a1-review-2.md). Not merged.

## Verdict: `APPROVE WITH NITS` (no blocker)

## Done
- Reviewed every new and changed `#[tauri::command]` (30 registered):
  - inputs are validated and capped;
  - errors map to `IpcError`;
  - no secret goes outward;
  - base64 is handled correctly;
  - the session channel lifecycle is sound;
  - capabilities are still `core:default` only and the CSP is unchanged.
- Reviewed the secret paths: `session_open`, `credential_copy_password`/arboard, and the
  `Answer` redaction. **L2 (durable header write) is now fixed.**
- Reviewed the SSH core: known_hosts, TOFU, algorithms, auth, keyboard-interactive, and the
  forwarding, SOCKS5 and SFTP code. I read the russh 0.65, russh-sftp 3.0.1 and xterm 6.0.0
  sources where the behaviour mattered.
- Reviewed UI v1 and v2: `invoke()` is only in `ipc.ts`, there is no `innerHTML`, secret fields
  are write-only, and I checked the terminal path.
- Dependency rulings:
  - Approved: arboard, base64, russh (ring only; no aws-lc in `Cargo.lock`), russh-sftp,
    hmac/sha1 (known_hosts only), @xterm/*, @fontsource/chakra-petch.
  - Accepted risks, recorded in the threat model:
    - the `age` git pin (R-AGE-PIN), with a removal condition;
    - the `rsa` Marvin advisory (R-RSA).
- Ruled on all open decisions in the ssh, ssh-b and tauri handoffs (review §Rulings).
- Updated `docs/security/threat-model.md`:
  - new assets: known_hosts, clipboard, forwards;
  - new STRIDE rows with a status for each;
  - R-AGE-PIN, R-SSH-STR, R-RSA, R-IPC-BUF;
  - open items and wiring gates.

## Left open (owners)
| ID | Owner | When |
| --- | --- | --- |
| M-1 clear the clipboard on exit and on lock (`state.rs:240`, `vault.rs:106`) | rust-core | before A1 exit |
| M-4 xterm `linkHandler` no-op (`xterm.ts:23`) + main-webview navigation guard | ui-engineer + rust-core | before A1 exit |
| M-2 `Exposure` enum, loopback default for local/remote/dynamic forwards | rust-core | **gate:** before any forwarding IPC |
| M-3 bound SFTP in-flight requests (8) under hostile `limits` | rust-core | **gate:** before any SFTP IPC |
| L-7 Windows ADS / device names in `LocalPath` | rust-core | **gate:** before any SFTP IPC |
| L-1 reject server-opened x11/agent/session/streamlocal/direct channels | rust-core | A1 exit |
| L-2 `Prompt.purpose` instead of a message regex (ADR-0008 amendment) | architect → rust-core + ui | A1 exit |
| L-3 KDF in `spawn_blocking`; L-4 async/cached `audit_verify` | rust-core | A1 exit |
| L-5 serialise known_hosts writes; L-6 expected fp in audit; N-3 session-only trust in audit | rust-core | A1 exit |
| N-1, N-2 | rust-core | A1 exit |
| N-4 full SHA in the `[patch]`; `deny.toml` ignore for RUSTSEC-2023-0071 with the R-RSA reason | orchestrator | next manifest touch / before `make audit` in CI |
| Fuzz targets `known_hosts_parse`, `socks_parse_request` (plus `Header::from_bytes`, `import_age`) | qa-engineer | A1 exit |
| Manual clipboard check on macOS / Windows / Linux (X11 + GNOME Wayland), including Handoff | qa-engineer | A1 exit |
| Carried: M1 keyring (HOLD), N5, N6 | rust-core | as in review 1 |

## Decision needed
- **Orchestrator:** add the RUSTSEC-2023-0071 `ignore` entry to `deny.toml`. Without it,
  `cargo deny check advisories` fails as soon as CI runs with an advisory DB.
- **Architect:** add the `Prompt.purpose` field (L-2) and the `Exposure` option for the forward
  IPC (M-2) to ADR-0008 / ADR-0007 before those commands are designed.

## Test evidence
- `cargo test --workspace` passes, including `mooring-app` (lib 41), which was compiled here.
  Counts per binary are in the review.
- `make test-vectors`: `OK: header + 6 sealed vectors verified with the age CLI; tamper rejected`.
- `grep aws-lc Cargo.lock`: no match.
- `pnpm audit --prod`: no known vulnerabilities.
- The `age` pin `b5b68c4` is on `str4d/rage` `origin/main` and contains `f7c95f4` (cargo git
  db).
- Not run, because the tools are not installed: cargo-deny, cargo-audit, gitleaks, semgrep,
  cargo-geiger. The clipboard was not checked on a real display.
