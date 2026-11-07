# A5 W1 — rust-core R1: jump hosts / hop streams (ADR-0025 §1–2, §4)

Branch `worktree-agent-af001baa9652696a9`. Resumed from a rate-limited predecessor; their
model/store/transport/RDP/VNC/`mooring-http` work was kept (verified, finished, tested).

## Done
- **Model + store** (`mooring-core`, `mooring-store`): `Connection.via: Vec<ConnectionId>`,
  `MAX_VIA = 3`, `validate_via` (depth, self, duplicate; ids never echoed). Migration
  `0008_connection_via.sql` (the ADR says 0010; the sequence here is contiguous, so 0008).
  The store checks that each hop exists, is SSH, and is not a two-way cycle. Deleting a hop that is in use
  → `InUse { kind: "connection" }`. **Folder delete** whose subtree holds a hop used from
  outside → the same `InUse`, checked before SQL. FK action is `NO ACTION` (checked at
  statement end) rather than `RESTRICT`, so a subtree holding a whole chain cascades cleanly.
- **Transport** (`mooring-core::transport`): `Dialer` / `SharedDialer` / `TcpDialer` / `Erased`.
  RDP (`RdpStream = TlsStream<Erased>`), VNC and `mooring-http` (`HttpConfig::via`) take any
  dialer; the TLS, pins and host name stay the same.
- **Hops** (`mooring-proto-ssh::hops`): `Hop`, `HopStream { Tcp, Channel }`, `HopChain::open`
  (hops + target `direct-tcpip`) and `open_hops` (hops only; caller dials). `HopChain`
  implements `Dialer`. ≤ 3 hops, 90 s chain deadline, reverse-order close, `lost_hop()`.
  Each hop has its own known_hosts TOFU/mismatch, its own credential (dropped after its auth round)
  and its own keepalive. `HopStatus` events, prompts tagged `hop: Some(i)` and titled "Hop N — host:port".
  Audit: `HopOpened`/`HopClosed {closed|hop_failed|hop_lost}`.
- **SSH target**: `SshSession::connect_chain(params, options, hops)` returns at once. The driver
  opens the chain in-task, sharing the session's broker, so the existing `Answer { id }` works per hop.
  A failure gives `Closed{hop_failed}` before any byte reaches the target. A lost hop gives `hop_lost`.
  SFTP and forwards ride the leaf as before.
- **RDP/VNC target**: `ViaSession` (generic `Session` wrapper) opens the hops, then builds the
  target with the chain as its dialer. Hop answers are routed by id (> `HOP_PROMPT_ID_BASE`),
  other input goes to the target, and a 1 s lost-hop watch runs. Every reconnect / TOFU retry
  rebuilds the whole chain. `CloseCode::HopLost` is retryable; `HopFailed` is not.
- **Tauri**: `connect_plan::hops_of` resolves each hop's own credential (added to
  `credential_used`). `hop_chain.rs` holds `HopSettings` and the graphical wrapper, plus
  `open_interactive` for the Kubernetes cluster task. With `via`, the kube API (and so exec /
  port-forward / logs) dials through the chain, with hop prompts and `hop_status` on the cluster
  channel and a `hop_lost` watch. `connection_create/update` accept `via`.
  **Update without `via` keeps the stored chain; `[]` clears it.** `ConnectionDto.via: string[]`.
  Web connections with `via` refuse to open (`web.via_unsupported`) until R6, so they never
  bypass the chain. vCenter connections refuse `via` at save and at login (`connection.via_invalid`).
- **Audit**: `session_hop_open { connection, hop, hop_connection, peer_identity, auth_method }`,
  `session_hop_close { connection, hop, hop_connection, code }`.
- **IPC codes** (golden blessed): `connection.via_invalid`, `connection.in_use_as_hop`,
  `session.hop_failed` (plan time: hop missing / non-SSH / external_ref hop),
  `web.via_unsupported`. `hop_failed`/`hop_lost` reach the UI as `closed.code`, not as IpcErrors,
  so `session.hop_lost` is not emitted as an IPC code.

## UI contract (for U1)
- `ConnectionDto.via: string[]` (first hop first). `connection_create/update({ …, via?: string[] })`:
  ≤ 3 SSH connection ids. Leave `via` out on update to keep the chain; send `[]` to clear it.
  Errors: `connection.via_invalid` (depth/self/duplicate/missing/non-SSH/cycle/vCenter),
  `connection.in_use_as_hop` on `connection_delete` / `folder_delete`.
- Session channel (SSH, RDP, VNC) and `kube_open` channel:
  `{ kind: "hop_status", hop, of, state: connecting|authenticating|up|failed, host: "h:p", peer_identity? }`,
  emitted in hop order before the target's events. `prompt` gains an optional `hop` (absent =
  target), answered with the usual `session_send { kind: "answer" | "credential_answer", id }`.
  Title: "Hop {hop+1} of {of} — {host}". `connected` gains an optional `hop` (always absent today).
  `closed.code` adds `hop_failed` (a hop never came up; the target was never contacted) and
  `hop_lost` (graphical sessions auto-reconnect and rebuild the chain).
- Warn when a plaintext protocol (VNC `none`) crosses a hop (ADR-0025 T8). This is UI-only.

## Left open
- `session_hops({ sessionId })` passive re-adoption command is not added. It needs a new
  command entry, capability/permission files and `ipc-manifest.json`, which are outside my scope.
  The UI can rebuild chip state from the `hop_status` stream meanwhile.
- `external_ref` credentials on a **hop** are refused (`session.hop_failed`). The leaf's own
  `external_ref` works as before. The ADR-0016 prefetch needs extending per hop.
- vSphere (sync runner, console) and Vault secret sources through a chain: crate support is
  ready (`HttpConfig::via`), but the Tauri lifecycle is not wired. Saving is refused for vCenter.
- Trust audit rows of a hop (`trust_decision`) carry the hop's host:port but no `hop` field.
- Integration tests for RDP/VNC/SFTP/forward through 2–3 hops: SSH covers 1 and 2 hops, and RDP
  and VNC are covered through 1 hop (E2E). The lab manual gate (`MOORING_LAB_JUMP_HOST`) was not run.

## Decision needed
- Migration number 0008 vs the ADR's 0010. R2/R3 must take 0009+ (whoever merges second
  renumbers).
- `ON DELETE NO ACTION` instead of `RESTRICT` (reason above). The security reviewer should confirm.
- Shared target dir hazard for the orchestrator: cargo fingerprints workspace members by
  *workspace-relative* paths, so parallel worktrees on one `CARGO_TARGET_DIR` silently link each
  other's crates. I touched sources before every build. Separate target dirs (and more disk)
  are recommended.

## Manifest needs
None (no new dependency).

## Test evidence
- `cargo fmt --all --check`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean (`Finished`, 0 warnings of ours).
- New tests, all green:
  - `mooring-proto-ssh --test hops` **8/8**: 1 hop, 2 hops + hop TOFU naming the hop, hop host-key
    change → `hop_failed` with no `direct-tcpip` sent, hop auth failure → target never tried,
    depth 4 / empty refused, hop lost (relay cut) → `hop_lost` + `session.hop.close{hop_lost}`,
    `ViaSession` routing hop answers / target input / wrong hop id, `ViaSession` hop failure
    → target factory never called.
  - `mooring-proto-ssh` unit: `hops_tests` 2/2, broker hop-id test 1/1.
  - `mooring-store via` **4/4**: round trip, validation table (self, dup, depth 4, non-SSH,
    missing, cycle, create path), delete of a hop in use, folder delete blocked by an outside leaf,
    and a self-contained subtree that cascades.
  - `mooring-core`: `via_shape_rules`, `hop_status_and_hop_tagged_prompt_wire_shape`, close-code
    table (+`hop_failed`/`hop_lost`), transport dialer tests 2/2.
  - `mooring-http --test via` **1/1** (TLS + pin through a dialer; refused dialer → `Connect`).
  - `mooring-audit` `hop_events_have_stable_wire_names`; `mooring-app` `session_audit`
    `hop_events_name_the_leaf_and_the_hop`; error-map table rows.
  - `mooring-app --test e2e_flow via` **4/4**: SSH through chains of 1 and 2 (per-hop TOFU,
    `hop_status` order, audit rows, update keeps/clears `via`), hostile table (depth 4, dup,
    RDP hop, missing hop, bad id, self, cycle, in-use delete, vCenter), hop key change and hop
    auth failure never reach the target, RDP (NLA + TOFU reconnect) and VNC (VeNCrypt) through a
    bastion with the real factory and MFR1 frames.
  - `MOORING_BLESS=1 cargo test -p mooring-app golden`: 6/6, `ipc-codes.json` +4 codes.
- **Full gate** `cargo test -p mooring-core -p mooring-proto-ssh -p mooring-proto-rdp -p
  mooring-proto-vnc -p mooring-http -p mooring-app -p mooring-store -p mooring-audit -p
  mooring-proto-kube`: **1136 passed, 0 failed, 4 ignored** (lab/manual) across 50 test binaries.
  This was rerun after `hops.rs` was split (`hop_stream.rs`) to stay under 500 lines.
- Disk: the shared volume hit ENOSPC twice during the run (four worktrees, one 26 GB `target/`).
  The run completed once other builds freed space.
