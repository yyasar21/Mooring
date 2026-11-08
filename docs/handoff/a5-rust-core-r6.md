# A5 W3 — rust-core R6: web sessions through jump hosts, `ManualReason::Winget`, lease TTL

Branch `worktree-agent-ac1e9f542cd1cfd59`, worktree
`/home/claude/nexus/.claude/worktrees/agent-ac1e9f542cd1cfd59`.
Specs: ADR-0025 §3 (web via SOCKS), ADR-0018 A2 (winget, amended by the orchestrator's
marker-only decision), `a5-ui-u4.md` Left open (lease `ttlSeconds`).

**No new crate, no manifest or lockfile change, no new IPC command, no new IPC error code**
(codes used: `web.via_unsupported`, `session.hop_failed`, `window.failed`, `update.manual_only`;
`ipc-codes.json` unchanged, golden test green).

## Done

### R6 web via (ADR-0025 §3)
- **`mooring-proto-ssh::ChainProxy`** (`chain_proxy.rs`). It is a SOCKS5 forward on the
  **last hop** of a `HopChain`.
  - It binds `127.0.0.1:0` only. SOCKS5 "no auth", `CONNECT` only, the same front and limits as a
    dynamic forward (`socks.rs`, `forward_io::dynamic_loop`, 128 connections).
  - Each CONNECT becomes a `direct-tcpip` of the last hop. Host names are sent unresolved, so the
    hop resolves them. The page keeps its real host name, so TLS validation is unchanged.
  - `close()` and `Drop` stop the accept loop and every spliced connection.
  - `HopChain::last_handle()` was added (crate-private).
- **Tauri (`src-tauri/src/web/via.rs`)**:
  - `web::plan` no longer refuses `via`. It checks `via::supported(os)` and sets `WebPlan.via`.
    - Linux (WebKitGTK) and Windows (WebView2) are supported.
    - **macOS is always refused** with `web.via_unsupported`, because the Tauri `macos-proxy`
      feature is not enabled: without it, `proxy_url` is silently ignored and the page would
      bypass the chain. The const `MACOS_PROXY_FEATURE` gates this (see Decision needed).
  - `web_open` with `via` opens the chain and its proxy **before** the window exists.
    - Hops resolve through `connect_plan::hops_of`: each hop's own credential, audited
      `credential_used`.
    - The chain opens unattended (`open_chain`). The web channel has no answer path, so the
      first hop prompt shuts the broker. The prompt can be an unknown host key,
      keyboard-interactive or a `prompt` credential. The open then fails with
      `session.hop_failed`: "jump host N asked a question a web window cannot answer (an unknown
      host key or a password); open it once as an SSH session, then try again". Nothing is
      trusted on the user's behalf.
    - The window is built with `proxy_url(socks5://127.0.0.1:<port>)`.
    - `window::build` fails closed (`window.failed`) if `plan.via` is set but there is no proxy.
  - **Lifetime.** The chain lives in `WebEntry.via`.
    - `closed_entry` (window destroyed, `web_close`, connection delete) runs
      `shutdown_later(.., "closed")`. This closes the proxy at once, then the chain in reverse
      order.
    - A 1 s watch closes the chain with `hop_lost` and destroys the window when a hop drops. The
      UI sees an ordinary `closed`.
    - If the build fails after the chain is up, the chain is shut down.
    - The listener survives a vault lock, like every loopback forward (ADR-0025 §3). The window
      is hidden as before.
- **Audit.**
  - `forward_opened` / `forward_closed { id: "web-via", kind: "dynamic", target: "socks5",
    exposure: "loopback", reason: "web_via" }`.
  - `mooring-audit` gained an optional `reason` on both events. It is skipped when `None`, so
    old rows read back byte-identically (test).
  - `session_hop_open` / `session_hop_close` are written with `protocol` web, as with every
    chain. Hop TOFU rejections are audited as usual.

### `ManualReason::Winget` (ADR-0018 A2, orchestrator decision: marker only)
- Wire value `winget`, code `update.manual_only`, message "installed by winget: run
  `winget upgrade yyasar21.Mooring`".
- `InstallFacts.winget` comes from `winget_marker(exe.parent())`, for **NSIS only**.
  - The file is `install-source`, read with a 64-byte cap.
  - Its trimmed UTF-8 content must be exactly `winget`.
  - A missing file, a directory, an oversized file, non-UTF-8 content or any other content →
    `false`.
- `decide`: dev build → portable → **winget (NSIS)** → bundle/writability. MSI stays
  `package_manager`.
- No path heuristic. My first cut checked the `WinGet\Packages` and `Links` paths. It was
  replaced after the release engineer found that winget runs the same per-user NSIS installer.
- **Inert by design**: no installer writes the marker yet.

### Carried items
- **`ttlSeconds` on leases**: `LeaseStatus.ttl` (`mooring-secrets`) → `LeaseInfoDto.ttlSeconds`
  (`session_list().leases[]`). It is the full TTL since issue or the last renewal, `null` when
  Vault reports none.
- **kube_open hop-prompt channel**: nothing to do in Rust. `kube_open({ connectionId, onEvent })`
  already takes `Channel<ClusterEvent>`. Hop `prompt`/`hop_status` events are forwarded on it
  (`ClusterEvent::from_hop`), and answers go through `session_send` on the cluster session id.
  The gap is UI-only: `kubeOpen` must pass `onEvent` and render the prompts.

## Left open
- **`revokeCertOnDisconnect` (PKI)**: not done, spec unclear (see Decision needed).
- Web-via **hop prompts** are refused, not asked (see Decision needed).
- **WebView2**: browser args (`--proxy-server`) are fixed per environment. Suppose a connection's
  persistent profile is still held by a running WebView2 browser process and its `via` changes.
  Then the next open can fail with `window.failed` until that process exits. This fails closed.
- **WebKitGTK**: the proxy is set on the window's web context. A persistent profile whose
  `via` was removed keeps the old (dead) proxy until restart. This fails closed.
- DNS goes through the hop for both engines (SOCKS5 with domain names). Check this at the manual
  gate with a name only the bastion can resolve.
- Two lines were edited outside `src-tauri/src/**` to keep the build green:
  `src-tauri/tests/e2e_flow/{a4_update,a4_1_portable}.rs` gain `winget: false` in their
  `InstallFacts` literals. QA should take ownership of this.

## Decision needed
1. **macOS web-via**: the orchestrator should enable the Tauri `macos-proxy` feature in
   `src-tauri/Cargo.toml` (`tauri = { version = "=2.12.5", features = ["macos-proxy"] }`, no new
   crate). Then flip `web::via::MACOS_PROXY_FEATURE` to `true`. The gate already requires
   major ≥ 14. Also check that a `mac-proxy` build still launches on macOS 11–13: the
   `nw_proxy_config_create_socksv5` symbol is macOS 14+.
2. **Interactive hop prompts for web windows**: today the first prompt is a refusal. Two options:
   - (a) Keep it. The user opens the bastion once as SSH to pin its key, and uses a stored
     credential.
   - (b) Register the web chain as a session, so `session_send` can answer. This needs
     `WebEvent` kinds `hop_status`/`prompt`.

   Note for (b): the UI's `decodeWebEvent` maps **unknown kinds to `closed`**. That is why R6
   emits no new web event kinds. The UI must first decode unknown kinds as "ignore".
3. **PKI `revokeCertOnDisconnect`**: R3 found that PKI has no connect consumer. `x509` is not an
   SSH, RDP or VNC login, and the kube plan does not take `external_ref`. So there is no session
   whose disconnect would revoke anything. The architect must name the consumer first, for
   example kube client certificates from `external_ref` PKI.
4. **Release engineer, winget marker**: the NSIS installer should write `$INSTDIR\install-source`
   containing `winget` when winget runs it. For example: the manifest's
   `InstallerSwitches.Custom: /WINGET` and an NSIS installer hook (`bundle.windows.nsis
   .installerHooks`) that writes the file when `/WINGET` is on the command line. A direct
   download must not write the file. An in-app update over a direct install must not create it
   either.

## UI contract
- `web_open` → `{ windowLabel, viaHops? }`. `web_list()` rows gain `viaHops?`. The value is the
  number of jump hosts; the field is absent for a direct window. Show "via bastion (SOCKS)" when
  present.
- `web_open` errors for a connection with `via`:
  - `web.via_unsupported` (macOS in this build).
  - `session.hop_failed` (hop missing, non-SSH or `external_ref`; hop down; hop needs an answer).
    The message is safe to show.
- `web_open` can now take up to 90 s (chain deadline) before it returns. Show a spinner.
- **No new `WebEvent` kinds.** A lost hop shows up as the usual `closed`.
- `UpdateManualReason` gains `"winget"`. Add it to `ipc.types.update.ts` and `REASONS` in
  `ipc.decode.update.ts`. The copy is the message above, with the command shown copyable.
- `LeaseInfoDto` gains `ttlSeconds: number | null`. Use it for the "renews in" figure instead of
  the estimated TTL.

## Test evidence
```
cargo fmt --all --check                                   clean
cargo clippy --workspace --all-targets -- -D warnings     clean (only the toolchain's known
                                                          unknown-lint note)
cargo deny --offline check                                advisories, bans, licenses, sources ok
cargo test -p mooring-audit / mooring-secrets / mooring-proto-ssh    all passed
cargo test -p mooring-app --lib                           463 passed / 1 ignored (golden green,
                                                          ipc-codes.json unchanged)
cargo test -p mooring-app --test e2e_flow                 55 passed
semgrep p/rust + p/secrets on the new/changed files       no findings
```
Disk: I deleted only `libmooring_app_lib.{a,so}` (rebuilt by every mooring-app build) and my
own two stale mooring-app test executables, plus the standard prune of files older than 90 min.
- `mooring-proto-ssh` `tests/chain_proxy.rs` (2): a round trip through a real bastion with an
  unresolved host name; the proxy and its connections die on close; no proxy over a closed chain.
- `mooring-app` `web::via::tests` (7):
  - the platform gate;
  - the URL target, including IPv6;
  - plan;
  - a full browse through an in-process bastion, with the `forward_opened`/`closed` `web_via`
    rows, the hop rows, `credential_used` and no password in the log;
  - the chain closed with the registry entry, plus `viaHops` in `web_list`;
  - an unknown bastion key is refused and nothing is trusted;
  - a dead bastion gives `hop_failed`.
- `mooring-app` `updater::install_mode::winget_tests` (3): the matrix order, the wire shape,
  and the marker present / absent / other content / non-UTF-8 / oversized / directory.
- `mooring-audit` `web_via_forward_rows_carry_their_reason`; `mooring-secrets`
  lease TTL assertion; `connect_plan::dynamic_tests` asserts `ttlSeconds: 3600` on the wire.
