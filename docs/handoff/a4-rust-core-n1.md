# A4 — rust-core N1: network tools (ADR-0020)

Branch: worktree `agent-a6cb852e46bc2f190`, from `a4` @ 351e30c. Not merged.
**New crate `mooring-net`: security review required before merge.** No new third-party
dependency: `tokio` gains the `process` feature at the workspace level (`signal-hook-registry`
was already locked); the lockfile only gains `mooring-net` itself. Orchestrator-owned files
touched: `Cargo.toml` (member + default-member + tokio feature), `Cargo.lock` (one package),
`fuzz/Cargo.toml` (dep + 3 bins), `src-tauri/Cargo.toml` (one path dependency line),
`.github/workflows/fuzz-nightly.yml` (3 matrix rows), `docs/qa/fuzzing.md` (A4 table).

## Done
- **`crates/mooring-net`** (`#![forbid(unsafe_code)]`, no `unwrap`, every file < 500 lines)
  - `Target::parse`: 1..=253 bytes ASCII, RFC 1123 labels (1..=63, no leading/trailing `-`)
    or IPv4/IPv6 literal (brackets stripped, `%zone` refused), never starts with `-` or `/`,
    no whitespace/controls. Errors never echo the input.
  - `ToolPaths::for_os(Os)`: the fixed absolute table of ADR-0020 §3–4 (Linux `/usr/bin/ping`,
    `/bin/ping`, `/usr/bin|/usr/sbin/traceroute`, `tracepath` fallback, `/usr/bin|/usr/local/bin/wg`;
    macOS `/sbin/ping`, `/sbin/ping6`, `/usr/sbin/traceroute[6]`, `/usr/local/bin|/opt/homebrew/bin/wg`;
    Windows `%SystemRoot%\System32\PING.EXE|TRACERT.EXE`, `%ProgramFiles%\WireGuard\wg.exe`).
    First existing file wins; no `PATH` lookup. `ToolPaths::custom` is the test-only injection
    point (shims). IPv6 literals pick `ping6` / `traceroute6` on macOS.
  - `argv(tool, target, os, flavour)` — golden-tested per OS: Linux ping `-n -c N -W W -- host`,
    macOS `-n -c N -t N×W -- host`, Windows `-n N -w W×1000 host`; traceroute
    `-n -q 1 -w 2 -m M -- host`, tracepath `-n -m M host`, tracert `-d -h M -w 2000 host`;
    `wg show …` only. Count clamped 1..=10, per-reply wait 1..=5 s, hops 1..=30. The target
    is always one element, last.
  - `WgQuery` = `Interfaces | Endpoints | LatestHandshakes | Transfer | ListenPort` (an
    exhaustive-match test pins that `dump`, `showconf`, `private-key`, `preshared-keys`,
    `set`, `syncconf` are unexpressible). `Iface` names validated `[A-Za-z0-9_=+.-]{1,15}`
    before argv. Public keys are shortened (`AAAAAAAA…AAAA`) inside the parser; the full key
    never leaves the crate.
  - `run::run_tool`: `tokio::process::Command`, `env_clear()` + `LC_ALL=C` (unix) /
    `SystemRoot` + `CREATE_NO_WINDOW` (windows), stdin null, `kill_on_drop`; stdout ≤ 64 KiB,
    stderr ≤ 16 KiB; the first cap stops both pipes and kills the child (`truncated`);
    deadline (ping 30 s, traceroute 60 s, wg 5 s) kills the child and returns the partial
    output (`timed_out`). Exit codes are data.
  - `sanitize::lines`: lossy UTF-8, ANSI CSI/OSC/two-char escapes, C0/C1 controls, bidi and
    the rest of Unicode `Cf` stripped, tabs → spaces, ≤ 200 lines × 512 bytes.
  - Parsers (never fail, number patterns not layouts): `parse_ping` (iputils, BSD, Windows
    en-US and tr-TR goldens; `<1ms` = 0.5), `parse_traceroute` (traceroute, tracepath rows
    merged per hop, tracert en/tr; `!H`-style notes), `parse_wg` per query + `merge_interface`.
  - `tcp_check`: `lookup_host` (≤ 16 addrs), one deadline 100..=10 000 ms (default 3 000),
    first handshake wins, stream dropped at once, no bytes; `open | closed | timeout |
    unreachable | dns_failed` (refusal beats unreachable beats timeout).
  - `Runner` (ping / traceroute / wg / wg_status / tools) and `fuzz::{fuzz_ping_output,
    fuzz_traceroute_output, fuzz_wg_output}`.
- **`src-tauri`**: `commands/net.rs` — `net_tools`, `net_port_check`, `net_ping`,
  `net_traceroute`, `net_wg_show` (names per the N1 task; the ADR spells them `net_tcp_check`
  / `net_wg_status`, see "Decision needed"). `NetRuntime` (managed state): fixed OS table,
  semaphore of 2 tool processes (`net.busy`), one port check per second (`net.rate_limited`).
  `TargetArg = { connectionId } | { host, port? }`; a connection target takes the stored host
  (web: URL host + port, Kubernetes / vSphere console refused with `net.invalid_host`), then
  the `mooring-core` host check, then `Target`. All five commands are vault-gated before any
  resolution or I/O. Audit rows `net_tcp_check { host, port, outcome }`, `net_ping { host,
  sent, received }`, `net_traceroute { host, hops }`, `net_wg_status { interfaces }` (names
  and counts only). Guard rows (`Scope::Main`), `permissions/mooring-main.toml`,
  `ipc-manifest.json` / `ipc-codes.json` re-blessed, gate-matrix rows
  (`vault_gated_codes_a4` in `tests/e2e_flow/support.rs`).
- **`mooring-audit`**: four `AuditEvent` variants above (+ serialisation test).
- **Fuzz**: targets `net_ping_output`, `net_traceroute_output`, `net_wg_output`
  (`fuzz/fuzz_targets`, `fuzz/entries`), seeds in `fuzz/corpus/<target>/` (force-added like
  the others), empty `fuzz/regressions/<target>/.gitkeep`, stable replay
  `crates/mooring-net/tests/fuzz_corpus.rs`, nightly matrix + `docs/qa/fuzzing.md` rows.

## UI contract (DTOs, camelCase)
```
net_tools() -> { ping: bool, traceroute: "traceroute" | "tracepath" | null, wg: bool }

TargetArg = { connectionId: string } | { host: string, port?: number }

net_port_check({ target: TargetArg, timeoutMs?: number /* 100..=10000, default 3000 */ })
  -> { outcome: "open", addr: "ip:port", rttMs: number }
   | { outcome: "closed" | "timeout" | "unreachable" | "dns_failed" }
  // port: from `port` or the connection's effective port; required (input.invalid otherwise)

net_ping({ target: TargetArg, count?: number /* 1..=10, default 4 */ })
  -> { result: PingResult, timedOut: bool, truncated: bool, exitCode: number | null }
PingResult = { sent, received, lossPercent, minMs?, avgMs?, maxMs?,
               replies: [{ seq?, ttl?, rttMs }], lines: string[] }   // lines = sanitised text

net_traceroute({ target: TargetArg, maxHops?: number /* 1..=30, default 20 */ })
  -> { result: TraceResult, tool: "traceroute" | "tracepath", timedOut, truncated, exitCode }
TraceResult = { hops: [{ hop, addr?, rttsMs: number[], timeouts, note? }], reached: bool, lines: string[] }

net_wg_show() -> { interfaces: [{ name, listenPort?, peers: [{ publicKey /* shortened */,
                   endpoint?, lastHandshakeSecs?, rxBytes, txBytes }] }] }

Codes: net.invalid_host, net.tool_missing, net.permission_denied ("WireGuard status needs
elevated rights; Mooring does not elevate"), net.busy, net.rate_limited, net.spawn,
input.invalid (port / count / maxHops / timeoutMs), vault.locked, tree.not_found.
A deadline or output cap is not an error: the run resolves with `timedOut` / `truncated`
set and a partial `result`.
```

## Left open
- No `net://progress` streaming event and no `net_cancel` (ADR-0020 §6): the commands
  resolve when the run ends (≤ 30 s ping, ≤ 60 s traceroute). A cancel needs a `runId`
  registry on `NetRuntime`; the runner already kills on drop, so wiring is small. The card
  should show a spinner and the `lines` once the promise resolves.
- Windows `CREATE_NO_WINDOW` and `SystemRoot` env are compiled but untested here (Linux CI);
  the Windows path table is shape-tested only. Needs the Mac/Windows manual gate.
- Real-tool goldens come from documentation samples (iputils, BSD, Windows en-US / tr-TR
  layouts). QA (Q1) should record real outputs from the three OSes into the corpora.
- `wg show` peer rows: the 200-line output cap binds before the 256-peer cap, so an
  interface shows at most 200 peers.
- `tcp_check` on the CI sandbox answers RST for RFC 5737 addresses (proxy); the integration
  test pins "never open, within the deadline" rather than a specific failure variant.

## Decision needed
- **Command names**: the task said `net_port_check` / `net_wg_show`; ADR-0020 §6 says
  `net_tcp_check` / `net_wg_status`. The implementation follows the task; renaming is a
  one-line change in `guard/table.rs`, `lib.rs`, the permission toml, `net.rs` and the
  goldens if the architect prefers the ADR spelling (the audit row names follow the ADR).
- `net_tools` is vault-gated like the rest (ADR §6 header); if the card must grey buttons on
  the lock screen it can move to `NOT_GATED` with a reason.
- Traceroute wall clock is 60 s (task) rather than the ADR's 90 s; 30 hops × 2 s × 1 probe
  fits, with `-m` capped at 30.

## Test evidence
```
cargo fmt --all -- --check                                  clean
cargo clippy -p mooring-net -p mooring-audit -p mooring-app --all-targets -- -D warnings
                                                            clean (Linux, rustc 1.97)
cargo test -p mooring-net     44 unit + 4 corpus + 8 shim + 5 tcp = 61 passed
cargo test -p mooring-audit   35 passed
cargo test -p mooring-app     282 unit (8 new in commands::net::tests, 1 pre-existing ignored)
                              + 21 e2e_flow passed (gate matrix covers the 5 net_* rows)
MOORING_BLESS=1 cargo test -p mooring-app golden   ipc-manifest.json, ipc-codes.json re-blessed
cargo metadata --locked       ok after `cargo metadata`; lock diff = + mooring-net package only
```
