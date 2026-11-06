# ADR-0020: Network tools — TCP port check, ping, traceroute, WireGuard status

Status: Accepted (owner decisions inline) · 2026-11-06 (Phase A4; moved from A3 by the A3
orchestrator; extends ADR-0003 trust boundaries, ADR-0008 IPC style)

## Context
When a connection fails, users leave Mooring to run `ping`, `nc -z` or `traceroute`. The roadmap
wants these in the app via OS tools. Mooring must not gain privileges to do so: no raw sockets,
no `CAP_NET_RAW`, no setuid helper, no elevation prompt. Tool output is untrusted text (it
carries remote-influenced data: addresses, ICMP errors, and with name lookups, PTR names).

## Decision

### 1. Crate `mooring-net` (pure: validation, argv builders, parsers, TCP check)
```rust
pub struct Target(String);                    // validated host: hostname (RFC 1123) or IP literal
pub enum Tool { Ping, Traceroute, Wg(WgQuery) }
pub enum WgQuery { Interfaces, Endpoints(Iface), LatestHandshakes(Iface), Transfer(Iface), ListenPort(Iface) }
pub fn argv(tool: &Tool, target: Option<&Target>, os: Os) -> (PathBuf, Vec<OsString>);
pub fn parse_ping(out: &[u8], os: Os) -> PingResult;           // capped, never fails: unparsed lines kept
pub fn parse_traceroute(out: &[u8], os: Os) -> TraceResult;
pub fn parse_wg(q: &WgQuery, out: &[u8]) -> WgResult;
pub async fn tcp_check(target: &Target, port: u16, timeout: Duration) -> TcpResult;
```
- `Target`: 1..=253 bytes, ASCII only, `[A-Za-z0-9.-]` labels or an IPv4/IPv6 literal (no zone
  id); **never starts with `-` or `/`** (argv option injection; Windows tools have no `--`).
  Connection hosts are taken through the same check; URLs (web) contribute their host only.
- No new dependency. tokio gains the `process` feature (same crate; `signal-hook-registry` is
  already in the lockfile). The orchestrator edits `Cargo.toml`.

### 2. TCP port check (own Rust code)
- `tokio::net::lookup_host` (≤ 16 addresses), then `TcpStream::connect` per address under one
  deadline (100..=10 000 ms, default 3 000); first success wins; the stream is dropped at once —
  **no bytes are sent or read**. One port per call; no ranges, no sweep.
- Result: `open { addr, rttMs } | closed (RST) | timeout | unreachable | dns_failed`.

### 3. Ping and traceroute (OS tools, fixed argv, no shell)
| OS | ping | traceroute |
| --- | --- | --- |
| Linux | `/usr/bin/ping` or `/bin/ping`: `-n -c <1..10> -W <1..5> -- <target>` | `/usr/bin/traceroute -n -q 1 -w 2 -m <1..30> -- <target>`; else `/usr/sbin/tracepath -n -m <n> <target>` |
| macOS | `/sbin/ping -n -c <n> -t <deadline> -- <target>` | `/usr/sbin/traceroute -n -q 1 -w 2 -m <n> -- <target>` |
| Windows | `%SystemRoot%\System32\PING.EXE -n <n> -w <ms> <target>` | `%SystemRoot%\System32\TRACERT.EXE -d -h <n> -w <ms> <target>` |
- **Absolute paths only** from this table (no `PATH` lookup, no PATH hijack); a missing binary →
  `net.tool_missing` and the button is greyed (`net_tools()`). `-n`/`-d` = no reverse DNS.
  `--` is passed only where the tool's parser accepts it (golden-tested per OS); the `Target`
  rule is the protection that holds everywhere.
- `tokio::process::Command` with explicit args: no shell, `stdin` null, environment cleared
  except `LC_ALL=C` (Unix) and `SystemRoot` (Windows), `CREATE_NO_WINDOW`, `kill_on_drop`.
  Deadlines: ping 30 s, traceroute 90 s; then kill → `net.timeout` with the partial result.
- Output caps: stdout + stderr ≤ 64 KiB, ≤ 200 lines, line ≤ 512 bytes; bytes are decoded as
  lossy UTF-8 (Windows OEM code pages included), then C0/C1 controls, ANSI escapes, bidi and `Cf`
  characters are removed before any line reaches the UI. Parsers extract numbers per known
  layouts; localized Windows output still parses by number patterns, else lines are shown raw.
- Exit codes are data (`ping` exits 1 on loss), not errors.

### 4. WireGuard status (read-only, only if `wg` exists)
- Binaries: `/usr/bin/wg`, `/usr/local/bin/wg`, `/opt/homebrew/bin/wg`,
  `%ProgramFiles%\WireGuard\wg.exe`. Absent → the section is hidden.
- Only the `WgQuery` subcommands: `wg show interfaces`, then per interface `wg show <if>
  endpoints | latest-handshakes | transfer | listen-port`. **Never** `dump`, `showconf`,
  `private-key`, `preshared-keys` (they print private keys), never `set`, `syncconf`, `wg-quick`.
  An interface name from `wg` must match `[A-Za-z0-9_=+.-]{1,15}` before it is used in argv.
- Output: per interface `{ name, listenPort, peers: [{ publicKey, endpoint, lastHandshakeSecs,
  rxBytes, txBytes }] }`, ≤ 32 interfaces, ≤ 256 peers each. Public keys are shown shortened.
- `wg` usually needs root or `CAP_NET_ADMIN`; "permission denied" → `net.permission_denied`
  with the text "WireGuard status needs elevated rights; Mooring does not elevate". Mooring
  never retries via sudo, pkexec, UAC or AppleScript.

### 5. No raw sockets, no elevation (owner decision 19)
Mooring holds no `CAP_NET_RAW`/`CAP_NET_ADMIN`, ships no setuid or helper binary and never asks
for elevation. ICMP comes only from the OS `ping`/`traceroute`, with whatever rights the
distribution gave them (file capabilities, `ping_group_range`); Mooring adds none. Raw-socket
code would need privileges on every OS and is a classic escalation and packet-injection target.

### 6. IPC (all in `mooring-main`; gated on an unlocked vault like the other app commands)
```
net_tools() -> { ping: bool, traceroute: "traceroute" | "tracepath" | null, wg: bool }
net_tcp_check({ target: { connectionId } | { host, port }, timeoutMs }) -> TcpResult
net_ping({ target: { connectionId } | { host }, count }) -> { runId, result: PingResult }
net_traceroute({ target, maxHops }) -> { runId, result: TraceResult }
net_wg_status() -> WgStatus
net_cancel({ runId }) -> void
```
- `runId` is returned at start through a progress event `net://progress { runId, line }`
  (sanitised lines, same caps) so the card can stream and cancel; the command resolves when the
  run ends. One run per tool in flight (`net.busy`); ≤ 1 TCP check per second (`net.rate_limited`).
- Codes: `net.invalid_host`, `net.tool_missing`, `net.timeout`, `net.cancelled`, `net.busy`,
  `net.rate_limited`, `net.permission_denied`, `net.dns`, `net.spawn`.
- Audit: `net.tcp_check { host, port, outcome }`, `net.ping { host, sent, received }`,
  `net.traceroute { host, hops }`, `net.wg_status { interfaces }`. One row per run.

### 7. UI: inspector "Network" card
Shown for SSH, RDP, VNC and web connections (hidden for Kubernetes and vSphere consoles, whose
"host" is not a network target). Defaults to the connection's host and port; an "other host"
field uses the same validation. Buttons: Check port, Ping, Traceroute (streamed lines, Cancel),
and a WireGuard row (interfaces, peer handshake age) when `wg` exists. Results are plain text.

## Alternatives considered
- Own ICMP via raw or datagram sockets (`surge-ping`, `socket2`): needs `CAP_NET_RAW`/root on
  macOS and Windows, or `ping_group_range` on Linux; adds `unsafe` socket code. Rejected.
- Running tools through a shell (`sh -c "ping …"`): command injection by design. Rejected.
- WireGuard via netlink/UAPI socket: needs the same privileges, and the UAPI `get` reply
  contains the private key. Rejected; `wg` with an allow-list keeps keys out of our memory.
- Port ranges / scan mode: turns a diagnostic into a scanner a compromised renderer can drive.
  Rejected.

## Security consequences
- A compromised renderer (T5 in `main`) can make Mooring connect to one host:port per second or
  run a bounded ping/traceroute; it cannot run other binaries, pass options, or read tool output
  beyond the sanitised caps. Accepted as R-NET-PROBE.
- No new privileges; no secret ever flows through these commands (WireGuard key subcommands are
  unreachable by construction of `WgQuery`).

## Test plan
- Unit: `Target` (leading `-`/`/`, spaces, unicode, `%zone`, 253/254 bytes, IP literals); `argv`
  golden per OS and tool (absolute path, no shell, option order); `WgQuery` cannot express `dump`
  or `showconf` (exhaustive match test); sanitiser strips ESC/bidi/C1; caps max/max+1.
- Parsers: golden outputs (iputils, BSD, Windows en-US and tr-TR ping/tracert; traceroute,
  tracepath; wg). Fuzz: `net_ping_output`, `net_traceroute_output`, `net_wg_output` (oracle: no
  panic, caps hold, no control characters in results).
- Integration: TCP check against a loopback listener (open), a closed port (closed), an RFC 5737
  address (timeout); a fake `ping` path in tests is injected through a test-only constructor, not
  `PATH`; cancel kills the child; rate limit and single flight.
- E2E: Network card on an SSH connection → Check port → result; button greyed when the tool is missing.
