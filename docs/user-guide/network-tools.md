# Network tools

When a connection fails, the inspector's **Network** card answers the first questions without
leaving Mooring: is the port open, does the host answer a ping, where does the path stop, is
my WireGuard tunnel up. The decision record is [ADR-0020](../adr/0020-network-tools.md).

## How it fits together

- The card sits in the inspector (right pane) below the credential block for **SSH, RDP, VNC
  and web** connections. Kubernetes and vSphere consoles have no network host to probe, so they
  have no card.
- It defaults to the connection's host and port (for a web connection, the URL's host and
  port). The optional **Other host** field probes something else; it accepts a host name
  (RFC 1123 labels) or an IPv4 / IPv6 address, nothing else.
- The **port check** is Mooring's own code: one TCP handshake, no data. **Ping**, **Traceroute**
  and **WireGuard** run the operating system's own tools at fixed paths and show their output
  as plain text. Nothing streams: each tool shows "Running…" until it finishes.
- Mooring never gains privileges for any of this: no raw sockets, no helper binary, no
  elevation prompt (see *What is never done*). Every run needs an unlocked vault.

## The four tools

| Button | Parameters | Result line | Details |
| --- | --- | --- | --- |
| **Check port** | **port** (prefilled from the connection; required) | **Open** `192.0.2.5:22 in 11 ms` · **Closed — the host refused the connection** · **Timed out — nothing answered within the deadline** · **Unreachable — no route to the host** · **DNS lookup failed** | The name is resolved (at most 16 addresses), each address is tried under one 3-second deadline, the first handshake wins and the socket is closed at once. No byte is sent or read |
| **Ping** | **count** 1–10 (default 4) | **Reachable** / **Partial loss** / **No reply** · *n sent, n received, n% loss* · min/avg/max | A table of replies (seq, ttl, rtt) and a collapsed **ping output** with the tool's text. Runs at most 30 s |
| **Traceroute** | **max hops** 1–30 (default 20) | **Reached** / **Not reached** · *n hops* · `traceroute` or `tracepath` | A hop table (address, round-trip times, `*` for no answer, notes such as `!H`) and a collapsed **traceroute output**. Runs at most 60 s |
| **WireGuard** | — | Per interface: name, listen port, peer count | Per peer: the shortened public key, endpoint, "handshake 42 s ago" or "never", bytes received / sent. Only shown when `wg` exists on this system |

The collapsed output names anything partial: "stopped at the deadline; the result is
partial", "output cap reached; the result is partial", "*n* more lines not shown", "exit code
*n*". A non-zero exit code is data (ping exits 1 on loss), not an error.

## Which OS tools are used, and from where

Mooring never searches `PATH`. Each tool is started at one of these absolute paths, with a
fixed argument list, no shell and an empty environment; the first path that exists wins. A
tool that is missing greys its button with "not found on this system".

| OS | ping | traceroute | wg |
| --- | --- | --- | --- |
| Linux | `/usr/bin/ping`, `/bin/ping` | `/usr/bin/traceroute`, `/usr/sbin/traceroute`; else `tracepath` from `/usr/bin`, `/usr/sbin` or `/bin` | `/usr/bin/wg`, `/usr/local/bin/wg` |
| macOS | `/sbin/ping` (`/sbin/ping6` for an IPv6 address) | `/usr/sbin/traceroute` (`traceroute6`) | `/usr/local/bin/wg`, `/opt/homebrew/bin/wg` |
| Windows | `%SystemRoot%\System32\PING.EXE` | `%SystemRoot%\System32\TRACERT.EXE` | `%ProgramFiles%\WireGuard\wg.exe` |

Arguments are the same every time: ping with a reply count and a per-reply wait, traceroute
with one probe per hop, a 2-second wait and your hop limit, both with reverse DNS off
(`-n` / `-d`). The target is always the last argument and can never start with `-` or `/`, so
a host name cannot smuggle in an option.

For WireGuard, Mooring runs `wg show interfaces` and then, per interface, `wg show <if>
endpoints | latest-handshakes | transfer | listen-port` — and nothing else. The subcommands
that print private or preshared keys (`dump`, `showconf`, `private-key`, `preshared-keys`)
and the ones that change anything (`set`, `syncconf`, `wg-quick`) cannot be expressed by the
code at all. Public keys are shortened before they reach the window. `wg` usually needs root
or `CAP_NET_ADMIN`; when it says so, the card shows "WireGuard status needs elevated rights;
Mooring does not elevate" (`net.permission_denied`) and leaves it there.

## What is never done

- **No raw sockets.** ICMP comes only from the OS `ping` and `traceroute`, with whatever rights
  your distribution gave those binaries (file capabilities, `ping_group_range`). Mooring adds
  none, holds no `CAP_NET_RAW` or `CAP_NET_ADMIN`, and ships no setuid helper.
- **No elevation.** Mooring never retries through `sudo`, `pkexec`, UAC or AppleScript.
- **No shell.** Tools are started directly with explicit arguments; there is nothing to inject.
- **No scanning.** One port per check, one host per run; there are no ranges or sweeps.
- Tool output is treated as hostile text: it is capped (64 KiB, 200 lines of 512 bytes),
  decoded leniently, and stripped of control characters, ANSI escapes and bidi overrides
  before a line is shown.

## Caps and messages

| Message | When |
| --- | --- |
| "Two network tools are already running. Wait for one to finish." (`net.busy`) | At most two tool processes run at once |
| "One port check per second. Try again in a moment." (`net.rate_limited`) | Port checks are limited to one per second |
| "That is not a valid host name or address, or this connection has no network host to probe." (`net.invalid_host`) | The **Other host** text failed validation, or the connection is a Kubernetes / vSphere one |
| "That tool was not found on this system. Mooring only runs the OS tools at their usual paths." (`net.tool_missing`) | None of the paths above exists |
| "The tool could not be started." (`net.spawn`) | The OS refused to run it |
| "WireGuard status needs elevated rights; Mooring does not elevate." (`net.permission_denied`) | `wg` needs root |

Deadlines (ping 30 s, traceroute 60 s, `wg` 5 s) and the output cap are not errors: the run
ends with the partial result and the flags described above. Hop limits, counts and ports
outside their ranges are refused before anything runs (`input.invalid`).

## What is audited

Every run writes one entry in the [audit log](audit-log.md) — the card says so underneath:
"Every run writes an audit entry with the host and the outcome."

| Entry | Fields |
| --- | --- |
| `net_tcp_check` | host, port, outcome |
| `net_ping` | host, packets sent and received |
| `net_traceroute` | host, hop count |
| `net_wg_status` | interface names |
| `net_suppressed` | count — after 32 network entries in an hour, further runs are summed up in one entry per hour instead of flooding the chain |

Tool output, addresses of intermediate hops and WireGuard keys are never written to the log.

## Limits

- No cancel button and no live output yet: a run ends at its deadline at the latest.
- At most 32 WireGuard interfaces and, in practice, 200 peers per interface (the output cap).
- Windows output in other languages is parsed by its numbers; lines that do not match a known
  layout are still shown in the raw output.
