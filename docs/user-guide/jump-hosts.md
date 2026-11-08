# Jump hosts

A jump host (bastion) is an SSH server you go *through* to reach a target that is not directly
reachable from your machine. In Mooring a jump host is an ordinary SSH connection in your tree,
and any other connection can use one, two or three of them in a row. The decision record is
[ADR-0025](../adr/0025-jump-hosts.md).

## Set it up

1. Make sure the jump host exists as an **SSH connection**, for example `bastion01` on
   `bastion01.example.test`, with its own credential.
2. Open the target connection (**Edit**), go to the **Gateway** section and find
   **Connect via**.
3. Use **Add jump host** and pick the SSH connection. Repeat for a second or third hop; use
   **Up**, **Down** and **Remove** to order them. The route line shows the path, for example
   `you → bastion01 → bastion02 → pg-primary`.
4. Save. The tree shows "via bastion01" next to the connection, and the details pane and the
   ready page show the route.

The picker only offers SSH connections, never the connection itself, a host already in the
list, or a host whose own route goes through this connection. At most three jump hosts can be
added.

## Where it works

| Connection | Through jump hosts |
| --- | --- |
| SSH, including SFTP and port forwards | Yes |
| RDP (also with an [RD Gateway](rd-gateway.md) behind the chain) | Yes |
| VNC | Yes. A VNC connection that allows an unencrypted session shows a warning: every jump host operator could read it |
| Kubernetes (cluster browser, `exec`, logs, port-forward) | Yes |
| Web | Windows and Linux: yes, see below. macOS: refused in this release |
| vCenter | No. Saving a vCenter connection with jump hosts is refused |

The chain is opened directly inside Mooring: nothing listens on a local port for SSH, RDP,
VNC or Kubernetes chains.

## What happens when you connect

- Each hop is opened in order. A row of chips over the session shows each hop as connecting,
  signing in, connected or failed, with its `host:port`.
- Each hop has its **own host-key check**. The first time, you see "Jump host bastion01:
  verify host identity" with that hop's fingerprint. A changed key on a hop is the same hard
  stop as on any SSH host.
- Each hop signs in with **its own credential** (the one on its connection or inherited from
  its folder). A "prompt on connect" credential asks "Jump host bastion01: sign in".
- If a hop fails, the session ends with "a jump host could not be used" and the target is
  never contacted. If a hop drops later, the session ends with "jump host lost"; RDP and VNC
  reconnect and rebuild the whole chain.
- Each hop is written to the [audit log](audit-log.md) when it opens and closes.

## Web sessions through jump hosts

On **Windows and Linux**, a web connection with jump hosts opens its window through a SOCKS
proxy on `127.0.0.1` that leads to the last hop:

- Opening can take up to 90 seconds while each hop signs in; the tab shows a spinner.
- Host names are resolved on the last hop, so internal names work. Certificates are checked as
  usual, against the real host name.
- The proxy only accepts the start page's host and the connection's **Allowed origins**, on
  ports 80, 443 and their own ports. Other targets are refused before they reach the jump host
  and are written to the audit log.
- A web window **cannot answer a jump host's questions**. If a hop has an unknown host key or
  needs a typed password, opening fails. Open the jump host once as an SSH session to trust its
  key, and give it a stored credential.
- The toolbar chip reads "via bastion01 (SOCKS)".

On **macOS**, opening a web connection with jump hosts is refused in this release ("Jump hosts
are not available for web windows on macOS"). Mooring never opens the page around the chain.
As a workaround, open the jump host as an SSH session, add a dynamic (SOCKS) port forward and
point a browser at it.

## Limits

- At most three jump hosts per connection, set per connection. Folders do not pass a route
  down to their connections.
- Every session opens its own chain; chains are not shared between tabs.
- A jump host cannot use a Secret manager reference credential yet; use a stored credential on
  the hop.
- A connection that is used as a jump host cannot be deleted, and neither can a folder that
  holds one used from outside it. Remove it from the other connections first; the dialog names
  them.
