# RD Gateway

A Remote Desktop Gateway lets you reach Windows computers on an internal network over HTTPS.
Mooring talks to the gateway with its own implementation of the MS-TSGU protocol over
WebSocket. The decision record is [ADR-0027](../adr/0027-rd-gateway-and-smart-card.md).

## Requirements

- An RD Gateway on Windows Server 2016 or later with the WebSocket transport (the default on
  current gateways). Older gateways that only offer RPC over HTTP are not supported: Mooring
  reports "RD Gateway not supported".
- NTLM sign-in on the gateway. Gateways that accept only Kerberos (Negotiate) are not supported
  yet.

## Set it up

1. Edit an RDP connection and open **RDP options** (Display section).
2. Turn on **Connect through an RD Gateway**.
3. Enter the **Gateway host** (for example `gw01.example.test`) and **port** (443 by default).
4. Choose **Use the gateway**:
   - **Always**, or
   - **Only when the computer is unreachable**: Mooring first tries the computer directly for
     3 seconds and uses the gateway only if that fails.
5. Optional: an **extra CA (PEM)** when the gateway's certificate comes from a private CA.
6. In the **Gateway** section, pick the **RD Gateway credential**:
   - **Same as sign-in** (the default) sends the connection's own sign-in to the gateway.
   - Or pick a separate **Username and password** or **Domain account** credential. Other
     kinds, including "prompt on connect", cannot sign in to a gateway.

Switching the gateway off keeps what you typed, so switching it on again restores it.

## Signing in

- Mooring signs in to the gateway with **NTLM**, bound to the gateway's TLS certificate
  (channel binding). Gateways that require Extended Protection accept it.
- **Basic** authentication is off by default. **Allow Basic authentication** sends the password
  in an HTTP header inside TLS; use it only when the gateway offers nothing else. Every Basic
  sign-in is written to the audit log as a warning.
- If the gateway refuses the credentials, the tab shows "The RD Gateway refused the
  credentials". If it refuses the connection, the message carries the gateway's hexadecimal
  error code to give to your administrator.

## Certificate trust

The gateway has its own trust store, separate from the RDP computers' certificates.

- A gateway certificate that is not publicly trusted shows the **RD Gateway certificate**
  dialog with its fingerprint and problems. Answer **Reject**, **Trust once** or **Trust and
  remember**.
- A **changed** gateway certificate is a hard stop before any password is sent: the tab shows
  "RD Gateway certificate changed". After you have confirmed the new certificate with your
  administrator, remove the old pin under **Settings → Known certificates → RD Gateway** and
  connect again.

## While connected

- The session toolbar shows "via RD Gateway gw01" and the security badge still describes the
  connection to the computer (for example NLA).
- The gateway keeps the tunnel alive; if the gateway closes it, the session reconnects through
  a new tunnel.
- An RD Gateway can be reached through [jump hosts](jump-hosts.md).

## Limits

- No Kerberos or Negotiate sign-in to the gateway, and no smart-card logon over RDP (both need
  Kerberos, which is planned).
- No RPC-over-HTTP (legacy) gateways, no UDP transport, no gateway consent messages.
