# Troubleshooting

## Getting diagnostic output

Start Mooring from a terminal with more logging:

```bash
MOORING_LOG=debug make dev            # from source
MOORING_LOG=debug /path/to/mooring    # installed binary (Linux, macOS)
```

On Windows PowerShell: `$env:MOORING_LOG="debug"; & "<install-dir>\Mooring.exe"`.

Logs never contain secrets, but they do contain hostnames and usernames. Redact them before
sharing in an issue.

`MOORING_LOG` accepts the usual `tracing` directive list (`debug`, `mooring_app=trace,info`).
Three targets are protected: `ironrdp_connector::credssp`, `ironrdp_connector::connection` and
`sspi` always stay at `info`, whatever you ask for, because below that they would log the raw
RDP CredSSP/NTLM exchange, which contains offline-crackable material for your domain password.
Directives naming them, and span-scoped directives (anything with `[` in it), are ignored.

## Vault

**"Wrong password" although I am sure it is right.** Mooring cannot tell a wrong password from
a tampered vault header — by design. Check keyboard layout and Caps Lock. If the header was
modified, restore `vault.header.json` from a backup; a `vault.header.json.bak` next to it is a
copy from the last password change if that write was interrupted.

**Unlock refuses with a memory error on a smaller machine.** The Argon2id cost is calibrated
on the machine that created the vault (up to 1 GiB). Mooring refuses to use more than half of
the physical memory. Change the master password on the original machine to recalibrate, or
use a machine with more memory.

**Unlocking takes several seconds.** Calibration targets about 0.5 s. If your machine was
under load during creation, change the master password (to the same or a new one) to
recalibrate.

## SSH

**`HOST KEY CHANGED for <host>`.** The server presented a different key than the one you
trusted earlier. Do not work around this until you know why: ask the server owner whether the
host was reinstalled or its keys rotated. If the change is legitimate, remove the old entry
for that host from Mooring's `known_hosts` file while Mooring is closed, then connect again
and verify the new fingerprint.

**`authentication failed`.** Mooring does not say which method failed. Check with
`MOORING_LOG=debug`:

- the username in the credential (or the connection's override);
- that the key is in OpenSSH format and the passphrase is right;
- that your ssh-agent is running (`ssh-add -l`) if you rely on it;
- that the server allows the method (`PasswordAuthentication`, `PubkeyAuthentication`).

**Negotiation fails with an older server or network device.** Mooring offers no SHA-1, CBC or
`ssh-rsa` algorithms. Update the server, or enable `rsa-sha2-256/512` and a modern KEX there.
A per-connection legacy option is planned (Phase A2).

**The session stays "connecting".** Close the tab and check host, port and firewall. A
handshake timeout in the core is planned.

**Ctrl+K / Ctrl+W do not open the palette or close the tab inside a terminal.** On Windows and
Linux they belong to the shell; use `Ctrl+Shift+K` / `Ctrl+Shift+W`.

**"RDP sessions are not available in this version".** Only SSH sessions open today. RDP, VNC
and web sessions are Phase A2.

## Clipboard

**Copied password does not disappear.** Mooring only clears the clipboard if it still holds the
value it copied (it never wipes something you copied later). On Linux with pure Wayland, the
clipboard is reached through XWayland; make sure XWayland is available. Clipboard history
managers that ignore the "exclude from history" hint can keep a copy — disable history for
sensitive work.

## Building from source

**`mooring-app` fails to compile on Linux with missing `webkit2gtk`.** Install the WebView
toolchain listed in the [build guide](../developer-guide/building.md#linux).

**`cargo` fetches `age` from GitHub.** Expected: `age` is pinned to a reviewed commit of its
official repository until version 0.13 is published (see the
[developer guide](../developer-guide/building.md#the-age-git-pin)).

## Still stuck?

Search [existing issues](https://github.com/yyasar21/Mooring/issues), ask in
[Discussions](https://github.com/yyasar21/Mooring/discussions) or open a bug report.
Security problems: see [SECURITY.md](../../SECURITY.md).
