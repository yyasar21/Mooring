# Keyboard shortcuts

Mooring is designed to be used without a mouse. **mod** is `⌘` on macOS and `Ctrl` on Windows
and Linux.

## Application

| Shortcut | Action |
| --- | --- |
| `mod K` | Open a connection or run a command (command palette) |
| `mod W` | Close the current tab |
| `Ctrl Tab` / `Ctrl Shift Tab` | Next / previous tab |
| `mod I` | Show or hide the details pane (inspector) |
| `mod Shift L` | Lock the vault |
| `mod 1` … `mod 4` | Hosts, Credentials, Audit, Settings (the navigation rail) |
| `mod Shift Y` | Open the audit log |
| `mod Shift D` | Detach the tab to its own window |

**Inside a terminal on Windows and Linux**, `Ctrl+K`, `Ctrl+W` and `Ctrl+I` belong to the
remote shell (kill line, delete word, tab completion). There, use `Ctrl+Shift+K`,
`Ctrl+Shift+W` and `Ctrl+Shift+I` instead. On macOS, `⌘` never reaches the shell, so the plain
shortcuts always work. Application shortcuts are never sent to the remote host.

The command palette lists these shortcuts as well.

## Command palette

| Key | Action |
| --- | --- |
| `↑` / `↓` | Move the selection |
| `Enter` | Open the selected connection or run the command |
| `mod Enter` | Open in a new tab |
| `Esc` | Close the palette |

## Connection tree

| Key | Action |
| --- | --- |
| `↑` / `↓` | Move between rows |
| `→` | Expand a folder, or go to its first child |
| `←` | Collapse a folder, or go to the parent |
| `Home` / `End` | First / last row |
| `Enter` | Open the connection, or expand/collapse the folder |
| `mod Enter` | Open in a new tab |
| `F2` | Rename |

## Tabs

With focus on the tab strip:

| Key | Action |
| --- | --- |
| `←` / `→` | Move between tabs |
| `Home` / `End` | First / last tab |
| `Enter` / `Space` | Activate the tab |
| `Delete` | Close the tab |

## Dialogs

`Esc` closes a dialog. In the host-key dialog, `Esc` means **reject** — the connection is not
made.
