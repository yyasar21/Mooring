# Native confirmation dialogs: per-OS Return / Escape / close-box check (review 6 M-16, 6b B-6)

The Rust-native confirmations are the control that keeps a compromised WebView (T5) from
powering off a VM, pinning a certificate or discarding a fork. After the B-6 fix every dialog
has three buttons: a refusing "Cancel" **first** (the OS default: Return), the confirming
button in the middle, and a refusing "Not now" in the plugin's **cancel slot** (Escape, the
close box, Alt+F4, Cmd+W: `tauri-plugin-dialog` rewrites the OS "dismissed" result into that
slot's label). The result is mapped by label; `rfd` sets no default button, so each OS picks
its own default (NSAlert: Return = first; Windows TaskDialog: first; GTK: first focused).
**That default and the dismiss path can only be verified on the real WebView of each OS.**
Nothing here is automated: `FixedConfirm::with_result` and `ScriptedPrompter::with_results`
replay the plugin's remap in Rust, but not what the OS does with Return, Escape and the close
box.

The sync storage trust prompt (row 4) is two dialogs: the first asks "Trust once (this sync
only)", the second, only after that, asks "Trust and remember" where "Not now" keeps the
trust-once answer and "Cancel" (Return) refuses everything.

Run on macOS (WKWebView), Windows (WebView2) and Linux (WebKitGTK) against the mock vCenter /
S3 mock of `mooring-testsrv` or a lab that is **read-only for agents**. Never run the power
actions against a real VM.

## Checklist (one row per dialog, three columns per OS)

For every dialog: open it, press **Return** → the action must be refused (nothing done, audited
as `cancelled`); open it again, press **Escape** → refused the same way; open it again and
dismiss it with the **close box / Alt+F4 (Windows, Linux) / Cmd+W (macOS)** → refused the same
way; open it once more and click the confirming (middle) button → the action runs. Record the
four outcomes per OS. For row 4 run the four checks on **both** dialogs (dialog 2 opens after a
click on "Trust once (this sync only)"): on dialog 2, Return refuses everything (nothing pinned,
the sync does not proceed), Escape / close box / Cmd+W keep the trust-once answer (nothing
pinned, the sync proceeds), and a click on "Trust and remember" pins.

| # | Dialog | How to raise it | Return refuses | Escape refuses | Close box / Alt+F4 / Cmd+W refuses | Click confirms |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | VM power action (`vsphere_vm_action`, power on / off / reset / shutdown / reboot) | VM row → Power → *Power off* with `allowPowerActions` on | | | | |
| 2 | VMRC hand-off (`vsphere_console { kind: "vmrc" }`) | VM row → VMRC with `allowVmrc` on | | | | |
| 3 | vSphere certificate trust (TOFU prompt in `vsphere_test` / `vsphere_refresh`) | Import inventory… against a vCenter with an unknown certificate | | | | |
| 4a | Sync storage trust, dialog 1 (`sync_gate`, "Trust once (this sync only)") | Settings → Vault sync → Sync now against an S3 endpoint with an unknown certificate | | | | |
| 4b | Sync storage trust, dialog 2 ("Trust and remember"; "Not now" = trust once) | Click "Trust once (this sync only)" on 4a | | | (keeps trust once, pins nothing) | |
| 5 | Fork / rollback resolution (`sync_resolve_fork`) | Fork banner → Resolve: keep local / keep remote | | | | |
| 6 | Directory sign-in ("Mooring · Directory sign-in", `ldap_import_test` / `ldap_import_preview`; Cancel / "Sign in to <host:port>" / Not now; review 7 L-43, F2) | Import → Directory (LDAPS) → fill the form → Test bind (or Preview) against a host not yet confirmed for that credential this session; after the certificate dialog (row 3 shape) on first contact | (refused `ldap.bind_declined`, audited `confirm_refused { kind: ldap_bind, reason: declined }`, no `ldap_bind` row) | | | (binds; the pair is silent until the vault locks) |

Additional checks on each OS, once:

- **Focus steal while typing.** Open an SSH terminal, start typing, raise dialog 1 from a second
  window (or through `make dev` with the mock) and keep typing Enter: the dialog must stay on
  the refusing choice and the typed Enter must not confirm.
- **Row 6 scope.** Lock and unlock the vault, raise row 6 again with the same credential and host:
  the dialog must appear again (confirmed pairs live in memory until lock). A second credential or
  a second host:port asks on its own; the dialog text names the credential's display name and the
  host only, never the bind DN or a password.
- **Single-flight.** Raise dialog 1 twice in a row without answering: the second call must fail
  `confirm.busy` and no second dialog may appear.
- **Cooldown.** Cancel dialog 1, retry at once: `confirm.cooldown` for 10 s, audited.
- **Audit.** After the run, `audit_tail` shows one row per dialog with the outcome; no row
  carries a ticket, token or password.

Record the OS, the WebView version (`app_info`), the date and the tester in
`docs/handoff/<phase>-qa-native-dialogs-<os>.md` and link it from the phase's QA handoff.
Until all three OS runs are green, B-6 stays open on the A3 tag conditions.
