# Native confirmation dialogs: per-OS Return / Escape check (review 6, M-16)

The Rust-native confirmations are the control that keeps a compromised WebView (T5) from
powering off a VM, pinning a certificate or discarding a fork. After the M-16 fix the refusing
choice is the first button and the result is mapped by label; `rfd` sets no default button, so
each OS picks its own default (NSAlert: Return = first; Windows TaskDialog: first; GTK: first
focused). **That default can only be verified on the real WebView of each OS.** Nothing here is
automated: `FixedConfirm` covers the label mapping, single-flight and cooldown in Rust, but not
what the OS does with Return and Escape.

Run on macOS (WKWebView), Windows (WebView2) and Linux (WebKitGTK) against the mock vCenter /
S3 mock of `mooring-testsrv` or a lab that is **read-only for agents**. Never run the power
actions against a real VM.

## Checklist (one row per dialog, three columns per OS)

For every dialog: open it, press **Return** → the action must be refused (nothing done, audited
as `cancelled`); open it again, press **Escape** → refused the same way; open it a third time
and click the confirming button → the action runs. Record the three outcomes per OS.

| # | Dialog | How to raise it | Return refuses | Escape refuses | Click confirms |
| --- | --- | --- | --- | --- | --- |
| 1 | VM power action (`vsphere_vm_action`, power off / reset / reboot) | VM row → Power → *Power off* with `allowPowerActions` on | | | |
| 2 | VMRC hand-off (`vsphere_console { kind: "vmrc" }`) | VM row → VMRC with `allowVmrc` on | | | |
| 3 | vSphere certificate trust (TOFU prompt in `vsphere_test` / `vsphere_refresh`) | Import inventory… against a vCenter with an unknown certificate | | | |
| 4 | Sync storage trust (`sync_gate`, "Trust once" / "Pin") | Settings → Vault sync → Sync now against an S3 endpoint with an unknown certificate | | | |
| 5 | Fork / rollback resolution (`sync_resolve_fork`) | Fork banner → Resolve: keep local / keep remote | | | |

Additional checks on each OS, once:

- **Focus steal while typing.** Open an SSH terminal, start typing, raise dialog 1 from a second
  window (or through `make dev` with the mock) and keep typing Enter: the dialog must stay on
  the refusing choice and the typed Enter must not confirm.
- **Single-flight.** Raise dialog 1 twice in a row without answering: the second call must fail
  `confirm.busy` and no second dialog may appear.
- **Cooldown.** Cancel dialog 1, retry at once: `confirm.cooldown` for 10 s, audited.
- **Audit.** After the run, `audit_tail` shows one row per dialog with the outcome; no row
  carries a ticket, token or password.

Record the OS, the WebView version (`app_info`), the date and the tester in
`docs/handoff/<phase>-qa-native-dialogs-<os>.md` and link it from the phase's QA handoff.
Until all three OS runs are green, M-16 stays open on the A3 tag conditions.
