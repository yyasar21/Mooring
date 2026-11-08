# Backup and restore

**Settings → Backup** writes your vault to a single encrypted file and reads such a file back,
on the same device or another one. The decision record is
[ADR-0023](../adr/0023-vault-export-import-ui.md).

## What a backup holds

- Folders, connections, credentials (their secrets still sealed under the vault's key) and your
  trusted host keys and certificates.
- Not included: secret-source sign-ins, vault sync settings, the audit log, and the biometric
  unlock enrolment.

The file is encrypted with the `age` format and a **backup passphrase** you choose. Without the
passphrase it is unreadable; with it, `age -d` shows the inventory (names, hosts, tags), but the
passwords and keys inside are still encrypted under your vault's key.

## Export

1. **Export…** asks for your **master password**.
2. Choose a **backup passphrase** and type it twice. It must be at least 12 characters and
   differ from the master password; a passphrase of several random words is best.
3. Pick where to save the file in the system dialog (`.age` is added). Mooring refuses to save
   it inside its own data folder.
4. The summary shows how many folders, connections and credentials were written and the file
   size.

The file is written privately (owner-only permissions) and only appears under its final name
when it is complete. Keep the passphrase somewhere other than the file.

## Import

1. **Import…** opens the system dialog. Files over 64 MiB are refused.
2. Enter the **backup passphrase**. Mooring shows when and with which version the file was
   made, what it holds, and whether it comes from **this vault** or **another vault**. After
   three wrong passphrases, choose the file again.
3. A backup of **another vault** also needs **that vault's master password**: its secrets are
   opened and sealed again under your vault's key.
4. Choose how to apply it:
   - **Merge** (the default) adds what is new. When a connection or credential changed on both
     sides, both copies are kept and the imported one is renamed "… (imported YYYY-MM-DD)". For
     folders the newer change wins. Trust for a host that this device already pins is never
     replaced; those lines are listed as "kept local".
   - **Replace** makes the vault match the file. Type `REPLACE` to confirm. **Export a backup
     first…** opens the export dialog before you continue.
5. Enter your **master password**. The result lists what was added, updated and skipped, the
   conflicts and how each was resolved, and the trust lines that were added.

Everything is applied in one step: if anything fails, nothing changes. Files in the older
format 1 are refused. Each export and import, and each refusal, is written
to the [audit log](audit-log.md).

## Notes

- Replacing the vault with a backup of another vault turns off
  [biometric unlock](vault-and-security.md#biometric-unlock); turn it on again in
  Settings → Security.
- Passwords you type in these dialogs are never kept by the interface; the fields are emptied
  after each attempt and when the dialog closes.
