# Vault and security model

This page explains, without jargon where possible, how Mooring protects your credentials. The
precise specification is in [ADR-0002](../adr/0002-vault-cryptography.md),
[ADR-0006](../adr/0006-vault-lifecycle.md) and the
[threat model](../security/threat-model.md).

## The short version

- Your passwords, keys and tokens are encrypted on disk. Without your master password they
  are useless to someone who copies your files.
- The master password itself is never stored.
- Decrypted secrets exist only inside Mooring's Rust core, only while they are needed, and
  are wiped from memory afterwards. The user interface never sees them.
- Everything security-relevant you do is written to a tamper-evident audit log.

## How the vault works

Think of three locks nested inside each other:

1. **Your master password** is turned into a key with **Argon2id**, a deliberately slow and
   memory-hungry function. Each guess costs an attacker the same half second and hundreds of
   megabytes of memory it costs you, which makes large-scale password guessing expensive.
2. That key unlocks a randomly generated **data key**. Changing your master password only
   re-locks the data key; your secrets do not need to be re-encrypted.
3. The data key encrypts **each secret field separately** with **XChaCha20-Poly1305**. Every
   sealed value is tied to the record and field it belongs to, so a value moved into another
   row by someone tampering with the file fails to decrypt instead of being misused.

The vault header (KDF parameters, salt and the locked data key) is stored in plain JSON but is
**authenticated**: changing any value, for example to weaken the Argon2id settings, makes
unlocking fail.

## What is encrypted and what is not

| Data | At rest |
| --- | --- |
| Passwords, private keys, passphrases, certificate keys | Encrypted per field |
| Master password | Never stored |
| Connection names, hosts, ports, tags, folder names | **Plain text** in the local database |
| Credential names and usernames | **Plain text** |
| Audit log | Plain text, hash-chained (tamper-evident) |
| Trusted host keys (`known_hosts`) | OpenSSH format, new entries hashed |

Inventory metadata is kept readable so the tree, search and inheritance work quickly. Someone
who copies your database learns *which* systems you manage, not how to log in to them. This is
an accepted risk (R-INV in the threat model); protect your device with full-disk encryption.

## Locking

The vault locks when you select **Lock** or press `Ctrl+Shift+L` (`⌘⇧L`), and automatically
after the idle time you set (Settings → Auto-lock), on screen lock, on sleep and, if you choose,
when the window is hidden. When the vault locks:

- the data key is removed from memory;
- a password you copied is cleared from the clipboard;
- port forwards that listen beyond loopback are closed, and secret-manager tokens and leases
  are revoked;
- open sessions continue; new sessions, credential changes and the audit view need an unlock.

## Clipboard

Copying a password happens inside the Rust core. Mooring asks the OS to keep the value out of
clipboard history and cloud clipboard where supported, clears it after **30 seconds** (only if
the clipboard still holds that value), clears it on lock and on exit, and writes an audit
entry. While it is on the clipboard, other programs in your session can read it — prefer
typing nothing at all and letting Mooring log in for you.

## What Mooring protects against

- A stolen laptop, disk image or backup (without your master password).
- A tampered vault header or database trying to weaken encryption or swap secrets.
- A malicious server sending hostile data: inputs are size-capped and parsers are tested
  against hostile input.
- A man-in-the-middle on SSH: host keys are verified, changed keys stop the connection.
- A compromised user interface: it can only call a fixed set of validated commands and never
  receives a secret.

## What it does not protect against

- Malware running as your user while the vault is unlocked, or an attacker with administrator
  rights on your machine.
- Someone who knows or guesses your master password. Use a long, unique one.
- The very first connection to a host whose fingerprint you do not check.

## Backups

**Settings → Backup** exports the vault to an `age`-encrypted file protected by a separate
backup passphrase, and imports such a file with a merge or a full replace. See
[Backup and restore](backup-and-restore.md).

## Biometric unlock

**Settings → Security → Unlock with Touch ID / Windows Hello** lets you unlock with a
fingerprint, face or device PIN instead of typing the master password. It is off until you
turn it on, and turning it on or off asks for the master password. The decision record is
[ADR-0022](../adr/0022-biometric-unlock.md).

- The key that unlocks the vault is held by the operating system behind a **fresh biometric
  check** (macOS keychain with "current biometry set"; on Windows it is derived from a Windows
  Hello signature). No process, Mooring included, can read it without your gesture.
- The unlock screen shows **Unlock with Touch ID** or **Unlock with Windows Hello** only when it
  is enabled; Mooring never starts the prompt by itself.
- It is **turned off automatically** after three failed or cancelled attempts within 10
  minutes, when you change the master password, when the enrolled fingers or faces change, and
  when the vault is replaced by another vault. After the next password unlock Mooring tells you
  why; turn it on again in Settings → Security.
- The master password is still needed to create the vault, change the password, export a
  backup and turn biometric unlock on or off.
- **macOS:** Touch ID needs a Developer-ID-signed build of Mooring. Builds without that
  signature say "Touch ID needs a signed build" and keep the switch off.
- **Windows:** Windows Hello needs to be set up in Windows settings.
- **Linux:** not offered, because Linux has no biometric access control for stored keys.
- It cannot be turned on while vault sync is configured.
