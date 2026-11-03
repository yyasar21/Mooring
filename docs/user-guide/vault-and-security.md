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

The vault locks when you select **Lock** or press `Ctrl+Shift+L` (`⌘⇧L`). Automatic locking on
idle time, screen lock and sleep is designed (default: 15 minutes idle) and is being wired to
the operating system signals. When the vault locks:

- the data key is removed from memory;
- a password you copied is cleared from the clipboard;
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

An `age`-compatible encrypted export, readable with the standard `age` tool and a separate
export passphrase, is implemented in the vault library and will be exposed in the app. Until
then, back up the application data directory (vault header, `mooring.db`) as a whole while
Mooring is closed.

## Biometric unlock

"Unlock with Touch ID / Windows Hello" is planned as an opt-in convenience. It will never
replace the master password for creating the vault, changing the password or exporting. It
is held back until each platform can protect the stored key with a biometric or user-presence
check; on Linux it will stay off by default.
