# ADR-0002: Vault cryptography

Status: Accepted · 2026-11-03

## Context
The vault holds passwords, private keys and tokens for every connection. A stolen vault file,
a stolen backup and a process reading our memory are in the threat model.

## Decision
```
master password ──Argon2id(salt 16 B, m=256 MiB, t=3, p=4)──► KEK (32 B)
KEK ──XChaCha20-Poly1305, AAD = header fields──► wraps DEK (32 B, random)
DEK ──XChaCha20-Poly1305, nonce 24 B random, AAD = record_id ‖ 0x1F ‖ field──► each secret field
```
- Header (JSON, versioned, `magic=NEXUSVAULT`, `version=1`) is plaintext but authenticated:
  it is the AAD of the DEK wrap. A tampered KDF parameter or salt fails unlock.
- A KDF floor (8 MiB / 1 / 1) is enforced when reading a header, before deriving.
- Password change re-wraps the DEK with a fresh salt + nonce; records are untouched.
- Keys live in `zeroize::Zeroizing`; the DEK is dropped on lock. No `Debug`/`Display` prints keys.
- Minimum master password: 12 characters, length only (NIST 800-63B). A1 adds calibration of
  the Argon2 memory cost to the host and an `age`-compatible export.

## Alternatives considered
- AES-256-GCM: 96-bit nonce → random-nonce collision risk at scale; XChaCha's 192-bit nonce
  removes nonce bookkeeping. Rejected.
- scrypt / PBKDF2: weaker GPU resistance than Argon2id for the same cost. Rejected.
- Age as the on-disk format directly: no per-field AAD binding, whole-file granularity. Used for
  export only.

## Security consequences
Wrong password and tampered header are indistinguishable by design. The DEK never touches the
WebView, logs or disk. Clipboard reveal is a Rust command with audit + 30 s clear (A1).

## Test plan
Unit: round trip, record/field binding, bit-flip detection (proptest), header tamper,
downgraded KDF floor, password change, Debug redaction. Vectors committed in A1 and verified
with the `age` CLI for the export path.
