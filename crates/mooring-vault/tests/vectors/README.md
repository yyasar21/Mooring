# mooring-vault test vectors (ADR-0006)

These files pin the vault format. `tests/vectors.rs` checks them on every `cargo test`.

| File | Contents |
| --- | --- |
| `header.json` | Header v2, `KdfParams::TEST` (8 MiB, t=1, p=1), fixed salt, DEK and vault id |
| `sealed.json` | `[{record_id, field, plaintext_hex, sealed}]` sealed under that DEK |
| `export.age` | Armored age v1 file (scrypt recipient, work factor 2^16) holding the export JSON |
| `age_decrypt.py` | Runs the reference `age` CLI on `export.age` under a pseudo-terminal |

## Test passwords — not secrets

The values below are fixed, public test values. They protect nothing but these vectors,
and they are committed on purpose:

- vault password of `header.json`: `nexus-test-vector-password`
- export passphrase of `export.age`: `nexus-export-vector-passphrase`

Never reuse them anywhere else. If a secret scanner flags them, allow-list this directory
(there is no `.gitleaks.toml` in the repo yet; that is the orchestrator's call).

## Regenerate

```sh
cargo test -p mooring-vault --lib -- --ignored regenerate_vectors
```

The generator lives in `src/vectors.rs`. `header.json` and `sealed.json` are deterministic
(fixed salt, DEK, nonces and vault id), so regenerating gives byte-identical files and the
unit test `committed_vectors_are_what_the_generator_builds` fails if they drift.
`export.age` is not deterministic (age draws a fresh file key, salt and nonce); a regenerated
file differs byte-for-byte but decrypts to the same document. Only regenerate on an
intentional format change, and say so in the commit.

## Verify with the `age` CLI

`age` reads passphrases only from a terminal. Interactively:

```sh
age --decrypt crates/mooring-vault/tests/vectors/export.age > /tmp/export.json
# type: nexus-export-vector-passphrase
```

Non-interactively (CI), from the repository root:

```sh
python3 crates/mooring-vault/tests/vectors/age_decrypt.py \
  crates/mooring-vault/tests/vectors/export.age > /tmp/export.json
```

Then compare: the `header` member of `/tmp/export.json` equals `header.json`, and every
`credentials[].fields.<field>` equals the `sealed` value of the matching `sealed.json` entry.
For example, with `jq`:

```sh
diff <(jq -S .header /tmp/export.json) <(jq -S . crates/mooring-vault/tests/vectors/header.json)
```

Verified with age v1.1.1 when the vectors were generated.
