# mooring-sync test vectors (ADR-0017 §2)

Checked by `src/tests/blob_tests.rs::committed_vectors_match_and_open` on every `cargo test`.

| File | Contents |
| --- | --- |
| `vault-header.json` | Copy of `crates/mooring-vault/tests/vectors/header.json` (fixed DEK, vault id `6e657875-732d-4000-8000-746573747631`) |
| `snapshot.json` | Canonical snapshot JSON (the blob plaintext), no trailing newline |
| `blob-v1.hex` | Hex of the `MSY1` blob: counter 7, parent 6, parent hash `5a…5a`, `header_hash = SHA-256(vault-header.json)`, `created_unix = 1793786400`, nonce `"msy1-vector-"` ‖ 12 zero bytes |

Key: `HKDF-SHA256(ikm = DEK, salt = vault_id bytes, info = "mooring sync v1")`; AAD = blob
bytes `0..125`. The DEK comes from unlocking `vault-header.json` with the public test password
`nexus-test-vector-password` (documented in the vault vectors README; not a secret).

Regenerate (deterministic, byte-identical unless the format changed):

```sh
MOORING_BLESS=1 cargo test -p mooring-sync committed_vectors
```
