//! Fuzz entry `import_age`: a hostile backup file chosen by the user (ADR-0006). Shared by
//! `fuzz/fuzz_targets/import_age.rs` and `crates/mooring-vault/tests/fuzz_corpus.rs`.
//!
//! The passphrase is the public test-vector one, so the committed `export.age` vector seeds the
//! fuzzer past decryption into the JSON / header checks. Inputs that keep a valid scrypt stanza
//! cost one scrypt run (the vector uses `N = 2^16`; at most `2^MAX_IMPORT_SCRYPT_LOG_N`).

use mooring_vault::{import_age, Header, MAX_EXPORT_BYTES};
use secrecy::SecretString;

/// Public test-vector passphrase (`crates/mooring-vault/tests/vectors/README.md`); not a secret.
const PASSPHRASE: &str = "nexus-export-vector-passphrase";

/// Never panics; an accepted export is size-bounded and carries a header that is accepted on
/// its own.
pub fn run(data: &[u8]) {
    let pass = SecretString::from(PASSPHRASE.to_owned());
    let Ok(doc) = import_age(data, &pass) else {
        return;
    };
    assert!(data.len() <= MAX_EXPORT_BYTES, "accepted an over-size export");
    let header = doc.header.to_bytes().expect("imported header serialises");
    Header::from_bytes(&header).expect("imported header passes Header::from_bytes");
}
