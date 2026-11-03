//! Committed test vectors (ADR-0006): pin the on-disk format across releases.
//!
//! The passwords below are fixed, public test values documented in `tests/vectors/README.md`.

use std::path::PathBuf;

use nexus_vault::{import_age, Header, Sealed, Vault, VaultError, FORMAT_VERSION};
use secrecy::SecretString;
use serde::Deserialize;

const PASSWORD: &str = "nexus-test-vector-password";
const EXPORT_PASSPHRASE: &str = "nexus-export-vector-passphrase";

#[derive(Debug, Deserialize)]
struct SealedVector {
    record_id: String,
    field: String,
    plaintext_hex: String,
    sealed: Sealed,
}

fn read(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn secret(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn unlocked() -> (Vault, Vec<SealedVector>) {
    let mut v = Vault::from_header_bytes(&read("header.json")).expect("header parses");
    assert_eq!(v.header().version, FORMAT_VERSION);
    assert!(!v.header().needs_upgrade());
    v.unlock(&secret(PASSWORD)).expect("unlock with the vector password");
    let sealed: Vec<SealedVector> = serde_json::from_slice(&read("sealed.json")).expect("json");
    assert!(!sealed.is_empty());
    (v, sealed)
}

#[test]
fn header_vector_unlocks_and_rejects_wrong_password() {
    let mut v = Vault::from_header_bytes(&read("header.json")).expect("parse");
    assert_eq!(v.unlock(&secret("not-the-vector-password")), Err(VaultError::Unlock));
    v.unlock(&secret(PASSWORD)).expect("unlock");
}

#[test]
fn every_sealed_vector_opens_and_is_bound() {
    let (v, sealed) = unlocked();
    for s in &sealed {
        let pt = v.open(&s.record_id, &s.field, &s.sealed).expect("open vector");
        assert_eq!(hex::encode(pt.as_slice()), s.plaintext_hex, "{}/{}", s.record_id, s.field);
        let moved = v.open(&s.record_id, "other-field", &s.sealed);
        assert_eq!(moved, Err(VaultError::Tampered));
    }
}

#[test]
fn export_vector_imports_and_matches() {
    let doc = import_age(&read("export.age"), &secret(EXPORT_PASSPHRASE)).expect("import");
    let header: Header = serde_json::from_slice(&read("header.json")).expect("header");
    assert_eq!(doc.header, header);

    let (v, sealed) = unlocked();
    let mut opened = 0;
    for rec in &doc.credentials {
        for (field, s) in &rec.fields {
            let want = sealed
                .iter()
                .find(|x| x.record_id == rec.record_id && &x.field == field)
                .expect("export field is in sealed.json");
            assert_eq!(s, &want.sealed);
            let pt = v.open(&rec.record_id, field, s).expect("open");
            assert_eq!(hex::encode(pt.as_slice()), want.plaintext_hex);
            opened += 1;
        }
    }
    assert_eq!(opened, sealed.len(), "every sealed vector is in the export");
    assert_eq!(doc.connections[0]["host"], "vector.example.test");

    let wrong = import_age(&read("export.age"), &secret("wrong export passphrase"));
    assert!(matches!(wrong, Err(VaultError::Export(_))));
}
