//! Test-vector generator (ADR-0006). Test-only; run with
//! `cargo test -p mooring-vault --lib -- --ignored regenerate_vectors`.
//!
//! `header.json` and `sealed.json` are fully deterministic (fixed salt, DEK, nonces, vault id),
//! so regenerating them yields byte-identical files. `export.age` is not: `age` draws a fresh
//! file key, salt and nonce, so a regenerated file differs but decrypts to the same document.

use std::collections::BTreeMap;
use std::path::PathBuf;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{field_aad, seal_with_nonce};
use crate::export::{export_age_inner, ExportDocument, ExportedRecord};
use crate::format::{Header, Sealed, FORMAT_VERSION, MAGIC, NONCE_LEN};
use crate::kdf::{derive_kek, KdfParams, KEY_LEN, SALT_LEN};

/// Fixed test password of `header.json`. Not a secret.
pub(crate) const VECTOR_PASSWORD: &str = "nexus-test-vector-password";
/// Fixed passphrase of `export.age`. Not a secret.
pub(crate) const VECTOR_EXPORT_PASSPHRASE: &str = "nexus-export-vector-passphrase";
/// scrypt work factor of `export.age`: 2^16 (64 MiB), well inside the `age` CLI's limits.
pub(crate) const VECTOR_SCRYPT_LOG_N: u8 = 16;

/// One entry of `sealed.json`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SealedVector {
    pub record_id: String,
    pub field: String,
    pub plaintext_hex: String,
    pub sealed: Sealed,
}

const VAULT_ID: u128 = 0x6e65_7875_732d_4000_8000_7465_7374_7631;
const SALT: [u8; SALT_LEN] = *b"moor-vector-salt";
const DEK: [u8; KEY_LEN] = *b"mooring-vector-data-encrypt-key!";

fn nonce(tag: u8) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..12].copy_from_slice(b"moor-nonce--");
    n[NONCE_LEN - 1] = tag;
    n
}

fn cases() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    vec![
        ("cred-0001", "password", b"hunter2".to_vec()),
        ("cred-0001", "username", b"admin".to_vec()),
        ("cred-0002", "private_key", b"-----BEGIN TEST KEY-----\nnot a real key\n".to_vec()),
        ("cred-0003", "token", Vec::new()),
        ("cred-0004", "note", "ünïcödé ✓ 🔐".as_bytes().to_vec()),
        ("cred-0005", "binary", (0u8..=255).collect()),
    ]
}

/// Build the deterministic header and sealed vectors.
pub(crate) fn build() -> (Header, Vec<SealedVector>) {
    let mut header = Header {
        magic: MAGIC.to_owned(),
        version: FORMAT_VERSION,
        vault_id: Uuid::from_u128(VAULT_ID),
        kdf: "argon2id".to_owned(),
        kdf_params: KdfParams::TEST,
        salt: SALT.to_vec(),
        wrapped_dek: Sealed { nonce: Vec::new(), ciphertext: Vec::new() },
        keyring_wrap: None,
    };
    let kek = derive_kek(VECTOR_PASSWORD.as_bytes(), &SALT, KdfParams::TEST)
        .expect("TEST params are valid");
    header.wrapped_dek =
        seal_with_nonce(&kek, nonce(0), &header.aad(), &DEK).expect("small input seals");

    let sealed = cases()
        .into_iter()
        .zip(1u8..)
        .map(|((record_id, field, plaintext), tag)| SealedVector {
            record_id: record_id.to_owned(),
            field: field.to_owned(),
            plaintext_hex: hex::encode(&plaintext),
            sealed: seal_with_nonce(&DEK, nonce(tag), &field_aad(record_id, field), &plaintext)
                .expect("small input seals"),
        })
        .collect();
    (header, sealed)
}

/// The document stored in `export.age`.
pub(crate) fn export_document(header: &Header, sealed: &[SealedVector]) -> ExportDocument {
    let mut records: BTreeMap<&str, BTreeMap<String, Sealed>> = BTreeMap::new();
    for v in sealed {
        records.entry(&v.record_id).or_default().insert(v.field.clone(), v.sealed.clone());
    }
    ExportDocument {
        header: header.clone(),
        credentials: records
            .into_iter()
            .map(|(id, fields)| ExportedRecord { record_id: id.to_owned(), fields })
            .collect(),
        folders: serde_json::json!([{ "id": "folder-1", "name": "Vectors", "parent": null }]),
        connections: serde_json::json!([{
            "id": "conn-1", "folder": "folder-1", "protocol": "ssh",
            "host": "vector.example.test", "port": 22, "credential": "cred-0001"
        }]),
    }
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("vectors")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;

    fn pretty<T: Serialize>(v: &T) -> Vec<u8> {
        let mut s = serde_json::to_vec_pretty(v).expect("json");
        s.push(b'\n');
        s
    }

    #[test]
    #[ignore = "writes crates/mooring-vault/tests/vectors/*; run on purpose only"]
    fn regenerate_vectors() {
        let (header, sealed) = build();
        let doc = export_document(&header, &sealed);
        let pass = SecretString::from(VECTOR_EXPORT_PASSPHRASE.to_owned());
        let age = export_age_inner(&doc, &pass, Some(VECTOR_SCRYPT_LOG_N)).expect("export");
        std::fs::create_dir_all(dir()).expect("mkdir");
        std::fs::write(dir().join("header.json"), pretty(&header)).expect("header");
        std::fs::write(dir().join("sealed.json"), pretty(&sealed)).expect("sealed");
        std::fs::write(dir().join("export.age"), age).expect("export");
    }

    #[test]
    fn committed_vectors_are_what_the_generator_builds() {
        let (header, sealed) = build();
        let on_disk = |name: &str| std::fs::read(dir().join(name)).expect("vector file");
        assert_eq!(on_disk("header.json"), pretty(&header), "header.json drifted");
        assert_eq!(on_disk("sealed.json"), pretty(&sealed), "sealed.json drifted");

        let mut v = Vault::from_header(header);
        v.unlock(&SecretString::from(VECTOR_PASSWORD.to_owned())).expect("unlock");
        for s in &sealed {
            let pt = v.open(&s.record_id, &s.field, &s.sealed).expect("open");
            assert_eq!(hex::encode(pt.as_slice()), s.plaintext_hex);
        }
    }
}
