//! Migration of `sk-*` `ssh_key` rows to `ssh_sk_key` (ADR-0024 §1).

use mooring_core::credential::testdata::{
    placeholder_key_pem, public_line, sk_ed25519_public, sk_key_handle_pem,
};
use mooring_core::credential::{CredentialError, SkBackend};
use mooring_vault::{KdfParams, Vault};
use secrecy::SecretString;
use serde_json::json;

use super::*;
use crate::credentials::{put_secret, seal};
use crate::schema;

fn vault() -> Vault {
    Vault::create(&SecretString::from("test-only master pw".to_owned()), KdfParams::TEST)
        .expect("vault")
}

/// An `ssh_key` as an A4 build could store it (before `sk-*` material was refused): a plain
/// key row whose sealed `private_key` is then replaced by an `sk-*` handle.
fn legacy_sk_row(s: &Store, v: &Vault, handle: &str, otp: bool) -> CredentialId {
    let pem = placeholder_key_pem();
    let mut secrets: crate::Secrets<'_> =
        [(SecretName::PrivateKey, pem.as_bytes()), (SecretName::Passphrase, &b"pw"[..])]
            .into_iter()
            .collect();
    if otp {
        secrets.insert(SecretName::OtpSeed, b"JBSWY3DPEHPK3PXP");
    }
    let id = s
        .create_credential(
            v,
            "yubikey",
            CredentialKind::SshKey,
            &json!({"username": "root"}),
            &secrets,
        )
        .expect("ssh_key")
        .id;
    let blob = seal(v, id, "private_key", handle.as_bytes()).expect("seal");
    put_secret(&s.conn, id, "private_key", &blob).expect("put");
    schema::put_setting(&s.conn, KEY_SK_SCAN_PENDING, "1").expect("flag");
    id
}

#[test]
fn migration_ten_accepts_the_kind() {
    let s = Store::open_in_memory().expect("store");
    assert!(s.schema_version().expect("v") >= 10);
    assert_eq!(schema::get_setting(&s.conn, KEY_SK_SCAN_PENDING).expect("get"), None, "empty db");
    let v = vault();
    let pk = public_line(&sk_ed25519_public([7; 32], "ssh:"));
    let m = s
        .create_credential(
            &v,
            "yk",
            CredentialKind::SshSkKey,
            &json!({"username": "a", "public_key": pk}),
            &crate::Secrets::new(),
        )
        .expect("ssh_sk_key without a handle");
    assert_eq!(s.get_credential(m.id).expect("get").kind, CredentialKind::SshSkKey);
}

/// ADR-0027: migration 11 is the latest and its CHECK takes `smart_card` (no secret).
#[test]
fn migration_eleven_is_latest_and_accepts_smart_card() {
    let s = Store::open_in_memory().expect("store");
    assert_eq!(s.schema_version().expect("v"), 11);
    let m = s
        .create_credential(
            &vault(),
            "piv",
            CredentialKind::SmartCard,
            &json!({"username": "a", "pkcs11_module": "ykcs11"}),
            &crate::Secrets::new(),
        )
        .expect("smart_card");
    assert_eq!(s.get_credential(m.id).expect("get").kind, CredentialKind::SmartCard);
}

#[test]
fn sk_rows_convert_once_and_keep_their_sealed_values() {
    let s = Store::open_in_memory().expect("store");
    let v = vault();
    let key = sk_ed25519_public([7; 32], "ssh:");
    let handle = sk_key_handle_pem(&key, 0x21, b"handle");
    let sk = legacy_sk_row(&s, &v, &handle, false);
    let with_seed = legacy_sk_row(&s, &v, &handle, true);
    let plain_pem = placeholder_key_pem();
    let plain = s
        .create_credential(
            &v,
            "plain",
            CredentialKind::SshKey,
            &json!({"username": "u"}),
            &[(SecretName::PrivateKey, plain_pem.as_bytes())].into_iter().collect(),
        )
        .expect("plain")
        .id;
    assert_eq!(s.convert_sk_keys(&v).expect("convert"), vec![sk]);
    let m = s.get_credential(sk).expect("get");
    assert_eq!(m.kind, CredentialKind::SshSkKey);
    let CredentialFields::SshSkKey(f) = &m.fields else { panic!("kind") };
    assert_eq!(f.username, "root");
    assert_eq!(f.backend, SkBackend::Agent);
    assert!(f.resident, "flags 0x20");
    assert_eq!(f.public_key, public_line(&key));
    let fp = mooring_core::credential::sk_key::parse_sk_public_line(&f.public_key).expect("pk");
    assert_eq!(m.fingerprint(), Some(fp.fingerprint.as_str()));
    let opened = s.open_secret(&v, sk, SecretName::PrivateKey).expect("same AAD");
    assert_eq!(&opened[..], handle.as_bytes());
    assert!(s.open_secret(&v, sk, SecretName::Passphrase).is_ok());
    assert_eq!(s.get_credential(with_seed).expect("get").kind, CredentialKind::SshKey, "TOTP kept");
    assert_eq!(s.get_credential(plain).expect("get").kind, CredentialKind::SshKey);
    assert!(s.convert_sk_keys(&v).expect("again").is_empty(), "flag cleared");
}

#[test]
fn ssh_key_refuses_new_sk_material() {
    let s = Store::open_in_memory().expect("store");
    let v = vault();
    let handle = sk_key_handle_pem(&sk_ed25519_public([7; 32], "ssh:"), 0x01, b"h");
    let e = s
        .create_credential(
            &v,
            "yk",
            CredentialKind::SshKey,
            &json!({"username": "a"}),
            &[(SecretName::PrivateKey, handle.as_bytes())].into_iter().collect(),
        )
        .expect_err("refused");
    assert!(matches!(e, StoreError::Credential(CredentialError::UseSkKind)), "{e:?}");
}
