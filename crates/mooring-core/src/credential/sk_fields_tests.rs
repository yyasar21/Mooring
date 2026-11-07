//! `ssh_sk_key` field rules and the `ssh_key` refusal of `sk-*` material (ADR-0024 §1).

use serde_json::json;

use crate::credential::testdata::{public_line, sk_ed25519_public, sk_key_handle_pem};
use crate::credential::{validate_secret, CredentialError, CredentialFields, CredentialKind as K};
use crate::credential::{SecretName as S, SkBackend};

fn sk() -> ssh_key::PublicKey {
    sk_ed25519_public([7; 32], "ssh:")
}

fn input(kind: K, v: &serde_json::Value) -> Result<CredentialFields, CredentialError> {
    CredentialFields::from_input(kind, v, None)
}

fn sk_fields(v: &serde_json::Value) -> crate::credential::SshSkKeyFields {
    match input(K::SshSkKey, v).expect("valid") {
        CredentialFields::SshSkKey(f) => f,
        other => panic!("{other:?}"),
    }
}

#[test]
fn derived_values_and_defaults() {
    let f = sk_fields(&json!({"username": " root ", "public_key": public_line(&sk())}));
    assert_eq!(f.username, "root");
    assert_eq!(f.backend, SkBackend::Agent);
    assert!(!f.resident);
    assert_eq!(f.application.as_deref(), Some("ssh:"));
    let fp = sk().fingerprint(ssh_key::HashAlg::Sha256).to_string();
    assert_eq!(f.fingerprint.as_deref(), Some(fp.as_str()));
    let f = sk_fields(&json!({"username": "a", "public_key": public_line(&sk()),
                              "backend": "helper", "resident": "true"}));
    assert_eq!((f.backend, f.resident), (SkBackend::Helper, true));
    assert!(input(
        K::SshSkKey,
        &json!({"username": "a", "public_key": public_line(&sk()),
                                      "resident": "maybe"})
    )
    .is_err());
}

#[test]
fn derived_and_non_sk_input_refused() {
    let pk = public_line(&sk());
    for extra in [json!({"fingerprint": "SHA256:x"}), json!({"application": "ssh:"})] {
        let mut v = json!({"username": "a", "public_key": pk});
        v.as_object_mut().expect("obj").extend(extra.as_object().expect("obj").clone());
        assert!(input(K::SshSkKey, &v).is_err(), "{v}");
    }
    let plain = crate::credential::testdata::ED25519_PUB;
    assert!(input(K::SshSkKey, &json!({"username": "a", "public_key": plain})).is_err());
    assert!(input(K::SshSkKey, &json!({"username": "a"})).is_err(), "public key required");
    let other_cert = crate::credential::testdata::SSH_CA_CERT;
    let v = json!({"username": "a", "public_key": pk, "certificate": other_cert});
    assert!(input(K::SshSkKey, &v).is_err(), "certificate of another key");
}

#[test]
fn ssh_key_refuses_sk_material_with_the_convert_hint() {
    let pk = public_line(&sk());
    let e = input(K::SshKey, &json!({"username": "a", "public_key": pk})).expect_err("refused");
    assert_eq!(e, CredentialError::UseSkKind);
    let mut f = input(K::SshKey, &json!({"username": "a"})).expect("plain");
    let handle = sk_key_handle_pem(&sk(), 0x01, b"h");
    assert_eq!(
        f.derive_from_secret(S::PrivateKey, handle.as_bytes()),
        Err(CredentialError::UseSkKind)
    );
}

#[test]
fn key_handle_must_match_and_sets_resident() {
    let mut f = input(K::SshSkKey, &json!({"username": "a", "public_key": public_line(&sk())}))
        .expect("valid");
    let resident = sk_key_handle_pem(&sk(), 0x21, b"h");
    assert!(validate_secret(K::SshSkKey, S::PrivateKey, resident.as_bytes()).is_ok());
    f.derive_from_secret(S::PrivateKey, resident.as_bytes()).expect("same key");
    let CredentialFields::SshSkKey(sf) = &f else { panic!("kind") };
    assert!(sf.resident);
    let other = sk_key_handle_pem(&sk_ed25519_public([8; 32], "ssh:"), 0x01, b"h");
    assert!(f.derive_from_secret(S::PrivateKey, other.as_bytes()).is_err());
    assert!(f.derive_from_secret(S::PrivateKey, b"not a key").is_err());
    let again = CredentialFields::from_input(
        K::SshSkKey,
        &json!({"username": "b", "public_key": public_line(&sk())}),
        Some(&f),
    )
    .expect("update");
    let CredentialFields::SshSkKey(g) = again else { panic!("kind") };
    assert!(g.resident, "carried while the key is the same");
    assert!(validate_secret(K::SshSkKey, S::OtpSeed, b"JBSWY3DPEHPK3PXP").is_err(), "no otp slot");
}
