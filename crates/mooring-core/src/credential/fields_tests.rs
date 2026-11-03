use proptest::prelude::*;
use serde_json::json;

use super::*;
use crate::credential::testdata::{CERT_FP, CERT_PEM, ED25519_FP, ED25519_PUB, KUBECONFIG};
use CredentialKind as K;

#[allow(clippy::needless_pass_by_value)] // call sites build the json inline
fn input(kind: K, v: Value) -> Result<CredentialFields, CredentialError> {
    CredentialFields::from_input(kind, &v, None)
}

/// One valid input per kind.
fn samples() -> Vec<(K, Value)> {
    vec![
        (
            K::UserPassword,
            json!({"username": " ops ", "domain": "", "otp": {"digits": 6, "period": 30, "algorithm": "sha1"}}),
        ),
        (K::DomainUser, json!({"user": "alice", "domain": "CORP", "form": "netbios"})),
        (K::SshKey, json!({"username": "root", "public_key": ED25519_PUB})),
        (K::SshAgent, json!({"username": "root", "key_fingerprint": ED25519_FP})),
        (K::X509, json!({"cert_pem": CERT_PEM})),
        (K::ApiToken, json!({"header_name": "X-Api-Key", "scheme": ""})),
        (
            K::OauthClient,
            json!({"token_url": "https://login.example.test/token", "client_id": "app"}),
        ),
        (K::Kubeconfig, json!({})),
        (K::KubeToken, json!({"subject": "system:serviceaccount:ns:bot"})),
        (K::VsphereUser, json!({"upn": "administrator@vsphere.local"})),
        (K::VncPassword, json!({})),
        (K::VncUserPassword, json!({"username": "viewer"})),
        (K::Prompt, json!({"username": "alice"})),
        (
            K::ExternalRef,
            json!({"provider": "onepassword", "reference": "op://vault/item/password", "target_kind": "user_password"}),
        ),
        (K::SudoBecome, json!({"method": "sudo", "become_user": ""})),
    ]
}

#[test]
fn every_kind_round_trips_through_storage() {
    for (kind, v) in samples() {
        let f = input(kind, v).unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        assert_eq!(f.kind(), kind);
        let json = f.to_json().expect("json");
        assert_eq!(CredentialFields::from_stored(kind, &json).expect("stored"), f, "{kind:?}");
    }
}

#[test]
fn normalisation_and_derived_values() {
    let CredentialFields::UserPassword(u) =
        input(K::UserPassword, samples()[0].1.clone()).expect("ok")
    else {
        panic!("kind")
    };
    assert_eq!((u.username.as_str(), u.domain.as_deref()), ("ops", None));
    let f = input(K::SshKey, samples()[2].1.clone()).expect("ok");
    assert_eq!(f.fingerprint(), Some(ED25519_FP));
    let f = input(K::X509, samples()[4].1.clone()).expect("ok");
    assert_eq!(f.fingerprint(), Some(CERT_FP));
    let CredentialFields::SudoBecome(b) =
        input(K::SudoBecome, json!({"method": "su"})).expect("ok")
    else {
        panic!("kind")
    };
    assert_eq!(b.become_user, "root");
}

#[test]
fn unknown_and_derived_fields_are_refused() {
    assert!(input(K::UserPassword, json!({"username": "a", "colour": "red"})).is_err());
    assert!(input(K::SshKey, json!({"username": "a", "fingerprint": ED25519_FP})).is_err());
    assert!(input(K::Kubeconfig, json!({"contexts": ["x"]})).is_err());
    assert!(input(K::VncPassword, json!({"password": "x"})).is_err(), "secrets are not fields");
    assert!(input(K::ApiToken, json!({"otp": {"digits": 6, "period": 30, "algorithm": "sha1"}}))
        .is_err());
    assert!(input(K::UserPassword, json!([1, 2])).is_err());
    assert!(input(K::UserPassword, json!({})).is_err(), "username required");
}

#[test]
fn per_kind_rules() {
    assert!(input(
        K::DomainUser,
        json!({"user": "a", "domain": "ABCDEFGHIJKLMNOP", "form": "netbios"})
    )
    .is_err());
    assert!(
        input(K::DomainUser, json!({"user": "a", "domain": "corp.example", "form": "upn"})).is_ok()
    );
    assert!(input(K::VsphereUser, json!({"upn": "CORP\\administrator"})).is_err(), "UPN form only");
    assert!(input(K::OauthClient, json!({"token_url": "http://x.example.test", "client_id": "a"}))
        .is_err());
    assert!(input(K::ApiToken, json!({"header_name": "Bad Header"})).is_err());
    assert!(input(K::SshAgent, json!({"username": "a", "key_fingerprint": "MD5:aa"})).is_err());
    assert!(input(K::SshKey, json!({"username": "a", "public_key": "garbage"})).is_err());
    assert!(input(K::X509, json!({"cert_pem": "not pem"})).is_err());
    assert!(input(
        K::ExternalRef,
        json!({"provider": "vault", "reference": "kv/x", "target_kind": "prompt"})
    )
    .is_err());
    assert!(input(K::SudoBecome, json!({"method": "pkexec"})).is_err());
    let at = input(K::UserPassword, json!({"username": "CORP\\alice"})).expect("verbatim");
    assert_eq!(at.account().0.as_deref(), Some("CORP\\alice"));
}

#[test]
fn caps_max_and_max_plus_one() {
    let ok = |n| input(K::UserPassword, json!({"username": "u".repeat(n)}));
    assert!(ok(256).is_ok());
    assert!(ok(257).is_err());
    let dom = |n| input(K::UserPassword, json!({"username": "u", "domain": "d".repeat(n)}));
    assert!(dom(253).is_ok());
    assert!(dom(254).is_err());
    let hdr = |n| input(K::ApiToken, json!({"header_name": "h".repeat(n)}));
    assert!(hdr(64).is_ok());
    assert!(hdr(65).is_err());
    let url = |n: usize| {
        input(
            K::OauthClient,
            json!({"token_url": format!("https://{}", "a".repeat(n - 8)), "client_id": "c"}),
        )
    };
    assert!(url(2048).is_ok());
    assert!(url(2049).is_err());
    let r = |n| {
        input(
            K::ExternalRef,
            json!({"provider": "vault", "reference": "r".repeat(n), "target_kind": "api_token"}),
        )
    };
    assert!(r(1024).is_ok());
    assert!(r(1025).is_err());
}

#[test]
fn forbidden_characters_never_echo() {
    for bad in ["ad\u{200b}min", "root\u{202e}", "a\nb", "\u{feff}x"] {
        let e = input(K::UserPassword, json!({"username": bad})).expect_err(bad);
        assert!(!e.to_string().contains(bad));
    }
}

#[test]
fn derive_from_secret_updates_contexts_and_fingerprints() {
    let mut k = input(K::Kubeconfig, json!({"context": "lab-admin"})).expect("ok");
    k.derive_from_secret(SecretName::KubeconfigYaml, KUBECONFIG.as_bytes()).expect("ok");
    let CredentialFields::Kubeconfig(kf) = &k else { panic!("kind") };
    assert_eq!(kf.contexts, ["lab", "lab-admin"]);
    assert_eq!(kf.context.as_deref(), Some("lab-admin"));
    let rejected = KUBECONFIG.replace("token: test-only-token", "exec: {command: sh}");
    assert!(matches!(
        k.derive_from_secret(SecretName::KubeconfigYaml, rejected.as_bytes()),
        Err(CredentialError::KubeconfigRejected(_))
    ));
    // an update keeps derived values that need the secret
    let upd = CredentialFields::from_input(K::Kubeconfig, &json!({"context": "lab"}), Some(&k))
        .expect("upd");
    let CredentialFields::Kubeconfig(u) = &upd else { panic!("kind") };
    assert_eq!(u.contexts.len(), 2);
    assert!(
        CredentialFields::from_input(K::Kubeconfig, &json!({"context": "nope"}), Some(&k)).is_err()
    );

    let mut s = input(K::SshKey, json!({"username": "a"})).expect("ok");
    let pem = crate::credential::testdata::placeholder_key_pem();
    s.derive_from_secret(SecretName::PrivateKey, pem.as_bytes()).expect("legacy pem");
    assert_eq!(s.fingerprint(), None);
}

#[test]
fn overrides_apply_only_where_the_kind_has_them() {
    let mut f = input(K::UserPassword, json!({"username": "shared"})).expect("ok");
    f.apply_overrides(Some(" admin "), Some("CORP")).expect("ok");
    assert_eq!(f.account(), (Some("admin".into()), Some("CORP".into())));
    let mut t = input(K::KubeToken, json!({})).expect("ok");
    assert!(t.apply_overrides(Some("x"), None).is_err());
    let mut k = input(K::SshKey, json!({"username": "a"})).expect("ok");
    assert!(k.apply_overrides(None, Some("CORP")).is_err());
    for kind in K::ALL {
        let has_user = CredentialFields::supports_override(kind, false);
        let has_dom = CredentialFields::supports_override(kind, true);
        assert!(!has_dom || has_user, "{kind:?}: domain override implies username override");
    }
}

#[test]
fn otp_slot() {
    let mut f = input(K::VsphereUser, json!({"upn": "a@vsphere.local"})).expect("ok");
    f.set_otp(Some(OtpParams::default())).expect("slot");
    assert_eq!(f.otp(), Some(OtpParams::default()));
    let mut g = input(K::VncPassword, json!({})).expect("ok");
    assert!(g.set_otp(Some(OtpParams::default())).is_err());
    g.set_otp(None).expect("clearing is a no-op");
}

#[test]
fn corrupt_rows_are_refused() {
    assert!(CredentialFields::from_stored(K::UserPassword, "not json").is_err());
    assert!(CredentialFields::from_stored(K::UserPassword, "{}").is_err());
    assert!(CredentialFields::from_stored(K::UserPassword, r#"{"username":"a\u0007"}"#).is_err());
    assert!(
        CredentialFields::from_stored(K::SshKey, r#"{"username":"a","fingerprint":"x"}"#).is_err()
    );
    let big = format!(r#"{{"username":"{}"}}"#, "a".repeat(MAX_FIELDS_JSON));
    assert!(CredentialFields::from_stored(K::UserPassword, &big).is_err());
}

proptest! {
    #[test]
    fn field_parsing_never_panics(kind in 0usize..15, key in "[a-z_]{1,12}", val in "\\PC{0,80}") {
        let kind = K::ALL[kind];
        let _ = CredentialFields::from_input(kind, &json!({ key.clone(): val.clone() }), None);
        let _ = CredentialFields::from_stored(kind, &val);
    }

    #[test]
    fn account_parsing_never_panics(s in "\\PC{0,300}") {
        let _ = crate::credential::parse_account(&s);
    }
}
