use serde_json::json;

use super::*;
use crate::credential::testdata::CERT_PEM;

fn input(v: serde_json::Value) -> Result<ValidSource> {
    serde_json::from_value::<SecretSourceInput>(v).expect("shape").validate()
}

fn token_src(address: &str) -> serde_json::Value {
    json!({"name": "Vault", "address": address, "authMethod": "token",
           "credentialId": CredentialId::new()})
}

#[test]
fn addresses() {
    for (a, want) in [
        ("https://vault.example.test", "https://vault.example.test"),
        ("https://VAULT.example.test:8200/", "https://vault.example.test:8200"),
        ("https://vault.example.test/prefix/v1x", "https://vault.example.test/prefix/v1x"),
        ("https://192.0.2.10:8200", "https://192.0.2.10:8200"),
        ("https://[2001:db8::1]:8200", "https://[2001:db8::1]:8200"),
    ] {
        assert_eq!(validate_address(a, false).expect(a), want);
    }
    for bad in [
        "",
        "vault.example.test",
        "http://vault.example.test",
        "http://127.0.0.1:8200",
        "ftp://vault.example.test",
        "https://user:pw@vault.example.test",
        "https://vault.example.test?x=1",
        "https://vault.example.test#f",
        "https://vault.example.test:0",
        "https://vault.example.test:99999",
        "https://vault.example.test:80a",
        "https://vault .example.test",
        "https://-bad.example.test",
        "https://vault.example.test/a//b",
        "https://vault.example.test/%2e%2e",
        "https://vault.example.test/..",
        "https://[zz::1]",
        "https://vault.example.test\u{202e}",
    ] {
        assert!(validate_address(bad, false).is_err(), "{bad:?}");
    }
    let long = format!("https://vault.example.test/{}", "a".repeat(MAX_ADDRESS));
    assert!(validate_address(&long, false).is_err());
    assert_eq!(
        validate_address("http://127.0.0.1:8200", true).expect("loop"),
        "http://127.0.0.1:8200"
    );
    assert!(validate_address("http://[::1]:8200", true).is_ok());
    assert!(validate_address("http://localhost:8200", true).is_err(), "names are not literals");
    assert!(validate_address("http://192.0.2.1:8200", true).is_err());
}

#[test]
fn methods_and_credentials() {
    let v = input(token_src("https://vault.example.test")).expect("token");
    assert_eq!(v.auth.method(), SourceAuthMethod::Token);
    assert_eq!(v.auth.mount(), "token");
    let cred = CredentialId::new();
    let a = input(
        json!({"name": "A", "address": "https://vault.example.test", "authMethod": "approle",
                         "authMount": "/approle-ci/", "credentialId": cred, "namespace": "team/a"}),
    )
    .expect("approle");
    assert_eq!(
        a.auth,
        SecretSourceAuth::AppRole { mount: "approle-ci".into(), credential_id: cred }
    );
    assert_eq!(a.namespace.as_deref(), Some("team/a"));
    let o = input(json!({"name": "O", "address": "https://vault.example.test", "authMethod": "oidc",
                         "oidcRole": "mooring", "options": {"allowedOrigins": ["https://idp.example.test/", "https://idp.example.test"]}}))
    .expect("oidc");
    assert_eq!(o.auth, SecretSourceAuth::Oidc { mount: "oidc".into(), role: "mooring".into() });
    assert_eq!(o.options.allowed_origins, ["https://idp.example.test"], "deduplicated");
    assert_eq!(o.auth.credential_id(), None);

    for bad in [
        json!({"name": "x", "address": "https://v.example.test", "authMethod": "token"}),
        json!({"name": "x", "address": "https://v.example.test", "authMethod": "oidc"}),
        json!({"name": "x", "address": "https://v.example.test", "authMethod": "oidc", "oidcRole": "r",
               "credentialId": cred}),
        json!({"name": "x", "address": "https://v.example.test", "authMethod": "approle",
               "credentialId": cred, "oidcRole": "r"}),
        json!({"name": "x", "address": "https://v.example.test", "authMethod": "token",
               "credentialId": cred, "authMount": "other"}),
        json!({"name": "x", "address": "https://v.example.test", "authMethod": "approle",
               "credentialId": cred, "authMount": "a/../b"}),
        json!({"name": "x", "address": "https://v.example.test", "authMethod": "token",
               "credentialId": cred, "namespace": "a b"}),
        json!({"name": "x", "address": "https://v.example.test", "authMethod": "token",
               "credentialId": cred, "options": {"allowedOrigins": ["https://idp.example.test"]}}),
        json!({"name": "", "address": "https://v.example.test", "authMethod": "token", "credentialId": cred}),
    ] {
        assert!(input(bad.clone()).is_err(), "{bad}");
    }
    assert!(serde_json::from_value::<SecretSourceInput>(json!({"name": "x", "address": "a",
        "authMethod": "kerberos"}))
    .is_err());
    assert!(
        serde_json::from_value::<SecretSourceInput>(json!({"name": "x", "address": "a",
        "authMethod": "token", "token": "s.x"}))
        .is_err(),
        "no secret field exists"
    );
}

#[test]
fn options() {
    let mut v = token_src("https://vault.example.test");
    v["options"] = json!({"caPem": CERT_PEM});
    assert_eq!(input(v.clone()).expect("ca").options.ca_pem.as_deref(), Some(CERT_PEM));
    v["options"] = json!({"caPem": "not pem"});
    assert!(input(v.clone()).is_err());
    v["options"] = json!({"caPem": "x".repeat(MAX_CA_PEM + 1)});
    assert!(input(v.clone()).is_err());
    v["options"] = json!({"unknown": true});
    assert!(serde_json::from_value::<SecretSourceInput>(v.clone()).is_err());
    let origins: Vec<String> = (0..17).map(|i| format!("https://idp{i}.example.test")).collect();
    let o = json!({"name": "O", "address": "https://vault.example.test", "authMethod": "oidc",
                   "oidcRole": "r", "options": {"allowedOrigins": origins}});
    assert!(input(o).is_err());
    for bad in [
        "http://idp.example.test",
        "https://idp.example.test/path",
        "https://u@idp.example.test",
        "*",
    ] {
        assert!(validate_origin(bad).is_err(), "{bad}");
    }
    assert_eq!(
        validate_origin("https://IdP.example.test:443").expect("ok"),
        "https://idp.example.test:443"
    );
}

#[test]
fn method_names() {
    for m in [SourceAuthMethod::Token, SourceAuthMethod::Approle, SourceAuthMethod::Oidc] {
        assert_eq!(SourceAuthMethod::parse(m.name()), Some(m));
        assert_eq!(serde_json::to_value(m).expect("json"), json!(m.name()));
    }
    assert_eq!(SourceAuthMethod::Approle.credential_kind(), Some(CredentialKind::VaultApprole));
    assert_eq!(SourceAuthMethod::Token.credential_kind(), Some(CredentialKind::ApiToken));
}
