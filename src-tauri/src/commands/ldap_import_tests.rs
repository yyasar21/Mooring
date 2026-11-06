use mooring_core::known_certs::{CertProtocol, KnownCerts};
use mooring_testsrv::ldap::{self, LdapConfig, LdapKnobs, LdapServer};

use super::*;
use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::import::{self, ApplyInput};
use crate::commands::vsphere_confirm::FixedConfirm;
use crate::state::testing;

const BIND_PW: &str = "test-bind-pw";

async fn mock(knobs: LdapKnobs) -> LdapServer {
    ldap::start(LdapConfig { knobs, ..LdapConfig::default() }, 0).await.expect("mock")
}

fn domain_user(state: &AppState) -> String {
    let c = NewCredential {
        name: "Directory bind".into(),
        kind: "domain_user".into(),
        fields: serde_json::json!({ "user": "svc-mooring", "domain": "corp.example.test", "form": "upn" }),
        secrets: WireSecrets::of(&[("password", BIND_PW)]),
    };
    credentials::create(state, c).expect("credential").id
}

fn input(srv: &LdapServer, credential_id: &str) -> LdapInput {
    LdapInput {
        url: srv.url(),
        base_dn: "DC=corp,DC=example,DC=test".into(),
        scope: SearchScope::Sub,
        kind: DirectoryKind::Ad,
        filter: None,
        credential_id: credential_id.to_owned(),
        ca_pem: None,
        size_limit: None,
    }
}

fn pins(state: &AppState) -> KnownCerts {
    KnownCerts::load(&state.data_dir.join(CertProtocol::Ldap.file_name())).expect("store")
}

#[tokio::test]
async fn preview_prompts_once_pins_and_applies_like_a_file_import() {
    let f = testing::unlocked();
    let st = &f.state;
    let srv = mock(LdapKnobs::default()).await;
    let cred = domain_user(st);
    let confirm = FixedConfirm::new(true);
    let p = preview(st, Some(Prompt::new(&confirm)), input(&srv, &cred)).await.expect("preview");
    assert_eq!(confirm.asked().len(), 1);
    assert!(confirm.asked()[0].text.contains("127.0.0.1"));
    assert!(pins(st).has_pin("127.0.0.1", srv.addr().port()));
    assert_eq!(p.format, ImportFormat::Ldap);
    assert!(p.root_name.starts_with("Imported from LDAP directory ("));
    assert_eq!((p.counts.folders, p.counts.connections, p.counts.credentials, p.counts.secrets, p.counts.skipped), (3, 3, 1, 0, 1));
    let web = p.items.iter().find(|i| i.name == "WEB01").expect("WEB01");
    assert_eq!((web.protocol, web.host.as_deref()), (Some(mooring_core::Protocol::Rdp), Some("web01.corp.example.test")));
    assert_eq!(p.credentials[0].kind, mooring_core::CredentialKind::Prompt);
    assert!(!p.credentials[0].has_secret);
    srv.recorder().assert_no_violations();
    assert_eq!(srv.recorder().ops(), ["bind", "search", "unbind"]);

    let report = import::apply(st, ApplyInput { plan_id: p.plan_id, exclude: vec![], duplicates: None }).expect("apply");
    assert_eq!((report.folders, report.connections, report.credentials, report.secrets), (3, 3, 1, 0));

    // The pin is used next time: no prompt, same result.
    let again = preview(st, None, input(&srv, &cred)).await.expect("pinned");
    assert_eq!(again.counts.connections, 3);
    assert_eq!(confirm.asked().len(), 1);
    assert_eq!(again.items.iter().filter(|i| i.duplicate_of.is_some()).count(), 3, "already imported");

    let events = testing::audit_events(st);
    for e in ["cert_decision", "ldap_bind", "import_previewed", "import_applied"] {
        assert!(events.contains(&e.to_owned()), "{e}");
    }
    let text = std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).expect("audit");
    assert!(text.contains("\"format\":\"ldap\""));
    assert!(text.contains("\"success\":true"));
    for secret in [BIND_PW, "svc-mooring", "web01", "DC=corp", "dc=corp"] {
        assert!(!text.contains(secret), "{secret} must not be audited");
    }
}

#[tokio::test]
async fn refused_prompt_and_missing_prompt_never_bind() {
    let f = testing::unlocked();
    let st = &f.state;
    let srv = mock(LdapKnobs::default()).await;
    let cred = domain_user(st);
    let confirm = FixedConfirm::new(false);
    let err = preview(st, Some(Prompt::new(&confirm)), input(&srv, &cred)).await.expect_err("rejected");
    assert_eq!(err.code, "http.trust_rejected");
    let err = preview(st, None, input(&srv, &cred)).await.expect_err("no prompt");
    assert_eq!(err.code, "http.trust_prompt");
    assert!(srv.recorder().requests().is_empty(), "nothing reaches the server without trust");
    assert!(!pins(st).has_pin("127.0.0.1", srv.addr().port()));
    let events = testing::audit_events(st);
    assert_eq!(events.iter().filter(|e| *e == "import_refused").count(), 2);
    assert!(!events.contains(&"ldap_bind".to_owned()));
}

#[tokio::test]
async fn bad_inputs_and_bad_credentials() {
    let f = testing::unlocked();
    let st = &f.state;
    let srv = mock(LdapKnobs::default()).await;
    let cred = domain_user(st);
    let confirm = FixedConfirm::new(true);
    let prompt = Some(Prompt::new(&confirm));
    let plain = LdapInput { url: srv.url().replace("ldaps://", "ldap://"), ..input(&srv, &cred) };
    assert_eq!(preview(st, prompt, plain).await.expect_err("plain").code, "ldap.insecure");
    let bad_dn = LdapInput { base_dn: "nope".into(), ..input(&srv, &cred) };
    assert_eq!(preview(st, prompt, bad_dn).await.expect_err("dn").code, "ldap.dn_invalid");
    let big_pem = LdapInput { ca_pem: Some("x".repeat(MAX_CA_PEM + 1)), ..input(&srv, &cred) };
    assert_eq!(preview(st, prompt, big_pem).await.expect_err("pem").code, "input.invalid");
    let zero = LdapInput { size_limit: Some(0), ..input(&srv, &cred) };
    assert_eq!(preview(st, prompt, zero).await.expect_err("zero").code, "ldap.invalid");
    assert!(srv.recorder().requests().is_empty());
    let events = testing::audit_events(st);
    assert_eq!(events.iter().filter(|e| *e == "import_refused").count(), 4);

    let bad_id = LdapInput { credential_id: "nope".into(), ..input(&srv, &cred) };
    assert_eq!(preview(st, prompt, bad_id).await.expect_err("id").code, "input.invalid");
    let ssh = credentials::create(
        st,
        NewCredential { name: "agent".into(), kind: "ssh_agent".into(), fields: serde_json::json!({ "username": "u" }), secrets: WireSecrets::of(&[]) },
    )
    .expect("ssh_agent");
    let wrong_kind = LdapInput { credential_id: ssh.id, ..input(&srv, &cred) };
    assert_eq!(preview(st, prompt, wrong_kind).await.expect_err("kind").code, "credential.incompatible");

    let wrong_pw = credentials::create(st, NewCredential::user_password("bad", "svc-mooring@corp.example.test", "nope")).expect("c");
    let err = preview(st, prompt, LdapInput { credential_id: wrong_pw.id, ..input(&srv, &cred) }).await.expect_err("bind");
    assert_eq!(err.code, "ldap.bind");
    assert_eq!(srv.recorder().ops(), ["bind", "unbind"]);
    let text = std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).expect("audit");
    assert!(text.contains("\"success\":false"));
    assert!(!text.contains("nope"));

    // user_password with a plain username binds with it verbatim.
    let up = credentials::create(st, NewCredential::user_password("ok", "svc-mooring@corp.example.test", BIND_PW)).expect("c");
    let r = test(st, prompt, LdapInput { credential_id: up.id, ..input(&srv, &cred) }).await.expect("test bind");
    assert_eq!((r.host.as_str(), r.port, r.bound_as.as_str()), ("127.0.0.1", srv.addr().port(), "svc-mooring@corp.example.test"));
    srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn test_binds_and_unbinds_only_and_locked_vault_refuses() {
    let f = testing::unlocked();
    let st = &f.state;
    let srv = mock(LdapKnobs::default()).await;
    let cred = domain_user(st);
    let confirm = FixedConfirm::new(true);
    let r = test(st, Some(Prompt::new(&confirm)), input(&srv, &cred)).await.expect("test");
    assert_eq!(r.bound_as, "svc-mooring@corp.example.test");
    assert_eq!(srv.recorder().ops(), ["bind", "unbind"]);
    let events = testing::audit_events(st);
    assert!(events.contains(&"ldap_bind".to_owned()) && !events.contains(&"import_previewed".to_owned()));

    crate::commands::vault::lock(st, None).expect("lock");
    assert_eq!(test(st, None, input(&srv, &cred)).await.expect_err("locked").code, "vault.locked");
    assert_eq!(preview(st, None, input(&srv, &cred)).await.expect_err("locked").code, "vault.locked");
    assert_eq!(srv.recorder().ops().len(), 2, "no traffic while locked");
}

#[tokio::test]
async fn server_limits_surface_as_ldap_codes() {
    let f = testing::unlocked();
    let st = &f.state;
    let srv = mock(LdapKnobs { size_limit_after: Some(1), ..LdapKnobs::default() }).await;
    let cred = domain_user(st);
    let confirm = FixedConfirm::new(true);
    let err = preview(st, Some(Prompt::new(&confirm)), input(&srv, &cred)).await.expect_err("limit");
    assert_eq!(err.code, "ldap.size_limit");
    assert!(st.import_plans.is_empty());
    let events = testing::audit_events(st);
    assert!(events.contains(&"import_refused".to_owned()));
}

#[test]
fn ldap_codes_match_the_crate() {
    let errors = [
        LdapError::Insecure,
        LdapError::Invalid("x"),
        LdapError::DnInvalid("x"),
        LdapError::Bind(49),
        LdapError::SizeLimit,
        LdapError::Timeout,
        LdapError::Unavailable("x".into()),
        LdapError::Response("x"),
    ];
    let mut codes: Vec<&str> = errors.iter().map(LdapError::code).collect();
    codes.sort_unstable();
    let mut listed = LDAP_CODES.to_vec();
    listed.sort_unstable();
    assert_eq!(codes, listed);
    assert_eq!(LdapError::Tls(HttpError::TrustStore).code(), "http.trust_store");
}
