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
    // L-43: the trust dialog, then the sign-in confirmation (trust → confirm → bind).
    assert_eq!(confirm.asked().len(), 2);
    assert!(confirm.asked()[0].text.contains("127.0.0.1"));
    assert!(confirm.asked()[0].title.contains("certificate"));
    assert!(confirm.asked()[1].title.contains("sign-in"), "{}", confirm.asked()[1].title);
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

    // The pin and the confirmed pair are used next time: no prompt, same result.
    let again = preview(st, None, input(&srv, &cred)).await.expect("pinned");
    assert_eq!(again.counts.connections, 3);
    assert_eq!(confirm.asked().len(), 2);
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
    assert_eq!(st.ldap_binds.len(), 1, "the pair is remembered");

    crate::commands::vault::lock(st, None).expect("lock");
    assert!(st.ldap_binds.is_empty(), "L-43: confirmed pairs do not survive a lock");
    assert_eq!(test(st, None, input(&srv, &cred)).await.expect_err("locked").code, "vault.locked");
    assert_eq!(preview(st, None, input(&srv, &cred)).await.expect_err("locked").code, "vault.locked");
    assert_eq!(srv.recorder().ops().len(), 2, "no traffic while locked");
}

/// F1 (Q1 observation b): a run that dies on a hostile frame after the server accepted the
/// bind writes `ldap_bind { success: true }` and then the refusal, so the chain reads
/// bind → refused; a refused bind is `success: false` and nothing else.
#[tokio::test]
async fn bind_rows_bracket_a_run_that_dies_after_the_bind() {
    let f = testing::unlocked();
    let st = &f.state;
    let srv = mock(LdapKnobs { hostile: Some(ldap::Hostile::Garbage), ..LdapKnobs::default() }).await;
    let cred = domain_user(st);
    let confirm = FixedConfirm::new(true);
    let err = preview(st, Some(Prompt::new(&confirm)), input(&srv, &cred)).await.expect_err("hostile");
    assert_eq!(err.code, "ldap.response");
    let events = testing::audit_events(st);
    let tail: Vec<&str> = events.iter().rev().take(2).rev().map(String::as_str).collect();
    assert_eq!(tail, ["ldap_bind", "import_refused"], "{events:?}");
    let text = std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).expect("audit");
    assert!(text.contains("\"success\":true"));
    assert!(!text.contains("\"success\":false"));

    let wrong_pw = credentials::create(st, NewCredential::user_password("bad", "svc-mooring@corp.example.test", "nope")).expect("c");
    let err = test(st, Some(Prompt::new(&confirm)), LdapInput { credential_id: wrong_pw.id, ..input(&srv, &cred) })
        .await
        .expect_err("bind");
    assert_eq!(err.code, "ldap.bind");
    let events = testing::audit_events(st);
    assert_eq!(events.last().map(String::as_str), Some("ldap_bind"));
    assert_eq!(events.iter().filter(|e| *e == "ldap_bind").count(), 2);
    let text = std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).expect("audit");
    assert!(text.contains("\"success\":false"));
    assert!(!text.contains("nope") && !text.contains("DC=corp"));
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

/// A mock whose leaf is signed by a test CA, with that CA as `caPem`: the chain validates,
/// so the TOFU dialog never appears — the L-43 attacker's setup.
async fn ca_valid_mock() -> (LdapServer, String) {
    let (cert, ca) = mooring_testsrv::tls::TestCert::generate_ca_issued(&["localhost", "127.0.0.1"]).expect("cert");
    let srv = ldap::start(LdapConfig { cert: Some(cert), ..LdapConfig::default() }, 0).await.expect("mock");
    (srv, ca)
}

/// Review 7 L-43: a T5-style `ldap_import_test` against a CA-valid host (`caPem`) raises the
/// sign-in dialog before any bind frame; declined → `ldap.bind_declined`, `confirm_refused`
/// audited, the password never leaves, and the Gate's cool-down blocks a re-ask.
#[tokio::test]
async fn first_bind_of_a_pair_asks_and_a_refusal_never_binds() {
    let f = testing::unlocked();
    let st = &f.state;
    let (srv, ca) = ca_valid_mock().await;
    let cred = domain_user(st);
    let with_ca = || LdapInput { ca_pem: Some(ca.clone()), ..input(&srv, &cred) };
    let no = FixedConfirm::new(false);
    let err = test(st, Some(Prompt::new(&no)), with_ca()).await.expect_err("declined");
    assert_eq!(err.code, "ldap.bind_declined");
    assert_eq!(no.asked().len(), 1, "no TOFU dialog for a CA-valid chain; the sign-in one only");
    let ask = &no.asked()[0];
    assert_eq!(ask.title, "Mooring \u{b7} Directory sign-in");
    assert_eq!(ask.ok, format!("Sign in to 127.0.0.1:{}", srv.addr().port()));
    assert!(ask.text.contains("Directory bind") && ask.text.contains("127.0.0.1"), "{}", ask.text);
    assert!(!ask.text.contains(BIND_PW) && !ask.text.contains("svc-mooring"), "names only: {}", ask.text);
    assert!(ask.warning);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(srv.recorder().requests().is_empty(), "no LDAP frame without the confirmation");
    assert!(st.ldap_binds.is_empty());
    // The same pair inside the cool-down is refused without a dialog (M-16); the preview is
    // an import, so its refusal is audited by code.
    let err = preview(st, Some(Prompt::new(&no)), with_ca()).await.expect_err("cool-down");
    assert_eq!(err.code, "confirm.cooldown");
    assert_eq!(no.asked().len(), 1);
    // No prompt object at all: refused before any frame.
    st.confirm.clear_cooldowns();
    let err = preview(st, None, with_ca()).await.expect_err("no prompt");
    assert_eq!(err.code, "ldap.confirm_required");
    assert!(srv.recorder().requests().is_empty());
    let text = std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).expect("audit");
    assert!(text.contains(r#""event":"confirm_refused","kind":"ldap_bind""#), "{text}");
    assert!(text.contains(r#""reason":"declined""#));
    assert!(text.contains(r#""event":"import_refused","code":"ldap.confirm_required""#));
    assert!(!text.contains("ldap_bind\"") || !text.contains(r#""event":"ldap_bind""#), "no bind row");
    assert!(!text.contains(BIND_PW) && !text.contains("svc-mooring"));
    assert!(!testing::audit_events(st).contains(&"cert_decision".to_owned()), "CA-valid: no TOFU row");
}

/// Review 7 L-43: a confirmed (credential, host:port) pair is remembered for the session —
/// the second call needs no prompt — while another credential or another port asks again;
/// a vault lock forgets every pair.
#[tokio::test]
async fn confirmed_pair_is_remembered_until_lock_and_scoped_to_credential_and_host() {
    let f = testing::unlocked();
    let st = &f.state;
    let (srv, ca) = ca_valid_mock().await;
    let cred = domain_user(st);
    let with_ca = |c: &str| LdapInput { ca_pem: Some(ca.clone()), ..input(&srv, c) };
    let yes = FixedConfirm::new(true);
    let r = test(st, Some(Prompt::new(&yes)), with_ca(&cred)).await.expect("confirmed");
    assert_eq!(r.bound_as, "svc-mooring@corp.example.test");
    assert_eq!(yes.asked().len(), 1);
    assert_eq!(srv.recorder().ops(), ["bind", "unbind"]);
    assert!(st.ldap_binds.contains(&cred, &format!("127.0.0.1:{}", srv.addr().port())));
    // Remembered: the preview runs with no prompt object at all.
    let p = preview(st, None, with_ca(&cred)).await.expect("remembered");
    assert_eq!(p.counts.connections, 3);
    assert_eq!(yes.asked().len(), 1);
    // Another credential to the same host is a new pair.
    let other = credentials::create(st, NewCredential::user_password("other", "svc-mooring@corp.example.test", BIND_PW)).expect("c");
    assert_eq!(preview(st, None, with_ca(&other.id)).await.expect_err("new pair").code, "ldap.confirm_required");
    test(st, Some(Prompt::new(&yes)), with_ca(&other.id)).await.expect("other confirmed");
    assert_eq!(yes.asked().len(), 2);
    assert_eq!(st.ldap_binds.len(), 2);
    // The same credential to another host:port is a new pair too: the key is `host:port`
    // (the trust probe runs first, so a dead port fails there; nothing is asked or remembered).
    let elsewhere = LdapInput { url: "ldaps://127.0.0.1:1".into(), ..with_ca(&cred) };
    assert_eq!(test(st, Some(Prompt::new(&yes)), elsewhere).await.expect_err("other port").code, "ldap.unavailable");
    assert_eq!(yes.asked().len(), 2);
    assert!(!st.ldap_binds.contains(&cred, "127.0.0.1:1"));
    // A lock forgets every pair; after the unlock the first bind asks again.
    crate::commands::vault::lock(st, None).expect("lock");
    assert!(st.ldap_binds.is_empty());
    crate::commands::vault::unlock(st, secrecy::SecretString::from(testing::MASTER.to_owned())).expect("unlock");
    assert_eq!(preview(st, None, with_ca(&cred)).await.expect_err("forgotten").code, "ldap.confirm_required");
    test(st, Some(Prompt::new(&yes)), with_ca(&cred)).await.expect("asked again");
    assert_eq!(yes.asked().len(), 3);
    srv.recorder().assert_no_violations();
    let text = std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).expect("audit");
    assert!(!text.contains("confirm_refused"));
}

/// Review 7 N-54: an empty stored password never leaves the client (RFC 4513 §5.1.2
/// unauthenticated bind); refused as `ldap.bind` before connecting. The store refuses to seal
/// an empty secret (`validate_secret`), so the command-level check is exercised on its own
/// and the store rule is pinned alongside.
#[test]
fn empty_bind_password_is_refused_before_any_network() {
    assert_eq!(bind_credential("svc".into(), b"").expect_err("empty").code, "ldap.bind");
    assert_eq!(bind_credential("svc".into(), &[0xff, 0xfe]).expect_err("binary").code, "credential.secret_missing");
    let ok = bind_credential("svc".into(), b"pw").expect("ok");
    assert_eq!((ok.name.as_str(), ok.password.as_str()), ("svc", "pw"));
    let f = testing::unlocked();
    let st = &f.state;
    let cred = domain_user(st);
    let id = crate::dto::credential_id("credentialId", &cred).expect("id");
    let err = st
        .with_ready(|vault, store| {
            let mut set = mooring_store::Secrets::new();
            set.insert(SecretName::Password, b"".as_slice());
            store.replace_secrets(vault, id, &set, &[])?;
            Ok(())
        })
        .expect_err("the store never seals an empty password");
    assert_eq!(err.code, "input.invalid");
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
