//! A4 Q1 (ADR-0019 §4 test plan): the LDAP mock's hostile knobs through `ldap_import_preview`
//! / `ldap_import_test` at the app level, every run ending with the recorder's
//! `assert_no_violations` (only bind / search / abandon / unbind, no search before a bind, no
//! SASL, no oversized frame) and an audit log that names no bind account, DN, entry or
//! password. Plus the three TOFU outcomes of the Rust-native certificate prompt: trust (pin
//! stored), trust once (the pin store cannot be written) and refuse.

use std::time::{Duration, Instant};

use mooring_core::known_certs::{CertProtocol, KnownCerts, MAX_LINE};
use mooring_import::ldap::{DirectoryKind, SearchScope};
use mooring_testsrv::ldap::{self, Hostile, LdapConfig, LdapKnobs, LdapServer};

use crate::a4_support::{
    assert_audit_free_of, assert_refusals_carry_only_a_code, audit_rows, audit_text,
};
use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::import::{self, ApplyInput};
use crate::commands::ldap_import::{self, LdapInput};
use crate::commands::vsphere_confirm::{FixedConfirm, Prompt};
use crate::state::testing;
use crate::state::AppState;

const BIND_PW: &str = "test-bind-pw";
const BIND_USER: &str = "svc-mooring";

/// Nothing of these may be audited: the bind account, the password, the base DN in either
/// case, the entries and their hosts.
const MARKERS: &[&str] = &[
    BIND_PW,
    BIND_USER,
    "DC=corp",
    "dc=corp",
    "OU=Servers",
    "WEB01",
    "web01",
    "corp.example.test",
];

async fn mock(knobs: LdapKnobs) -> LdapServer {
    ldap::start(LdapConfig { knobs, ..LdapConfig::default() }, 0).await.expect("mock")
}

fn domain_user(st: &AppState) -> String {
    let c = NewCredential {
        name: "Directory bind".into(),
        kind: "domain_user".into(),
        fields: serde_json::json!({ "user": BIND_USER, "domain": "corp.example.test", "form": "upn" }),
        secrets: WireSecrets::of(&[("password", BIND_PW)]),
    };
    credentials::create(st, c).expect("credential").id
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

fn pins(st: &AppState) -> KnownCerts {
    KnownCerts::load(&st.data_dir.join(CertProtocol::Ldap.file_name())).expect("store")
}

#[tokio::test]
async fn hostile_server_frames_fail_fast_with_ldap_response_and_no_violation() {
    let f = testing::unlocked();
    let st = &f.state;
    let cred = domain_user(st);
    let confirm = FixedConfirm::new(true);
    let cases = [
        Hostile::EmptyMessage,
        Hostile::Garbage,
        Hostile::DeepNesting(40),
        Hostile::DeepNesting(2_000),
        Hostile::DeepNesting(100_000),
        Hostile::HugeLength,
    ];
    for h in cases {
        let srv = mock(LdapKnobs { hostile: Some(h), ..LdapKnobs::default() }).await;
        let started = Instant::now();
        let err = ldap_import::preview(st, Some(Prompt::new(&confirm)), input(&srv, &cred))
            .await
            .expect_err("hostile");
        assert_eq!(err.code, "ldap.response", "{h:?}: {}", err.message);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{h:?} must fail fast, took {:?}",
            started.elapsed()
        );
        assert!(
            !err.message.contains("DC=") && !err.message.contains(BIND_USER),
            "{h:?}: {}",
            err.message
        );
        srv.recorder().assert_no_violations();
        assert_eq!(srv.recorder().searches().len(), 1, "{h:?}: one search, never retried");
        assert!(st.import_plans.is_empty(), "{h:?}: no plan from a hostile reply");
    }
    // A malformed entry (three elements) and an oversized attribute value are per-entry
    // problems: the run completes and the entry / value is dropped.
    let srv =
        mock(LdapKnobs { hostile: Some(Hostile::ExtraElement), ..LdapKnobs::default() }).await;
    let p = ldap_import::preview(st, Some(Prompt::new(&confirm)), input(&srv, &cred))
        .await
        .expect("malformed entry skipped");
    assert_eq!(p.counts.connections, 0);
    srv.recorder().assert_no_violations();
    import::discard(st, &p.plan_id).expect("discard");
    let srv =
        mock(LdapKnobs { hostile: Some(Hostile::OversizedValue(5_000)), ..LdapKnobs::default() })
            .await;
    let p = ldap_import::preview(st, Some(Prompt::new(&confirm)), input(&srv, &cred))
        .await
        .expect("oversized value dropped");
    assert_eq!(p.counts.connections, 1);
    assert!(
        serde_json::to_string(&p).expect("json").len() < 4_000,
        "the oversized value never reaches the DTO"
    );
    srv.recorder().assert_no_violations();

    // Audit: one refusal per hostile case, by code only; a bind row for every run, since the
    // server accepted each bind before the hostile frame (F1: bind → refused); no names.
    let refused = audit_rows(st, "import_refused");
    assert_eq!(refused.len(), cases.len(), "{refused:?}");
    assert!(refused.iter().all(|r| r["code"] == "ldap.response"));
    assert_refusals_carry_only_a_code(st, "import_refused");
    let binds = audit_rows(st, "ldap_bind");
    assert_eq!(binds.len(), cases.len() + 2, "{binds:?}");
    assert!(binds
        .iter()
        .all(|b| b["success"] == true
            && b["host"].as_str().is_some_and(|h| h.starts_with("127.0.0.1:"))));
    assert_audit_free_of(st, MARKERS);
}

#[tokio::test]
async fn server_limits_referrals_and_unpaged_answers_are_handled_read_only() {
    let f = testing::unlocked();
    let st = &f.state;
    let cred = domain_user(st);
    let confirm = FixedConfirm::new(true);
    let prompt = Some(Prompt::new(&confirm));
    // A referral is never followed: the entries after it still import.
    let srv = mock(LdapKnobs { referral: true, ..LdapKnobs::default() }).await;
    let p = ldap_import::preview(st, prompt, input(&srv, &cred)).await.expect("referral ignored");
    assert_eq!(p.counts.connections, 3);
    srv.recorder().assert_no_violations();
    assert_eq!(
        srv.recorder().ops(),
        ["bind", "search", "unbind"],
        "no request towards the referral"
    );
    import::discard(st, &p.plan_id).expect("discard");
    // A server that ignores paging answers in one go.
    let srv = mock(LdapKnobs { ignore_paging: true, ..LdapKnobs::default() }).await;
    let p = ldap_import::preview(st, prompt, input(&srv, &cred)).await.expect("unpaged");
    assert_eq!(p.counts.connections, 3);
    srv.recorder().assert_no_violations();
    import::discard(st, &p.plan_id).expect("discard");
    // A server that ignores the request's sizeLimit is abandoned by the client at the cap.
    let srv = mock(LdapKnobs { ignore_size_limit: true, ..LdapKnobs::default() }).await;
    let err =
        ldap_import::preview(st, prompt, LdapInput { size_limit: Some(1), ..input(&srv, &cred) })
            .await
            .expect_err("client cap");
    assert_eq!(err.code, "ldap.size_limit");
    srv.recorder().assert_no_violations();
    assert!(srv.recorder().ops().contains(&"abandon".to_owned()), "{:?}", srv.recorder().ops());
    // A server-side limit surfaces as the same code.
    let srv = mock(LdapKnobs { size_limit_after: Some(1), ..LdapKnobs::default() }).await;
    let err = ldap_import::preview(st, prompt, input(&srv, &cred)).await.expect_err("server cap");
    assert_eq!(err.code, "ldap.size_limit");
    srv.recorder().assert_no_violations();
    // The name filter is escaped on the wire: an injection attempt is one literal substring.
    let srv = mock(LdapKnobs::default()).await;
    let hostile = "*)(objectClass=*";
    let p = ldap_import::preview(
        st,
        prompt,
        LdapInput { filter: Some(hostile.into()), ..input(&srv, &cred) },
    )
    .await
    .expect("escaped");
    assert_eq!(p.counts.connections, 0, "nothing matches the literal");
    let filter = srv.recorder().searches()[0].filter.clone().expect("filter");
    assert!(
        filter.contains("\\2a\\29\\28objectClass=\\2a") || filter.contains("\\2a\\29\\28"),
        "{filter}"
    );
    assert!(!filter.contains("(objectClass=*)"), "injection reached the wire: {filter}");
    srv.recorder().assert_no_violations();
    assert_eq!(st.import_plans.len(), 1);
    import::discard(st, &p.plan_id).expect("discard");
    assert_eq!(audit_rows(st, "import_refused").len(), 2);
    assert_refusals_carry_only_a_code(st, "import_refused");
    assert_audit_free_of(st, MARKERS);
    assert_audit_free_of(st, &["objectClass", hostile]);
}

#[tokio::test]
async fn tofu_accept_pins_and_the_pin_is_used_next_time() {
    let f = testing::unlocked();
    let st = &f.state;
    let cred = domain_user(st);
    let srv = mock(LdapKnobs::default()).await;
    let confirm = FixedConfirm::new(true);
    let t = ldap_import::test(st, Some(Prompt::new(&confirm)), input(&srv, &cred))
        .await
        .expect("test bind");
    assert_eq!(confirm.asked().len(), 1, "one prompt");
    let ask = &confirm.asked()[0];
    assert!(
        ask.text.contains("127.0.0.1") && ask.text.contains("Fingerprint: SHA256:"),
        "{}",
        ask.text
    );
    assert!(
        !ask.text.contains(BIND_USER) && !ask.text.contains("DC="),
        "the dialog names the host, not the query"
    );
    assert_eq!(t.bound_as, format!("{BIND_USER}@corp.example.test"));
    assert!(pins(st).has_pin("127.0.0.1", srv.addr().port()));
    assert_eq!(srv.recorder().ops(), ["bind", "unbind"], "test never searches");
    // Pinned: the preview runs with no prompt object at all.
    let p = ldap_import::preview(st, None, input(&srv, &cred)).await.expect("pinned preview");
    assert_eq!(p.counts.connections, 3);
    assert_eq!(confirm.asked().len(), 1);
    let r = import::apply(st, ApplyInput { plan_id: p.plan_id, exclude: vec![], duplicates: None })
        .expect("apply");
    assert_eq!(r.connections, 3);
    srv.recorder().assert_no_violations();
    let decisions = audit_rows(st, "cert_decision");
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        (decisions[0]["protocol"].as_str(), decisions[0]["decision"].as_str()),
        (Some("ldap"), Some("accepted"))
    );
    assert_audit_free_of(st, MARKERS);
}

#[tokio::test]
async fn tofu_accept_without_a_writable_store_trusts_this_run_only() {
    let f = testing::unlocked();
    let st = &f.state;
    let cred = domain_user(st);
    let srv = mock(LdapKnobs::default()).await;
    // A line over the cap loads (flagged truncated) but is never rewritten, so the pin save
    // fails and the certificate is trusted for this run only (N-3 semantics, like known_hosts).
    let path = st.data_dir.join(CertProtocol::Ldap.file_name());
    std::fs::write(&path, format!("{}\n", "#".repeat(MAX_LINE + 1))).expect("oversized store");
    let confirm = FixedConfirm::new(true);
    let p = ldap_import::preview(st, Some(Prompt::new(&confirm)), input(&srv, &cred))
        .await
        .expect("trusted once");
    assert_eq!(p.counts.connections, 3);
    assert_eq!(confirm.asked().len(), 1);
    assert!(!pins(st).has_pin("127.0.0.1", srv.addr().port()), "nothing was stored");
    srv.recorder().assert_no_violations();
    import::discard(st, &p.plan_id).expect("discard");
    // Not stored: the next run without a prompt is refused before any bind.
    let before = srv.recorder().ops().len();
    let err = ldap_import::preview(st, None, input(&srv, &cred)).await.expect_err("no pin");
    assert_eq!(err.code, "http.trust_prompt");
    assert_eq!(srv.recorder().ops().len(), before, "no traffic without trust");
    let decisions = audit_rows(st, "cert_decision");
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["decision"], "accepted_session_only");
    assert!(!audit_text(st).contains("\"decision\":\"accepted\""));
    assert_audit_free_of(st, MARKERS);
}

#[tokio::test]
async fn tofu_refuse_never_binds_and_a_changed_certificate_is_a_mismatch() {
    let f = testing::unlocked();
    let st = &f.state;
    let cred = domain_user(st);
    let srv = mock(LdapKnobs::default()).await;
    let no = FixedConfirm::new(false);
    let err = ldap_import::test(st, Some(Prompt::new(&no)), input(&srv, &cred))
        .await
        .expect_err("refused");
    assert_eq!(err.code, "http.trust_rejected");
    // Review 6 M-16: the same dialog for the same target is not re-asked inside the cool-down
    // (a stray Enter cannot be fished for), and without a prompt object it is never asked.
    let err = ldap_import::preview(st, Some(Prompt::new(&no)), input(&srv, &cred))
        .await
        .expect_err("cool-down");
    assert_eq!(err.code, "confirm.cooldown");
    assert_eq!(no.asked().len(), 1);
    for _ in 0..2 {
        let err = ldap_import::preview(st, None, input(&srv, &cred)).await.expect_err("no prompt");
        assert_eq!(err.code, "http.trust_prompt");
    }
    assert!(srv.recorder().requests().is_empty(), "nothing reaches the server without trust");
    assert!(!pins(st).has_pin("127.0.0.1", srv.addr().port()));
    let codes: Vec<String> = audit_rows(st, "import_refused")
        .iter()
        .filter_map(|r| r["code"].as_str().map(str::to_owned))
        .collect();
    // `ldap_import_test` is not an import: its refusal is the `cert_decision: rejected` row
    // only; the three preview refusals are audited by code.
    assert_eq!(codes, ["confirm.cooldown", "http.trust_prompt", "http.trust_prompt"]);
    assert!(audit_rows(st, "ldap_bind").is_empty());
    let decisions = audit_rows(st, "cert_decision");
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["decision"], "rejected");
    // Pin a different certificate for this host:port: the mock's real one is then a mismatch,
    // and the prompt is not even offered (a pinned host never gets a TOFU dialog).
    let yes = FixedConfirm::new(true);
    KnownCerts::add_and_save(
        &st.data_dir.join(CertProtocol::Ldap.file_name()),
        "127.0.0.1",
        srv.addr().port(),
        &[7u8; 32],
        time::OffsetDateTime::now_utc(),
    )
    .expect("pin");
    let err = ldap_import::test(st, Some(Prompt::new(&yes)), input(&srv, &cred))
        .await
        .expect_err("mismatch");
    assert_eq!(err.code, "http.trust_mismatch");
    assert!(yes.asked().is_empty(), "no override dialog on a mismatch");
    assert!(srv.recorder().requests().is_empty(), "the handshake failed before any LDAP request");
    assert_refusals_carry_only_a_code(st, "import_refused");
    assert_audit_free_of(st, MARKERS);
}
