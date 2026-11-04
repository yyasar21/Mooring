//! Login, logout, re-login on 401, redaction.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::{password, serve, PASSWORD, UPN};
use mooring_http::CertProtocol;
use mooring_vsphere::{Credential, VsphereClient};
use secrecy::SecretString;

#[tokio::test]
async fn login_uses_basic_then_the_session_header_and_logout_deletes() {
    let m = serve().await;
    let s = m.login().await;
    assert_eq!(s.datacenters().await.expect("dcs").len(), 1);
    let reqs = m.vc.requests();
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/api/session");
    assert!(reqs[0].session.is_none());
    assert_eq!(reqs[1].session.as_deref(), Some("tok-0"));
    assert!(reqs[1].auth.is_none(), "no Basic credential after login");
    let dbg = format!("{s:?}");
    assert!(!dbg.contains("tok-0") && !dbg.contains(PASSWORD), "{dbg}");
    s.logout().await.expect("logout");
    assert_eq!(m.vc.count("DELETE", "/api/session"), 1);
    assert!(m.vc.valid.lock().expect("lock").is_none());
}

#[tokio::test]
async fn wrong_password_is_vsphere_auth() {
    let m = serve().await;
    let bad = SecretString::from("nope".to_owned());
    let e = VsphereClient::login(m.base(), UPN, &bad, m.config()).await.expect_err("refused");
    assert_eq!(e.code(), "vsphere.auth_failed");
    assert!(!e.to_string().contains("nope"));
}

#[tokio::test]
async fn bad_inputs_are_refused_before_io() {
    let m = serve().await;
    let mut kube = m.config();
    kube.protocol = CertProtocol::Kube;
    let e = VsphereClient::login(m.base(), UPN, &password(), kube).await.expect_err("protocol");
    assert_eq!(e.code(), "vsphere.invalid");
    let e =
        VsphereClient::login(m.base(), "a:b@x", &password(), m.config()).await.expect_err("upn");
    assert_eq!(e.code(), "vsphere.invalid");
    let path = url::Url::parse(&format!("{}ui", m.base())).expect("url");
    assert!(VsphereClient::login(path, UPN, &password(), m.config()).await.is_err());
    assert_eq!(m.vc.requests().len(), 0);
}

#[tokio::test]
async fn expired_session_relogs_in_once_with_the_closure_credential() {
    let m = serve().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    let s = m.login().await.with_reauth(Arc::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
        Some(Credential { upn: UPN.into(), password: password() })
    }));
    m.vc.expire();
    assert_eq!(s.datacenters().await.expect("after re-login").len(), 1);
    assert_eq!((calls.load(Ordering::SeqCst), s.generation()), (1, 1));
    assert_eq!(m.vc.count("POST", "/api/session"), 2);
    // the retried request carried the new token
    let last = m.vc.requests().pop().expect("req");
    assert_eq!(last.session.as_deref(), Some("tok-1"));
}

#[tokio::test]
async fn locked_vault_or_no_source_ends_with_auth() {
    let m = serve().await;
    let s = m.login().await;
    m.vc.expire();
    assert_eq!(s.datacenters().await.expect_err("no source").code(), "vsphere.auth_failed");

    let s = m.login().await.with_reauth(Arc::new(|| None));
    m.vc.expire();
    assert_eq!(s.datacenters().await.expect_err("locked").code(), "vsphere.auth_failed");
}

#[tokio::test]
async fn persistent_401_does_not_loop() {
    let m = serve().await;
    m.vc.on("/api/vcenter/datacenter", |_, _| common::reply(401, "{}"));
    let s = m
        .login()
        .await
        .with_reauth(Arc::new(|| Some(Credential { upn: UPN.into(), password: password() })));
    assert_eq!(s.datacenters().await.expect_err("401").code(), "vsphere.auth_failed");
    assert_eq!(m.vc.count("POST", "/api/session"), 2, "exactly one re-login");
    assert_eq!(m.vc.count("GET", "/api/vcenter/datacenter"), 2);
}

#[tokio::test]
async fn logout_after_expiry_is_ok() {
    let m = serve().await;
    let s = m.login().await;
    m.vc.expire();
    s.logout().await.expect("401 on logout is fine");
}
