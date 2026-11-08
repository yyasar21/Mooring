//! ADR-0025 §3 web-via: platform gate, plan, the unattended chain (a prompt is a refusal, never
//! an answer), the SOCKS forward through a real in-process bastion, and its audit rows.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::commands::credentials::{self, NewCredential};
use crate::commands::tree::{self, ConnectionFields};
use crate::state::testing::{unlocked, Fixture};
use crate::test_secrets::audit_rows;
use crate::test_ssh_server::{self as server, PASSWORD, USER};
use crate::web::{plan, StorageOs};

const T: Duration = Duration::from_secs(10);

/// A bastion SSH connection on `port` (own credential) and a web connection behind it.
fn web_behind_bastion(f: &Fixture, port: u16, url: &str) -> (String, String) {
    let st = &f.state;
    let root = tree::list(st).expect("tree").folders[0].id.clone();
    let cred =
        credentials::create(st, NewCredential::user_password("bastion", USER, PASSWORD)).expect("cred");
    let bastion = tree::create_connection(st, ConnectionFields {
        port: Some(u32::from(port)),
        credential_id: Some(cred.id.clone()),
        ..ConnectionFields::basic(&root, "bastion", "ssh", "127.0.0.1")
    })
    .expect("bastion")
    .id;
    let web = tree::create_connection(st, ConnectionFields {
        via: Some(vec![bastion.clone()]),
        ..ConnectionFields::basic(&root, "intranet", "web", "intranet.example.test")
    })
    .expect("web")
    .id;
    let options = if url.starts_with("http://") { json!({ "url": url, "allowHttp": true }) } else { json!({ "url": url }) };
    crate::commands::conn_options::set(st, &web, options).expect("options");
    (bastion, web)
}

fn trust(f: &Fixture, srv: &server::TestServer) {
    let mut kh = mooring_proto_ssh::KnownHosts::new();
    kh.add_hashed("127.0.0.1", srv.port, &srv.host_public).expect("add");
    kh.save(&f.state.known_hosts_path()).expect("save");
}

/// SOCKS5 CONNECT to `localhost:<port>` through the proxy; the stream and the reply code.
async fn socks_connect(proxy: u16, port: u16) -> (TcpStream, u8) {
    let mut conn = TcpStream::connect(("127.0.0.1", proxy)).await.expect("proxy");
    conn.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0u8; 2];
    conn.read_exact(&mut method).await.expect("method");
    let mut req = vec![5, 1, 0, 3, 9];
    req.extend_from_slice(b"localhost");
    req.extend_from_slice(&port.to_be_bytes());
    conn.write_all(&req).await.expect("request");
    let mut rep = [0u8; 10];
    tokio::time::timeout(T, conn.read_exact(&mut rep)).await.expect("in time").expect("reply");
    (conn, rep[1])
}

async fn echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

#[test]
fn only_platforms_whose_webview_takes_a_proxy_open() {
    assert!(supported(StorageOs::Linux).is_ok());
    assert!(supported(StorageOs::Windows).is_ok());
    for major in [0, 13, 14, 15] {
        let e = supported(StorageOs::MacOs { major }).expect_err("macOS without macos-proxy");
        assert_eq!(e.code, "web.via_unsupported");
    }
}

#[test]
fn target_is_the_start_url_host_and_port() {
    let t = |u: &str| target_of(&Url::parse(u).expect("url")).expect("target");
    assert_eq!(t("https://intranet.example.test/app"), ("intranet.example.test".into(), 443));
    assert_eq!(t("http://192.0.2.10:8080/"), ("192.0.2.10".into(), 8080));
    assert_eq!(t("https://[2001:db8::1]/"), ("2001:db8::1".into(), 443));
}

#[test]
fn proxy_allow_is_the_start_host_and_the_allowed_origins() {
    let opts: mooring_core::options::WebConnOptions = serde_json::from_value(json!({
        "url": "https://intranet.example.test:8443/app",
        "allowedOrigins": ["https://sso.example.test", "http://[2001:db8::1]:8080"],
        "allowHttp": true
    }))
    .expect("opts");
    let (policy, url) = NavPolicy::from_options(&opts, None).expect("policy");
    let a = proxy_allow(&url, &policy);
    for (h, p) in [
        ("intranet.example.test", 8443),
        ("intranet.example.test", 443),
        ("intranet.example.test", 80),
        ("sso.example.test", 443),
        ("sso.example.test", 8443),
        ("2001:db8::1", 8080),
    ] {
        assert!(a.permits(h, p), "{h}:{p}");
    }
    assert!(!a.permits("intranet.example.test", 22));
    assert!(!a.permits("db.example.test", 443));
    assert!(!a.permits("192.0.2.1", 443));
}

#[test]
fn plan_marks_via_and_never_carries_a_proxy_yet() {
    let f = unlocked();
    let (_, web) = web_behind_bastion(&f, 22, "https://intranet.example.test/");
    let p = plan(&f.state, &web, StorageOs::Linux, None).expect("plan");
    assert!(p.via && p.proxy.is_none());
    let e = plan(&f.state, &web, StorageOs::MacOs { major: 15 }, None).expect_err("macOS");
    assert_eq!(e.code, "web.via_unsupported");
}

#[tokio::test]
async fn web_via_browses_through_the_bastion_and_audits_the_forward() {
    let srv = server::start(71).await;
    let f = unlocked();
    trust(&f, &srv);
    // The start URL is the echo service as the bastion sees it (`localhost:<port>`).
    let port = echo().await;
    let start = format!("http://localhost:{port}/");
    let (bastion, web) = web_behind_bastion(&f, srv.port, &start);
    let p = plan(&f.state, &web, StorageOs::Linux, None).expect("plan");
    let via = open(&f.state, &web, &p.url, &p.policy).await.expect("chain up");
    assert_eq!(via.hops(), 1);
    let url = via.proxy_url().expect("url");
    assert_eq!((url.scheme(), url.host_str()), ("socks5", Some("127.0.0.1")));
    let proxy_port = url.port().expect("port");

    // Review 9 L-48: a target outside the window's allow-list is refused before the hop.
    let (_refused, rep) = socks_connect(proxy_port, port.wrapping_add(1).max(1)).await;
    assert_eq!(rep, 2, "connection not allowed by ruleset");
    assert_eq!(via.refused(), 1);

    // A SOCKS5 CONNECT (domain name, resolved by the bastion) reaches an echo service.
    let (mut conn, rep) = socks_connect(proxy_port, port).await;
    assert_eq!(rep, 0, "CONNECT through the chain");
    conn.write_all(b"page").await.expect("write");
    let mut buf = [0u8; 4];
    tokio::time::timeout(T, conn.read_exact(&mut buf)).await.expect("in time").expect("read");
    assert_eq!(&buf, b"page");

    let opened = audit_rows(&f.state, "forward_opened");
    assert_eq!(opened.len(), 1, "{opened:?}");
    assert_eq!(opened[0]["reason"], "web_via");
    assert_eq!((opened[0]["exposure"].as_str(), opened[0]["connection"].as_str()), (Some("loopback"), Some(web.as_str())));
    let hop = audit_rows(&f.state, "session_hop_open");
    assert_eq!(hop[0]["hop_connection"], bastion.as_str());
    assert!(audit_rows(&f.state, "credential_used").iter().any(|r| r["connection"] == web.as_str()));

    via.shutdown(&f.state.audit, "closed").await;
    via.shutdown(&f.state.audit, "closed").await;
    assert_eq!(audit_rows(&f.state, "forward_closed").len(), 1, "idempotent");
    let refused = audit_rows(&f.state, "forward_refused");
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["target"], format!("localhost:{}", port.wrapping_add(1).max(1)));
    assert_eq!(refused[0]["id"], FORWARD_ID);
    assert_eq!(audit_rows(&f.state, "session_hop_close")[0]["code"], "closed");
    let mut one = [0u8; 1];
    let ended = tokio::time::timeout(T, conn.read(&mut one)).await.expect("in time");
    assert!(matches!(ended, Ok(0) | Err(_)), "the page's connection dies with the window");
    let log = std::fs::read_to_string(f.state.data_dir.join(AppState::AUDIT_FILE)).expect("log");
    assert!(!log.contains(PASSWORD), "no secret in the audit log");
}

#[tokio::test]
async fn the_chain_lives_with_the_window_entry() {
    let srv = server::start(73).await;
    let f = unlocked();
    trust(&f, &srv);
    let (_, web) = web_behind_bastion(&f, srv.port, "https://intranet.example.test/");
    let mut p = plan(&f.state, &web, StorageOs::Linux, None).expect("plan");
    let via = Arc::new(open(&f.state, &web, &p.url, &p.policy).await.expect("chain up"));
    p.proxy = Some(via.proxy_url().expect("url"));
    let sink: crate::web::WebSink = Arc::new(|_| true);
    crate::commands::web::register_with(&f.state, &p, sink, Some(Arc::clone(&via))).expect("reg");
    let rows = serde_json::to_value(crate::web::list(&f.state).expect("list")).expect("json");
    assert_eq!(rows[0]["viaHops"], 1, "{rows}");
    let addr = ("127.0.0.1", p.proxy.as_ref().and_then(Url::port).expect("port"));
    drop(via);
    assert!(crate::commands::web::closed(&f.state, &web), "window gone");
    for _ in 0..200 {
        if !audit_rows(&f.state, "forward_closed").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(audit_rows(&f.state, "forward_closed")[0]["reason"], "web_via");
    assert!(TcpStream::connect(addr).await.is_err(), "listener closed with the window");
}

#[tokio::test]
async fn an_unknown_bastion_key_is_a_refusal_not_an_answer() {
    let srv = server::start(72).await;
    let f = unlocked();
    let (_, web) = web_behind_bastion(&f, srv.port, "https://intranet.example.test/");
    let p = plan(&f.state, &web, StorageOs::Linux, None).expect("plan");
    let e = open(&f.state, &web, &p.url, &p.policy).await.expect_err("prompt refused");
    assert_eq!(e.code, "session.hop_failed");
    assert!(e.message.contains("jump host 1 asked a question"), "{}", e.message);
    assert!(audit_rows(&f.state, "forward_opened").is_empty(), "no forward without a chain");
    let kh = std::fs::read_to_string(f.state.known_hosts_path()).unwrap_or_default();
    assert!(kh.is_empty(), "nothing was trusted on the user's behalf");
}

#[tokio::test]
async fn a_dead_bastion_fails_before_any_window() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = closed.local_addr().expect("addr").port();
    drop(closed);
    let f = unlocked();
    let (_, web) = web_behind_bastion(&f, port, "https://intranet.example.test/");
    let p = plan(&f.state, &web, StorageOs::Linux, None).expect("plan");
    let e = open(&f.state, &web, &p.url, &p.policy).await.expect_err("down");
    assert_eq!(e.code, "session.hop_failed");
    assert!(e.message.starts_with("hop 1 failed"), "{}", e.message);
}
