//! `session_*` tests against the in-process russh server (loopback only).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use secrecy::SecretString;
use tokio::sync::mpsc;

use super::*;
use crate::commands::credentials::{self, NewCredential};
use crate::commands::tree::{self, ConnectionFields};
use crate::state::testing::*;
use crate::test_ssh_server::{self as server, PASSWORD, USER};

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

fn sink() -> (EventSink, mpsc::UnboundedReceiver<serde_json::Value>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let sink: EventSink =
        Arc::new(move |e| tx.send(serde_json::to_value(&e).expect("json")).is_ok());
    (sink, rx)
}

async fn next(rx: &mut mpsc::UnboundedReceiver<serde_json::Value>) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("event within 20 s")
        .expect("channel open")
}

async fn read_until(rx: &mut mpsc::UnboundedReceiver<serde_json::Value>, needle: &str) {
    let mut out = String::new();
    while !out.contains(needle) {
        let e = next(rx).await;
        assert_eq!(e["kind"], "bytes", "{e}");
        let data = base64::engine::general_purpose::STANDARD
            .decode(e["data"].as_str().expect("data"))
            .expect("base64");
        out.push_str(&String::from_utf8_lossy(&data));
    }
}

const SIZE: Size = Size { width: 80, height: 24 };

/// Unlocked state with one SSH connection to `port` using a password credential.
fn ssh_fixture(port: u16, protocol: &str) -> (Fixture, String) {
    let f = unlocked();
    let cred = credentials::create(
        &f.state,
        NewCredential {
            name: "alice".into(),
            kind: "password".into(),
            username: USER.into(),
            secret: SecretString::from(PASSWORD),
            secret2: None,
        },
    )
    .expect("cred");
    let root = f.state.with_ready(|_, s| Ok(tree::root_id(s).to_string())).expect("root");
    let c = tree::create_connection(
        &f.state,
        ConnectionFields {
            folder_id: root,
            name: "test server".into(),
            protocol: protocol.into(),
            host: "127.0.0.1".into(),
            port: Some(u32::from(port)),
            credential_id: Some(cred.id),
            tags: vec![],
        },
    )
    .expect("connection");
    (f, c.id)
}

fn audit_log(f: &Fixture) -> String {
    std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("audit")
}

#[tokio::test]
async fn tofu_connect_echo_close_and_audit() {
    let srv = server::start(201).await;
    let (f, conn) = ssh_fixture(srv.port, "ssh");
    let (sink, mut rx) = sink();
    let opened = open(&f.state, &conn, SIZE, sink).await.expect("open");
    assert_eq!(list(&f.state).expect("list")[0].state, "connecting");

    let prompt = next(&mut rx).await;
    assert_eq!(prompt["kind"], "prompt", "{prompt}");
    assert_eq!(prompt["purpose"], "host_key_trust", "{prompt}");
    assert!(prompt["message"].as_str().expect("msg").ends_with("trust this host?"));
    let id = u32::try_from(prompt["id"].as_u64().expect("id")).expect("u32");
    // Wrong prompt id is refused and the prompt stays open.
    let bad = WireInput::Answer { id: id + 100, text: SecretString::from("yes") };
    assert_eq!(
        send(&f.state, &opened.session_id, bad).await.expect_err("id").code,
        "input.invalid"
    );
    let yes = WireInput::Answer { id, text: SecretString::from("yes") };
    send(&f.state, &opened.session_id, yes).await.expect("answer");

    let connected = next(&mut rx).await;
    assert_eq!(connected["kind"], "connected", "{connected}");
    assert_eq!(connected["protocol"], "ssh");
    assert!(connected["peer_identity"].as_str().expect("peer").starts_with("ssh-ed25519 SHA256:"));
    read_until(&mut rx, "welcome").await;
    assert_eq!(list(&f.state).expect("list")[0].state, "connected");

    let input = WireInput::Bytes { data: b64("hello") };
    send(&f.state, &opened.session_id, input).await.expect("send");
    read_until(&mut rx, "hello").await;
    let resize = WireInput::Resize { size: Size { width: 100, height: 30 } };
    send(&f.state, &opened.session_id, resize).await.expect("resize");

    close(&f.state, &opened.session_id).await.expect("close");
    loop {
        if next(&mut rx).await["kind"] == "closed" {
            break;
        }
    }
    assert!(list(&f.state).expect("list").is_empty(), "removed from the registry");
    let e = send(&f.state, &opened.session_id, WireInput::Bytes { data: b64("x") }).await;
    assert_eq!(e.expect_err("gone").code, "session.not_found");

    let events = audit_events(&f.state);
    for want in ["credential_used", "trust_decision", "session_opened", "session_closed"] {
        assert!(events.iter().any(|e| e == want), "{want} missing in {events:?}");
    }
    let log = audit_log(&f);
    assert!(log.contains("\"decision\":\"accepted\"") && log.contains("\"purpose\":\"connect\""));
    assert!(!log.contains(PASSWORD), "no secret in the audit log");
    assert!(std::fs::read_to_string(f.state.known_hosts_path()).expect("kh").starts_with("|1|"));
}

#[tokio::test]
async fn remote_exit_closes_and_cleans_up() {
    let srv = server::start(202).await;
    let (f, conn) = ssh_fixture(srv.port, "ssh");
    let mut kh = mooring_proto_ssh::KnownHosts::new();
    kh.add_hashed("127.0.0.1", srv.port, &srv.host_public).expect("add");
    kh.save(&f.state.known_hosts_path()).expect("save");
    let (sink, mut rx) = sink();
    let opened = open(&f.state, &conn, SIZE, sink).await.expect("open");
    assert_eq!(next(&mut rx).await["kind"], "connected", "known host: no prompt");
    send(&f.state, &opened.session_id, WireInput::Bytes { data: b64("exit\r") }).await.expect("x");
    loop {
        if next(&mut rx).await["kind"] == "closed" {
            break;
        }
    }
    for _ in 0..50 {
        if list(&f.state).expect("list").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(list(&f.state).expect("list").is_empty());
    assert!(!audit_events(&f.state).contains(&"trust_decision".to_owned()));
}

#[tokio::test]
async fn host_key_mismatch_is_a_hard_stop_and_audited() {
    let srv = server::start(203).await;
    let (f, conn) = ssh_fixture(srv.port, "ssh");
    let other = server::start(204).await; // a different host key
    let mut kh = mooring_proto_ssh::KnownHosts::new();
    kh.add_hashed("127.0.0.1", srv.port, &other.host_public).expect("add");
    kh.save(&f.state.known_hosts_path()).expect("save");
    let (sink, mut rx) = sink();
    open(&f.state, &conn, SIZE, sink).await.expect("open");
    let closed = next(&mut rx).await;
    assert_eq!(closed["kind"], "closed");
    assert!(closed["reason"].as_str().expect("r").starts_with("HOST KEY CHANGED"), "{closed}");
    for _ in 0..50 {
        if audit_log(&f).contains("\"decision\":\"changed\"") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(audit_log(&f).contains("\"decision\":\"changed\""));
}

#[tokio::test]
async fn open_validation_and_protocol_gate() {
    let (f, conn) = ssh_fixture(9, "rdp");
    let (s, _rx) = sink();
    let e = open(&f.state, &conn, SIZE, s.clone()).await.expect_err("rdp");
    assert_eq!(e.code, "session.failed");
    assert!(e.message.contains("not available in this version"), "{}", e.message);
    let e = open(&f.state, "nope", SIZE, s.clone()).await.expect_err("id");
    assert_eq!(e.code, "input.invalid");
    let e =
        open(&f.state, &conn, Size { width: 0, height: 24 }, s.clone()).await.expect_err("size");
    assert_eq!(e.code, "input.invalid");
    let missing = mooring_core::ConnectionId::new().to_string();
    let e = open(&f.state, &missing, SIZE, s.clone()).await.expect_err("missing");
    assert_eq!(e.code, "tree.not_found");
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(open(&f.state, &conn, SIZE, s).await.expect_err("locked").code, "vault.locked");
}

#[tokio::test]
async fn refused_tcp_is_session_failed_without_secret() {
    let port = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        l.local_addr().expect("addr").port()
    }; // listener dropped: connection refused
    let (f, conn) = ssh_fixture(port, "ssh");
    let (s, _rx) = sink();
    let e = open(&f.state, &conn, SIZE, s).await.expect_err("refused");
    assert_eq!(e.code, "session.failed");
    assert!(!e.message.contains(PASSWORD));
}

#[tokio::test]
async fn unknown_sessions_and_input_caps() {
    let f = unlocked();
    let e = send(&f.state, "missing", WireInput::Bytes { data: b64("x") }).await;
    assert_eq!(e.expect_err("nf").code, "session.not_found");
    assert_eq!(close(&f.state, "missing").await.expect_err("nf").code, "session.not_found");
    assert_eq!(close(&f.state, &"x".repeat(65)).await.expect_err("long").code, "input.invalid");
    let big = base64::engine::general_purpose::STANDARD.encode(vec![0u8; MAX_INPUT_BYTES + 3]);
    assert_eq!(
        decode_input(WireInput::Bytes { data: big }).expect_err("big").code,
        "input.invalid"
    );
    let bad = WireInput::Bytes { data: "***".into() };
    assert_eq!(decode_input(bad).expect_err("b64").code, "input.invalid");
    let long = WireInput::Answer { id: 1, text: SecretString::from("a".repeat(4097)) };
    assert_eq!(decode_input(long).expect_err("answer").code, "input.invalid");
    let huge = WireInput::Resize { size: Size { width: 100_000, height: 10 } };
    assert_eq!(decode_input(huge).expect_err("resize").code, "input.invalid");
    assert_eq!(window_detach("s".into()).expect_err("a2").code, "ipc.unknown");
}

#[test]
fn wire_input_parses_ui_shapes_and_never_prints_answers() {
    let i: WireInput =
        serde_json::from_str(r#"{"kind":"answer","id":3,"text":"otp-271828"}"#).expect("answer");
    assert!(!format!("{i:?}").contains("otp-271828"));
    let i: WireInput = serde_json::from_str(r#"{"kind":"bytes","data":"aGk="}"#).expect("bytes");
    let SessionInput::Bytes { data } = decode_input(i).expect("decode") else {
        panic!("bytes");
    };
    assert_eq!(data, b"hi");
    let r: Result<WireInput, _> = serde_json::from_str(r#"{"kind":"bytes","data":[104,105]}"#);
    assert!(r.is_err(), "byte arrays are refused; base64 only");
    let r: Result<WireInput, _> = serde_json::from_str(r#"{"kind":"shell","cmd":"rm"}"#);
    assert!(r.is_err());
}

#[test]
fn sink_type_is_shareable() {
    // Compile-time check that a sink can be shared with the session task.
    let seen = Arc::new(Mutex::new(0));
    let s2 = Arc::clone(&seen);
    let sink: EventSink = Arc::new(move |_| {
        *s2.lock().expect("lock") += 1;
        true
    });
    assert!(sink(WireEvent::Closed { reason: "x".into() }));
    assert_eq!(*seen.lock().expect("lock"), 1);
}
