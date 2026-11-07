//! ADR-0025 (A5 R1) through the command layer: SSH sessions through chains of one and two
//! loopback bastions (`mooring-testsrv`-style in-process servers), per-hop TOFU with the hop
//! named in the prompt, `hop_status` progress, `session_hop_open` / `_close` audit rows, and
//! the hostile cases: depth 4, self, cycle, missing and non-SSH hops, a hop in use, a hop
//! host-key change (hard stop, target never tried) and a hop auth failure (target never tried).

use mooring_core::session::Size;
use secrecy::SecretString;

use crate::commands::credentials::{self, NewCredential};
use crate::commands::sessions::{self as sess, WireInput};
use crate::commands::tree::{self, ConnectionFields};
use crate::state::testing;
use crate::state::AppState;
use crate::support::{next, read_until, sink, wait_until_empty, Events};
use crate::test_ssh_server::{self as server, PASSWORD, USER};

type R = crate::error::IpcResult<mooring_app_lib::dto::ConnectionDto>;

const SIZE: Size = Size { width: 100, height: 30 };

struct Lab {
    folder: String,
}

fn lab(st: &AppState) -> Lab {
    let root = tree::list(st).expect("tree").folders[0].id.clone();
    let folder = tree::create_folder(st, &root, "Lab").expect("folder");
    let cred =
        credentials::create(st, NewCredential::user_password("lab", USER, PASSWORD)).expect("cred");
    tree::set_default_credential(st, &folder.id, Some(&cred.id)).expect("default");
    Lab { folder: folder.id }
}

fn ssh(st: &AppState, lab: &Lab, name: &str, port: u16, via: Option<Vec<String>>) -> R {
    tree::create_connection(
        st,
        ConnectionFields {
            port: Some(u32::from(port)),
            via,
            ..ConnectionFields::basic(&lab.folder, name, "ssh", "127.0.0.1")
        },
    )
}

fn id(r: R) -> String {
    r.expect("connection").id
}

fn code(r: R) -> &'static str {
    r.expect_err("refused").code
}

fn as_id(v: &serde_json::Value) -> u32 {
    u32::try_from(v["id"].as_u64().expect("id")).expect("u32")
}

async fn yes(st: &AppState, session: &str, prompt: &serde_json::Value) {
    let answer =
        WireInput::Answer { id: as_id(prompt), text: SecretString::from("yes".to_owned()) };
    sess::send(st, session, answer).await.expect("answer");
}

/// Hop `hop` of `of`: `connecting`, its TOFU prompt (answered yes), `authenticating`, `up`.
async fn hop_up_with_tofu(st: &AppState, session: &str, rx: &mut Events, hop: u64, of: u64) {
    let e = next(rx).await;
    assert_eq!(
        (e["kind"].as_str(), e["hop"].as_u64(), e["of"].as_u64()),
        (Some("hop_status"), Some(hop), Some(of)),
        "{e}"
    );
    assert_eq!(e["state"], "connecting", "{e}");
    let p = next(rx).await;
    assert_eq!(
        (p["kind"].as_str(), p["purpose"].as_str()),
        (Some("prompt"), Some("host_key_trust")),
        "{p}"
    );
    assert_eq!(p["hop"].as_u64(), Some(hop), "{p}");
    let msg = p["message"].as_str().expect("message");
    assert!(msg.starts_with(&format!("Hop {}", hop + 1)), "{msg}");
    yes(st, session, &p).await;
    for want in ["authenticating", "up"] {
        let e = next(rx).await;
        assert_eq!(
            (e["kind"].as_str(), e["state"].as_str()),
            (Some("hop_status"), Some(want)),
            "{e}"
        );
    }
}

/// The target's TOFU (no `hop` field), then `connected` and the shell banner.
async fn target_up(st: &AppState, session: &str, rx: &mut Events) {
    let p = next(rx).await;
    assert_eq!(p["purpose"], "host_key_trust", "{p}");
    assert!(p.get("hop").is_none(), "the target's prompt carries no hop: {p}");
    yes(st, session, &p).await;
    let c = next(rx).await;
    assert_eq!(c["kind"], "connected", "{c}");
    assert!(c.get("hop").is_none(), "{c}");
    read_until(rx, "welcome").await;
}

async fn close(st: &AppState, session: &str, rx: &mut Events) {
    sess::close(st, session).await.expect("close");
    while next(rx).await["kind"] != "closed" {}
    wait_until_empty(st).await;
}

async fn closed_code(rx: &mut Events) -> (String, Vec<serde_json::Value>) {
    let mut seen = Vec::new();
    loop {
        let e = next(rx).await;
        if e["kind"] == "closed" {
            return (e["code"].as_str().expect("code").to_owned(), seen);
        }
        seen.push(e);
    }
}

#[tokio::test]
async fn ssh_through_one_and_two_bastions_with_per_hop_tofu_and_audit() {
    let (srv_a, srv_b, srv_t) =
        (server::start(61).await, server::start(62).await, server::start(63).await);
    let f = testing::unlocked();
    let st = &f.state;
    let lab = lab(st);
    let bastion_a = id(ssh(st, &lab, "bastion-a", srv_a.port, None));
    let bastion_b = id(ssh(st, &lab, "bastion-b", srv_b.port, None));
    let one =
        ssh(st, &lab, "target via a", srv_t.port, Some(vec![bastion_a.clone()])).expect("create");
    assert_eq!(one.via, vec![bastion_a.clone()], "DTO carries the chain");

    // Chain of 1: hop TOFU, then the target's own TOFU.
    let (s1, mut rx) = sink();
    let opened = sess::open(st, &one.id, SIZE, s1).await.expect("open");
    hop_up_with_tofu(st, &opened.session_id, &mut rx, 0, 1).await;
    target_up(st, &opened.session_id, &mut rx).await;
    close(st, &opened.session_id, &mut rx).await;

    // Chain of 2 (bastion-a is pinned now: no prompt for hop 1; bastion-b is new).
    let two = id(ssh(
        st,
        &lab,
        "target via a, b",
        srv_t.port,
        Some(vec![bastion_a.clone(), bastion_b.clone()]),
    ));
    let (s2, mut rx) = sink();
    let opened = sess::open(st, &two, SIZE, s2).await.expect("open");
    for want in ["connecting", "authenticating", "up"] {
        let e = next(&mut rx).await;
        assert_eq!(
            (e["hop"].as_u64(), e["of"].as_u64(), e["state"].as_str()),
            (Some(0), Some(2), Some(want)),
            "{e}"
        );
    }
    hop_up_with_tofu(st, &opened.session_id, &mut rx, 1, 2).await;
    // The target is pinned from the first run: straight to connected.
    assert_eq!(next(&mut rx).await["kind"], "connected");
    read_until(&mut rx, "welcome").await;
    close(st, &opened.session_id, &mut rx).await;

    let events = testing::audit_events(st);
    for want in ["session_hop_open", "session_hop_close", "trust_decision", "session_opened"] {
        assert!(events.iter().any(|e| e == want), "{want} missing in {events:?}");
    }
    let raw = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("log");
    assert!(raw.contains(&format!(r#""hop_connection":"{bastion_b}""#)), "the hop is named");
    assert!(!raw.contains(PASSWORD), "no secret in the audit log");

    // `connection_update` without `via` keeps the chain; `[]` clears it.
    let fields = ConnectionFields {
        port: Some(u32::from(srv_t.port)),
        ..ConnectionFields::basic(&lab.folder, "renamed", "ssh", "127.0.0.1")
    };
    let kept = tree::update_connection(st, &two, fields.clone()).expect("update");
    assert_eq!(kept.via, vec![bastion_a.clone(), bastion_b.clone()]);
    let cleared =
        tree::update_connection(st, &two, ConnectionFields { via: Some(vec![]), ..fields })
            .expect("update");
    assert!(cleared.via.is_empty());
}

#[tokio::test]
async fn hostile_chains_are_refused_with_typed_codes() {
    let f = testing::unlocked();
    let st = &f.state;
    let lab = lab(st);
    let hops: Vec<String> = (0..4).map(|i| id(ssh(st, &lab, &format!("h{i}"), 22, None))).collect();
    let rdp = tree::create_connection(
        st,
        ConnectionFields::basic(&lab.folder, "rdp", "rdp", "127.0.0.1"),
    )
    .expect("rdp")
    .id;
    assert_eq!(code(ssh(st, &lab, "depth 4", 22, Some(hops.clone()))), "connection.via_invalid");
    assert_eq!(
        code(ssh(st, &lab, "dup", 22, Some(vec![hops[0].clone(), hops[0].clone()]))),
        "connection.via_invalid"
    );
    assert_eq!(code(ssh(st, &lab, "rdp hop", 22, Some(vec![rdp]))), "connection.via_invalid");
    let missing = mooring_core::ConnectionId::new().to_string();
    assert_eq!(code(ssh(st, &lab, "missing", 22, Some(vec![missing]))), "connection.via_invalid");
    assert_eq!(code(ssh(st, &lab, "not an id", 22, Some(vec!["x".into()]))), "input.invalid");
    // Self and two-way cycle on update.
    let leaf = id(ssh(st, &lab, "leaf", 22, Some(vec![hops[0].clone()])));
    let me = ConnectionFields {
        via: Some(vec![leaf.clone()]),
        ..ConnectionFields::basic(&lab.folder, "leaf", "ssh", "127.0.0.1")
    };
    assert_eq!(
        tree::update_connection(st, &leaf, me).expect_err("self").code,
        "connection.via_invalid"
    );
    let back = ConnectionFields {
        via: Some(vec![leaf.clone()]),
        ..ConnectionFields::basic(&lab.folder, "h0", "ssh", "127.0.0.1")
    };
    assert_eq!(
        tree::update_connection(st, &hops[0], back).expect_err("cycle").code,
        "connection.via_invalid"
    );
    // A hop in use cannot be deleted; its folder neither.
    assert_eq!(
        tree::delete_connection(st, &hops[0]).expect_err("in use").code,
        "connection.in_use_as_hop"
    );
    tree::delete_connection(st, &leaf).expect("the leaf goes");
    tree::delete_connection(st, &hops[0]).expect("free now");
    // vCenter connections refuse a chain in this version.
    let vc = ConnectionFields {
        via: Some(vec![hops[1].clone()]),
        ..ConnectionFields::basic(&lab.folder, "vc", "vsphere-console", "vc.example.test")
    };
    assert_eq!(tree::create_connection(st, vc).expect_err("vc").code, "connection.via_invalid");
}

#[tokio::test]
async fn hop_host_key_change_and_hop_auth_failure_never_reach_the_target() {
    let (a, t) = (server::start(64).await, server::start(65).await);
    let f = testing::unlocked();
    let st = &f.state;
    let lab = lab(st);
    // Pin a different key for the bastion: a changed hop key is the usual hard stop.
    let other = server::start(66).await;
    let mut kh = mooring_proto_ssh::KnownHosts::new();
    kh.add_hashed("127.0.0.1", a.port, &other.host_public).expect("add");
    kh.add_hashed("127.0.0.1", t.port, &t.host_public).expect("add");
    kh.save(&st.known_hosts_path()).expect("save");
    let bastion = id(ssh(st, &lab, "bastion", a.port, None));
    let leaf = id(ssh(st, &lab, "leaf", t.port, Some(vec![bastion.clone()])));
    let (s, mut rx) = sink();
    sess::open(st, &leaf, SIZE, s).await.expect("open");
    let (code, seen) = closed_code(&mut rx).await;
    assert_eq!(code, "hop_failed");
    assert!(seen.iter().any(|e| e["kind"] == "hop_status" && e["state"] == "failed"), "{seen:?}");
    assert!(!seen.iter().any(|e| e["kind"] == "prompt" || e["kind"] == "connected"), "{seen:?}");
    wait_until_empty(st).await;
    let raw = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("log");
    assert!(raw.contains(r#""decision":"changed""#), "the mismatch is audited");
    assert!(!raw.contains("session_hop_open"));

    // Hop auth failure: the bastion's own credential is wrong; the target is never tried.
    let mut kh = mooring_proto_ssh::KnownHosts::new();
    kh.add_hashed("127.0.0.1", a.port, &a.host_public).expect("add");
    kh.add_hashed("127.0.0.1", t.port, &t.host_public).expect("add");
    kh.save(&st.known_hosts_path()).expect("save");
    let wrong =
        credentials::create(st, NewCredential::user_password("wrong", USER, "not the password"))
            .expect("cred");
    let own = ConnectionFields {
        port: Some(u32::from(a.port)),
        credential_id: Some(wrong.id),
        ..ConnectionFields::basic(&lab.folder, "bastion", "ssh", "127.0.0.1")
    };
    tree::update_connection(st, &bastion, own).expect("own credential");
    let (s, mut rx) = sink();
    sess::open(st, &leaf, SIZE, s).await.expect("open");
    let (code, seen) = closed_code(&mut rx).await;
    assert_eq!(code, "hop_failed");
    let states: Vec<_> = seen.iter().filter_map(|e| e["state"].as_str()).collect();
    assert_eq!(states, ["connecting", "authenticating", "failed"], "{seen:?}");
    assert!(!seen.iter().any(|e| e["kind"] == "connected"));
    wait_until_empty(st).await;
}

// ------------------------------------------------------------- RDP / VNC through one hop

struct Graphical {
    id: String,
    events: Events,
    frames: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
}

async fn open_graphical(st: &AppState, conn: &str) -> Graphical {
    let (s, events) = sink();
    let (ftx, frames) = tokio::sync::mpsc::unbounded_channel();
    let out: mooring_app_lib::frame_pump::FrameOut =
        std::sync::Arc::new(move |m| ftx.send(m).is_ok());
    let desktop = Size { width: 320, height: 240 };
    let id = sess::open_with(st, conn, desktop, s, Some(out)).await.expect("open").session_id;
    Graphical { id, events, frames }
}

/// Events until `connected`, answering certificate prompts `yes`; returns the hop states seen.
async fn graphical_connected(st: &AppState, g: &mut Graphical) -> (serde_json::Value, Vec<String>) {
    let mut hops = Vec::new();
    loop {
        let e = next(&mut g.events).await;
        match e["kind"].as_str() {
            Some("connected") => return (e, hops),
            Some("hop_status") => hops.push(e["state"].as_str().expect("state").to_owned()),
            Some("prompt") => {
                assert_eq!(e["purpose"], "certificate_trust", "{e}");
                yes(st, &g.id, &e).await;
            }
            _ => panic!("{e}"),
        }
    }
}

async fn graphical_closes(st: &AppState, g: &mut Graphical) {
    sess::close(st, &g.id).await.expect("close");
    loop {
        let e = next(&mut g.events).await;
        if e["kind"] == "closed" {
            assert_eq!(e["code"], "user", "{e}");
            break;
        }
    }
    wait_until_empty(st).await;
}

/// A pinned bastion, so the graphical flows need no host-key prompt.
async fn pinned_bastion(st: &AppState, lab: &Lab, seed: u8) -> String {
    let a = server::start(seed).await;
    let mut kh = mooring_proto_ssh::KnownHosts::new();
    kh.add_hashed("127.0.0.1", a.port, &a.host_public).expect("add");
    kh.save(&st.known_hosts_path()).expect("save");
    let id = id(ssh(st, lab, "bastion", a.port, None));
    std::mem::forget(a);
    id
}

#[tokio::test]
async fn rdp_and_vnc_open_through_a_bastion_with_the_real_factory() {
    use mooring_testsrv::{rdp, rfb};
    let f = testing::unlocked();
    let st = &f.state;
    let lab = lab(st);
    let bastion = pinned_bastion(st, &lab, 67).await;

    let srv =
        rdp::start(rdp::RdpConfig { width: 320, height: 240, ..rdp::RdpConfig::default() }, 0)
            .expect("rdp");
    let cred =
        credentials::create(st, NewCredential::user_password("rdp", "alice", "correct horse"))
            .expect("cred");
    let desk = tree::create_connection(
        st,
        ConnectionFields {
            port: Some(u32::from(srv.addr().port())),
            credential_id: Some(cred.id),
            via: Some(vec![bastion.clone()]),
            ..ConnectionFields::basic(&lab.folder, "desk", "rdp", "127.0.0.1")
        },
    )
    .expect("rdp connection")
    .id;
    let mut g = open_graphical(st, &desk).await;
    let (c, hops) = graphical_connected(st, &mut g).await;
    assert_eq!(c["security"], "nla", "{c}");
    assert!(
        hops.starts_with(&["connecting".into(), "authenticating".into(), "up".into()]),
        "{hops:?}"
    );
    let m = tokio::time::timeout(std::time::Duration::from_secs(20), g.frames.recv())
        .await
        .expect("frame")
        .expect("open");
    assert!(mooring_core::frame::decode_mfr1(&m).expect("mfr1").is_full());
    graphical_closes(st, &mut g).await;

    let cfg = rfb::RfbConfig {
        width: 320,
        height: 240,
        security: vec![rfb::SecurityOffer::VeNCrypt(vec![rfb::VeNCryptSub::X509None])],
        ..rfb::RfbConfig::default()
    };
    let vnc_srv = rfb::start(cfg, 0).await.expect("rfb");
    let root = tree::list(st)
        .expect("tree")
        .folders
        .iter()
        .find(|f| f.parent_id.is_none())
        .expect("root")
        .id
        .clone();
    let vnc = tree::create_connection(
        st,
        ConnectionFields {
            port: Some(u32::from(vnc_srv.addr().port())),
            via: Some(vec![bastion]),
            // The root has no default credential (the lab's SSH login does not fit VNC).
            ..ConnectionFields::basic(&root, "vnc", "vnc", "127.0.0.1")
        },
    )
    .expect("vnc connection")
    .id;
    let mut g = open_graphical(st, &vnc).await;
    let (c, hops) = graphical_connected(st, &mut g).await;
    assert_eq!(c["security"], "vencrypt-x509", "{c}");
    assert!(hops.contains(&"up".to_owned()), "{hops:?}");
    let m = tokio::time::timeout(std::time::Duration::from_secs(20), g.frames.recv())
        .await
        .expect("frame")
        .expect("open");
    assert!(mooring_core::frame::decode_mfr1(&m).expect("mfr1").is_full());
    graphical_closes(st, &mut g).await;

    let events = testing::audit_events(st);
    assert!(events.iter().filter(|e| *e == "session_hop_open").count() >= 2, "{events:?}");
}
