//! Hostile IPC input, fixed-shape cases: numeric ranges, wire shapes serde must refuse, base64
//! garbage for `session_send`, vault inputs, a live SSH session, and the fixed bug A1-QA-4.
//! Shared helpers and the string corpus live in `hostile.rs`.

use mooring_core::session::Size;
use secrecy::SecretString;

use crate::commands::credentials::{self, NewCredential};
use crate::commands::sessions::{self as sess, WireInput};
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::{audit, vault};
use crate::hostile::{assert_state_healthy, check, fields, preview, seed, Rng, MARK};
use crate::state::testing;
use crate::state::AppState;
use crate::support::{self, b64, next, read_until, sink};
use crate::test_ssh_server::{self as server, PASSWORD, USER};

#[tokio::test]
async fn numbers_out_of_range() {
    let f = testing::unlocked();
    let st = &f.state;
    let ids = seed(st);
    for port in [0, 65_536, u32::MAX] {
        let r = tree::create_connection(st, fields(&ids.folder, "p", "ssh", "h", Some(port)));
        assert_eq!(r.expect_err("port").code, "input.invalid", "port {port}");
    }
    let many = ConnectionFields {
        tags: (0..51).map(|i| format!("t{i}")).collect(),
        ..fields(&ids.folder, "t", "ssh", "h", None)
    };
    assert_eq!(tree::create_connection(st, many).expect_err("tags").code, "input.invalid");
    let huge_tags = ConnectionFields {
        tags: vec!["t".into(); 1_000_000],
        ..fields(&ids.folder, "t", "ssh", "h", None)
    };
    assert_eq!(tree::create_connection(st, huge_tags).expect_err("1M tags").code, "input.invalid");
    for limit in [0, 1, 200, 201, u32::MAX] {
        let hits = tree::search(st, "seed", limit).expect("search clamps");
        assert!(hits.len() <= 200);
    }
    for (limit, before) in [(0, None), (u32::MAX, None), (10, Some(0)), (10, Some(u64::MAX))] {
        let page = audit::tail(st, limit, before).expect("tail clamps");
        assert!(page.len() <= 500);
        if before == Some(0) {
            assert!(page.is_empty());
        }
    }
    for size in [
        Size { width: 0, height: 24 },
        Size { width: 80, height: 0 },
        Size { width: 16_385, height: 24 },
        Size { width: u32::MAX, height: u32::MAX },
    ] {
        let (sk, _rx) = sink();
        let r = sess::open(st, &ids.conn, size, sk).await;
        assert_eq!(r.expect_err("size").code, "input.invalid", "{size:?}");
        let d = sess::decode_input(WireInput::Resize { size });
        assert_eq!(d.expect_err("resize").code, "input.invalid");
    }
    // Negative numbers and wrong types never reach the handler: serde refuses them (Tauri turns
    // that into a plain string error, which ipc.ts maps to ipc.unknown).
    for raw in [
        serde_json::json!({"kind":"resize","size":{"width":-1,"height":24}}),
        serde_json::json!({"kind":"resize","size":{"width":1e20,"height":24}}),
        serde_json::json!({"kind":"pointer","x":-5,"y":0,"buttons":256}),
        serde_json::json!({"kind":"answer","id":-1,"text":"yes"}),
        serde_json::json!({"kind":"answer","id":1,"text":"yes","extra":true}),
        serde_json::json!({"kind":"bytes","data":null}),
        serde_json::json!({"kind":"BYTES","data":"eA=="}),
        serde_json::json!({"data":"eA=="}),
        serde_json::json!([1, 2, 3]),
    ] {
        assert!(support::wire_input(&raw).is_err(), "accepted {raw}");
    }
    assert_state_healthy(st);
}

#[test]
fn base64_garbage_for_session_send() {
    let cap: usize = 64 * 1024;
    let cases: Vec<String> = vec![
        "***".into(),
        "eA".into(),     // missing padding
        "eA===".into(),  // too much padding
        "e A==".into(),  // inner space
        "eA==\n".into(), // trailing newline
        "-_-_".into(),   // URL-safe alphabet
        "\0\0\0\0".into(),
        "🦀🦀".into(),
        "=".repeat(8),
        format!("{}!", "A".repeat(1023)),
        "A".repeat(cap.div_ceil(3) * 4 + 4), // one block over the cap
        "A".repeat(10 * 1024 * 1024),        // 10 MiB, refused before decoding
    ];
    for data in cases {
        let r = std::panic::catch_unwind(|| {
            sess::decode_input(WireInput::Bytes { data: data.clone() })
        });
        let r = r.unwrap_or_else(|_| panic!("decode panicked on {:?}", preview(&data)));
        assert_eq!(r.expect_err("garbage").code, "input.invalid", "{:?}", preview(&data));
    }
    // Boundary: exactly 64 KiB decodes; empty is accepted (no-op keystroke).
    let ok = b64(&vec![0u8; cap]);
    assert!(sess::decode_input(WireInput::Bytes { data: ok }).is_ok());
    assert!(sess::decode_input(WireInput::Bytes { data: String::new() }).is_ok());
    let mut rng = Rng(0xbad_b64);
    for _ in 0..2000 {
        let len = usize::try_from(rng.below(64)).unwrap_or(0);
        let data: String =
            (0..len).map(|_| char::from(u8::try_from(rng.below(128)).unwrap_or(b'A'))).collect();
        let r = std::panic::catch_unwind(|| {
            sess::decode_input(WireInput::Bytes { data: data.clone() })
        })
        .unwrap_or_else(|_| panic!("decode panicked on {data:?}"));
        if let Err(e) = r {
            assert_eq!(e.code, "input.invalid");
        }
    }
}

#[test]
fn vault_inputs() {
    let f = testing::empty();
    let st = &f.state;
    let too_long = "p".repeat(1025);
    assert_eq!(
        vault::password_from_ipc(too_long).expect_err("long").code,
        "vault.password_too_long"
    );
    assert!(vault::password_from_ipc("p".repeat(1024)).is_ok());
    let r = vault::create(st, SecretString::from("short".to_owned()));
    assert_eq!(r.expect_err("weak").code, "vault.weak_password");
    let r = vault::unlock(st, SecretString::from(testing::MASTER.to_owned()));
    assert_eq!(r.expect_err("missing").code, "vault.missing");
    vault::create(st, SecretString::from(testing::MASTER.to_owned())).expect("create");
    let r = vault::create(st, SecretString::from(testing::MASTER.to_owned()));
    assert_eq!(r.expect_err("exists").code, "vault.exists");
    // Unknown lock reasons are recorded as a user lock, never echoed into the audit log.
    vault::lock(st, Some(&format!("{MARK}\u{1b}[2J"))).expect("lock");
    let log = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("log");
    assert!(!log.contains(MARK), "lock reason echoed into the audit log");
    assert!(log.contains("\"reason\":\"user\""));
    // Control characters in a password are just bytes: they cannot unlock and do not panic.
    let r = vault::unlock(st, SecretString::from(format!("{}\0\u{202e}", testing::MASTER)));
    assert_eq!(r.expect_err("wrong").code, "vault.unlock");
}

#[tokio::test]
async fn hostile_input_on_a_live_ssh_session() {
    let srv = server::start(33).await;
    let f = testing::unlocked();
    let st = &f.state;
    let root = tree::list(st).expect("tree").folders[0].id.clone();
    let cred =
        credentials::create(st, NewCredential::user_password("c", USER, PASSWORD)).expect("cred");
    let conn = tree::create_connection(
        st,
        ConnectionFields {
            credential_id: Some(cred.id),
            ..fields(&root, "live", "ssh", "127.0.0.1", Some(u32::from(srv.port)))
        },
    )
    .expect("conn");
    let mut kh = mooring_proto_ssh::KnownHosts::new();
    kh.add_hashed("127.0.0.1", srv.port, &srv.host_public).expect("add");
    kh.save(&st.known_hosts_path()).expect("save");
    let (sk, mut rx) = sink();
    let opened = sess::open(st, &conn.id, Size { width: 80, height: 24 }, sk).await.expect("open");
    assert_eq!(next(&mut rx).await["kind"], "connected");
    read_until(&mut rx, "welcome").await;
    let id = opened.session_id.clone();

    // Graphical input on an SSH session, answers with no open prompt, garbage payloads.
    for input in [
        WireInput::Pointer { x: u32::MAX, y: u32::MAX, buttons: u8::MAX },
        WireInput::Key { scancode: u32::MAX, pressed: true },
        WireInput::Answer { id: u32::MAX, text: SecretString::from("yes".to_owned()) },
        WireInput::Answer { id: 0, text: SecretString::from(format!("{MARK}\0")) },
        WireInput::Bytes { data: "not base64!".into() },
    ] {
        let r = sess::send(st, &id, input).await;
        check("session_send.input", "", &r);
        assert_eq!(r.expect_err("refused").code, "input.invalid");
    }
    // Control bytes are terminal data: forwarded as-is, session keeps working.
    let ctl = WireInput::Bytes { data: b64(b"\x1b[6n\x03\x04\x00\xff ctl-ok") };
    sess::send(st, &id, ctl).await.expect("control bytes are valid keystrokes");
    read_until(&mut rx, "ctl-ok").await;
    sess::close(st, &id).await.expect("close");
    support::wait_until_empty(st).await;
    assert_state_healthy(st);
}

/// A1-QA-4 (fixed): Unicode bidi overrides and invisible format characters (Cf: U+202E,
/// U+2066..2069, U+200B, U+FEFF, ...) in names, hosts and tags would let a shared or imported
/// tree display `prod-db` for a connection whose host is something else (Trojan-Source-style
/// spoofing, CVE-2021-42574 class). The shared `mooring-core` validators refuse them.
#[test]
fn bidi_and_invisible_format_characters_are_refused() {
    let f = testing::unlocked();
    let st = &f.state;
    let ids = seed(st);
    for bad in ["db\u{202e}gnp.exe", "prod\u{2066}-db", "a\u{200b}b", "\u{feff}x"] {
        let r = tree::create_folder(st, &ids.folder, bad).map(|_| ());
        assert_eq!(r.expect_err(bad).code, "input.invalid", "folder name {bad:?}");
        let r = tree::create_connection(st, fields(&ids.folder, "n", "ssh", bad, None)).map(|_| ());
        assert_eq!(r.expect_err(bad).code, "input.invalid", "host {bad:?}");
        let tagged = ConnectionFields {
            tags: vec![bad.into()],
            ..fields(&ids.folder, "n", "ssh", "h", None)
        };
        let r = tree::create_connection(st, tagged).map(|_| ());
        assert_eq!(r.expect_err(bad).code, "input.invalid", "tag {bad:?}");
    }
}
