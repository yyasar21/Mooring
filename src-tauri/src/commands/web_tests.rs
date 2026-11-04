//! Web command logic without a `WebView`: register / reopen / close, zoom, clear data.

use std::sync::Mutex;

use serde_json::json;

use super::*;
use crate::state::testing::{audit_events, unlocked};
use crate::web::tests::web_connection;

fn recorder() -> (WebSink, Arc<Mutex<Vec<serde_json::Value>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&seen);
    let sink: WebSink = Arc::new(move |e| {
        rec.lock().expect("m").push(serde_json::to_value(&e).expect("json"));
        true
    });
    (sink, seen)
}

#[test]
fn register_reopen_and_close_once() {
    let f = unlocked();
    let id = web_connection(&f, json!({ "url": "https://console.example.test/" }));
    let plan = web::plan(&f.state, &id, StorageOs::WindowsOrLinux, None).expect("plan");
    let (first, first_seen) = recorder();
    assert_eq!(reopen(&f.state, &id, Arc::clone(&first)).expect("reopen"), None);
    register(&f.state, &plan, first).expect("register");
    assert_eq!(open_label(&f.state, &id).expect("open"), format!("web-{id}"));
    let rows = web::list(&f.state).expect("list");
    assert_eq!((rows.len(), rows[0].persistent), (1, false));

    let (second, second_seen) = recorder();
    assert_eq!(reopen(&f.state, &id, second).expect("reopen"), Some(format!("web-{id}")));
    assert!(closed(&f.state, &id));
    assert!(!closed(&f.state, &id), "web_close + Destroyed close once");
    assert!(first_seen.lock().expect("m").is_empty());
    assert_eq!(*second_seen.lock().expect("m"), [json!({"kind": "closed"})], "the new channel");
    assert_eq!(open_label(&f.state, &id).expect_err("closed").code, "session.not_found");
    let events = audit_events(&f.state);
    assert!(events.contains(&"web_opened".to_owned()) && events.contains(&"web_closed".to_owned()));
    let log = std::fs::read_to_string(f.state.data_dir.join(crate::state::AppState::AUDIT_FILE))
        .expect("audit");
    assert!(log.contains(r#""origin":"https://console.example.test""#), "origin, never a path");
}

#[test]
fn persistent_flag_is_the_effective_storage() {
    let f = unlocked();
    let id = web_connection(&f, json!({ "url": "https://console.example.test", "persistent": true }));
    let plan = web::plan(&f.state, &id, StorageOs::MacOs { major: 12 }, None).expect("plan");
    register(&f.state, &plan, recorder().0).expect("register");
    assert!(!web::list(&f.state).expect("list")[0].persistent, "macOS 12 fell back");
}

#[test]
fn zoom_range() {
    for ok in [0.25, 1.0, 5.0] {
        assert!((check_zoom(ok).expect("ok") - ok).abs() < f64::EPSILON);
    }
    for bad in [0.0, 0.24, 5.01, f64::NAN, f64::INFINITY, -1.0] {
        assert_eq!(check_zoom(bad).expect_err("bad").code, "input.invalid");
    }
}

#[test]
fn clear_data_needs_a_web_connection_and_is_audited() {
    let f = unlocked();
    let id = web_connection(&f, json!({ "url": "https://console.example.test", "persistent": true }));
    let dir = web::store_dir(&f.state, &id);
    std::fs::create_dir_all(&dir).expect("mk");
    assert!(clear_data(&f.state, &id).expect("clear"));
    assert!(!dir.exists());
    assert!(!clear_data(&f.state, &id).expect("clear again"));
    assert!(audit_events(&f.state).contains(&"web_data_cleared".to_owned()));
    let root = f.state.with_ready(|_, s| Ok(crate::commands::tree::root_id(s).to_string())).expect("root");
    let ssh = crate::commands::tree::ConnectionFields::basic(&root, "b", "ssh", "ssh.example.test");
    let ssh = crate::commands::tree::create_connection(&f.state, ssh).expect("ssh").id;
    assert_eq!(clear_data(&f.state, &ssh).expect_err("ssh").code, "input.invalid");
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(clear_data(&f.state, &id).expect_err("locked").code, "vault.locked");
}
