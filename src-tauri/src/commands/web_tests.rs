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
    let plan = web::plan(&f.state, &id, StorageOs::Linux, None).expect("plan");
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

/// Review 5 L-30: `folder_delete` closes the windows and wipes the stores of every web
/// connection below the folder; `connection_delete` destroys the window before the store goes.
#[test]
fn folder_delete_closes_windows_and_wipes_stores() {
    use crate::commands::tree;
    let f = unlocked();
    let root = f.state.with_ready(|_, s| Ok(tree::root_id(s).to_string())).expect("root");
    let folder = tree::create_folder(&f.state, &root, "consoles").expect("folder").id;
    let sub = tree::create_folder(&f.state, &folder, "deep").expect("sub").id;
    let mk = |folder: &str, host: &str, opts: serde_json::Value| {
        let fields = tree::ConnectionFields::basic(folder, host, "web", host);
        let id = tree::create_connection(&f.state, fields).expect("web").id;
        crate::commands::conn_options::set(&f.state, &id, opts).expect("options");
        id
    };
    let a = mk(&folder, "a.example.test", json!({ "url": "https://a.example.test", "persistent": true }));
    let b = mk(&sub, "b.example.test", json!({ "url": "https://b.example.test" }));
    let outside = mk(&root, "c.example.test", json!({ "url": "https://c.example.test", "persistent": true }));
    for id in [&a, &outside] {
        std::fs::create_dir_all(web::store_dir(&f.state, id).join("Cookies")).expect("mk");
    }
    // `a` is open with a persistent store, `b` open as a Windows ephemeral window.
    let plan_a = web::plan(&f.state, &a, StorageOs::Linux, None).expect("plan");
    let plan_b = web::plan(&f.state, &b, StorageOs::Windows, None).expect("plan");
    std::fs::create_dir_all(plan_b.ephemeral_dir().expect("dir")).expect("mk");
    let (sink_a, seen_a) = recorder();
    let (sink_b, seen_b) = recorder();
    register(&f.state, &plan_a, sink_a).expect("register a");
    register(&f.state, &plan_b, sink_b).expect("register b");
    let destroyed_labels = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&destroyed_labels);
    let destroy = move |label: &str| rec.lock().expect("m").push(label.to_owned());

    let mut gone = tree::delete_folder_with(&f.state, &folder, &destroy).expect("delete");
    gone.sort();
    let mut want = vec![a.clone(), b.clone()];
    want.sort();
    assert_eq!(gone, want, "descendant web connections, both levels");
    let mut labels = destroyed_labels.lock().expect("m").clone();
    labels.sort();
    assert_eq!(labels, [format!("web-{}", want[0]), format!("web-{}", want[1])], "windows closed");
    assert!(!web::store_dir(&f.state, &a).exists(), "store of a gone");
    assert!(!plan_b.ephemeral_dir().expect("dir").exists(), "ephemeral profile of b gone");
    assert!(web::store_dir(&f.state, &outside).exists(), "a sibling outside the folder stays");
    assert_eq!(*seen_a.lock().expect("m"), [json!({"kind": "closed"})]);
    assert_eq!(*seen_b.lock().expect("m"), [json!({"kind": "closed"})]);
    assert!(web::list(&f.state).expect("list").is_empty(), "registry entries gone");
    let events = audit_events(&f.state);
    assert_eq!(events.iter().filter(|e| *e == "web_closed").count(), 2);

    // connection_delete: the window is destroyed before the directory is removed.
    let plan_c = web::plan(&f.state, &outside, StorageOs::Linux, None).expect("plan");
    register(&f.state, &plan_c, recorder().0).expect("register c");
    let order = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&order);
    let dir_c = web::store_dir(&f.state, &outside);
    let destroy = move |label: &str| rec.lock().expect("m").push((label.to_owned(), dir_c.exists()));
    tree::delete_connection_with(&f.state, &outside, &destroy).expect("delete");
    assert_eq!(*order.lock().expect("m"), [(format!("web-{outside}"), true)], "destroyed first");
    assert!(!web::store_dir(&f.state, &outside).exists());
    // No window: still a clean delete.
    let d = mk(&root, "d.example.test", json!({ "url": "https://d.example.test" }));
    let calls = Arc::new(Mutex::new(0));
    let rec = Arc::clone(&calls);
    tree::delete_connection_with(&f.state, &d, &move |_| *rec.lock().expect("m") += 1).expect("delete");
    assert_eq!(*calls.lock().expect("m"), 0);
}

/// Review 5 N-37: the lock and protocol checks run before any browsing data is touched.
#[test]
fn clear_data_checks_before_wiping_the_open_window() {
    let f = unlocked();
    let id = web_connection(&f, json!({ "url": "https://console.example.test", "persistent": true }));
    let wiped = Arc::new(Mutex::new(0));
    let wipe = |ok: bool| {
        let rec = Arc::clone(&wiped);
        Some(move || {
            *rec.lock().expect("m") += 1;
            if ok { Ok(()) } else { Err(IpcError::new("window.failed", "nope")) }
        })
    };
    let dir = web::store_dir(&f.state, &id);
    std::fs::create_dir_all(&dir).expect("mk");
    clear_data_with(&f.state, &id, wipe(true)).expect("clear");
    assert_eq!((*wiped.lock().expect("m"), dir.exists()), (1, false));
    assert_eq!(clear_data_with(&f.state, &id, wipe(false)).expect_err("wipe failed").code, "window.failed");
    let root = f.state.with_ready(|_, s| Ok(crate::commands::tree::root_id(s).to_string())).expect("root");
    let ssh = crate::commands::tree::ConnectionFields::basic(&root, "b", "ssh", "ssh.example.test");
    let ssh = crate::commands::tree::create_connection(&f.state, ssh).expect("ssh").id;
    assert_eq!(clear_data_with(&f.state, &ssh, wipe(true)).expect_err("ssh").code, "input.invalid");
    assert_eq!(clear_data_with(&f.state, "nope", wipe(true)).expect_err("id").code, "input.invalid");
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(clear_data_with(&f.state, &id, wipe(true)).expect_err("locked").code, "vault.locked");
    assert_eq!(*wiped.lock().expect("m"), 2, "refused calls never reached the window");
    let cleared = audit_events(&f.state).iter().filter(|e| *e == "web_data_cleared").count();
    assert_eq!(cleared, 1);
}

/// Review 5 N-30: a window built after a lock landed is hidden.
#[test]
fn window_built_during_a_lock_is_hidden() {
    let f = unlocked();
    let hidden = Arc::new(Mutex::new(0));
    let hide = || {
        let rec = Arc::clone(&hidden);
        move || *rec.lock().expect("m") += 1
    };
    assert!(!hide_if_locked(&f.state, hide()));
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert!(hide_if_locked(&f.state, hide()));
    assert_eq!(*hidden.lock().expect("m"), 1);
    let no_vault = crate::state::testing::empty();
    assert!(hide_if_locked(&no_vault.state, hide()), "no vault counts as locked");
}

/// Review 5 L-29: the `Destroyed` event removes the ephemeral profile.
#[test]
fn closing_removes_the_ephemeral_profile() {
    let f = unlocked();
    let id = web_connection(&f, json!({ "url": "https://console.example.test" }));
    let plan = web::plan(&f.state, &id, StorageOs::Windows, None).expect("plan");
    let dir = plan.ephemeral_dir().expect("dir").clone();
    std::fs::create_dir_all(&dir).expect("mk");
    register(&f.state, &plan, recorder().0).expect("register");
    assert!(!web::list(&f.state).expect("list")[0].persistent);
    destroyed(&f.state, &id);
    assert!(!dir.exists());
    assert!(!closed(&f.state, &id), "once");
}

/// Review 5 N-32: the init script keeps its upload hooks (best effort, string-checked).
#[test]
fn init_script_hooks() {
    let s = web::window::INIT_SCRIPT;
    for hook in [
        "showOpenFilePicker",
        "showSaveFilePicker",
        "showDirectoryPicker",
        "HTMLInputElement.prototype",
        "'showPicker'",
        "addEventListener('click'",
        "addEventListener('drop'",
        "t.type === 'file'",
        "NotAllowedError",
    ] {
        assert!(s.contains(hook), "{hook}");
    }
}
