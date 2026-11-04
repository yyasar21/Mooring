//! Web plan (stored data only), storage per OS, titles, registry.

use serde_json::json;

use super::*;
use crate::commands::{conn_options, tree, vault};
use crate::state::testing::{unlocked, Fixture};

pub(crate) fn web_connection(f: &Fixture, options: serde_json::Value) -> String {
    let root = f.state.with_ready(|_, s| Ok(tree::root_id(s).to_string())).expect("root");
    let fields = tree::ConnectionFields::basic(&root, "vCenter", "web", "console.example.test");
    let id = tree::create_connection(&f.state, fields).expect("web connection").id;
    conn_options::set(&f.state, &id, options).expect("options");
    id
}

const LINUX: StorageOs = StorageOs::WindowsOrLinux;

#[test]
fn plan_uses_stored_options_only() {
    let f = unlocked();
    let id = web_connection(&f, json!({
        "url": "https://console.example.test/ui/",
        "allowedOrigins": ["https://sso.example.test"],
    }));
    let p = plan(&f.state, &id, LINUX, None).expect("plan");
    assert_eq!(p.label, format!("web-{id}"));
    assert_eq!(p.name, "vCenter");
    assert_eq!(p.url.as_str(), "https://console.example.test/ui/");
    assert_eq!(p.origin(), "https://console.example.test");
    assert_eq!(p.policy.allowed(), ["https://console.example.test", "https://sso.example.test"]);
    assert_eq!(p.storage, Storage::Ephemeral, "ephemeral by default (owner decision 7)");
    assert!(!p.persistent_refused);
    assert_eq!(native_title(&p.name, &p.origin()), "Mooring \u{b7} vCenter \u{b7} https://console.example.test");
}

#[test]
fn plan_refusals() {
    let f = unlocked();
    assert_eq!(plan(&f.state, "nope", LINUX, None).expect_err("id").code, "input.invalid");
    let missing = mooring_core::ConnectionId::new().to_string();
    assert_eq!(plan(&f.state, &missing, LINUX, None).expect_err("gone").code, "tree.not_found");
    let root = f.state.with_ready(|_, s| Ok(tree::root_id(s).to_string())).expect("root");
    let ssh = tree::ConnectionFields::basic(&root, "box", "ssh", "ssh.example.test");
    let ssh = tree::create_connection(&f.state, ssh).expect("ssh").id;
    assert_eq!(plan(&f.state, &ssh, LINUX, None).expect_err("ssh").code, "input.invalid");
    // A web connection without a stored URL does not validate.
    let fields = tree::ConnectionFields::basic(&root, "empty", "web", "console.example.test");
    let empty = tree::create_connection(&f.state, fields).expect("web").id;
    assert_eq!(plan(&f.state, &empty, LINUX, None).expect_err("no url").code, "input.invalid");
    let app = web_connection(&f, json!({ "url": "https://tauri.localhost/" }));
    assert_eq!(plan(&f.state, &app, LINUX, None).expect_err("app").code, "web.origin_refused");
    vault::lock(&f.state, None).expect("lock");
    // Any well-formed id: the vault check comes first.
    let id = mooring_core::ConnectionId::new().to_string();
    assert_eq!(plan(&f.state, &id, LINUX, None).expect_err("locked").code, "vault.locked");
}

#[test]
fn persistent_storage_per_os() {
    let f = unlocked();
    let id = web_connection(&f, json!({ "url": "https://console.example.test", "persistent": true }));
    let p = plan(&f.state, &id, LINUX, None).expect("plan");
    assert_eq!(p.storage, Storage::Directory(f.state.data_dir.join("web").join(&id)));
    let p = plan(&f.state, &id, StorageOs::MacOs { major: 14 }, None).expect("plan");
    let uuid = uuid::Uuid::parse_str(&id).expect("uuid");
    assert_eq!(p.storage, Storage::Identifier(*uuid.as_bytes()));
    for major in [0, 11, 13] {
        let p = plan(&f.state, &id, StorageOs::MacOs { major }, None).expect("plan");
        assert_eq!((p.storage, p.persistent_refused), (Storage::Ephemeral, true), "macOS {major}");
    }
    assert_eq!(macos_major("14.2.1"), 14);
    assert_eq!(macos_major(" 13 "), 13);
    assert_eq!(macos_major("garbage"), 0);
}

#[test]
fn store_dir_removal_is_scoped_to_the_connection() {
    let f = unlocked();
    let id = web_connection(&f, json!({ "url": "https://console.example.test", "persistent": true }));
    let dir = store_dir(&f.state, &id);
    std::fs::create_dir_all(dir.join("Cookies")).expect("mk");
    let other = store_dir(&f.state, &mooring_core::ConnectionId::new().to_string());
    std::fs::create_dir_all(&other).expect("mk other");
    assert!(remove_store_dir(&f.state, &id).expect("rm"));
    assert!(!dir.exists() && other.exists());
    assert!(!remove_store_dir(&f.state, &id).expect("again"), "already gone");
    for bad in ["../../etc", "", "web", "*"] {
        assert_eq!(remove_store_dir(&f.state, bad).expect_err(bad).code, "input.invalid");
    }
    // connection_delete wipes the store too.
    std::fs::create_dir_all(&dir).expect("mk");
    tree::delete_connection(&f.state, &id).expect("delete");
    assert!(!dir.exists(), "store removed with its connection");
}

#[test]
fn titles_are_sanitised() {
    assert_eq!(sanitize_title("  vSphere\tClient \n"), "vSphere Client");
    assert_eq!(sanitize_title("evil\u{202e}txt.exe\u{200b}\u{7}"), "eviltxt.exe");
    let long = "x".repeat(1000);
    assert_eq!(sanitize_title(&long).chars().count(), MAX_TITLE_CHARS);
    assert_eq!(sanitize_title("\u{fc}ber \u{1f600}"), "\u{fc}ber \u{1f600}");
}

#[test]
fn list_and_forget() {
    let f = unlocked();
    assert!(list(&f.state).expect("list").is_empty());
    let sink: WebSink = Arc::new(|_| true);
    let entry = WebEntry {
        label: "web-a".into(),
        origin: "https://a.example.test".into(),
        title: "A".into(),
        persistent: false,
        opened_at: "2026-11-04T10:00:00Z".into(),
        sink,
    };
    f.state.web.lock().expect("m").insert("a".into(), entry);
    let rows = list(&f.state).expect("list");
    let v = serde_json::to_value(&rows).expect("json");
    assert_eq!(v, json!([{
        "connectionId": "a", "windowLabel": "web-a", "origin": "https://a.example.test",
        "title": "A", "persistent": false, "openedAt": "2026-11-04T10:00:00Z"
    }]));
    assert!(forget(&f.state, "a").is_some());
    assert!(forget(&f.state, "a").is_none());
}

#[test]
fn web_events_wire_shape() {
    let cases = [
        (WebEvent::Title { title: "T".into() }, json!({"kind": "title", "title": "T"})),
        (WebEvent::Navigated { origin: "https://a.test".into() }, json!({"kind": "navigated", "origin": "https://a.test"})),
        (WebEvent::Blocked { origin: "https://b.test".into() }, json!({"kind": "blocked", "origin": "https://b.test"})),
        (WebEvent::DownloadBlocked { origin: "https://a.test".into() }, json!({"kind": "download_blocked", "origin": "https://a.test"})),
        (WebEvent::Closed, json!({"kind": "closed"})),
    ];
    for (e, want) in cases {
        assert_eq!(serde_json::to_value(&e).expect("json"), want);
    }
}
