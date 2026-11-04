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

const LINUX: StorageOs = StorageOs::Linux;

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
    // N-31: the app origin never reaches the store (options validation refuses *.localhost).
    let fields = tree::ConnectionFields::basic(&root, "app", "web", "tauri.localhost");
    let app = tree::create_connection(&f.state, fields).expect("web").id;
    let e = conn_options::set(&f.state, &app, json!({ "url": "https://tauri.localhost/" }));
    assert_eq!(e.expect_err("app origin").code, "input.invalid");
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
        ephemeral_dir: None,
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

/// Review 5 L-29: on Windows an ephemeral window gets its own profile directory (own
/// `WebView2` environment); elsewhere plain incognito.
#[test]
fn windows_ephemeral_gets_a_per_connection_directory() {
    let f = unlocked();
    let id = web_connection(&f, json!({ "url": "https://console.example.test" }));
    let p = plan(&f.state, &id, StorageOs::Windows, None).expect("plan");
    let dir = f.state.cache_dir.join(WEB_EPHEMERAL_DIR).join(&id);
    assert_eq!(p.storage, Storage::EphemeralDirectory(dir.clone()));
    assert_eq!(p.ephemeral_dir(), Some(&dir));
    assert!(!p.persistent(), "an ephemeral profile is not persistence");
    let other = web_connection(&f, json!({ "url": "https://other.example.test" }));
    let q = plan(&f.state, &other, StorageOs::Windows, None).expect("plan");
    assert_ne!(q.storage, p.storage, "one environment per connection");
    for os in [LINUX, StorageOs::MacOs { major: 14 }, StorageOs::MacOs { major: 12 }] {
        let p = plan(&f.state, &id, os, None).expect("plan");
        assert_eq!(p.storage, Storage::Ephemeral, "{os:?}");
        assert_eq!(p.ephemeral_dir(), None);
    }
    // Persistent on Windows is the data directory, as on Linux.
    let pid = web_connection(&f, json!({ "url": "https://console.example.test", "persistent": true }));
    let p = plan(&f.state, &pid, StorageOs::Windows, None).expect("plan");
    assert_eq!(p.storage, Storage::Directory(store_dir(&f.state, &pid)));
    assert!(p.persistent());
    assert_eq!(ephemeral_storage(&f.state, &id, StorageOs::Windows), Storage::EphemeralDirectory(dir));
    assert_eq!(ephemeral_storage(&f.state, &id, LINUX), Storage::Ephemeral);
}

/// Review 5 L-29 / L-30: the start sweeps.
#[test]
fn start_sweeps_remove_orphans_only() {
    let f = unlocked();
    let keep = web_connection(&f, json!({ "url": "https://a.example.test", "persistent": true }));
    let ephemeral = web_connection(&f, json!({ "url": "https://b.example.test" }));
    let web_root = f.state.data_dir.join(WEB_DATA_DIR);
    let orphan = web_root.join(mooring_core::ConnectionId::new().to_string());
    for d in [store_dir(&f.state, &keep), store_dir(&f.state, &ephemeral), orphan.clone(), web_root.join("junk")] {
        std::fs::create_dir_all(d.join("Cookies")).expect("mk");
    }
    std::fs::write(web_root.join("stray.file"), b"x").expect("file");
    assert_eq!(sweep::orphan_stores(&f.state), 4);
    assert!(store_dir(&f.state, &keep).exists(), "persistent web connection kept");
    assert!(!store_dir(&f.state, &ephemeral).exists(), "persistent: false has no store");
    assert!(!orphan.exists() && !web_root.join("junk").exists() && !web_root.join("stray.file").exists());
    assert_eq!(sweep::orphan_stores(&f.state), 0, "idempotent");
    // Locked: nothing is touched.
    std::fs::create_dir_all(&orphan).expect("mk");
    vault::lock(&f.state, None).expect("lock");
    assert_eq!(sweep::orphan_stores(&f.state), 0);
    assert!(orphan.exists());

    // Ephemeral profiles: everything not held by an open window goes (none at start).
    let stale = ephemeral_dir(&f.state, &ephemeral);
    let open = ephemeral_dir(&f.state, &keep);
    std::fs::create_dir_all(&stale).expect("mk");
    std::fs::create_dir_all(&open).expect("mk");
    let entry = WebEntry {
        label: format!("web-{keep}"),
        origin: "https://a.example.test".into(),
        title: String::new(),
        persistent: false,
        ephemeral_dir: Some(open.clone()),
        opened_at: "2026-11-04T10:00:00Z".into(),
        sink: Arc::new(|_| true),
    };
    f.state.web.lock().expect("m").insert(keep.clone(), entry);
    assert_eq!(sweep::ephemeral_profiles(&f.state), 1);
    assert!(!stale.exists() && open.exists());
    assert_eq!(sweep::ephemeral_profiles(&f.state), 0);
    assert_eq!(sweep::ephemeral_profiles(&crate::state::testing::empty().state), 0, "no directory yet");
}

/// Review 6 L-33: the OIDC window gets an own ephemeral profile on Windows, plain incognito
/// elsewhere; a profile left behind is swept at start with the web ones.
#[test]
fn oidc_window_storage_is_an_own_profile_on_windows() {
    let f = unlocked();
    let source = mooring_core::ConnectionId::new().to_string();
    let plan = crate::oidc_window::storage(&f.state, &source, StorageOs::Windows);
    let dir = plan.ephemeral_dir().expect("own profile on Windows").clone();
    assert_eq!(dir, f.state.cache_dir.join(WEB_EPHEMERAL_DIR).join(format!("oidc-{source}")));
    for os in [StorageOs::Linux, StorageOs::MacOs { major: 14 }, StorageOs::MacOs { major: 13 }] {
        assert_eq!(crate::oidc_window::storage(&f.state, &source, os), Storage::Ephemeral, "{os:?}");
    }
    std::fs::create_dir_all(dir.join("EBWebView")).expect("mk");
    assert_eq!(sweep::ephemeral_profiles(&f.state), 1, "leftover OIDC profile swept at start");
    assert!(!dir.exists());
}
