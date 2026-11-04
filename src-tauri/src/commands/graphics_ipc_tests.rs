//! `known_certs_*` and `connection_options_*` against a temp state.

use mooring_core::known_certs::{fingerprint, CertProtocol, KnownCerts};
use serde_json::json;
use time::OffsetDateTime;

use super::*;
use crate::commands::conn_options;
use crate::commands::tree::{self, ConnectionFields};
use crate::state::testing::*;

fn connection(f: &Fixture, protocol: &str) -> String {
    let root = f.state.with_ready(|_, s| Ok(tree::root_id(s).to_string())).expect("root");
    let fields = ConnectionFields::basic(&root, "c", protocol, "desk.example.test");
    tree::create_connection(&f.state, fields).expect("connection").id
}

#[test]
fn list_and_remove_pins_with_audit() {
    let f = unlocked();
    assert!(list(&f.state, CertProtocol::Rdp).expect("empty").is_empty());
    let path = known_certs_path(&f.state, CertProtocol::Rdp);
    let sha = fingerprint(b"leaf");
    KnownCerts::add_and_save(&path, "Desk.example.test", 3389, &sha, OffsetDateTime::UNIX_EPOCH)
        .expect("pin");
    let pins = list(&f.state, CertProtocol::Rdp).expect("list");
    assert_eq!(pins.len(), 1);
    let v = serde_json::to_value(&pins[0]).expect("json");
    assert!(v["fingerprint"].as_str().expect("fp").starts_with("SHA256:"), "{v}");
    assert!(v["hostHash"].as_str().expect("h").starts_with("|2|"), "host names stay hashed: {v}");
    assert!(v.get("addedAt").is_some(), "{v}");
    assert!(v.get("host").is_none(), "no connection names this host yet: {v}");
    // U2: a pin for one of the user's own connections is named in Rust.
    connection(&f, "rdp");
    connection(&f, "vnc");
    let v = serde_json::to_value(&list(&f.state, CertProtocol::Rdp).expect("list")[0]).expect("j");
    assert_eq!((v["host"].clone(), v["port"].clone()), (json!("desk.example.test"), json!(3389)), "{v}");
    assert!(list(&f.state, CertProtocol::Vnc).expect("vnc").is_empty(), "separate stores");

    assert_eq!(remove(&f.state, CertProtocol::Rdp, "other.example.test", 3389).expect("r").removed, 0);
    assert_eq!(remove(&f.state, CertProtocol::Rdp, "desk.example.test", 3389).expect("r").removed, 1);
    assert!(list(&f.state, CertProtocol::Rdp).expect("list").is_empty());
    let log = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("audit");
    assert_eq!(log.matches(r#""event":"cert_removed""#).count(), 2, "{log}");
    assert!(log.contains(r#""host":"desk.example.test:3389","removed":1"#), "{log}");
}

#[test]
fn hostile_known_certs_input_is_refused() {
    let f = unlocked();
    for (host, port) in [("", 3389), ("a b", 3389), ("x\u{202e}y", 3389), ("h", 0), ("h", 70_000)] {
        let e = remove(&f.state, CertProtocol::Vnc, host, port).expect_err("bad");
        assert_eq!(e.code, "input.invalid", "{host:?}:{port}");
    }
    let long = "h".repeat(mooring_core::MAX_HOST + 1);
    assert_eq!(remove(&f.state, CertProtocol::Vnc, &long, 1).expect_err("long").code, "input.invalid");
    assert!(serde_json::from_value::<CertProtocol>(json!("ssh")).is_err(), "rdp | vnc only");
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(list(&f.state, CertProtocol::Rdp).expect_err("locked").code, "vault.locked");
    let e = remove(&f.state, CertProtocol::Rdp, "h", 1).expect_err("locked");
    assert_eq!(e.code, "vault.locked");
}

#[test]
fn options_round_trip_and_validation() {
    let f = unlocked();
    let rdp = connection(&f, "rdp");
    let v = serde_json::to_value(conn_options::get(&f.state, &rdp).expect("defaults")).expect("j");
    assert_eq!(v["keyboardLayout"], 0x0409, "{v}");
    assert_eq!(v["maxFps"], 30, "{v}");
    let stored = conn_options::set(
        &f.state,
        &rdp,
        json!({"keyboardLayout": 0x041F, "clipboard": "off", "maxFps": 60, "allowTlsWithoutNla": true}),
    )
    .expect("set");
    let v = serde_json::to_value(&stored).expect("json");
    assert_eq!((v["clipboard"].clone(), v["maxFps"].clone()), (json!("off"), json!(60)));
    let again = serde_json::to_value(conn_options::get(&f.state, &rdp).expect("get")).expect("j");
    assert_eq!(again, v, "round trip");

    for bad in [
        json!({"maxFps": 45}),
        json!({"keyboardLayout": 1}),
        json!({"unknown": true}),
        json!({"clipboard": "everything"}),
        json!([1, 2]),
        json!({"caPem": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}),
    ] {
        let e = conn_options::set(&f.state, &rdp, bad.clone()).expect_err("refused");
        assert_eq!(e.code, "input.invalid", "{bad}");
        assert!(!e.message.contains("everything") && !e.message.contains("PRIVATE"), "{}", e.message);
    }
    let huge = json!({ "caPem": "x".repeat(200 * 1024) });
    assert_eq!(conn_options::set(&f.state, &rdp, huge).expect_err("big").code, "input.invalid");

    let ssh = connection(&f, "ssh");
    assert!(conn_options::set(&f.state, &ssh, json!({})).is_ok(), "{{}} for protocols without options");
    let e = conn_options::set(&f.state, &ssh, json!({"maxFps": 30})).expect_err("rdp field on ssh");
    assert_eq!(e.code, "input.invalid");
    let vnc = connection(&f, "vnc");
    let v = conn_options::set(&f.state, &vnc, json!({"viewOnly": true})).expect("vnc");
    assert_eq!(serde_json::to_value(&v).expect("j")["shared"], true, "defaults filled in");
    assert_eq!(conn_options::get(&f.state, "nope").expect_err("id").code, "input.invalid");
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(conn_options::get(&f.state, &rdp).expect_err("locked").code, "vault.locked");
}

fn option_changes(f: &Fixture) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(f.dir.path().join(crate::state::AppState::AUDIT_FILE)).unwrap_or_default();
    text.lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("json"))
        .filter(|v| v["event"] == "connection_options_changed")
        .collect()
}

/// L-22: every change is audited by field name; weakening changes are flagged; no values.
#[test]
fn option_changes_are_audited_by_name() {
    const PEM_A: &str = "-----BEGIN CERTIFICATE-----\nMAAAAAAAAAAAAAAAAAAAAAAA\n-----END CERTIFICATE-----\n";
    const PEM_B: &str = "-----BEGIN CERTIFICATE-----\nMAEBAQEBAQEBAQEBAQEBAQEB\n-----END CERTIFICATE-----\n";
    let f = unlocked();
    let rdp = connection(&f, "rdp");
    let vnc = connection(&f, "vnc");
    let web = connection(&f, "web");
    let set = |id: &str, v: serde_json::Value| conn_options::set(&f.state, id, v).expect("set");
    set(&rdp, json!({"maxFps": 60}));
    set(&rdp, json!({"maxFps": 60}));
    set(&rdp, json!({"maxFps": 60, "allowTlsWithoutNla": true}));
    set(&rdp, json!({"maxFps": 60, "allowTlsWithoutNla": true, "caPem": format!("{PEM_A}{PEM_B}")}));
    set(&vnc, json!({"security": "allow_plaintext"}));
    set(&vnc, json!({"security": "allow_plaintext", "allowNoAuth": true}));
    set(&vnc, json!({"security": "require_tls", "viewOnly": true}));
    set(&web, json!({"url": "https://app.example.test/", "persistent": true}));
    let log = option_changes(&f);
    let summary: Vec<(String, bool)> = log
        .iter()
        .map(|e| (e["changed"].as_array().expect("changed").iter().map(|c| c.as_str().expect("s")).collect::<Vec<_>>().join(","), e["weakened"] == true))
        .collect();
    let want = [
        ("maxFps", false),
        ("allowTlsWithoutNla", true),
        ("caPem", true),
        ("security", true),
        ("allowNoAuth", true),
        // `set` replaces every option: allowNoAuth falls back to its default.
        ("allowNoAuth,security,viewOnly", false),
        // No readable previous web options (an empty url does not validate): all fields.
        ("allowHttp,allowedOrigins,persistent,url", true),
    ];
    let want: Vec<(String, bool)> = want.iter().map(|(c, w)| ((*c).to_owned(), *w)).collect();
    assert_eq!(summary, want, "an unchanged re-save is not audited");
    assert_eq!(log[2]["ca_pem"], json!([
        "SHA256:blF92pAAXGktNKs+PW9WDfwVsFFAHs+/wXZsKe17guc",
        "SHA256:PWrgacgLLVfqmfBfK2zpKcTGOPaNXO2tivitvX5Sy88"
    ]));
    let text = std::fs::read_to_string(f.dir.path().join(crate::state::AppState::AUDIT_FILE)).expect("log");
    assert!(!text.contains("app.example.test") && !text.contains("MAAAA"), "no option values: {text}");
}
