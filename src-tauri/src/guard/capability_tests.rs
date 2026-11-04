//! Capability snapshots (ADR-0013 test plan): `main` keeps `core:default` plus the full app
//! set, `detached` holds exactly the six session commands, `web` grants nothing, and no
//! capability names a dialog, file-system or shell permission.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use super::{Scope, COMMANDS};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(rel: &str) -> Value {
    let text = std::fs::read_to_string(root().join(rel)).expect(rel);
    serde_json::from_str(&text).expect(rel)
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string entry").to_owned())
        .collect()
}

fn allow(command: &str) -> String {
    format!("allow-{}", command.replace('_', "-"))
}

/// Every capability file as `(file name, json)`.
fn capabilities() -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = std::fs::read_dir(root().join("capabilities"))
        .expect("capabilities dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .map(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned();
            (name.clone(), read_json(&format!("capabilities/{name}")))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn exactly_three_capabilities_are_registered() {
    let names: Vec<String> = capabilities().into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["detached.json", "main.json", "web.json"]);
    let conf = read_json("tauri.conf.json");
    assert_eq!(strings(&conf["app"]["security"]["capabilities"]), ["main", "detached", "web"]);
    assert_eq!(conf["app"]["withGlobalTauri"], false);
}

#[test]
fn main_capability_is_core_default_plus_the_app_set() {
    let main = read_json("capabilities/main.json");
    assert_eq!(main["identifier"], "main");
    assert_eq!(strings(&main["windows"]), ["main"]);
    assert_eq!(strings(&main["permissions"]), ["core:default", "mooring-main"]);
    assert!(main.get("remote").is_none());
}

#[test]
fn main_permission_set_lists_every_command() {
    let text = std::fs::read_to_string(root().join("permissions/mooring-main.toml")).expect("set");
    assert!(text.contains("identifier = \"mooring-main\""));
    let listed: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix('"').and_then(|l| l.strip_suffix("\",")))
        .collect();
    let want: Vec<String> = COMMANDS.iter().map(|(n, _)| allow(n)).collect();
    assert_eq!(listed, want, "permissions/mooring-main.toml != guard/table.rs");
}

#[test]
fn detached_capability_is_exactly_the_six_session_commands() {
    let d = read_json("capabilities/detached.json");
    assert_eq!(strings(&d["windows"]), ["detached-*"]);
    assert!(d.get("remote").is_none() && d.get("webviews").is_none());
    let have: BTreeSet<String> = strings(&d["permissions"]).into_iter().collect();
    let want: BTreeSet<String> = [
        "allow-session-attach",
        "allow-session-send",
        "allow-session-close",
        "allow-session-frame-ack",
        "allow-session-screenshot",
        "allow-window-attach",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(have, want);
    assert_eq!(strings(&d["permissions"]).len(), 6, "no duplicates");
    let session: BTreeSet<String> =
        COMMANDS.iter().filter(|(_, s)| *s == Scope::Session).map(|(n, _)| allow(n)).collect();
    assert_eq!(have, session, "detached.json != Scope::Session rows");
    for refused in ["vault", "credential", "session-open", "core:"] {
        assert!(have.iter().all(|p| !p.contains(refused)), "{refused}");
    }
}

#[test]
fn web_capability_grants_nothing() {
    let w = read_json("capabilities/web.json");
    assert_eq!(w["identifier"], "web");
    assert_eq!(strings(&w["windows"]), ["web-*"]);
    assert_eq!(w["permissions"], serde_json::json!([]));
    for key in ["remote", "webviews", "local", "platforms"] {
        assert!(w.get(key).is_none(), "web.json must not set {key}");
    }
}

#[test]
fn no_capability_names_dialog_fs_or_shell() {
    for (name, cap) in capabilities() {
        for p in strings(&cap["permissions"]) {
            for bad in ["dialog:", "fs:", "shell:", "http:", "opener:", "core:webview", "core:window"] {
                assert!(!p.starts_with(bad), "{name}: {p}");
            }
        }
        assert!(cap.get("remote").is_none(), "{name}: no remote capability in A2");
    }
}
