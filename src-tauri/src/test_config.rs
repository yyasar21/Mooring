//! Test-only: the checked-in Tauri configs as JSON (ADR-0028 §1). `tauri.conf.json` is the dev
//! identity; the release identity is that file merged with `tauri.release.conf.json` under RFC
//! 7396, exactly as `release.yml` passes it (`--config`, overlay first).

use crate::build_channel::merge_patch;

fn read(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
    let text = std::fs::read_to_string(&path).expect("config file");
    serde_json::from_str(&text).expect("config json")
}

/// `tauri.conf.json` as checked in (dev identity).
pub fn base() -> serde_json::Value {
    read("tauri.conf.json")
}

/// `tauri.release.conf.json` alone.
pub fn overlay() -> serde_json::Value {
    read("tauri.release.conf.json")
}

/// Base merged with the release overlay: what a tag build compiles with.
pub fn release() -> serde_json::Value {
    let mut config = base();
    merge_patch(&mut config, &overlay());
    config
}
