//! Checked-in JSON lists that other parts of the repo (the UI's vitest) read: a `#[test]`
//! keeps each one equal to the Rust source of truth.
//!
//! Regenerate with `MOORING_BLESS=1 cargo test -p mooring-app golden`.

use std::path::Path;

/// Assert that `file` (relative to `src-tauri/`) holds `items`, sorted and deduplicated, as a
/// pretty JSON array. With `MOORING_BLESS=1` the file is rewritten instead.
pub fn check_sorted_list(file: &str, items: &[&str]) {
    let mut want: Vec<&str> = items.to_vec();
    want.sort_unstable();
    want.dedup();
    let mut text = serde_json::to_string_pretty(&want).expect("json");
    text.push('\n');
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
    if std::env::var_os("MOORING_BLESS").is_some() {
        std::fs::write(&path, &text).expect("write golden file");
        return;
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        have.replace("\r\n", "\n"),
        text,
        "{file} is out of date; run `MOORING_BLESS=1 cargo test -p mooring-app golden`"
    );
}

/// Assert that `file` (relative to `src-tauri/`) holds `value` as pretty JSON. With
/// `MOORING_BLESS=1` the file is rewritten instead.
pub fn check_json(file: &str, value: &impl serde::Serialize) {
    let mut text = serde_json::to_string_pretty(value).expect("json");
    text.push('\n');
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
    if std::env::var_os("MOORING_BLESS").is_some() {
        std::fs::write(&path, &text).expect("write golden file");
        return;
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        have.replace("\r\n", "\n"),
        text,
        "{file} is out of date; run `MOORING_BLESS=1 cargo test -p mooring-app golden`"
    );
}

/// String literals in `src/` that look like `area.reason` but are not error codes.
const NOT_CODES: &[&str] = &[
    "app.autolock",
    "app.syslog",
    "app.update",
    // ADR-0024: the ssh-sk-helper setting key, not an error code.
    "app.ssh_sk_helper",
    "audit.jsonl",
    // Review 9 L-50: the persisted bws pin file name.
    "bws_pins.json",
    "mooring.db",
    "sync.config",
    "tauri.localhost",
    // ADR-0021: a web storage-fallback reason for the log, not an error code.
    "web.portable_ephemeral",
];

/// Every `IpcError` code the app can emit, collected from the non-test sources: each
/// `"area.reason"` literal (codes are only ever written as literals: `IpcError::new("…")`,
/// `Self::new("…")` and the `VaultError` match arms) minus [`NOT_CODES`], plus the first
/// argument of any `IpcError::new(` / `Self::new(` call (catches dot-less codes such as
/// `internal`). A new non-code `a.b` literal must be added to [`NOT_CODES`].
fn emitted_codes() -> Vec<String> {
    let mut codes = std::collections::BTreeSet::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src dir") {
            let path = entry.expect("entry").path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let skip =
                name.ends_with("_tests.rs") || name.starts_with("test_") || name == "golden.rs";
            if skip || path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source");
            let text = text.split("#[cfg(test)]\nmod tests").next().unwrap_or_default();
            for (i, lit) in text.split('"').enumerate() {
                let is_code_shape = !lit.is_empty()
                    && lit.bytes().all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.')
                    && lit.as_bytes()[0].is_ascii_lowercase();
                if i % 2 == 0 || !is_code_shape {
                    continue;
                }
                let before = text.split('"').nth(i - 1).unwrap_or_default().trim_end();
                // Codes are exactly `area.reason`; `x_tests.rs` (`#[path]`) is a file name.
                let dotted = lit.matches('.').count() == 1
                    && !lit.ends_with('.')
                    && Path::new(lit).extension().and_then(|e| e.to_str()) != Some("rs")
                    && !NOT_CODES.contains(&lit);
                let error_new =
                    before.ends_with("IpcError::new(") || before.ends_with("Self::new(");
                if dotted || error_new {
                    codes.insert(lit.to_owned());
                }
            }
        }
    }
    codes.into_iter().collect()
}

#[test]
fn golden_ipc_codes_file_is_in_sync() {
    let codes = emitted_codes();
    let refs: Vec<&str> = codes.iter().map(String::as_str).collect();
    for expected in ["input.invalid", "sftp.exists", "vault.locked", "session.not_found"] {
        assert!(refs.contains(&expected), "{expected} not found by the scanner");
    }
    check_sorted_list("ipc-codes.json", &refs);
}

/// The exact versions `Cargo.lock` must hold for the `WebView` layer. Security review 6
/// (`docs/security/a3-review-6.md`, N-46, closing review 5 L-32): `tauri` is pinned in
/// `src-tauri/Cargo.toml`, but `wry` and `tauri-runtime-wry` carry the storage semantics
/// behind L-29 / L-33 (per-webview `WebView2` environments, `incognito` + `data_directory`)
/// and are held only by the lock file. A bump must go through security review: update this
/// list in the same change. Review 6b B-6 / N-49: the safety of the native confirmations
/// depends on how `tauri-plugin-dialog` remaps rfd's positional results (its cancel slot
/// carries Escape and the close box) and on `rfd`'s per-OS result mapping; bumping either
/// needs a security re-read of `desktop.rs` and the three `message_dialog.rs` backends.
const LOCKED_WEBVIEW_CRATES: &[(&str, &str)] = &[
    ("wry", "0.57.1"),
    ("tauri-runtime-wry", "2.12.3"),
    ("tauri-plugin-dialog", "2.8.4"),
    ("rfd", "0.17.2"),
];

fn locked_version(lock: &str, name: &str) -> Option<String> {
    let header = format!("name = \"{name}\"\n");
    lock.split("[[package]]\n")
        .find(|pkg| pkg.starts_with(&header))
        .and_then(|pkg| pkg.lines().find_map(|l| l.strip_prefix("version = ")))
        .map(|v| v.trim_matches('"').to_owned())
}

/// Review 6 N-46: the `WebView` crates stay at the reviewed versions until the next review.
#[test]
fn cargo_lock_pins_the_reviewed_webview_crates() {
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.lock");
    let lock =
        std::fs::read_to_string(&lock_path).expect("workspace Cargo.lock").replace("\r\n", "\n");
    for (name, want) in LOCKED_WEBVIEW_CRATES {
        let have = locked_version(&lock, name);
        assert_eq!(
            have.as_deref(),
            Some(*want),
            "{name} must stay at {want} (security review 6 N-46, 6b N-49, review 5 L-32); found {have:?}"
        );
    }
    assert_eq!(
        locked_version("[[package]]\nname = \"x\"\nversion = \"1.2.3\"\n", "x").as_deref(),
        Some("1.2.3")
    );
    assert_eq!(
        locked_version("[[package]]\nname = \"xy\"\nversion = \"1.2.3\"\n", "x"),
        None,
        "exact names only"
    );
}
