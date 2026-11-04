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
