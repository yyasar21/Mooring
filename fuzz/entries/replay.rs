//! Replays the committed seed corpus and the crash regressions of one fuzz target through its
//! entry point under plain `cargo test` (stable toolchain, no libFuzzer). Included with
//! `#[path]` by `crates/*/tests/fuzz_corpus.rs`; see docs/qa/fuzzing.md.

use std::path::{Path, PathBuf};

/// `<repo>/fuzz`, from a crate under `crates/`.
pub fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

/// Run `entry` on every file in `fuzz/corpus/<target>/` and `fuzz/regressions/<target>/`
/// (dot-files skipped). Returns how many inputs ran. Panics, naming the file, when the entry
/// panics, and when the seed corpus is missing or empty (a silent pass would hide a broken path).
#[allow(dead_code)] // not every including test uses both forms
pub fn replay(target: &str, entry: fn(&[u8])) -> usize {
    replay_except(target, entry, &[])
}

/// [`replay`], minus the named files in `fuzz/regressions/<target>/`. Only for a regression
/// whose parser fix is still open; the caller must replay it in its own `#[ignore]`d test that
/// names the finding, and each name must exist (a stale exception fails).
#[allow(dead_code)] // not every including test uses both forms
pub fn replay_except(target: &str, entry: fn(&[u8]), open_regressions: &[&str]) -> usize {
    for name in open_regressions {
        let path = fuzz_dir().join("regressions").join(target).join(name);
        assert!(path.is_file(), "open regression {} does not exist", path.display());
    }
    let mut ran = 0;
    for kind in ["corpus", "regressions"] {
        let dir = fuzz_dir().join(kind).join(target);
        let Ok(read) = std::fs::read_dir(&dir) else {
            assert!(kind != "corpus", "missing seed corpus {}", dir.display());
            continue;
        };
        let mut files: Vec<PathBuf> = read
            .map(|e| e.expect("read corpus entry").path())
            .filter(|p| p.is_file())
            .filter(|p| p.file_name().is_some_and(|n| !n.to_string_lossy().starts_with('.')))
            .filter(|p| {
                kind != "regressions"
                    || !p.file_name().is_some_and(|n| open_regressions.iter().any(|o| n == *o))
            })
            .collect();
        files.sort();
        for file in files {
            let data = std::fs::read(&file).expect("read corpus file");
            let outcome = std::panic::catch_unwind(|| entry(&data));
            assert!(outcome.is_ok(), "fuzz entry `{target}` panicked on {}", file.display());
            ran += 1;
        }
    }
    assert!(ran > 0, "no inputs replayed for `{target}`");
    ran
}
