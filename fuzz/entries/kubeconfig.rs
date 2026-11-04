//! Fuzz entry `kubeconfig_parse`: hostile kubeconfig YAML pasted or imported by the user
//! (ADR-0009). Shared by `fuzz/fuzz_targets/kubeconfig_parse.rs` and
//! `crates/mooring-core/tests/fuzz_corpus.rs`.

use std::collections::BTreeSet;

use mooring_core::credential::kubeconfig::{self, MAX_CONTEXTS, MAX_CONTEXT_NAME, MAX_YAML};

/// Never panics; an accepted file honours the documented caps and is parsed deterministically.
pub fn run(data: &[u8]) {
    let Ok(info) = kubeconfig::parse(data) else {
        return;
    };
    assert!(data.len() <= MAX_YAML, "accepted an over-size kubeconfig");
    assert!(info.contexts.len() <= MAX_CONTEXTS, "context cap exceeded");
    let mut seen = BTreeSet::new();
    for name in &info.contexts {
        assert!(!name.is_empty() && name.len() <= MAX_CONTEXT_NAME, "context name out of bounds");
        assert!(seen.insert(name), "duplicate context name");
    }
    if let Some(current) = &info.current_context {
        assert!(info.contexts.contains(current), "current-context not among the contexts");
    }
    assert_eq!(kubeconfig::parse(data).ok(), Some(info), "parse is not deterministic");
}
