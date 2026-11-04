//! Fuzz entry `oidc_callback_url`: a navigation URL intercepted in the OIDC window, plus the
//! `auth_url` Vault returns (ADR-0016 §4). Shared by `fuzz/fuzz_targets/oidc_callback_url.rs`
//! and the stable replay in `crates/mooring-secrets/tests/fuzz_corpus.rs`.

use mooring_core::secret_source::OIDC_REDIRECT_URI;
use mooring_secrets::parse_callback;

/// Never panics. Only a URL on the fixed redirect origin + path is a callback at all, and only
/// with `code` and `state` and without `error` is it a valid one; the result is deterministic.
pub fn run(data: &[u8]) {
    mooring_secrets::fuzz::fuzz_oidc_callback_url(data);
    let Ok(s) = std::str::from_utf8(data) else { return };
    let first = parse_callback(s).map(|r| r.is_ok());
    assert_eq!(first, parse_callback(s).map(|r| r.is_ok()), "parse_callback is not deterministic");
    if first.is_some() {
        let path = OIDC_REDIRECT_URI.split_once("//").map_or("", |(_, r)| r);
        let path = path.find('/').map_or("", |i| &path[i..]);
        let lower = s.to_ascii_lowercase();
        assert!(lower.contains(path), "callback recognised on another path: {s:?}");
    }
}
