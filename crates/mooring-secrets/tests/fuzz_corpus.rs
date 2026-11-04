//! Stable replay of the Vault / OIDC fuzz corpora (`vault_kv_response`,
//! `vault_login_response`, `oidc_callback_url`) and crash regressions through the same entry
//! points the cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/oidc_callback_url.rs"]
mod oidc_callback_url;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;
#[path = "../../../fuzz/entries/vault_kv_response.rs"]
mod vault_kv_response;
#[path = "../../../fuzz/entries/vault_login_response.rs"]
mod vault_login_response;

use mooring_secrets::parse_callback;

fn seed(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(replay::fuzz_dir().join("corpus").join(target).join(name)).expect("seed")
}

#[test]
fn vault_kv_response_corpus() {
    assert!(replay::replay("vault_kv_response", vault_kv_response::run) >= 2);
}

#[test]
fn vault_login_response_corpus() {
    assert!(replay::replay("vault_login_response", vault_login_response::run) >= 2);
}

#[test]
fn oidc_callback_url_corpus() {
    assert!(replay::replay("oidc_callback_url", oidc_callback_url::run) >= 2);
}

/// The callback seed must stay a valid callback and the other-origin seed must stay `None`,
/// or the fuzzer only explores one branch.
#[test]
fn oidc_seeds_split_callback_and_other() {
    let text = |n: &str| String::from_utf8(seed("oidc_callback_url", n)).expect("utf-8");
    let cb = parse_callback(&text("callback")).expect("is the redirect").expect("well formed");
    assert_eq!((cb.0.as_str(), cb.1.as_str()), ("test-oidc-code", "st_00"));
    assert!(parse_callback(&text("other-origin")).is_none());
}
