//! Stable replay of the Vault / OIDC fuzz corpora (`vault_kv_response`,
//! `vault_login_response`, `oidc_callback_url`), the A5 secrets-engine corpora
//! (`vault_db_creds`, `vault_ssh_sign`, `vault_pki_issue`, `connect_item_json`,
//! `bws_secret_json`) and crash regressions through the same entry points the cargo-fuzz targets
//! use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/bws_secret_json.rs"]
mod bws_secret_json;
#[path = "../../../fuzz/entries/connect_item_json.rs"]
mod connect_item_json;
#[path = "../../../fuzz/entries/oidc_callback_url.rs"]
mod oidc_callback_url;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;
#[path = "../../../fuzz/entries/vault_db_creds.rs"]
mod vault_db_creds;
#[path = "../../../fuzz/entries/vault_kv_response.rs"]
mod vault_kv_response;
#[path = "../../../fuzz/entries/vault_login_response.rs"]
mod vault_login_response;
#[path = "../../../fuzz/entries/vault_pki_issue.rs"]
mod vault_pki_issue;
#[path = "../../../fuzz/entries/vault_ssh_sign.rs"]
mod vault_ssh_sign;

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
fn vault_db_creds_corpus() {
    assert!(replay::replay("vault_db_creds", vault_db_creds::run) >= 5);
}

#[test]
fn vault_ssh_sign_corpus() {
    assert!(replay::replay("vault_ssh_sign", vault_ssh_sign::run) >= 2);
}

#[test]
fn vault_pki_issue_corpus() {
    assert!(replay::replay("vault_pki_issue", vault_pki_issue::run) >= 2);
}

#[test]
fn connect_item_json_corpus() {
    assert!(replay::replay("connect_item_json", connect_item_json::run) >= 4);
}

#[test]
fn bws_secret_json_corpus() {
    assert!(replay::replay("bws_secret_json", bws_secret_json::run) >= 5);
}

/// The `ssh/sign` seed carries the certificate of the entry's fixed subject key, so the fuzzer
/// starts past the certificate parser; no seed of the A5 corpora holds a private-key PEM block.
#[test]
fn a5_secrets_seeds_reach_the_mapping_and_hold_no_key_material() {
    let signed = String::from_utf8(seed("vault_ssh_sign", "signed-key")).expect("utf-8");
    let v: serde_json::Value = serde_json::from_str(&signed).expect("json");
    let cert = v["data"]["signed_key"].as_str().expect("signed_key");
    let subject = mooring_core::credential::testdata::SSH_CA_SUBJECT_PUB;
    mooring_core::credential::check_signed_certificate(cert, subject, 1).expect("seed cert fits");
    for target in [
        "vault_db_creds",
        "vault_ssh_sign",
        "vault_pki_issue",
        "connect_item_json",
        "bws_secret_json",
    ] {
        for e in std::fs::read_dir(replay::fuzz_dir().join("corpus").join(target)).expect("dir") {
            let text =
                String::from_utf8_lossy(&std::fs::read(e.expect("entry").path()).expect("read"))
                    .into_owned();
            assert!(!text.contains("PRIVATE KEY"), "{target}: no private-key PEM in a seed");
        }
    }
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
