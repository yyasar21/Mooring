use std::time::{Duration, UNIX_EPOCH};

use serde_json::json;

use super::*;
use crate::commands::credentials::{create, NewCredential, WireSecrets};
use crate::state::testing::*;

fn new(kind: &str, fields: serde_json::Value, secrets: &[(&str, &str)]) -> NewCredential {
    NewCredential { name: "ops".into(), kind: kind.into(), fields, secrets: WireSecrets::of(secrets) }
}

/// RFC 6238 SHA-1 seed "12345678901234567890" in base32.
const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[tokio::test]
async fn copy_secret_sets_clears_and_audits_with_the_name() {
    let f = unlocked();
    let c = create(&f.state, NewCredential::user_password("c", "u", "test-only clip")).expect("create");
    let r = copy_secret(&f.state, &c.id, "password").expect("copy");
    assert_eq!(r.clears_in_ms, 200);
    assert_eq!(f.clipboard.peek().as_deref(), Some("test-only clip"));
    assert_eq!(audit_events(&f.state).last().map(String::as_str), Some("credential_copied"));
    let log = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("log");
    assert!(log.contains("\"name\":\"password\"") && !log.contains("test-only clip"));
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(f.clipboard.peek(), None, "cleared after the delay");
}

#[tokio::test]
async fn only_copyable_and_stored_secrets_copy() {
    let f = unlocked();
    let key = mooring_core::credential::testdata::placeholder_key_pem();
    let k = create(&f.state, new("ssh_key", json!({"username": "u"}), &[("private_key", &key)])).expect("key");
    assert_eq!(copy_secret(&f.state, &k.id, "private_key").expect_err("pk").code, "input.invalid");
    assert_eq!(copy_secret(&f.state, &k.id, "passphrase").expect_err("absent").code, "credential.secret_missing");
    assert_eq!(copy_secret(&f.state, &k.id, "token").expect_err("kind").code, "input.invalid");
    assert_eq!(copy_secret(&f.state, &k.id, "nope").expect_err("name").code, "input.invalid");
    assert_eq!(f.clipboard.peek(), None);
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(copy_secret(&f.state, &k.id, "passphrase").expect_err("lock").code, "vault.locked");
}

#[tokio::test]
async fn copy_otp_writes_the_rfc_code_and_clears_before_it_expires() {
    let mut f = unlocked();
    f.state.settings.clipboard_clear_after = Duration::from_secs(30);
    let fields = json!({"username": "u"});
    let c = create(&f.state, new("user_password", fields, &[("password", "p"), ("otp_seed", SEED)])).expect("c");
    // T = 59 s: RFC 6238 SHA-1 8-digit code 94287082; 6-digit = 287082, valid 1 s more.
    let at = UNIX_EPOCH + Duration::from_secs(59);
    let r = copy_otp_at(&f.state, &c.id, at).expect("otp");
    assert_eq!(f.clipboard.peek().as_deref(), Some("287082"));
    assert_eq!(r.valid_for_ms, 1000);
    assert!(r.clears_in_ms <= r.valid_for_ms, "{r:?}");
    let json = serde_json::to_value(r).expect("json");
    assert_eq!(json, json!({"clearsInMs": 1000, "validForMs": 1000}), "the code is never returned");
    let log = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("log");
    assert!(log.contains("\"name\":\"otp\"") && !log.contains("287082"));
}

#[tokio::test]
async fn copy_otp_needs_a_seed_and_a_kind_with_the_slot() {
    let f = unlocked();
    let c = create(&f.state, NewCredential::user_password("c", "u", "p")).expect("c");
    assert_eq!(copy_otp(&f.state, &c.id).expect_err("no seed").code, "credential.secret_missing");
    let t = create(&f.state, new("api_token", json!({}), &[("token", "t")])).expect("t");
    assert_eq!(copy_otp(&f.state, &t.id).expect_err("kind").code, "input.invalid");
}

/// M-1: a fixture whose timer never fires during the test, so only lock/shutdown can clear.
fn copied_with_slow_timer() -> Fixture {
    let mut f = unlocked();
    f.state.settings.clipboard_clear_after = Duration::from_secs(3600);
    let c = create(&f.state, NewCredential::user_password("c", "u", "test-only clip")).expect("create");
    copy_secret(&f.state, &c.id, "password").expect("copy");
    assert_eq!(f.clipboard.peek().as_deref(), Some("test-only clip"));
    f
}

#[tokio::test]
async fn vault_lock_clears_a_pending_copy_synchronously() {
    let f = copied_with_slow_timer();
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(f.clipboard.peek(), None, "lock clears the copied secret");
}

#[tokio::test]
async fn shutdown_clears_a_pending_copy_synchronously() {
    let f = copied_with_slow_timer();
    f.state.shutdown();
    assert_eq!(f.clipboard.peek(), None, "exit clears the copied secret");
}

#[tokio::test]
async fn a_newer_clipboard_value_is_left_alone() {
    let f = copied_with_slow_timer();
    f.clipboard.set("user copied this").expect("set");
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(f.clipboard.peek().as_deref(), Some("user copied this"));
    f.state.shutdown();
    assert_eq!(f.clipboard.peek().as_deref(), Some("user copied this"));
}
