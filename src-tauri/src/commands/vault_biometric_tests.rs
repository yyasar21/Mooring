//! ADR-0022 §2: status matrix, enrol / unlock / disable, the 3-in-10-minutes rule, the
//! automatic suspensions (`failed_attempts`, `biometry_changed`, `password_changed`,
//! `vault_rotated`), stale and legacy wraps cleared on a password unlock.

use std::time::{Duration, Instant};

use mooring_vault::MemoryWrapKeyStore;

use super::*;
use crate::biometric::memory::MemoryBiometricStore;
use crate::biometric::{BioError, BiometricStore, Unavailable, FAILURE_WINDOW};
use crate::commands::vault;
use crate::state::testing::{self, audit_events, Fixture, MASTER};

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

/// Unlocked vault over a memory store reporting `platform`.
fn fixture(platform: &'static str) -> (Fixture, std::sync::Arc<MemoryBiometricStore>) {
    let (f, bio) = testing::with_biometric(platform);
    vault::create(&f.state, pw(MASTER)).expect("create");
    (f, bio)
}

fn enrolled(platform: &'static str) -> (Fixture, std::sync::Arc<MemoryBiometricStore>) {
    let (f, bio) = fixture(platform);
    let s = enroll(&f.state, pw(MASTER)).expect("enrol");
    assert_eq!((s.enabled, s.reason, s.label), (true, "ok", bio.label()));
    (f, bio)
}

fn locked(state: &AppState) {
    vault::lock(state, None).expect("lock");
}

#[test]
fn status_matrix_per_platform_and_signing_state() {
    let (f, bio) = fixture("linux");
    bio.set_unavailable(Some(Unavailable::NoAcl));
    let s = status(&f.state).expect("status");
    assert_eq!((s.available, s.enabled, s.reason, s.label), (false, false, "no_acl", None));
    assert_eq!(enroll(&f.state, pw(MASTER)).expect_err("linux").code, "biometric.unavailable");
    assert_eq!(bio.len(), 0);

    let (f, bio) = fixture("macos");
    bio.set_unavailable(Some(Unavailable::UnsignedBuild));
    let s = status(&f.state).expect("status");
    assert_eq!((s.available, s.reason, s.label), (false, "unsigned_build", Some("Touch ID")));
    let e = enroll(&f.state, pw(MASTER)).expect_err("unsigned");
    assert!(e.message.contains("signed build"), "{e:?}");
    bio.set_unavailable(None);
    let s = status(&f.state).expect("status");
    assert_eq!((s.available, s.enabled, s.reason), (true, false, "not_enrolled"));
    let json = serde_json::to_value(&s).expect("json");
    assert!(json["suspendedReason"].is_null() && json["platform"] == "macos");

    let (f, bio) = fixture("windows");
    bio.set_unavailable(Some(Unavailable::KeychainUnavail));
    assert_eq!(status(&f.state).expect("status").reason, "keychain_unavailable");
    // status is passive: it never prompts, locked or not
    locked(&f.state);
    assert_eq!(status(&f.state).expect("locked status").label, Some("Windows Hello"));
    assert_eq!(*bio.prompts.lock().expect("lock"), 0);
}

#[test]
fn enrol_then_unlock_without_the_password() {
    let (f, bio) = enrolled("windows");
    assert_eq!(bio.len(), 1);
    locked(&f.state);
    assert_eq!(unlock_at(&f.state, Instant::now()).expect("unlock"), VaultStatus::Unlocked);
    assert_eq!(vault::status(&f.state).expect("status"), VaultStatus::Unlocked);
    let ev = audit_events(&f.state);
    assert!(ev.contains(&"vault.biometric_enabled".to_owned()), "{ev:?}");
    assert!(ev.contains(&"vault.unlock_biometric".to_owned()), "{ev:?}");
    // already unlocked: no prompt
    let before = *bio.prompts.lock().expect("lock");
    unlock_at(&f.state, Instant::now()).expect("noop");
    assert_eq!(*bio.prompts.lock().expect("lock"), before);
}

#[test]
fn enrol_needs_an_unlocked_vault_and_the_master_password() {
    let (f, bio) = fixture("macos");
    assert_eq!(enroll(&f.state, pw("not the master pw")).expect_err("wrong").code, "vault.unlock");
    assert_eq!(bio.len(), 0, "no item without the password");
    bio.fail_next(BioError::Cancelled);
    assert_eq!(enroll(&f.state, pw(MASTER)).expect_err("cancel").code, "biometric.cancelled");
    assert!(!status(&f.state).expect("s").enabled);
    locked(&f.state);
    assert_eq!(enroll(&f.state, pw(MASTER)).expect_err("locked").code, "vault.locked");
    assert_eq!(unlock_at(&f.state, Instant::now()).expect_err("none").code, "biometric.not_enrolled");
}

#[test]
fn three_failures_in_ten_minutes_suspend_and_success_resets() {
    let (f, bio) = enrolled("macos");
    locked(&f.state);
    let t0 = Instant::now();
    bio.fail_next(BioError::Cancelled);
    bio.fail_next(BioError::Failed);
    assert_eq!(unlock_at(&f.state, t0).expect_err("1").code, "biometric.cancelled");
    assert_eq!(unlock_at(&f.state, t0).expect_err("2").code, "biometric.failed");
    // a success in between resets the window
    unlock_at(&f.state, t0).expect("success");
    assert_eq!(f.state.biometric.failures(t0), 0);
    locked(&f.state);
    for _ in 0..3 {
        bio.fail_next(BioError::Cancelled);
    }
    assert!(unlock_at(&f.state, t0).is_err());
    assert!(unlock_at(&f.state, t0 + Duration::from_secs(60)).is_err());
    let e = unlock_at(&f.state, t0 + Duration::from_secs(120)).expect_err("third");
    assert_eq!(e.code, "biometric.suspended");
    assert_eq!(bio.len(), 0, "the OS item is deleted at once");
    let s = status(&f.state).expect("status");
    assert_eq!((s.enabled, s.reason, s.suspended_reason.as_deref()), (false, "suspended", Some("failed_attempts")));
    assert_eq!(unlock_at(&f.state, t0).expect_err("still").code, "biometric.suspended");
    let ev = audit_events(&f.state);
    assert_eq!(ev.iter().filter(|e| *e == "vault.biometric_failed").count(), 5, "{ev:?}");
    assert!(ev.contains(&"vault.biometric_suspended".to_owned()));
}

#[test]
fn failures_spread_over_more_than_ten_minutes_never_suspend() {
    let (f, bio) = enrolled("windows");
    locked(&f.state);
    let t0 = Instant::now();
    for i in 0..4u32 {
        bio.fail_next(BioError::Cancelled);
        let e = unlock_at(&f.state, t0 + FAILURE_WINDOW * i).expect_err("fail");
        assert_eq!(e.code, "biometric.cancelled");
    }
    assert!(status(&f.state).expect("s").suspended_reason.is_none());
}

#[test]
fn biometry_change_suspends_and_password_unlock_clears_the_stale_wrap() {
    let (f, bio) = enrolled("macos");
    let id = f.state.vault().expect("v").as_ref().expect("v").vault_id();
    locked(&f.state);
    bio.forget(id); // fingers re-enrolled: BiometryCurrentSet dropped the item
    assert_eq!(unlock_at(&f.state, Instant::now()).expect_err("gone").code, "biometric.suspended");
    assert_eq!(suspended_reason(&f.state).as_deref(), Some("biometry_changed"));
    assert!(header_has_wrap(&f.state).expect("wrap"), "inert wrap stays until a password unlock");
    vault::unlock(&f.state, pw(MASTER)).expect("password unlock");
    assert!(!header_has_wrap(&f.state).expect("wrap"), "stale wrap cleared");
    // the reason is still shown once; re-enrolment clears it
    assert_eq!(status(&f.state).expect("s").reason, "suspended");
    enroll(&f.state, pw(MASTER)).expect("re-enrol");
    assert_eq!(status(&f.state).expect("s").reason, "ok");
}

#[test]
fn password_change_suspends_and_deletes_the_item() {
    let (f, bio) = enrolled("windows");
    vault::change_password(&f.state, pw(MASTER), pw("a brand new master pw")).expect("change");
    assert_eq!(bio.len(), 0);
    assert!(!header_has_wrap(&f.state).expect("wrap"));
    assert_eq!(suspended_reason(&f.state).as_deref(), Some("password_changed"));
    locked(&f.state);
    assert_eq!(unlock_at(&f.state, Instant::now()).expect_err("off").code, "biometric.suspended");
}

#[test]
fn disable_needs_the_password_and_removes_everything() {
    let (f, bio) = enrolled("macos");
    assert_eq!(disable(&f.state, pw("wrong password!!")).expect_err("wrong").code, "vault.unlock");
    assert_eq!(bio.len(), 1);
    locked(&f.state);
    let s = disable(&f.state, pw(MASTER)).expect("disable while locked");
    assert_eq!((s.enabled, s.reason), (false, "not_enrolled"));
    assert_eq!(bio.len(), 0);
    assert_eq!(vault::status(&f.state).expect("s"), VaultStatus::Locked, "disable does not unlock");
    // disabling again (no wrap) still proves the password
    assert_eq!(disable(&f.state, pw("wrong password!!")).expect_err("wrong").code, "vault.unlock");
    disable(&f.state, pw(MASTER)).expect("idempotent");
    assert!(audit_events(&f.state).contains(&"vault.biometric_disabled".to_owned()));
}

#[test]
fn legacy_keyring_wrap_is_removed_on_a_password_unlock() {
    let (f, _bio) = fixture("macos");
    {
        let mut g = f.state.vault().expect("v");
        let v = g.as_mut().expect("v");
        v.enable_keyring_unlock(&MemoryWrapKeyStore::new(), &pw(MASTER)).expect("legacy wrap");
        f.state.save_header(v).expect("save");
    }
    locked(&f.state);
    assert_eq!(unlock_at(&f.state, Instant::now()).expect_err("legacy").code, "biometric.not_enrolled");
    vault::unlock(&f.state, pw(MASTER)).expect("unlock");
    assert!(!header_has_wrap(&f.state).expect("wrap"));
    assert!(audit_events(&f.state).contains(&"keyring.removed".to_owned()));
}

#[test]
fn vault_rotation_suspends_an_enrolment() {
    let (f, bio) = enrolled("windows");
    on_vault_rotated(&f.state);
    assert_eq!(bio.len(), 0);
    assert_eq!(suspended_reason(&f.state).as_deref(), Some("vault_rotated"));
    // not enrolled: nothing to do
    let (g, _) = fixture("windows");
    on_vault_rotated(&g.state);
    assert!(suspended_reason(&g.state).is_none());
}

#[test]
fn a_key_that_does_not_open_the_wrap_counts_as_a_failure() {
    let (f, bio) = enrolled("windows");
    let id = f.state.vault().expect("v").as_ref().expect("v").vault_id();
    // Replace the item with another key behind the store's back.
    bio.forget(id);
    bio.create(id).expect("other key");
    locked(&f.state);
    assert_eq!(unlock_at(&f.state, Instant::now()).expect_err("wrong key").code, "biometric.failed");
    assert_eq!(f.state.biometric.failures(Instant::now()), 1);
    assert_eq!(vault::status(&f.state).expect("s"), VaultStatus::Locked);
}
