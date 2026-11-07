//! `update_*` command flow with the scripted source: gate, codes, audit, settings, matrix,
//! downgrade, version re-check, sessions.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::state::testing::{audit_events, unlocked, Fixture};
use crate::updater::install_mode::{Bundle, InstallFacts};
use crate::updater::source::SourceError;
use crate::updater::tests::{facts, in_app_probe, offered, runtime, v, FakeProbe, FakeSource};
use crate::updater::MIN_CHECK_GAP;

fn audit_text(f: &Fixture) -> String {
    std::fs::read_to_string(f.state.data_dir.join(AppState::AUDIT_FILE)).unwrap_or_default()
}

fn install_input(version: &str, close_sessions: bool) -> InstallInput {
    InstallInput { version: version.to_owned(), close_sessions }
}

#[tokio::test]
async fn check_reports_a_newer_release_and_audits() {
    let f = unlocked();
    let src = FakeSource::offering(Some(offered("0.2.0")));
    let rt = runtime(Arc::clone(&src), in_app_probe());
    let info = check(&f.state, &rt, Instant::now(), true).await.expect("check");
    assert_eq!(info.current, "0.1.0");
    assert_eq!(info.install_mode, "in_app");
    assert_eq!(info.manual_reason, None);
    let a = info.available.clone().expect("available");
    assert_eq!((a.version.as_str(), a.notes.as_str(), a.size), ("0.2.0", "Fixes", Some(12_345)));
    assert_eq!(a.date.as_deref(), Some("2026-11-06T10:00:00Z"));
    assert!(info.checked_at.ends_with('Z'));
    assert_eq!(settings_get(&f.state).expect("settings").last_check, Some(info.checked_at.clone()));
    assert_eq!(rt.last_available().map(|r| r.version), Some(v("0.2.0")));
    assert!(audit_text(&f).contains(r#""event":"update.check","current":"0.1.0","available":"0.2.0""#));
    let json = serde_json::to_value(&info).expect("json");
    assert_eq!(json["installMode"], "in_app");
    assert!(json.get("manualReason").is_none(), "absent when in_app: {json}");
    assert_eq!(json["available"]["version"], "0.2.0");
}

#[tokio::test]
async fn check_hides_downgrades_and_the_running_version() {
    let f = unlocked();
    for old in ["0.1.0", "0.0.9", "0.1.0-rc.2"] {
        let src = FakeSource::offering(Some(offered(old)));
        let rt = runtime(src, in_app_probe());
        let info = check(&f.state, &rt, Instant::now(), true).await.expect("check");
        assert!(info.available.is_none(), "{old}");
        assert!(rt.last_available().is_none(), "{old}");
    }
    assert!(audit_text(&f).contains(r#""event":"update.check","current":"0.1.0","available":null"#));
}

#[tokio::test]
async fn check_sanitises_notes_and_reports_the_manual_matrix() {
    let f = unlocked();
    let mut r = offered("0.2.0");
    r.notes = Some("ok\u{202E}evil\x1b[0m".to_owned());
    r.date = None;
    r.size = None;
    let probe = Arc::new(FakeProbe(Some(facts(Bundle::Deb, "/usr/bin/mooring", false))));
    let rt = runtime(FakeSource::offering(Some(r)), probe);
    let info = check(&f.state, &rt, Instant::now(), true).await.expect("check");
    let a = info.available.clone().expect("available");
    assert_eq!(a.notes, "okevil");
    assert_eq!((a.date, a.size), (None, None));
    assert_eq!(info.install_mode, "manual");
    assert_eq!(info.manual_reason, Some(ManualReason::PackageManager));
    let json = serde_json::to_value(&info).expect("json");
    assert_eq!(json["manualReason"], "package_manager");
    assert!(json["available"].get("date").is_none());
}

#[tokio::test]
async fn check_maps_source_errors_and_rate_limits() {
    let f = unlocked();
    let src = FakeSource::failing(SourceError::Network);
    let rt = runtime(Arc::clone(&src), in_app_probe());
    let t0 = Instant::now();
    let e = check(&f.state, &rt, t0, true).await.expect_err("network");
    assert_eq!(e.code, "update.network");
    assert!(!audit_text(&f).contains("update.check"), "a failed check is not a check");
    assert!(!rt.busy(), "the flight is released on error");
    let e = check(&f.state, &rt, t0 + Duration::from_secs(5), true).await.expect_err("gap");
    assert_eq!(e.code, "update.rate_limited");
    assert_eq!(src.checks.load(Ordering::SeqCst), 1, "no network call while rate-limited");
    src.set(Err(SourceError::Manifest));
    let e = check(&f.state, &rt, t0 + Duration::from_secs(5), false).await.expect_err("manifest");
    assert_eq!(e.code, "update.manifest", "background checks skip the gap");
    src.set(Err(SourceError::Signature));
    let e = check(&f.state, &rt, t0 + Duration::from_secs(120), true).await.expect_err("sig");
    assert_eq!(e.code, "update.signature");
}

#[tokio::test]
async fn every_command_is_vault_gated_and_unconfigured_wins_after_the_gate() {
    let f = unlocked();
    let rt = UpdateRuntime::unconfigured(v("0.1.0"));
    let now = Instant::now();
    assert_eq!(check(&f.state, &rt, now, true).await.expect_err("unconf").code, "update.unconfigured");
    let e = install(&f.state, &rt, now, install_input("0.2.0", false)).await.expect_err("unconf");
    assert_eq!(e.code, "update.unconfigured");
    assert!(settings_get(&f.state).is_ok());
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(check(&f.state, &rt, now, true).await.expect_err("locked").code, "vault.locked");
    let e = install(&f.state, &rt, now, install_input("0.2.0", false)).await.expect_err("locked");
    assert_eq!(e.code, "vault.locked");
    assert_eq!(settings_get(&f.state).expect_err("locked").code, "vault.locked");
    let input = UpdateSettingsInput { background_check: true, channel: None };
    assert_eq!(settings_set(&f.state, input).expect_err("locked").code, "vault.locked");
    assert!(!audit_events(&f.state).iter().any(|e| e.starts_with("update.")));
}

/// ADR-0021 §2: in a portable folder the background opt-in is refused with
/// `update.manual_only` (audited as a refusal, nothing stored); switching it off, a manual
/// `update_check` and `update_install`'s own matrix answer still work.
#[tokio::test]
async fn portable_mode_refuses_the_background_opt_in_but_checks_on_demand() {
    let f = crate::state::testing::empty_portable();
    crate::commands::vault::create(&f.state, secrecy::SecretString::from(crate::state::testing::MASTER.to_owned()))
        .expect("vault");
    let e = settings_set(&f.state, UpdateSettingsInput { background_check: true, channel: None }).expect_err("portable");
    assert_eq!(e.code, "update.manual_only");
    assert_eq!(e.message, "portable build: download the new zip and replace the folder");
    assert!(!settings_get(&f.state).expect("get").background_check, "nothing stored");
    assert!(audit_text(&f).contains(r#""event":"update.refused","code":"update.manual_only""#));
    settings_set(&f.state, UpdateSettingsInput { background_check: false, channel: None }).expect("off is fine");
    // On-demand check still answers, with the portable manual reason.
    let src = FakeSource::offering(Some(offered("0.2.0")));
    let portable = InstallFacts { portable: true, ..facts(Bundle::Nsis, "D:\\Mooring", true) };
    let rt = runtime(Arc::clone(&src), Arc::new(FakeProbe(Some(portable))));
    let info = check(&f.state, &rt, Instant::now(), true).await.expect("check");
    assert_eq!((info.install_mode, info.manual_reason), ("manual", Some(ManualReason::Portable)));
    assert_eq!(info.available.as_ref().map(|a| a.version.clone()), Some("0.2.0".to_owned()));
    assert_eq!(src.checks.load(Ordering::SeqCst), 1);
    let e = install(&f.state, &rt, Instant::now(), install_input("0.2.0", false)).await.expect_err("manual");
    assert_eq!(e.code, "update.manual_only");
    assert_eq!(src.installs.lock().expect("lock").len(), 0);
    assert_eq!(serde_json::to_value(&info).expect("json")["manualReason"], "portable");
}

#[tokio::test]
async fn settings_round_trip_validation_and_audit() {
    let f = unlocked();
    assert_eq!(settings_get(&f.state).expect("default"), UpdateSettings::default());
    let s = settings_set(&f.state, UpdateSettingsInput { background_check: true, channel: Some("stable".into()) })
        .expect("set");
    assert_eq!((s.background_check, s.channel.as_str(), s.last_check.as_deref()), (true, "stable", None));
    assert_eq!(settings_get(&f.state).expect("get"), s);
    assert_eq!(stored(&f.state), s, "ungated read sees the same");
    let e = settings_set(&f.state, UpdateSettingsInput { background_check: false, channel: Some("beta".into()) })
        .expect_err("channel");
    assert_eq!(e.code, "input.invalid");
    assert!(e.message.contains("channel"));
    assert!(settings_get(&f.state).expect("get").background_check, "invalid input changed nothing");
    settings_set(&f.state, UpdateSettingsInput { background_check: true, channel: None }).expect("same");
    settings_set(&f.state, UpdateSettingsInput { background_check: false, channel: None }).expect("off");
    let text = audit_text(&f);
    assert_eq!(text.matches(r#""event":"update.settings_changed""#).count(), 2, "unchanged = no row");
    assert!(text.contains(r#""event":"update.settings_changed","background_check":true"#));
    // Wire shape and unknown fields.
    assert!(serde_json::from_str::<UpdateSettingsInput>(r#"{"backgroundCheck":true,"x":1}"#).is_err());
    let json = serde_json::to_string(&UpdateSettings::default()).expect("json");
    assert_eq!(json, r#"{"backgroundCheck":false,"channel":"stable","lastCheck":null,"lastVerified":null}"#);
    let partial: UpdateSettings = serde_json::from_str(r#"{"backgroundCheck":true}"#).expect("defaults");
    assert_eq!(partial.channel, "stable");
}

#[test]
fn corrupt_stored_settings_fall_back_to_default() {
    let f = unlocked();
    let slot = f.state.store.lock().expect("lock");
    slot.store.as_ref().expect("s").set_app_setting(KEY, "not json").expect("write");
    drop(slot);
    assert_eq!(stored(&f.state), UpdateSettings::default());
}

#[tokio::test]
async fn install_happy_path_audits_before_writing() {
    let f = unlocked();
    let src = FakeSource::offering(Some(offered("0.2.0")));
    let rt = runtime(Arc::clone(&src), in_app_probe());
    install(&f.state, &rt, Instant::now(), install_input("0.2.0", false)).await.expect("install");
    assert_eq!(*src.installs.lock().expect("lock"), vec!["0.2.0".to_owned()]);
    assert_eq!(src.before_install_calls.load(Ordering::SeqCst), 1);
    assert!(audit_text(&f).contains(r#""event":"update.install","from":"0.1.0","to":"0.2.0""#));
    assert!(!rt.busy());
}

#[tokio::test]
async fn install_refusals_are_audited_with_their_code() {
    let f = unlocked();
    let now = Instant::now();
    // Input and downgrade.
    let src = FakeSource::offering(Some(offered("0.2.0")));
    let rt = runtime(Arc::clone(&src), in_app_probe());
    let e = install(&f.state, &rt, now, install_input("v0.2", false)).await.expect_err("semver");
    assert_eq!(e.code, "input.invalid");
    let e = install(&f.state, &rt, now, install_input("0.1.0", false)).await.expect_err("same");
    assert_eq!(e.code, "update.none");
    // The re-check offers something else than the user confirmed (TOCTOU swap).
    let e = install(&f.state, &rt, now, install_input("0.3.0", false)).await.expect_err("swap");
    assert_eq!(e.code, "update.none");
    assert!(src.installs.lock().expect("lock").is_empty());
    // Nothing offered any more.
    let rt2 = runtime(FakeSource::offering(None), in_app_probe());
    let e = install(&f.state, &rt2, now, install_input("0.2.0", false)).await.expect_err("gone");
    assert_eq!(e.code, "update.none");
    // Signature failure after download, install failure after verification.
    for (err, code) in [(SourceError::Signature, "update.signature"), (SourceError::Install, "update.install_failed")] {
        let src = FakeSource::offering(Some(offered("0.2.0")));
        *src.install_error.lock().expect("lock") = Some(err);
        let rt = runtime(src, in_app_probe());
        let e = install(&f.state, &rt, now, install_input("0.2.0", false)).await.expect_err("fail");
        assert_eq!(e.code, code);
        // F1: static text per class, no path or URL (`SourceError::message`), nothing from
        // the source's own error.
        assert_eq!(e.message, err.message());
        assert!(!e.message.contains('/') && !e.message.contains("://"), "{}", e.message);
        assert!(!rt.busy());
    }
    let text = audit_text(&f);
    for code in ["update.none", "update.signature", "update.install_failed"] {
        assert!(text.contains(&format!(r#""event":"update.refused","code":"{code}""#)), "{code}");
    }
    assert!(!text.contains(r#""code":"input.invalid""#), "input errors are not refusals");
    assert!(!text.contains("update.install\""), "nothing was installed");
}

#[tokio::test]
async fn install_refuses_the_manual_matrix_before_any_network_call() {
    let f = unlocked();
    let rows = [
        (facts(Bundle::Deb, "/usr/bin/mooring", true), "update.manual_only"),
        (facts(Bundle::Rpm, "/usr/bin/mooring", true), "update.manual_only"),
        (facts(Bundle::Msi, "C:\\Program Files\\Mooring", true), "update.manual_only"),
        (facts(Bundle::MacApp, "/opt/homebrew/Caskroom/mooring/0.1.0/Mooring.app", true), "update.manual_only"),
        (facts(Bundle::Unknown, "/tmp/mooring", true), "update.manual_only"),
        (facts(Bundle::MacApp, "/Applications/Mooring.app", false), "update.not_writable"),
        (facts(Bundle::Nsis, "C:\\Program Files\\Mooring", false), "update.not_writable"),
        (facts(Bundle::AppImage, "/opt/Mooring.AppImage", false), "update.not_writable"),
    ];
    for (facts, code) in rows {
        let src = FakeSource::offering(Some(offered("0.2.0")));
        let rt = runtime(Arc::clone(&src), Arc::new(FakeProbe(Some(facts.clone()))));
        let e = install(&f.state, &rt, Instant::now(), install_input("0.2.0", false)).await.expect_err("manual");
        assert_eq!(e.code, code, "{facts:?}");
        assert_eq!(src.checks.load(Ordering::SeqCst), 0, "{facts:?}: the plugin is never asked");
        assert!(src.installs.lock().expect("lock").is_empty());
    }
    let text = audit_text(&f);
    assert_eq!(text.matches(r#""event":"update.refused","code":"update.manual_only""#).count(), 5);
    assert_eq!(text.matches(r#""event":"update.refused","code":"update.not_writable""#).count(), 3);
}

/// Review 7 N-51: a second install attempt within 60 s of the previous one is refused
/// before any network call; matrix, input and session refusals do not start the gap.
#[tokio::test]
async fn install_is_rate_limited_between_attempts() {
    let f = unlocked();
    let src = FakeSource::offering(Some(offered("0.2.0")));
    let rt = runtime(Arc::clone(&src), in_app_probe());
    let t0 = Instant::now();
    let e = install(&f.state, &rt, t0, install_input("0.1.0", false)).await.expect_err("same");
    assert_eq!(e.code, "update.none");
    *src.install_error.lock().expect("lock") = Some(SourceError::Signature);
    let e = install(&f.state, &rt, t0, install_input("0.2.0", false)).await.expect_err("sig");
    assert_eq!(e.code, "update.signature", "the refused version did not start the gap");
    assert_eq!(src.checks.load(Ordering::SeqCst), 1);
    *src.install_error.lock().expect("lock") = None;
    let e = install(&f.state, &rt, t0 + Duration::from_secs(30), install_input("0.2.0", false)).await.expect_err("gap");
    assert_eq!(e.code, "update.rate_limited");
    assert_eq!(src.checks.load(Ordering::SeqCst), 1, "no network while rate-limited");
    assert!(!rt.busy());
    install(&f.state, &rt, t0 + MIN_CHECK_GAP, install_input("0.2.0", false)).await.expect("after the gap");
    assert_eq!(*src.installs.lock().expect("lock"), vec!["0.2.0".to_owned()]);
    assert!(!audit_text(&f).contains("update.rate_limited"), "rate limiting is not audited (noise)");
}

/// Review 7 L-39: a verified install raises a persisted floor; a later offer below it is
/// `update.downgrade` for both the check and the install, before any network call.
#[tokio::test]
async fn verified_floor_refuses_a_later_downgrade_offer() {
    let f = unlocked();
    let src = FakeSource::offering(Some(offered("0.3.0")));
    let rt = runtime(Arc::clone(&src), in_app_probe());
    let t0 = Instant::now();
    assert_eq!(settings_get(&f.state).expect("s").last_verified, None);
    install(&f.state, &rt, t0, install_input("0.3.0", false)).await.expect("install");
    assert_eq!(settings_get(&f.state).expect("s").last_verified.as_deref(), Some("0.3.0"));
    // The same process (the restart is the source's job) is now offered 0.2.0 > current.
    src.set(Ok(Some(offered("0.2.0"))));
    let e = check(&f.state, &rt, t0 + MIN_CHECK_GAP, true).await.expect_err("downgrade");
    assert_eq!(e.code, "update.downgrade");
    assert!(rt.last_available().is_none());
    let before = src.checks.load(Ordering::SeqCst);
    let e = install(&f.state, &rt, t0 + 2 * MIN_CHECK_GAP, install_input("0.2.0", false)).await.expect_err("downgrade");
    assert_eq!(e.code, "update.downgrade");
    assert_eq!(src.checks.load(Ordering::SeqCst), before, "refused before the source is asked");
    assert_eq!(*src.installs.lock().expect("lock"), vec!["0.3.0".to_owned()]);
    // A failed verification leaves the floor alone; the floor never goes down.
    src.set(Ok(Some(offered("0.4.0"))));
    *src.install_error.lock().expect("lock") = Some(SourceError::Signature);
    let e = install(&f.state, &rt, t0 + 3 * MIN_CHECK_GAP, install_input("0.4.0", false)).await.expect_err("sig");
    assert_eq!(e.code, "update.signature");
    assert_eq!(settings_get(&f.state).expect("s").last_verified.as_deref(), Some("0.3.0"));
    *src.install_error.lock().expect("lock") = None;
    install(&f.state, &rt, t0 + 4 * MIN_CHECK_GAP, install_input("0.4.0", false)).await.expect("0.4.0");
    assert_eq!(settings_get(&f.state).expect("s").last_verified.as_deref(), Some("0.4.0"));
    raise_floor(&f.state.store, &v("0.3.5"));
    assert_eq!(settings_get(&f.state).expect("s").last_verified.as_deref(), Some("0.4.0"), "monotonic");
    // A corrupt floor is ignored, never trusted; the floor survives a settings change.
    let text = audit_text(&f);
    assert_eq!(text.matches(r#""event":"update.refused","code":"update.downgrade""#).count(), 2);
    settings_set(&f.state, UpdateSettingsInput { background_check: true, channel: None }).expect("set");
    assert_eq!(settings_get(&f.state).expect("s").last_verified.as_deref(), Some("0.4.0"));
    {
        let slot = f.state.store.lock().expect("lock");
        slot.store.as_ref().expect("s").set_app_setting(KEY, r#"{"lastVerified":"nope"}"#).expect("write");
    }
    src.set(Ok(Some(offered("0.2.0"))));
    assert!(check(&f.state, &rt, t0 + 5 * MIN_CHECK_GAP, true).await.expect("unparsable floor ignored").available.is_some());
}

#[tokio::test]
async fn install_is_single_flight() {
    let f = unlocked();
    let src = FakeSource::offering(Some(offered("0.2.0")));
    let rt = runtime(src, in_app_probe());
    let flight = rt.begin_check(Instant::now(), false).expect("hold the flight");
    let e = install(&f.state, &rt, Instant::now(), install_input("0.2.0", false)).await.expect_err("busy");
    assert_eq!(e.code, "update.busy");
    drop(flight);
    assert!(!audit_text(&f).contains("update.refused"), "busy is not audited (noise)");
}

#[tokio::test]
async fn install_refuses_open_sessions_unless_asked_to_close_them() {
    let srv = crate::test_ssh_server::start(93).await;
    let live = crate::commands::test_session::connect(&srv).await;
    let src = FakeSource::offering(Some(offered("0.2.0")));
    let rt = runtime(Arc::clone(&src), in_app_probe());
    let e = install(&live.f.state, &rt, Instant::now(), install_input("0.2.0", false)).await.expect_err("open");
    assert_eq!(e.code, "update.sessions_open");
    assert_eq!(src.checks.load(Ordering::SeqCst), 0);
    assert_eq!(crate::commands::sessions::list(&live.f.state).expect("list").len(), 1, "still open");
    install(&live.f.state, &rt, Instant::now(), install_input("0.2.0", true)).await.expect("closed first");
    assert_eq!(*src.installs.lock().expect("lock"), vec!["0.2.0".to_owned()]);
    for _ in 0..200 {
        if crate::commands::sessions::list(&live.f.state).expect("list").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(crate::commands::sessions::list(&live.f.state).expect("list").is_empty());
    let text = audit_text(&live.f);
    assert!(text.contains(r#""event":"update.refused","code":"update.sessions_open""#));
    assert!(text.contains(r#""event":"session_closed""#));
}

#[test]
fn install_input_wire_shape() {
    let i: InstallInput = serde_json::from_str(r#"{"version":"0.2.0"}"#).expect("default");
    assert!(!i.close_sessions);
    let i: InstallInput = serde_json::from_str(r#"{"version":"0.2.0","closeSessions":true}"#).expect("camel");
    assert!(i.close_sessions);
    assert!(serde_json::from_str::<InstallInput>(r#"{"version":"0.2.0","url":"x"}"#).is_err(), "no renderer URL");
}

/// ADR-0028 §1: in a development build every command answers `update.manual_only` with the
/// dev sentence (not `update.unconfigured`), the background opt-in is refused and audited
/// before the portable rule, and switching it off still works.
#[tokio::test]
async fn development_build_is_manual_everywhere() {
    let f = crate::state::testing::unlocked_dev();
    let rt = UpdateRuntime::development(v("0.1.0"));
    let dev = ManualReason::DevBuild.message();
    let now = Instant::now();
    let e = check(&f.state, &rt, now, true).await.expect_err("dev");
    assert_eq!((e.code, e.message.as_str()), ("update.manual_only", dev));
    let e = install(&f.state, &rt, now, install_input("0.2.0", false)).await.expect_err("dev");
    assert_eq!((e.code, e.message.as_str()), ("update.manual_only", dev));
    let e = settings_set(&f.state, UpdateSettingsInput { background_check: true, channel: None }).expect_err("dev");
    assert_eq!((e.code, e.message.as_str()), ("update.manual_only", dev));
    assert!(!settings_get(&f.state).expect("get").background_check, "nothing stored");
    assert!(audit_text(&f).contains(r#""event":"update.refused","code":"update.manual_only""#));
    settings_set(&f.state, UpdateSettingsInput { background_check: false, channel: None }).expect("off is fine");
}
