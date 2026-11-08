//! A4 Q1 (ADR-0018 §Test plan, integration): the `update_*` commands over a scripted
//! `UpdateSource` and a fixed install probe — the Rust-side matrix the plugin sits behind.
//! The plugin itself (`PluginSource`, `latest.json` over HTTPS + minisign) cannot be driven
//! here: its `Update` type is private to the plugin, its client is `https_only`, and a
//! loopback endpoint would need a certificate the plugin's verifier does not accept. That
//! leg is the per-OS manual step in `docs/handoff/a4-qa-q1.md`. What is pinned here: an
//! offer is never installed in manual mode (and the source is never asked), manual checks are
//! rate limited while the background check is not, a background check downloads nothing, a
//! tampered manifest / signature is refused by code and audited as `update.refused` without
//! an `update.install` row, and the single flight.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use semver::Version;

use crate::a4_support::{assert_audit_free_of, audit_rows, audit_text};
use crate::commands::update::{self, InstallInput, UpdateSettingsInput};
use crate::state::testing;
use crate::updater::background::{due, TickInput, PERIOD, START_DELAY};
use crate::updater::install_mode::{Bundle, InstallFacts, InstallProbe};
use crate::updater::source::{BeforeInstall, BoxFuture, RemoteUpdate, SourceError, UpdateSource};
use crate::updater::{UpdateRuntime, MIN_CHECK_GAP};

/// What a manifest would say; the notes carry a URL and markup the UI must not interpret.
const NOTES: &str = "Fixes.\n\nSee https://updates.example.test/notes <b>bold</b>";

/// A scripted source: every call answers `answer`; `install` records the version and the
/// `before_install` audit hook, and fails with `install_error` when set. Downloads are
/// counted so a background check can be shown to download nothing.
struct Scripted {
    answer: Mutex<Result<Option<RemoteUpdate>, SourceError>>,
    install_error: Mutex<Option<SourceError>>,
    checks: AtomicUsize,
    downloads: AtomicUsize,
    installed: Mutex<Vec<String>>,
}

impl Scripted {
    fn offering(version: &str) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(Ok(Some(RemoteUpdate {
                version: Version::parse(version).expect("semver"),
                date: Some("2026-11-06T10:00:00Z".into()),
                notes: Some(NOTES.into()),
                size: Some(48_000_000),
            }))),
            install_error: Mutex::new(None),
            checks: AtomicUsize::new(0),
            downloads: AtomicUsize::new(0),
            installed: Mutex::new(Vec::new()),
        })
    }

    fn set(&self, r: Result<Option<RemoteUpdate>, SourceError>) {
        *self.answer.lock().expect("lock") = r;
    }

    fn fail_install(&self, e: SourceError) {
        *self.install_error.lock().expect("lock") = Some(e);
    }
}

impl UpdateSource for Scripted {
    fn check(&self) -> BoxFuture<'_, Result<Option<RemoteUpdate>, SourceError>> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let r = self.answer.lock().expect("lock").clone();
        Box::pin(async move { r })
    }

    fn install<'a>(
        &'a self,
        version: &'a Version,
        before_install: BeforeInstall,
    ) -> BoxFuture<'a, Result<(), SourceError>> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let offered = self.answer.lock().expect("lock").clone();
        Box::pin(async move {
            let offered = offered?.ok_or(SourceError::None)?;
            if offered.version != *version {
                return Err(SourceError::None);
            }
            // The real source downloads and verifies here; a verification failure is the
            // scripted error, raised before the audit hook and before anything is written.
            self.downloads.fetch_add(1, Ordering::SeqCst);
            if let Some(e) = *self.install_error.lock().expect("lock") {
                return Err(e);
            }
            before_install();
            self.installed.lock().expect("lock").push(version.to_string());
            Ok(())
        })
    }
}

struct Probe(InstallFacts);

impl InstallProbe for Probe {
    fn facts(&self) -> Option<InstallFacts> {
        Some(self.0.clone())
    }
}

fn probe(bundle: Bundle, path: &str, writable: bool) -> Arc<Probe> {
    probe_winget(bundle, path, writable, false)
}

/// `winget` is what `OsProbe` reads from the `install-source` marker, and only for NSIS
/// (ADR-0018 A2): every other bundle row reports `false`, as these probes do.
fn probe_winget(bundle: Bundle, path: &str, writable: bool, winget: bool) -> Arc<Probe> {
    Arc::new(Probe(InstallFacts {
        bundle,
        install_path: path.into(),
        writable,
        cask_present: false,
        portable: false,
        dev_build: false,
        winget,
    }))
}

fn runtime(source: Arc<Scripted>, probe: Arc<Probe>) -> UpdateRuntime {
    UpdateRuntime::new(source, probe, Version::parse("0.1.0").expect("semver"))
}

fn install_input(version: &str) -> InstallInput {
    InstallInput { version: version.into(), close_sessions: false }
}

#[tokio::test]
async fn offer_in_manual_mode_is_shown_but_install_is_refused_before_the_source() {
    let f = testing::unlocked();
    let st = &f.state;
    let source = Scripted::offering("0.2.0");
    let rows: [(Bundle, &str, bool, bool, &str, &str); 5] = [
        (Bundle::Deb, "/usr/bin/mooring", false, false, "package_manager", "update.manual_only"),
        (
            Bundle::MacApp,
            "/opt/homebrew/Caskroom/mooring/0.1.0/Mooring.app",
            true,
            false,
            "homebrew",
            "update.manual_only",
        ),
        (
            Bundle::MacApp,
            "/Applications/Mooring.app",
            false,
            false,
            "not_writable",
            "update.not_writable",
        ),
        (Bundle::Unknown, "/tmp/mooring", true, false, "not_bundled", "update.manual_only"),
        // A5 R6 (ADR-0018 A2): a writable NSIS install that winget made stays manual.
        (
            Bundle::Nsis,
            "C:/Users/u/AppData/Local/Mooring",
            true,
            true,
            "winget",
            "update.manual_only",
        ),
    ];
    for (bundle, path, writable, winget, reason, code) in rows {
        let rt = runtime(Arc::clone(&source), probe_winget(bundle, path, writable, winget));
        let info = update::check(st, &rt, Instant::now(), true).await.expect("check");
        assert_eq!(info.install_mode, "manual", "{reason}");
        let r = info.manual_reason.expect("reason");
        assert_eq!(
            (serde_json::to_value(r).expect("json"), r.code()),
            (serde_json::json!(reason), code),
            "{reason}"
        );
        let a = info.available.expect("offer is still shown in manual mode");
        assert_eq!(a.version, "0.2.0");
        assert!(
            a.notes.contains("https://updates.example.test/notes"),
            "URLs stay text, never a link: {}",
            a.notes
        );
        let before = source.checks.load(Ordering::SeqCst);
        let err = update::install(st, &rt, Instant::now(), install_input("0.2.0"))
            .await
            .expect_err(reason);
        assert_eq!(err.code, code, "{reason}");
        assert_eq!(
            source.checks.load(Ordering::SeqCst),
            before,
            "{reason}: the source is never asked to install"
        );
        assert_eq!(source.downloads.load(Ordering::SeqCst), 0);
    }
    assert!(source.installed.lock().expect("lock").is_empty());
    let refused = audit_rows(st, "update.refused");
    assert_eq!(refused.len(), 5, "{refused:?}");
    assert!(audit_rows(st, "update.install").is_empty());
    assert_eq!(audit_rows(st, "update.check").len(), 5);
    assert_audit_free_of(st, &["updates.example.test", "<b>", "Caskroom"]);
}

#[tokio::test]
async fn manual_checks_are_rate_limited_and_the_background_check_downloads_nothing() {
    let f = testing::unlocked();
    let st = &f.state;
    let source = Scripted::offering("0.2.0");
    let rt = runtime(
        Arc::clone(&source),
        probe(Bundle::AppImage, "/home/u/Applications/Mooring.AppImage", true),
    );
    let t0 = Instant::now();
    let first = update::check(st, &rt, t0, true).await.expect("first");
    assert_eq!(first.install_mode, "in_app");
    assert!(first.available.is_some());
    // A second manual check inside the gap is refused without touching the source.
    let before = source.checks.load(Ordering::SeqCst);
    let err = update::check(st, &rt, t0 + Duration::from_secs(5), true).await.expect_err("rate");
    assert_eq!(err.code, "update.rate_limited");
    assert!(err.message.contains('s'), "{}", err.message);
    assert_eq!(source.checks.load(Ordering::SeqCst), before);
    // The background path (its 24 h schedule is the gap) is not rate limited, downloads
    // nothing and installs nothing; it only fetches the manifest.
    let bg = update::check(st, &rt, t0 + Duration::from_secs(5), false).await.expect("background");
    assert_eq!(bg.available.map(|a| a.version), Some("0.2.0".into()));
    assert_eq!(source.checks.load(Ordering::SeqCst), before + 1);
    assert_eq!(source.downloads.load(Ordering::SeqCst), 0);
    assert!(source.installed.lock().expect("lock").is_empty());
    assert_eq!(rt.last_available().map(|r| r.version.to_string()), Some("0.2.0".into()));
    // The background check counts for the gap; after it a manual check is accepted again.
    assert_eq!(
        update::check(st, &rt, t0 + MIN_CHECK_GAP, true).await.expect_err("counted").code,
        "update.rate_limited"
    );
    assert!(update::check(st, &rt, t0 + Duration::from_secs(5) + MIN_CHECK_GAP, true)
        .await
        .is_ok());
    // The stored lastCheck is what the background scheduler reads; a fresh check is not due
    // again for 24 h, and never before 60 s of uptime or while locked / opted out.
    let settings = update::settings_get(st).expect("settings");
    let last = crate::updater::background::parse_last_check(settings.last_check.as_deref())
        .expect("lastCheck stored");
    let now = time::OffsetDateTime::now_utc();
    let tick = |uptime: Duration,
                enabled: bool,
                unlocked: bool,
                last_check: Option<time::OffsetDateTime>| {
        due(&TickInput { uptime, enabled, unlocked, now, last_check })
    };
    assert!(!tick(START_DELAY, true, true, Some(last)), "just checked");
    assert!(tick(START_DELAY, true, true, Some(last - PERIOD)), "a day later");
    assert!(tick(START_DELAY, true, true, None), "never checked");
    assert!(!tick(START_DELAY / 2, true, true, None), "too early after start");
    assert!(!tick(START_DELAY, false, true, None), "opted out");
    assert!(!tick(START_DELAY, true, false, None), "locked");
    assert!(!tick(START_DELAY, true, true, Some(now + PERIOD)), "clock moved back");
    // The opt-in itself is a setting change that is audited once, and `channel` is fixed.
    let on =
        update::settings_set(st, UpdateSettingsInput { background_check: true, channel: None })
            .expect("on");
    assert!(on.background_check);
    update::settings_set(
        st,
        UpdateSettingsInput { background_check: true, channel: Some("stable".into()) },
    )
    .expect("same");
    assert_eq!(
        update::settings_set(
            st,
            UpdateSettingsInput { background_check: true, channel: Some("beta".into()) }
        )
        .expect_err("beta")
        .code,
        "input.invalid"
    );
    assert_eq!(audit_rows(st, "update.settings_changed").len(), 1);
    assert_audit_free_of(st, &["updates.example.test"]);
}

#[tokio::test]
async fn tampered_manifest_or_signature_is_refused_by_code_and_never_installed() {
    let f = testing::unlocked();
    let st = &f.state;
    let source = Scripted::offering("0.2.0");
    let rt = runtime(
        Arc::clone(&source),
        probe(Bundle::AppImage, "/home/u/Applications/Mooring.AppImage", true),
    );
    let t0 = Instant::now();
    // Review 7 N-51: install attempts that reach the source are 60 s apart; `t(n)` steps.
    let t = |n: u32| t0 + n * MIN_CHECK_GAP;
    update::check(st, &rt, t0, true).await.expect("offer");
    // The asset's minisign signature does not verify (tampered bytes, swapped URL, wrong
    // key): refused after the download, before the audit hook, nothing written.
    source.fail_install(SourceError::Signature);
    let err = update::install(st, &rt, t(1), install_input("0.2.0")).await.expect_err("signature");
    assert_eq!(err.code, "update.signature");
    assert!(!err.message.contains("http"), "{}", err.message);
    assert!(source.installed.lock().expect("lock").is_empty());
    assert!(audit_rows(st, "update.install").is_empty(), "no install row for a refused bundle");
    // A manifest that no longer parses / has no entry for this target.
    source.set(Err(SourceError::Manifest));
    assert_eq!(
        update::install(st, &rt, t(1) + Duration::from_secs(30), install_input("0.2.0"))
            .await
            .expect_err("rate-limited: N-51")
            .code,
        "update.rate_limited"
    );
    assert_eq!(
        update::install(st, &rt, t(2), install_input("0.2.0")).await.expect_err("manifest").code,
        "update.manifest"
    );
    assert_eq!(
        update::check(st, &rt, t(3), true).await.expect_err("manifest").code,
        "update.manifest"
    );
    // The re-check offers a different version than the one confirmed: not installed.
    source.set(Ok(Some(RemoteUpdate {
        version: Version::parse("0.3.0").expect("semver"),
        date: None,
        notes: None,
        size: None,
    })));
    *source.install_error.lock().expect("lock") = None;
    assert_eq!(
        update::install(st, &rt, t(4), install_input("0.2.0")).await.expect_err("swapped").code,
        "update.none"
    );
    // Downgrades and non-semver versions never reach the source.
    let before = source.checks.load(Ordering::SeqCst);
    assert_eq!(
        update::install(st, &rt, t0, install_input("0.0.9")).await.expect_err("downgrade").code,
        "update.none"
    );
    assert_eq!(
        update::install(st, &rt, t0, install_input("0.1.0-rc.1"))
            .await
            .expect_err("pre-release of current")
            .code,
        "update.none"
    );
    assert_eq!(
        update::install(st, &rt, t0, install_input("latest")).await.expect_err("not semver").code,
        "input.invalid"
    );
    assert_eq!(source.checks.load(Ordering::SeqCst), before);
    assert!(source.installed.lock().expect("lock").is_empty());
    // The happy path, for contrast: the audit row is written right before the bundle is.
    assert_eq!(
        update::install(st, &rt, t(5), install_input("0.3.0")).await.map_err(|e| e.code),
        Ok(())
    );
    assert_eq!(*source.installed.lock().expect("lock"), ["0.3.0"]);
    let installed = audit_rows(st, "update.install");
    assert_eq!(installed.len(), 1);
    assert_eq!(
        (installed[0]["from"].as_str(), installed[0]["to"].as_str()),
        (Some("0.1.0"), Some("0.3.0"))
    );
    let refused: Vec<String> = audit_rows(st, "update.refused")
        .iter()
        .filter_map(|r| r["code"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(
        refused,
        ["update.signature", "update.manifest", "update.none", "update.none", "update.none"]
    );
    assert!(!audit_text(st).contains("latest"), "a refused input is not audited");
    assert_audit_free_of(st, &["updates.example.test", "minisign", "0.0.9", "rc.1"]);
}

#[tokio::test]
async fn single_flight_and_unconfigured_runtime() {
    let f = testing::unlocked();
    let st = &f.state;
    let source = Scripted::offering("0.2.0");
    let rt = runtime(
        Arc::clone(&source),
        probe(Bundle::AppImage, "/home/u/Applications/Mooring.AppImage", true),
    );
    let now = Instant::now();
    {
        let _flight = rt.begin_check(now, true).expect("flight");
        assert_eq!(update::check(st, &rt, now, false).await.expect_err("busy").code, "update.busy");
        assert_eq!(
            update::install(st, &rt, now, install_input("0.2.0")).await.expect_err("busy").code,
            "update.busy"
        );
    }
    assert!(!rt.busy(), "the flight is released with the guard");
    // No pubkey in the build: every command answers `update.unconfigured` after the vault gate.
    let off = UpdateRuntime::unconfigured(Version::parse("0.1.0").expect("semver"));
    assert_eq!(
        update::check(st, &off, now, true).await.expect_err("off").code,
        "update.unconfigured"
    );
    assert_eq!(
        update::install(st, &off, now, install_input("9.9.9")).await.expect_err("off").code,
        "update.unconfigured"
    );
    assert!(update::settings_get(st).is_ok(), "settings are readable without a source");
    assert!(audit_rows(st, "update.refused").is_empty(), "busy / unconfigured are not refusals");
}
