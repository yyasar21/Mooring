//! Runtime tests: single flight, rate limit, the install-mode matrix, the pubkey gate. The
//! scripted [`FakeSource`] / [`FakeProbe`] are shared with `commands/update_tests.rs`.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use semver::Version;

use super::install_mode::{decide, Bundle, InstallFacts, InstallMode, InstallProbe, ManualReason};
use super::source::{BeforeInstall, BoxFuture, RemoteUpdate, SourceError, UpdateSource};
use super::{configured_pubkey, UpdateRuntime, MIN_CHECK_GAP};

/// Scripted source: each `check` pops the next scripted answer (the last one repeats).
#[derive(Default)]
pub struct FakeSource {
    script: Mutex<VecDeque<Result<Option<RemoteUpdate>, SourceError>>>,
    /// `install` outcome after its own re-check (`None` = install succeeds).
    pub install_error: Mutex<Option<SourceError>>,
    pub checks: AtomicUsize,
    pub installs: Mutex<Vec<String>>,
    pub before_install_calls: AtomicUsize,
}

impl FakeSource {
    pub fn offering(update: Option<RemoteUpdate>) -> Arc<Self> {
        let s = Self::default();
        s.script.lock().expect("lock").push_back(Ok(update));
        Arc::new(s)
    }

    pub fn failing(e: SourceError) -> Arc<Self> {
        let s = Self::default();
        s.script.lock().expect("lock").push_back(Err(e));
        Arc::new(s)
    }

    /// Replace the script with one answer.
    pub fn set(&self, r: Result<Option<RemoteUpdate>, SourceError>) {
        let mut q = self.script.lock().expect("lock");
        q.clear();
        q.push_back(r);
    }

    fn next(&self) -> Result<Option<RemoteUpdate>, SourceError> {
        let mut q = self.script.lock().expect("lock");
        if q.len() > 1 {
            q.pop_front().expect("non-empty")
        } else {
            q.front().cloned().unwrap_or(Ok(None))
        }
    }
}

impl UpdateSource for FakeSource {
    fn check(&self) -> BoxFuture<'_, Result<Option<RemoteUpdate>, SourceError>> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let r = self.next();
        Box::pin(async move { r })
    }

    fn install<'a>(
        &'a self,
        version: &'a Version,
        before_install: BeforeInstall,
    ) -> BoxFuture<'a, Result<(), SourceError>> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let offered = self.next();
        Box::pin(async move {
            let offered = offered?.ok_or(SourceError::None)?;
            if offered.version != *version {
                return Err(SourceError::None);
            }
            if let Some(e) = *self.install_error.lock().expect("lock") {
                return Err(e);
            }
            self.before_install_calls.fetch_add(1, Ordering::SeqCst);
            before_install();
            self.installs.lock().expect("lock").push(version.to_string());
            Ok(())
        })
    }
}

/// Fixed facts.
pub struct FakeProbe(pub Option<InstallFacts>);

impl InstallProbe for FakeProbe {
    fn facts(&self) -> Option<InstallFacts> {
        self.0.clone()
    }
}

pub fn facts(bundle: Bundle, path: &str, writable: bool) -> InstallFacts {
    InstallFacts { bundle, install_path: PathBuf::from(path), writable, cask_present: false, portable: false, dev_build: false, winget: false }
}

/// An in-app `AppImage` install at a writable path.
pub fn in_app_probe() -> Arc<FakeProbe> {
    Arc::new(FakeProbe(Some(facts(Bundle::AppImage, "/home/u/Applications/Mooring.AppImage", true))))
}

pub fn v(s: &str) -> Version {
    Version::parse(s).expect("semver")
}

pub fn offered(version: &str) -> RemoteUpdate {
    RemoteUpdate {
        version: v(version),
        date: Some("2026-11-06T10:00:00Z".to_owned()),
        notes: Some("Fixes".to_owned()),
        size: Some(12_345),
    }
}

pub fn runtime(source: Arc<FakeSource>, probe: Arc<FakeProbe>) -> UpdateRuntime {
    UpdateRuntime::new(source, probe, v("0.1.0"))
}

// ------------------------------------------------------------------ matrix

#[test]
fn install_mode_matrix() {
    use Bundle as B;
    use InstallMode as M;
    use ManualReason as R;
    let rows: &[(Bundle, &str, bool, InstallMode)] = &[
        // Linux
        (B::AppImage, "/home/u/Applications/Mooring.AppImage", true, M::InApp),
        (B::AppImage, "/opt/Mooring.AppImage", false, M::Manual(R::NotWritable)),
        (B::Deb, "/usr/bin/mooring", false, M::Manual(R::PackageManager)),
        (B::Deb, "/usr/bin/mooring", true, M::Manual(R::PackageManager)),
        (B::Rpm, "/usr/bin/mooring", true, M::Manual(R::PackageManager)),
        // macOS
        (B::MacApp, "/Users/u/Applications/Mooring.app", true, M::InApp),
        (B::MacApp, "/Applications/Mooring.app", true, M::InApp),
        (B::MacApp, "/Applications/Mooring.app", false, M::Manual(R::NotWritable)),
        (B::MacApp, "/opt/homebrew/Caskroom/mooring/0.1.0/Mooring.app", true, M::Manual(R::Homebrew)),
        (B::MacApp, "/usr/local/Caskroom/mooring/0.1.0/Mooring.app", true, M::Manual(R::Homebrew)),
        (B::MacApp, "/opt/homebrew/Cellar/mooring/Mooring.app", true, M::InApp),
        (B::MacApp, "/usr/local/Caskroom-not/Mooring.app", true, M::InApp),
        // Windows
        (B::Nsis, "C:\\Users\\u\\AppData\\Local\\Mooring", true, M::InApp),
        (B::Nsis, "C:\\Program Files\\Mooring", false, M::Manual(R::NotWritable)),
        (B::Msi, "C:\\Program Files\\Mooring", true, M::Manual(R::PackageManager)),
        // dev build
        (B::Unknown, "/tmp/target/debug/mooring", true, M::Manual(R::NotBundled)),
    ];
    for (bundle, path, writable, want) in rows {
        assert_eq!(decide(&facts(*bundle, path, *writable)), *want, "{bundle:?} {path} w={writable}");
    }
}

/// ADR-0021 §2: a portable folder is manual whatever the bundle, the path, writability or
/// the cask say; the code is `update.manual_only` with the fixed zip-replace message.
#[test]
fn portable_beats_every_bundle_kind() {
    use Bundle as B;
    for (bundle, path) in [
        (B::AppImage, "/home/u/Applications/Mooring.AppImage"),
        (B::Deb, "/usr/bin/mooring"),
        (B::Rpm, "/usr/bin/mooring"),
        (B::MacApp, "/Users/u/Desktop/Mooring/Mooring.app"),
        (B::MacApp, "/opt/homebrew/Caskroom/mooring/0.1.0/Mooring.app"),
        (B::Msi, "C:\\Program Files\\Mooring"),
        (B::Nsis, "D:\\Mooring"),
        (B::Unknown, "D:\\Mooring\\Mooring.exe"),
    ] {
        for writable in [true, false] {
            for cask_present in [true, false] {
                let f = InstallFacts { portable: true, cask_present, ..facts(bundle, path, writable) };
                assert_eq!(decide(&f), InstallMode::Manual(ManualReason::Portable), "{bundle:?} {path}");
            }
        }
    }
    assert_eq!(ManualReason::Portable.code(), "update.manual_only");
    assert_eq!(ManualReason::Portable.message(), "portable build: download the new zip and replace the folder");
    assert_eq!(serde_json::to_value(ManualReason::Portable).expect("json"), "portable");
}

/// Review 7 N-55: a cask that moved its `.app` into `/Applications` is still Homebrew's
/// (the `Caskroom/mooring` directory exists), and a symlinked `/Applications/Mooring.app`
/// resolves under the Caskroom.
#[test]
fn homebrew_cask_is_detected_by_caskroom_presence_and_resolved_path() {
    use super::install_mode::{cask_present_in, under_roots, CASKROOMS, CASK_TOKEN};
    let moved = InstallFacts { cask_present: true, ..facts(Bundle::MacApp, "/Applications/Mooring.app", true) };
    assert_eq!(decide(&moved), InstallMode::Manual(ManualReason::Homebrew));
    let plain = facts(Bundle::MacApp, "/Applications/Mooring.app", true);
    assert_eq!(decide(&plain), InstallMode::InApp);
    // AppImage / NSIS never consult the cask fact.
    let other = InstallFacts { cask_present: true, ..facts(Bundle::AppImage, "/home/u/Mooring.AppImage", true) };
    assert_eq!(decide(&other), InstallMode::InApp);
    assert_eq!(CASKROOMS, &["/opt/homebrew/Caskroom/", "/usr/local/Caskroom/"]);
    assert_eq!(CASK_TOKEN, "mooring");

    // Both prefixes, as the probe sees them after canonicalisation, in a temp tree.
    let dir = tempfile::tempdir().expect("tmp");
    let arm = dir.path().join("opt/homebrew/Caskroom");
    let intel = dir.path().join("usr/local/Caskroom");
    let roots = [arm.as_path(), intel.as_path()];
    assert!(!cask_present_in(&roots, CASK_TOKEN), "nothing installed yet");
    for root in [&arm, &intel] {
        let app = root.join("mooring/0.1.0/Mooring.app");
        std::fs::create_dir_all(&app).expect("mkdir");
        assert!(under_roots(&app, &roots), "{}", app.display());
        assert!(cask_present_in(&roots, CASK_TOKEN));
        std::fs::remove_dir_all(root.join("mooring")).expect("rm");
    }
    assert!(!under_roots(&dir.path().join("Applications/Other.app"), &roots));
    #[cfg(unix)]
    {
        let target = arm.join("mooring/0.2.0/Mooring.app");
        std::fs::create_dir_all(&target).expect("mkdir");
        let apps = dir.path().join("Applications");
        std::fs::create_dir_all(&apps).expect("mkdir");
        let link = apps.join("Mooring.app");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let resolved = std::fs::canonicalize(&link).expect("canonical");
        let canonical_roots = [std::fs::canonicalize(&arm).expect("c"), std::fs::canonicalize(&intel).expect("c")];
        let canonical_roots: Vec<&std::path::Path> = canonical_roots.iter().map(PathBuf::as_path).collect();
        assert!(under_roots(&resolved, &canonical_roots), "{}", resolved.display());
        assert!(!under_roots(&link, &canonical_roots), "the unresolved link is outside");
    }
}

#[test]
fn manual_reasons_map_to_the_adr_codes() {
    assert_eq!(ManualReason::NotWritable.code(), "update.not_writable");
    for r in [ManualReason::PackageManager, ManualReason::Homebrew, ManualReason::NotBundled] {
        assert_eq!(r.code(), "update.manual_only");
        assert!(!r.message().is_empty());
    }
    assert_eq!(serde_json::to_value(ManualReason::PackageManager).expect("json"), "package_manager");
    assert_eq!(serde_json::to_value(ManualReason::NotBundled).expect("json"), "not_bundled");
}

#[test]
fn runtime_treats_a_missing_probe_result_as_not_bundled() {
    let rt = UpdateRuntime::new(FakeSource::offering(None), Arc::new(FakeProbe(None)), v("0.1.0"));
    assert_eq!(rt.install_mode(), InstallMode::Manual(ManualReason::NotBundled));
    assert_eq!(runtime(FakeSource::offering(None), in_app_probe()).install_mode(), InstallMode::InApp);
}

#[cfg(unix)]
#[test]
fn os_writability_probes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tmp");
    let file = dir.path().join("app.AppImage");
    std::fs::write(&file, b"x").expect("write");
    assert!(super::install_mode::dir_writable(Some(dir.path())));
    assert!(super::install_mode::file_writable(&file));
    assert!(!super::install_mode::dir_writable(None));
    assert!(!super::install_mode::dir_writable(Some(&dir.path().join("missing"))));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o444)).expect("chmod");
    // root ignores file modes; only assert when not root.
    if std::fs::OpenOptions::new().append(true).open(&file).is_err() {
        assert!(!super::install_mode::file_writable(&file));
    }
    let left: Vec<_> = std::fs::read_dir(dir.path()).expect("ls").collect();
    assert_eq!(left.len(), 1, "the probe file is removed");
}

// ------------------------------------------------------------------ runtime

#[test]
fn unconfigured_runtime_has_no_source() {
    let rt = UpdateRuntime::unconfigured(v("0.1.0"));
    assert!(!rt.configured());
    assert_eq!(rt.source().map(|_| ()).expect_err("unconfigured").code, "update.unconfigured");
    assert!(format!("{rt:?}").contains("configured: false"));
}

#[test]
fn single_flight_and_rate_limit() {
    let rt = runtime(FakeSource::offering(None), in_app_probe());
    let t0 = Instant::now();
    let flight = rt.begin_check(t0, true).expect("first");
    assert!(rt.busy());
    assert_eq!(rt.begin_check(t0, true).expect_err("busy").code, "update.busy");
    assert_eq!(rt.begin_install(t0).expect_err("busy").code, "update.busy");
    drop(flight);
    assert!(!rt.busy());
    let e = rt.begin_check(t0 + Duration::from_secs(10), true).expect_err("too soon");
    assert_eq!(e.code, "update.rate_limited");
    assert!(e.message.contains("50 s"), "{}", e.message);
    // The background loop is not subject to the manual gap.
    drop(rt.begin_check(t0 + Duration::from_secs(10), false).expect("background"));
    // Its network use still counts for the next manual check.
    assert_eq!(rt.begin_check(t0 + Duration::from_secs(30), true).expect_err("gap").code, "update.rate_limited");
    drop(rt.begin_check(t0 + Duration::from_secs(10) + MIN_CHECK_GAP, true).expect("after the gap"));
    // An install right after a check is fine (the check gap does not apply to it)…
    let t1 = t0 + Duration::from_secs(10) + MIN_CHECK_GAP;
    let f = rt.begin_install(t1 + Duration::from_secs(1)).expect("install");
    assert_eq!(rt.begin_check(t0 + Duration::from_secs(1000), true).expect_err("busy").code, "update.busy");
    drop(f);
    // …but installs are throttled against each other (review 7 N-51).
    let e = rt.begin_install(t1 + Duration::from_secs(31)).expect_err("too soon");
    assert_eq!(e.code, "update.rate_limited");
    assert!(e.message.contains("30 s"), "{}", e.message);
    assert!(!rt.busy(), "a refused install takes no flight");
    drop(rt.begin_install(t1 + Duration::from_secs(1) + MIN_CHECK_GAP).expect("after the gap"));
    // An install also counts as network use for the next manual check.
    assert_eq!(rt.begin_check(t1 + Duration::from_secs(2) + MIN_CHECK_GAP, true).expect_err("gap").code, "update.rate_limited");
}

#[test]
fn strict_semver_newer() {
    let rt = runtime(FakeSource::offering(None), in_app_probe());
    assert!(rt.is_newer(&v("0.1.1")));
    assert!(rt.is_newer(&v("1.0.0")));
    assert!(!rt.is_newer(&v("0.1.0")));
    assert!(!rt.is_newer(&v("0.0.9")));
    assert!(!rt.is_newer(&v("0.1.0-rc.2")), "a pre-release of the running version is older");
    assert!(rt.is_newer(&v("0.1.1-rc.1")), "a pre-release of a later version is newer");
    assert_eq!(*rt.current(), v("0.1.0"));
    assert!(Version::parse("1.0").is_err(), "strict: no partial versions");
    assert!(Version::parse("v1.0.0").is_err(), "strict: no prefix");
}

#[test]
fn last_available_round_trip() {
    let rt = runtime(FakeSource::offering(None), in_app_probe());
    assert!(rt.last_available().is_none());
    rt.set_last_available(Some(offered("0.2.0")));
    assert_eq!(rt.last_available().map(|r| r.version), Some(v("0.2.0")));
}

#[test]
fn pubkey_gate_reads_the_plugin_config() {
    let mut config = tauri::Config::default();
    assert!(configured_pubkey(&config).is_none(), "no plugins block");
    config.plugins.0.insert("updater".into(), serde_json::json!({ "endpoints": [] }));
    assert!(configured_pubkey(&config).is_none(), "no pubkey");
    config.plugins.0.insert("updater".into(), serde_json::json!({ "pubkey": "   " }));
    assert!(configured_pubkey(&config).is_none(), "blank pubkey");
    config.plugins.0.insert("updater".into(), serde_json::json!({ "pubkey": 42 }));
    assert!(configured_pubkey(&config).is_none(), "wrong type");
    config.plugins.0.insert("updater".into(), serde_json::json!({ "pubkey": " dW50cnVzdGVkIGNvbW1lbnQ6 " }));
    assert_eq!(configured_pubkey(&config).as_deref(), Some("dW50cnVzdGVkIGNvbW1lbnQ6"));
}

/// The checked-in config must not carry a pubkey the owner has not generated (ADR-0018 §7):
/// until R1 sets it, the plugin stays unregistered and `update.unconfigured` is the answer.
#[test]
fn checked_in_config_is_read_without_panicking() {
    // ADR-0028: the dev base and the merged release config.
    for v in [crate::test_config::base(), crate::test_config::release()] {
        checked_config(&v);
    }
    let release = crate::test_config::release();
    assert!(release.pointer("/plugins/updater/pubkey").is_some(), "the release overlay carries the pubkey");
}

fn checked_config(v: &serde_json::Value) {
    if let Some(key) = v.pointer("/plugins/updater/pubkey").and_then(serde_json::Value::as_str) {
        assert!(!key.trim().is_empty(), "an empty pubkey must be absent, not blank");
        let endpoints = v.pointer("/plugins/updater/endpoints").and_then(serde_json::Value::as_array).expect("endpoints");
        for e in endpoints {
            assert!(e.as_str().is_some_and(|u| u.starts_with("https://")), "{e}");
        }
    }
}

#[test]
fn source_errors_map_to_codes() {
    for (e, code) in [
        (SourceError::Network, "update.network"),
        (SourceError::Manifest, "update.manifest"),
        (SourceError::Signature, "update.signature"),
        (SourceError::None, "update.none"),
        (SourceError::Install, "update.install_failed"),
        (SourceError::Unconfigured, "update.unconfigured"),
    ] {
        assert_eq!(e.code(), code);
        assert!(!e.message().is_empty());
        // F1: the UI sentence is a fixed string per class; the plugin's own text (URLs,
        // bundle paths, temp dirs) stays in the warn log and never reaches an `IpcError`.
        let m = e.message();
        assert!(
            !m.contains('/') && !m.contains('\\') && !m.contains("://") && !m.contains("..") && !m.contains('%'),
            "{code}: {m}"
        );
    }
}

/// ADR-0028 §1: a development build is manual before anything else — portable, Homebrew,
/// package managers and writability never get a say — with the fixed dev sentence.
#[test]
fn dev_build_beats_every_install_mode() {
    use Bundle as B;
    for bundle in [B::AppImage, B::Deb, B::Rpm, B::MacApp, B::Msi, B::Nsis, B::Unknown] {
        for writable in [true, false] {
            for cask_present in [true, false] {
                for portable in [true, false] {
                    let f = InstallFacts {
                        dev_build: true,
                        portable,
                        cask_present,
                        ..facts(bundle, "/Applications/Mooring Dev.app", writable)
                    };
                    assert_eq!(decide(&f), InstallMode::Manual(ManualReason::DevBuild), "{f:?}");
                }
            }
        }
    }
    let r = ManualReason::DevBuild;
    assert_eq!(r.code(), "update.manual_only");
    assert_eq!(r.message(), "development build: updates come from your own builds");
    assert_eq!(serde_json::to_value(r).expect("json"), "dev_build");
}

/// The development runtime: no source, `update.manual_only` instead of `update.unconfigured`,
/// and its install mode is `DevBuild` even when the probe has nothing to say.
#[test]
fn development_runtime_answers_dev_build() {
    let rt = UpdateRuntime::development(v("0.1.0"));
    assert!(rt.dev_build() && !rt.configured());
    let e = rt.source().err().expect("no source");
    assert_eq!((e.code, e.message.as_str()), ("update.manual_only", ManualReason::DevBuild.message()));
    assert_eq!(rt.install_mode(), InstallMode::Manual(ManualReason::DevBuild));
    assert!(!UpdateRuntime::unconfigured(v("0.1.0")).dev_build());
}
