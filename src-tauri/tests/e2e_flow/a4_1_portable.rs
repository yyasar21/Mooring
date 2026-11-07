//! A4.1 Q1 (ADR-0021 §Test plan, integration): portable mode through the command layer with
//! an `AppState` built from a `Dirs` that `Dirs::resolve` produced for a tempdir holding a
//! `portable` marker, and the `icacls` argv pin. The hostile resolver cases live in
//! `a4_1_portable_dirs.rs` and share this file's helpers.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use secrecy::SecretString;
use semver::Version;

use crate::a4_support::{assert_audit_free_of, audit_rows};
use crate::commands::credentials::{self, NewCredential};
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::update::{self, UpdateSettingsInput};
use crate::commands::vault::{self, VaultStatus};
use crate::dirs::Dirs;
use crate::state::testing::{self, MASTER};
use crate::state::AppState;
use crate::updater::install_mode::{Bundle, InstallFacts, InstallProbe};
use crate::updater::source::{BeforeInstall, BoxFuture, RemoteUpdate, SourceError, UpdateSource};
use crate::updater::UpdateRuntime;

/// ADR-0021 §2: the exact wording of the portable refusal (pinned by the UI as well).
const PORTABLE_MESSAGE: &str = "portable build: download the new zip and replace the folder";

// ----------------------------------------------------------------- helpers

/// The OS directories must never be consulted once a marker is present.
pub fn never_os() -> tauri::Result<(PathBuf, PathBuf)> {
    panic!("the OS directories were consulted in portable mode")
}

/// Create-and-remove probe with a per-call unique name (two threads may probe one dir).
pub fn probe(p: &Path) -> bool {
    static N: AtomicUsize = AtomicUsize::new(0);
    let f = p.join(format!(
        ".qa-probe-{:?}-{}",
        std::thread::current().id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let ok = std::fs::OpenOptions::new().write(true).create_new(true).open(&f).is_ok();
    if ok {
        let _ = std::fs::remove_file(&f);
    }
    ok
}

/// `<dir>/mooring` (empty file) with an empty `portable` marker beside it.
pub fn portable_app(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir).expect("mkdir");
    let exe = dir.join("mooring");
    std::fs::write(&exe, b"").expect("exe");
    std::fs::write(dir.join(Dirs::MARKER), b"").expect("marker");
    exe
}

/// Every path under `root`, relative to it (files, dirs, links), depth first.
pub fn tree_of(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            out.push(p.strip_prefix(root).expect("under root").to_path_buf());
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                walk(&p, root, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

/// A source that offers `0.2.0` and counts how often it is asked.
struct Offering(AtomicUsize);

impl UpdateSource for Offering {
    fn check(&self) -> BoxFuture<'_, Result<Option<RemoteUpdate>, SourceError>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(Some(RemoteUpdate {
                version: Version::new(0, 2, 0),
                date: None,
                notes: Some("See https://updates.example.test/notes".into()),
                size: None,
            }))
        })
    }

    fn install<'a>(
        &'a self,
        _: &'a Version,
        _: BeforeInstall,
    ) -> BoxFuture<'a, Result<(), SourceError>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { panic!("install must never be reached in portable mode") })
    }
}

/// What `OsProbe { portable: true }` would report for an NSIS-looking exe that is writable:
/// every other fact says "in-app", so only the portable flag can make it manual.
struct PortableProbe;

impl InstallProbe for PortableProbe {
    fn facts(&self) -> Option<InstallFacts> {
        Some(InstallFacts {
            bundle: Bundle::AppImage,
            install_path: "/media/stick/Mooring/Mooring.AppImage".into(),
            writable: true,
            cask_present: false,
            portable: true,
            dev_build: false,
        })
    }
}

pub fn mode_of(p: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).expect("meta").permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        0o700
    }
}

// --------------------------------------------------------------- E2E flow

#[tokio::test]
async fn portable_flow_keeps_every_file_under_mooring_data() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = portable_app(&app);
    let dirs = Dirs::resolve(&exe, None, &never_os, &probe).expect("resolve");
    let root = app.join(Dirs::ROOT);
    assert_eq!(dirs.portable_root.as_deref(), Some(root.as_path()));
    assert_eq!(mode_of(&root), 0o700);

    let clipboard = Arc::new(crate::clipboard::MemoryClipboard::default());
    let st = AppState::new(dirs.clone(), testing::settings(clipboard)).expect("state");
    // `lib.rs` setup writes this row right after the state exists; replayed here (the Tauri
    // setup hook cannot run without a WebView).
    st.audit(mooring_audit::AuditEvent::AppStart { portable: st.portable_root.is_some() });

    // vault create → lock → unlock → one connection.
    assert_eq!(vault::status(&st).expect("status"), VaultStatus::Missing);
    assert_eq!(vault::create(&st, pw(MASTER)).expect("create"), VaultStatus::Unlocked);
    assert_eq!(vault::lock(&st, Some("user")).expect("lock"), VaultStatus::Locked);
    assert_eq!(vault::unlock(&st, pw(MASTER)).expect("unlock"), VaultStatus::Unlocked);
    let folder = tree::list(&st).expect("tree").folders[0].id.clone();
    credentials::create(&st, NewCredential::password_for_tests("stick login")).expect("cred");
    let conn = tree::create_connection(
        &st,
        ConnectionFields {
            port: Some(22),
            ..ConnectionFields::basic(&folder, "usb01", "ssh", "usb01.example.test")
        },
    )
    .expect("connection");
    assert_eq!(tree::search(&st, "usb01", 10).expect("search")[0].id, conn.id);

    // app.start { portable: true }, no path.
    let starts = audit_rows(&st, "app.start");
    assert_eq!(starts.len(), 1, "{starts:?}");
    assert_eq!(starts[0]["portable"], serde_json::Value::Bool(true), "{}", starts[0]);
    assert_audit_free_of(&st, &[&root.display().to_string(), Dirs::ROOT, "stick login"]);

    // app_info().portableDataDir is the `Mooring Data` path, camelCase on the wire.
    let info = serde_json::to_value(vault::info(&st)).expect("json");
    assert_eq!(info["portableDataDir"], serde_json::json!(root.display().to_string()), "{info}");
    assert!(info.get("portable_data_dir").is_none(), "snake_case key leaked: {info}");

    // update_settings_set { backgroundCheck: true } → update.manual_only with the exact text,
    // nothing stored; `false` is accepted.
    let on = UpdateSettingsInput { background_check: true, channel: None };
    let err = update::settings_set(&st, on).expect_err("refused");
    assert_eq!((err.code, err.message.as_str()), ("update.manual_only", PORTABLE_MESSAGE));
    assert!(!update::settings_get(&st).expect("get").background_check, "nothing stored");
    let refused = audit_rows(&st, "update.refused");
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["code"], "update.manual_only");
    let off = UpdateSettingsInput { background_check: false, channel: None };
    assert!(!update::settings_set(&st, off).expect("off is fine").background_check);

    // update_check on demand: one source call, manual mode, reason `portable`; install refused
    // before the source is asked.
    let source = Arc::new(Offering(AtomicUsize::new(0)));
    let rt = UpdateRuntime::new(source.clone(), Arc::new(PortableProbe), Version::new(0, 1, 0));
    let checked = update::check(&st, &rt, Instant::now(), true).await.expect("check");
    assert_eq!(checked.install_mode, "manual");
    let reason = checked.manual_reason.expect("reason");
    assert_eq!(serde_json::to_value(reason).expect("json"), serde_json::json!("portable"));
    assert_eq!((reason.code(), reason.message()), ("update.manual_only", PORTABLE_MESSAGE));
    assert_eq!(checked.available.map(|a| a.version), Some("0.2.0".into()));
    assert_eq!(source.0.load(Ordering::SeqCst), 1, "exactly one on-demand request");
    let install = update::InstallInput { version: "0.2.0".into(), close_sessions: false };
    let err = update::install(&st, &rt, Instant::now(), install).await.expect_err("manual");
    assert_eq!((err.code, err.message.as_str()), ("update.manual_only", PORTABLE_MESSAGE));
    assert_eq!(source.0.load(Ordering::SeqCst), 1, "install never reaches the source");
    assert_audit_free_of(&st, &["updates.example.test", "/media/stick"]);

    // lock: every file written so far lives under `Mooring Data/`; the OS dirs were never
    // consulted (`never_os`), the marker dir got nothing else.
    assert_eq!(vault::lock(&st, Some("user")).expect("lock"), VaultStatus::Locked);
    let written = tree_of(tmp.path());
    assert!(written.len() > 5, "the flow wrote files: {written:?}");
    let rel_root = Path::new("app").join(Dirs::ROOT);
    let allowed = |p: &Path| {
        p == Path::new("app")
            || p == Path::new("app/mooring")
            || p == Path::new("app/portable")
            || p.starts_with(&rel_root)
    };
    let outside: Vec<&PathBuf> = written.iter().filter(|p| !allowed(p)).collect();
    assert!(outside.is_empty(), "written outside Mooring Data: {outside:?}");
    for want in [rel_root.join("data"), rel_root.join("cache")] {
        assert!(written.contains(&want), "{} missing in {written:?}", want.display());
    }
    let rel_data = rel_root.join("data");
    assert!(
        written.iter().any(|p| p.starts_with(&rel_data) && *p != rel_data),
        "data holds the vault files"
    );
    assert_eq!(mode_of(&dirs.data), 0o700);
    assert_eq!(mode_of(&dirs.cache), 0o700);
    // Not portable: the same state shape reports null.
    let plain = testing::empty();
    assert_eq!(
        serde_json::to_value(vault::info(&plain.state)).expect("json")["portableDataDir"],
        serde_json::Value::Null
    );
    let on = UpdateSettingsInput { background_check: true, channel: None };
    vault::create(&plain.state, pw(MASTER)).expect("create");
    assert!(
        update::settings_set(&plain.state, on).expect("opt-in allowed elsewhere").background_check
    );
}

// ----------------------------------------------------------- Windows ACL

#[test]
fn icacls_argv_is_one_element_per_argument_with_the_root_first() {
    use crate::portable_acl::{argv, GRANT};
    // Spaces and a trailing backslash stay inside one argv element (no shell, no quoting).
    let root = Path::new("D:\\My Stuff\\Mooring Data\\");
    let a = argv(root);
    assert_eq!(a.len(), 4);
    assert_eq!(a[0], root.as_os_str());
    assert_eq!(a[0].to_string_lossy(), "D:\\My Stuff\\Mooring Data\\");
    assert_eq!(&a[1..], ["/inheritance:r", "/grant:r", GRANT].map(std::ffi::OsString::from));
    // A root that looks like an option is still the first element, after the exe (icacls
    // has no `--`), so the fixed options always follow it in that order.
    for odd in ["-Mooring Data", "/Mooring Data", "--inheritance:e", "/grant:r"] {
        let a = argv(Path::new(odd));
        assert_eq!(a[0].to_string_lossy(), odd);
        assert_eq!(a[1], "/inheritance:r");
        assert_eq!(a[2], "/grant:r");
        assert_eq!(a[3], "*S-1-3-4:(OI)(CI)F");
    }
    assert_eq!(GRANT, "*S-1-3-4:(OI)(CI)F");
    assert!(!GRANT.contains(' '));
}
