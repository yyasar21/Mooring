use std::path::Path;
use std::time::{Duration, Instant};

use mooring_core::CredentialKind;
use mooring_import::{ImportFormat, ImportOptions, ImportSource};
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::LineEnding;
use russh::keys::PrivateKey;

use super::*;
use crate::commands::tree;
use crate::state::testing;

const TERMIUS_CSV: &[u8] = include_bytes!("../../../crates/mooring-import/tests/fixtures/termius.csv");
const SSH_CONFIG: &[u8] = include_bytes!("../../../crates/mooring-import/tests/fixtures/ssh_config");

fn plan_of(format: ImportFormat, name: &str, bytes: &[u8], secrets: bool) -> ImportPlan {
    let opts = ImportOptions { include_plaintext_secrets: secrets, ..ImportOptions::default() };
    parse(format, ImportSource::File { name, bytes }, &opts).expect("plan")
}

fn preview_termius(state: &AppState, secrets: bool) -> ImportPreview {
    let plan = plan_of(ImportFormat::Termius, "hosts.csv", TERMIUS_CSV, secrets);
    finish_preview(state, Path::new("/nonexistent"), ImportFormat::Termius, plan, false).expect("preview")
}

fn tree_totals(state: &AppState) -> (usize, usize) {
    let t = tree::list(state).expect("tree");
    (t.folders.len(), t.connections.len())
}

#[test]
fn formats_catalogue() {
    let f = formats();
    assert_eq!(f.len(), 6);
    let putty = f.iter().find(|f| f.format == ImportFormat::Putty).expect("putty");
    assert_eq!(putty.known_location, Some("putty"));
    assert!(!putty.secrets_possible);
    let termius = f.iter().find(|f| f.format == ImportFormat::Termius).expect("termius");
    assert!(termius.secrets_possible && termius.known_location.is_none());
    let json = serde_json::to_value(&f[0]).expect("json");
    assert_eq!(json["format"], "royal_ts");
    assert!(json["secretsPossible"].is_boolean());
}

#[test]
fn preview_then_apply_writes_a_new_root_folder_and_audits() {
    let f = testing::unlocked();
    let st = &f.state;
    let p = preview_termius(st, true);
    assert_eq!(p.format, ImportFormat::Termius);
    assert!(p.root_name.starts_with("Imported from Termius ("));
    assert_eq!((p.counts.folders, p.counts.connections, p.counts.credentials, p.counts.secrets), (3, 4, 3, 1));
    assert_eq!(p.items.iter().filter(|i| i.kind == "folder").count(), 3);
    let web = p.items.iter().find(|i| i.name == "web01").expect("web01");
    assert_eq!((web.kind, web.host.as_deref(), web.port, web.username.as_deref()), ("connection", Some("web01.example.test"), Some(22), Some("deploy")));
    assert!(web.duplicate_of.is_none());
    let deploy = p.credentials.iter().find(|c| c.name == "deploy").expect("cred");
    assert!(deploy.has_secret && deploy.kind == CredentialKind::UserPassword);
    // The DTO never carries a secret, whatever the opt-in.
    let json = serde_json::to_string(&p).expect("json");
    assert!(!json.contains("test-only-pw"));
    assert!(json.contains("\"hasSecret\":true"));
    assert_eq!(st.import_plans.len(), 1);

    let before = tree_totals(st);
    let report = apply(st, ApplyInput { plan_id: p.plan_id.clone(), exclude: vec![], duplicates: None }).expect("apply");
    assert_eq!((report.folders, report.connections, report.credentials, report.secrets), (3, 4, 3, 1));
    assert_eq!(report.skipped, 2);
    assert_eq!(tree_totals(st), (before.0 + 4, before.1 + 4));
    let t = tree::list(st).expect("tree");
    let root = t.folders.iter().find(|f| f.id == report.root_folder_id).expect("import root");
    assert!(root.name.starts_with("Imported from Termius"));
    // Single use.
    assert_eq!(apply(st, ApplyInput { plan_id: p.plan_id, exclude: vec![], duplicates: None }).expect_err("used").code, "import.plan_expired");
    let events = testing::audit_events(st);
    assert!(events.contains(&"import_previewed".to_owned()));
    assert!(events.contains(&"import_applied".to_owned()));
    let text = std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).expect("audit");
    assert!(!text.contains("web01.example.test"), "no host in the audit");
    assert!(!text.contains("test-only-pw"));
}

#[test]
fn exclusions_duplicates_and_discard() {
    let f = testing::unlocked();
    let st = &f.state;
    // First apply, then a second preview of the same file flags every connection as duplicate.
    let p = preview_termius(st, false);
    apply(st, ApplyInput { plan_id: p.plan_id, exclude: vec![], duplicates: None }).expect("first");
    let p = preview_termius(st, false);
    let dups: Vec<&ItemDto> = p.items.iter().filter(|i| i.duplicate_of.is_some()).collect();
    assert_eq!(dups.len(), 4);
    let before = tree_totals(st);
    let r = apply(st, ApplyInput { plan_id: p.plan_id, exclude: vec![], duplicates: Some("skip".into()) }).expect("skip");
    assert_eq!(r.connections, 0);
    assert_eq!(r.credentials, 0, "unreferenced prompt credentials are not written");
    assert_eq!(tree_totals(st), (before.0 + 4, before.1));
    // Import duplicates anyway, excluding the Web folder (its connection lifts to Prod) and
    // one credential (its connection is unlinked).
    let p = preview_termius(st, false);
    let web_folder = p.items.iter().find(|i| i.kind == "folder" && i.name == "Web").expect("Web").key.clone();
    let dba = p.credentials.iter().find(|c| c.name == "dba").expect("dba").key.clone();
    let r = apply(st, ApplyInput { plan_id: p.plan_id, exclude: vec![web_folder, dba], duplicates: Some("import".into()) }).expect("import");
    assert_eq!((r.folders, r.connections, r.credentials), (2, 4, 2));
    let t = tree::list(st).expect("tree");
    let root = t.folders.iter().find(|f| f.id == r.root_folder_id).expect("root");
    let prod = t.folders.iter().find(|f| f.parent_id.as_deref() == Some(root.id.as_str()) && f.name == "Prod").expect("Prod");
    let web01 = t.connections.iter().find(|c| c.folder_id == prod.id && c.name == "web01").expect("lifted");
    assert!(web01.credential_id.is_some());
    let db01 = t.connections.iter().find(|c| c.folder_id == prod.id && c.name == "db01").expect("db01");
    assert!(db01.credential_id.is_none(), "excluded credential unlinked");
    // Bad arguments and discard.
    let p = preview_termius(st, false);
    assert_eq!(apply(st, ApplyInput { plan_id: p.plan_id.clone(), exclude: vec![], duplicates: Some("merge".into()) }).expect_err("bad").code, "input.invalid");
    discard(st, &p.plan_id).expect("discard");
    assert_eq!(discard(st, &p.plan_id).expect_err("gone").code, "import.plan_expired");
    assert!(st.import_plans.is_empty());
}

#[test]
fn locked_vault_refuses_and_drops_plans() {
    let f = testing::unlocked();
    let st = &f.state;
    let p = preview_termius(st, true);
    crate::commands::vault::lock(st, None).expect("lock");
    assert!(st.import_plans.is_empty(), "plans (and their secrets) do not survive a lock");
    let home = Path::new("/nonexistent");
    let input = PreviewInput { source: SourceInput { pick_id: None, known: Some("openssh".into()) }, include_plaintext_secrets: false, import_key_files: false };
    assert_eq!(preview(st, home, input).expect_err("locked").code, "vault.locked");
    assert_eq!(apply(st, ApplyInput { plan_id: p.plan_id.clone(), exclude: vec![], duplicates: None }).expect_err("locked").code, "vault.locked");
    assert_eq!(discard(st, &p.plan_id).expect_err("locked").code, "vault.locked");
}

#[test]
fn known_openssh_source_and_key_file_opt_in() {
    let f = testing::unlocked();
    let st = &f.state;
    let home = tempfile::tempdir().expect("home");
    let ssh = home.path().join(".ssh");
    std::fs::create_dir_all(&ssh).expect("mkdir");
    std::fs::write(ssh.join("config"), SSH_CONFIG).expect("config");
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
    std::fs::write(ssh.join("id_ed25519"), key.to_openssh(LineEnding::LF).expect("pem").as_bytes()).expect("key");
    std::fs::write(ssh.join("id_rsa"), b"not a key").expect("junk");
    let outside = home.path().join("lab key");
    std::fs::write(&outside, key.to_openssh(LineEnding::LF).expect("pem").as_bytes()).expect("outside");
    let input = |keys: bool| PreviewInput {
        source: SourceInput { pick_id: None, known: Some("openssh".into()) },
        include_plaintext_secrets: false,
        import_key_files: keys,
    };
    let p = preview(st, home.path(), input(false)).expect("preview");
    assert_eq!(p.format, ImportFormat::Openssh);
    assert_eq!(p.counts.connections, 5);
    assert!(p.credentials.iter().all(|c| c.kind == CredentialKind::SshAgent && !c.has_secret));
    let p = preview(st, home.path(), input(true)).expect("preview with keys");
    let kinds: Vec<(&str, CredentialKind, bool)> = p.credentials.iter().map(|c| (c.name.as_str(), c.kind, c.has_secret)).collect();
    assert_eq!(
        kinds,
        vec![
            ("deploy (id_ed25519)", CredentialKind::SshKey, true),
            ("dba (id_rsa)", CredentialKind::SshAgent, false),
            ("ops (lab key)", CredentialKind::SshAgent, false),
            ("%r (id_rsa)", CredentialKind::SshAgent, false),
        ]
    );
    let unreadable: Vec<&str> = p.skipped.iter().filter(|s| s.reason == mooring_import::SkipReason::KeyUnreadable).map(|s| s.source_ref.as_str()).collect();
    assert_eq!(unreadable.len(), 3, "junk, a path outside ~/.ssh and a literal %r key: {unreadable:?}");
    let r = apply(st, ApplyInput { plan_id: p.plan_id, exclude: vec![], duplicates: None }).expect("apply");
    assert_eq!((r.connections, r.credentials, r.secrets), (5, 4, 1));
    // Unknown locations and a missing file.
    let missing = PreviewInput { source: SourceInput { pick_id: None, known: Some("putty".into()) }, include_plaintext_secrets: false, import_key_files: false };
    assert_eq!(preview(st, home.path(), missing).expect_err("no putty dir").code, "import.not_found");
    let both = PreviewInput { source: SourceInput { pick_id: Some("x".into()), known: Some("putty".into()) }, include_plaintext_secrets: false, import_key_files: false };
    assert_eq!(preview(st, home.path(), both).expect_err("both").code, "input.invalid");
    let bad_pick = PreviewInput { source: SourceInput { pick_id: Some("zz".into()), known: None }, include_plaintext_secrets: false, import_key_files: false };
    assert_eq!(preview(st, home.path(), bad_pick).expect_err("pick").code, "input.invalid");
}

#[test]
fn putty_sessions_dir_and_refused_file_audit() {
    let f = testing::unlocked();
    let st = &f.state;
    let home = tempfile::tempdir().expect("home");
    let dir = home.path().join(".putty").join("sessions");
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(dir.join("lab%20box"), b"HostName=ops@192.0.2.7\nProtocol=ssh\nPortNumber=22\n").expect("session");
    std::fs::write(dir.join("Default%20Settings"), b"Protocol=ssh\n").expect("default");
    let input = PreviewInput { source: SourceInput { pick_id: None, known: Some("putty".into()) }, include_plaintext_secrets: false, import_key_files: false };
    let p = preview(st, home.path(), input).expect("preview");
    assert_eq!(p.format, ImportFormat::Putty);
    assert_eq!(p.items.iter().filter(|i| i.kind == "connection").map(|i| i.name.as_str()).collect::<Vec<_>>(), vec!["lab box"]);
    assert_eq!(p.skipped.len(), 1);
    // A refused source is audited by code only.
    std::fs::write(home.path().join(".ssh.config"), b"").ok();
    let ssh = home.path().join(".ssh");
    std::fs::create_dir_all(&ssh).expect("mkdir");
    std::fs::write(ssh.join("config"), b"\xFF\xFEa").expect("bad config");
    let input = PreviewInput { source: SourceInput { pick_id: None, known: Some("openssh".into()) }, include_plaintext_secrets: false, import_key_files: false };
    assert_eq!(preview(st, home.path(), input).expect_err("refused").code, "import.format");
    let events = testing::audit_events(st);
    assert!(events.contains(&"import_refused".to_owned()));
}

#[test]
fn parser_codes_are_listed_for_the_golden() {
    use mooring_import::ImportError as E;
    let all = [
        E::TooLarge { max: 1 },
        E::Format { format: "x", what: "y", at: 0 },
        E::Encrypted,
        E::Doctype { at: 0 },
        E::Limits { what: "z" },
        E::UnsupportedContainer { what: "zip" },
    ];
    for e in all {
        assert!(PARSER_CODES.contains(&e.code()), "{}", e.code());
    }
    assert_eq!(PARSER_CODES.len(), 6);
}

/// Review 7 L-41: a picked `ssh_config` (a file from someone else) never has its
/// `IdentityFile`s read, whatever the flag says; the plan says why.
#[test]
fn picked_ssh_config_ignores_the_key_file_opt_in_with_a_warning() {
    use crate::picks::PickMode;
    let f = testing::unlocked();
    let st = &f.state;
    let home = tempfile::tempdir().expect("home");
    let ssh = home.path().join(".ssh");
    std::fs::create_dir_all(&ssh).expect("mkdir");
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
    std::fs::write(ssh.join("id_ed25519"), key.to_openssh(LineEnding::LF).expect("pem").as_bytes()).expect("key");
    // A "connection pack" that names the user's real key under its own host.
    let pack = home.path().join("pack_ssh_config");
    std::fs::write(&pack, SSH_CONFIG).expect("pack");
    let picked = |path: &Path| {
        st.picks
            .insert(st.picks.epoch(), import_source::IMPORT_PICK_SESSION, PickMode::File, path.to_path_buf(), Instant::now())
            .expect("pick")
    };
    let input = |pick_id: String, keys: bool| PreviewInput {
        source: SourceInput { pick_id: Some(pick_id), known: None },
        include_plaintext_secrets: false,
        import_key_files: keys,
    };
    let p = preview(st, home.path(), input(picked(&pack), true)).expect("preview");
    assert_eq!(p.format, ImportFormat::Openssh);
    assert_eq!(p.counts.connections, 5);
    assert!(p.credentials.iter().all(|c| c.kind == CredentialKind::SshAgent && !c.has_secret), "{:?}", p.credentials);
    assert_eq!(p.counts.secrets, 0);
    assert!(!p.skipped.iter().any(|s| s.reason == mooring_import::SkipReason::KeyUnreadable), "no key was even tried");
    let warned: Vec<&mooring_import::Warning> =
        p.warnings.iter().filter(|w| w.code == mooring_import::WarningCode::KeyFilesOnlyForKnownLocation).collect();
    assert_eq!(warned.len(), 1);
    assert_eq!(warned[0].source_ref, "importKeyFiles");
    assert_eq!(serde_json::to_value(warned[0]).expect("json")["code"], "key_files_only_for_known_location");
    let r = apply(st, ApplyInput { plan_id: p.plan_id, exclude: vec![], duplicates: None }).expect("apply");
    assert_eq!(r.secrets, 0, "nothing from ~/.ssh reached the vault");
    // The same file without the flag carries no such warning.
    let p = preview(st, home.path(), input(picked(&pack), false)).expect("preview");
    assert!(!p.warnings.iter().any(|w| w.code == mooring_import::WarningCode::KeyFilesOnlyForKnownLocation));
    // The known location with the flag still reads the key (the L-41 boundary).
    std::fs::write(ssh.join("config"), SSH_CONFIG).expect("config");
    let known = PreviewInput {
        source: SourceInput { pick_id: None, known: Some("openssh".into()) },
        include_plaintext_secrets: false,
        import_key_files: true,
    };
    let p = preview(st, home.path(), known).expect("known");
    assert_eq!(p.counts.secrets, 1);
    assert!(!p.warnings.iter().any(|w| w.code == mooring_import::WarningCode::KeyFilesOnlyForKnownLocation));
}

/// Review 7 N-60: `import_preview` / `import_apply` are `async` commands whose work runs on
/// the blocking pool. On a single-threaded runtime a 16 MiB preview and an apply through
/// `off_thread` leave the runtime free: a 10 ms ticker keeps ticking while they run, and the
/// parse runs on another thread than the caller. (A `#[tauri::command]` wrapper can only be
/// `async` when it returns a future; the type assertion below pins that for both.)
#[tokio::test]
async fn preview_and_apply_run_off_the_ipc_thread() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use crate::picks::PickMode;
    fn assert_async<F: std::future::Future>(_: &F) {}
    let f = Arc::new(testing::unlocked());
    let home = tempfile::tempdir().expect("home");
    // 16 MiB at the input cap: one real host, the rest comment lines.
    let mut big = Vec::with_capacity(mooring_import::Limits::DEFAULT.max_input);
    big.extend_from_slice(b"Host big01\n  HostName big01.example.test\n  User deploy\n");
    let line = b"# padding padding padding padding padding padding padding padding\n";
    while big.len() + line.len() <= mooring_import::Limits::DEFAULT.max_input {
        big.extend_from_slice(line);
    }
    let path = home.path().join("big_ssh_config");
    std::fs::write(&path, &big).expect("fixture");
    let pick_id = f
        .state
        .picks
        .insert(f.state.picks.epoch(), import_source::IMPORT_PICK_SESSION, PickMode::File, path, Instant::now())
        .expect("pick");
    let caller = std::thread::current().id();
    let ticks = Arc::new(AtomicUsize::new(0));
    let ticker = {
        let ticks = Arc::clone(&ticks);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(5)).await;
                ticks.fetch_add(1, Ordering::SeqCst);
            }
        })
    };
    let fx = Arc::clone(&f);
    let home_path = home.path().to_path_buf();
    let fut = super::super::off_thread(fx, move |fx| {
        // Make the parse observably long on the blocking thread, whatever the machine.
        std::thread::sleep(Duration::from_millis(100));
        let input = PreviewInput {
            source: SourceInput { pick_id: Some(pick_id), known: None },
            include_plaintext_secrets: false,
            import_key_files: false,
        };
        preview(&fx.state, &home_path, input).map(|p| (p, std::thread::current().id()))
    });
    assert_async(&fut);
    let (p, worker) = fut.await.expect("preview");
    assert_ne!(worker, caller, "the parse ran on the blocking pool");
    assert_eq!(p.counts.connections, 1);
    assert!(ticks.load(Ordering::SeqCst) >= 5, "the runtime kept ticking: {} ticks", ticks.load(Ordering::SeqCst));
    let before = ticks.load(Ordering::SeqCst);
    let fx = Arc::clone(&f);
    let plan_id = p.plan_id.clone();
    let fut = super::super::off_thread(fx, move |fx| {
        std::thread::sleep(Duration::from_millis(60));
        apply(&fx.state, ApplyInput { plan_id, exclude: vec![], duplicates: None })
    });
    assert_async(&fut);
    let r = fut.await.expect("apply");
    assert_eq!(r.connections, 1);
    assert!(ticks.load(Ordering::SeqCst) > before, "the runtime kept ticking during the apply");
    ticker.abort();
    assert!(f.state.import_plans.is_empty());
}

/// F1: every `import.*` refusal before the parser (missing source) is audited as
/// `import_refused { code }`; a malformed request (`input.invalid`) is not.
#[test]
fn read_stage_refusals_are_audited_and_malformed_requests_are_not() {
    let f = testing::unlocked();
    let st = &f.state;
    let home = tempfile::tempdir().expect("home");
    let known = |k: &str| PreviewInput {
        source: SourceInput { pick_id: None, known: Some(k.into()) },
        include_plaintext_secrets: false,
        import_key_files: false,
    };
    assert_eq!(preview(st, home.path(), known("openssh")).expect_err("no config").code, "import.not_found");
    assert_eq!(preview(st, home.path(), known("putty")).expect_err("no sessions").code, "import.not_found");
    assert_eq!(preview(st, home.path(), known("nope")).expect_err("bad known").code, "input.invalid");
    let both = PreviewInput {
        source: SourceInput { pick_id: Some("x".into()), known: Some("openssh".into()) },
        include_plaintext_secrets: false,
        import_key_files: false,
    };
    assert_eq!(preview(st, home.path(), both).expect_err("both").code, "input.invalid");
    let events = testing::audit_events(st);
    assert_eq!(events.iter().filter(|e| *e == "import_refused").count(), 2, "{events:?}");
}
