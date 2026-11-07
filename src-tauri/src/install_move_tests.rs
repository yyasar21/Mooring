use std::sync::Mutex;

use super::*;

const OURS: &str = "io.github.yyasar21.mooring";

/// Scripted tools: `ditto` really copies a directory tree (so the swap runs on real files),
/// `PlistBuddy` answers from a per-bundle table, everything else from `replies`.
#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<(&'static str, Vec<OsString>)>>,
    ids: Vec<(PathBuf, &'static str, &'static str)>,
    ditto_ok: bool,
    codesign_ok: bool,
    ps: Option<&'static str>,
    hdiutil: Option<String>,
    open_ok: bool,
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_tree(&e.path(), &to)?;
        } else {
            std::fs::copy(e.path(), to)?;
        }
    }
    Ok(())
}

impl Tools for Fake {
    fn run(&self, tool: &'static str, args: &[OsString], _deadline: Duration) -> Option<ToolOutput> {
        self.calls.lock().expect("calls").push((tool, args.to_vec()));
        let ok = |success: bool, stdout: &str| Some(ToolOutput { stdout: stdout.to_owned(), success, truncated: false });
        match tool {
            DITTO => {
                let done = self.ditto_ok && copy_tree(Path::new(&args[0]), Path::new(&args[1])).is_ok();
                ok(done, "")
            }
            CODESIGN => ok(self.codesign_ok, ""),
            PLIST_BUDDY => {
                let plist = PathBuf::from(&args[2]);
                let key = args[1].to_string_lossy().trim_start_matches("Print :").to_owned();
                let hit = self.ids.iter().find(|(app, _, _)| app.join("Contents/Info.plist") == plist);
                match (hit, key.as_str()) {
                    (Some((_, id, _)), "CFBundleIdentifier") => ok(true, &format!("{id}\n")),
                    (Some((_, _, v)), "CFBundleShortVersionString") => ok(true, &format!("{v}\n")),
                    _ => ok(false, ""),
                }
            }
            PS => self.ps.map(|s| ToolOutput { stdout: s.to_owned(), success: true, truncated: false }),
            HDIUTIL if args.first().is_some_and(|a| a == "info") => self.hdiutil.as_deref().and_then(|s| ok(true, s)),
            HDIUTIL => ok(true, ""),
            OPEN => ok(self.open_ok, ""),
            _ => None,
        }
    }
}

fn calls(f: &Fake) -> Vec<&'static str> {
    f.calls.lock().expect("calls").iter().map(|(t, _)| *t).collect()
}

fn bundle(dir: &Path, marker: &str) -> PathBuf {
    let app = dir.join(BUNDLE_NAME);
    std::fs::create_dir_all(app.join("Contents/MacOS")).expect("bundle");
    std::fs::write(app.join("Contents/MacOS/mooring"), marker).expect("exe");
    app
}

fn exe(app: &Path) -> String {
    std::fs::read_to_string(app.join("Contents/MacOS/mooring")).expect("read")
}

fn leftovers(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir).expect("dir").map(|e| e.expect("e").file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

struct Setup {
    _tmp: tempfile::TempDir,
    src: PathBuf,
    home: PathBuf,
    dir: PathBuf,
}

/// `src/Mooring.app` (new, 0.2.0) and a home whose `~/Applications` is the target (the system
/// one is "not writable" in these tests, decision 44).
fn setup() -> Setup {
    let tmp = tempfile::tempdir().expect("tmp");
    let src = bundle(&tmp.path().join("vol"), "new");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let dir = home.join("Applications");
    Setup { _tmp: tmp, src, home, dir }
}

fn user_only(home: PathBuf) -> impl Fn(&Path) -> bool {
    move |p: &Path| p.starts_with(&home)
}

fn fake(s: &Setup) -> Fake {
    Fake { ditto_ok: true, codesign_ok: true, open_ok: true, ps: Some("/sbin/launchd\n"), ids: vec![(s.dir.join(BUNDLE_NAME), OURS, "0.1.2")], ..Fake::default() }
}

#[test]
fn fresh_copy_into_user_applications() {
    let s = setup();
    let f = fake(&s);
    let m = perform(&f, &s.src, &s.home, OURS, &Version::new(0, 2, 0), &user_only(s.home.clone())).expect("moved");
    assert_eq!(m, Moved { app: s.dir.join(BUNDLE_NAME), replaced: false, new_instance: true });
    assert_eq!(exe(&m.app), "new");
    assert_eq!(leftovers(&s.dir), vec![BUNDLE_NAME.to_owned()], "no temporary left");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&s.dir).expect("m").permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "~/Applications created 0755");
    }
    // ditto, then codesign on the temporary copy, never on the target.
    let c = f.calls.lock().expect("calls").clone();
    let ditto = c.iter().find(|(t, _)| *t == DITTO).expect("ditto");
    assert_eq!(ditto.1[0], s.src.as_os_str());
    assert!(Path::new(&ditto.1[1]).file_name().is_some_and(|n| n.to_string_lossy().starts_with(".Mooring.app.")));
    assert!(calls(&f).contains(&CODESIGN));
    relaunch(&f, &m, Some(Path::new("/Volumes/Mooring 1"))).expect("open");
    let c = f.calls.lock().expect("calls").clone();
    let open = &c.last().expect("open").1;
    assert_eq!(open[0], "-n");
    assert!(open.contains(&OsString::from("--mooring-moved")) && !open.contains(&OsString::from("--mooring-replaced")));
}

#[test]
fn an_older_copy_of_ours_is_replaced_and_rolled_back_on_failure() {
    let s = setup();
    bundle(&s.dir, "old");
    let f = fake(&s);
    let m = perform(&f, &s.src, &s.home, OURS, &Version::new(0, 2, 0), &user_only(s.home.clone())).expect("moved");
    assert!(m.replaced && m.new_instance);
    assert_eq!(exe(&m.app), "new");
    assert_eq!(leftovers(&s.dir), vec![BUNDLE_NAME.to_owned()], "the old copy is gone, nothing set aside");
    // A failing signature check leaves the installed copy untouched and no temporary.
    let s = setup();
    bundle(&s.dir, "old");
    let f = Fake { codesign_ok: false, ..fake(&s) };
    let e = perform(&f, &s.src, &s.home, OURS, &Version::new(0, 2, 0), &user_only(s.home.clone()));
    assert_eq!(e, Err(MoveError::CopyFailed));
    assert_eq!(exe(&s.dir.join(BUNDLE_NAME)), "old");
    assert_eq!(leftovers(&s.dir), vec![BUNDLE_NAME.to_owned()]);
    // So does a failing ditto.
    let f = Fake { ditto_ok: false, ..fake(&s) };
    assert_eq!(perform(&f, &s.src, &s.home, OURS, &Version::new(0, 2, 0), &user_only(s.home.clone())), Err(MoveError::CopyFailed));
    assert_eq!(leftovers(&s.dir), vec![BUNDLE_NAME.to_owned()]);
}

#[test]
fn a_foreign_bundle_is_never_replaced() {
    let s = setup();
    bundle(&s.dir, "theirs");
    let f = Fake { ids: vec![(s.dir.join(BUNDLE_NAME), "com.example.other", "9.9.9")], ..fake(&s) };
    let e = perform(&f, &s.src, &s.home, OURS, &Version::new(0, 2, 0), &user_only(s.home.clone()));
    assert_eq!(e, Err(MoveError::NotOurs));
    assert_eq!(exe(&s.dir.join(BUNDLE_NAME)), "theirs");
    assert!(!calls(&f).contains(&DITTO), "nothing copied");
    // Unreadable Info.plist: foreign too.
    let f = Fake { ids: vec![], ..fake(&s) };
    assert_eq!(existing(&f, &s.dir.join(BUNDLE_NAME), OURS), Existing::Foreign);
    // A symlink or a file named Mooring.app: foreign, whatever it points to.
    #[cfg(unix)]
    {
        let other = setup();
        std::fs::create_dir_all(&other.dir).expect("dir");
        std::os::unix::fs::symlink(&s.src, other.dir.join(BUNDLE_NAME)).expect("link");
        assert_eq!(existing(&fake(&other), &other.dir.join(BUNDLE_NAME), OURS), Existing::Foreign);
    }
}

#[test]
fn running_or_newer_copies_are_not_replaced() {
    let s = setup();
    let installed = bundle(&s.dir, "old");
    let ps: &'static str = Box::leak(format!("{}/Contents/MacOS/mooring\n", installed.display()).into_boxed_str());
    let f = Fake { ps: Some(ps), ..fake(&s) };
    assert_eq!(perform(&f, &s.src, &s.home, OURS, &Version::new(0, 2, 0), &user_only(s.home.clone())), Err(MoveError::Running));
    // ps unreadable: fail closed.
    let f = Fake { ps: None, ..fake(&s) };
    assert!(running(&f, &installed));
    // Same or newer installed: open it, copy nothing.
    let f = Fake { ids: vec![(installed.clone(), OURS, "0.2.0")], ..fake(&s) };
    let m = perform(&f, &s.src, &s.home, OURS, &Version::new(0, 2, 0), &user_only(s.home.clone())).expect("open existing");
    assert_eq!(m, Moved { app: installed.clone(), replaced: false, new_instance: false });
    assert!(!calls(&f).contains(&DITTO));
    assert_eq!(exe(&installed), "old");
}

#[test]
fn not_writable_anywhere_never_elevates() {
    let s = setup();
    let f = fake(&s);
    assert_eq!(perform(&f, &s.src, &s.home, OURS, &Version::new(0, 2, 0), &|_| false), Err(MoveError::NotWritable));
    assert!(calls(&f).is_empty(), "no tool ran");
    let (t, d) = target_dir(&s.home, &|_| true).expect("system");
    assert_eq!((t, d), (Target::Applications, PathBuf::from("/Applications")));
}

#[test]
fn swap_without_replace_refuses_a_raced_target() {
    let tmp = tempfile::tempdir().expect("tmp");
    let t = bundle(&tmp.path().join("t"), "new");
    let tmp_copy = tmp.path().join(".Mooring.app.x");
    std::fs::rename(&t, &tmp_copy).expect("mv");
    let dst = bundle(tmp.path(), "raced");
    assert_eq!(swap(&dst, &tmp_copy, false, "x"), Err(MoveError::CopyFailed));
    assert_eq!(exe(&dst), "raced");
    assert!(!tmp_copy.exists(), "temporary removed");
}

#[test]
fn detach_only_our_image_without_a_vault() {
    let tmp = tempfile::tempdir().expect("tmp");
    let vol = tmp.path().join("Mooring 1");
    let app = bundle(&vol, "dmg");
    let f = Fake { ids: vec![(app.clone(), OURS, "0.2.0")], ..Fake::default() };
    assert!(volume_is_ours(&f, &vol, OURS));
    assert!(!volume_is_ours(&f, &vol, "com.example.other"));
    for vault in [Dirs::root_name(Channel::Release), Dirs::root_name(Channel::Dev), Dirs::MARKER] {
        let p = vol.join(vault);
        std::fs::write(&p, b"").expect("entry");
        assert!(!volume_is_ours(&f, &vol, OURS), "{vault}");
        std::fs::remove_file(&p).expect("rm");
    }
    // Not under /Volumes (and not an image mount here): never detached, no hdiutil detach.
    let f = Fake { hdiutil: Some(String::new()), ..f };
    assert!(!detach_if_ours(&f, &vol, OURS));
    assert!(!f.calls.lock().expect("c").iter().any(|(t, a)| *t == HDIUTIL && a.first().is_some_and(|x| x == "detach")));
    // A listed image mount whose app is not reachable is refused too.
    let f = Fake { hdiutil: Some("/dev/disk4s1\tApple_HFS\t/Volumes/Mooring 1\n".into()), ..Fake::default() };
    assert!(!detach_if_ours(&f, Path::new("/Volumes/Mooring 1"), OURS));
}

#[test]
fn bundle_ids_are_bounded() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = bundle(tmp.path(), "x");
    let long: &'static str = Box::leak("a".repeat(300).into_boxed_str());
    let f = Fake { ids: vec![(app.clone(), long, "1")], ..Fake::default() };
    assert_eq!(bundle_id(&f, &app), None);
    let f = Fake { ids: vec![(app.clone(), OURS, "1")], ..Fake::default() };
    assert_eq!(bundle_id(&f, &app).as_deref(), Some(OURS));
}

#[cfg(unix)]
#[test]
fn os_tools_run_with_a_cleared_environment_and_a_deadline() {
    let out = OsTools.run("/usr/bin/env", &[], QUERY_DEADLINE).expect("env");
    assert!(out.success);
    assert_eq!(out.stdout.trim(), "LC_ALL=C", "nothing inherited");
    let none = OsTools.run("/no/such/tool", &[], QUERY_DEADLINE);
    assert!(none.is_none());
    let slow = OsTools.run("/bin/sleep", &[OsString::from("5")], Duration::from_millis(100));
    assert!(slow.is_none(), "killed at the deadline");
}
