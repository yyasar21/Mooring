use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tauri_plugin_dialog::{MessageDialogButtons, MessageDialogResult};

use super::*;

fn roots() -> Roots {
    Roots::production(Some(Path::new("/Users/u")), Some(PathBuf::from("/Users/u/Downloads")))
}

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

#[test]
fn classification_table() {
    let r = roots();
    let vol = |n: &str| Location::Volume(p(n));
    for (bundle, want) in [
        ("/Volumes/Mooring/Mooring.app", vol("/Volumes/Mooring")),
        ("/Volumes/Mooring 1/Mooring.app", vol("/Volumes/Mooring 1")),
        ("/Volumes/Mooring 0.2.0/Mooring.app", vol("/Volumes/Mooring 0.2.0")),
        ("/Volumes/Mooring/nested/deeper/Mooring.app", vol("/Volumes/Mooring")),
        ("/Volumes/Mooring.app", Location::Other),
        ("/Volumes/../Applications/Mooring.app", Location::Other),
        (
            "/private/var/folders/ab/cd/T/AppTranslocation/0E1F-22/d/Mooring.app",
            Location::Translocated,
        ),
        ("/Volumes/Mooring/AppTranslocation/Mooring.app", Location::Translocated),
        ("/Users/u/Downloads/Mooring.app", Location::Downloads),
        ("/Users/u/Downloads/Mooring_0.2.0/Mooring.app", Location::Downloads),
        ("/Applications/Mooring.app", Location::Applications),
        ("/Applications/Utilities/Mooring.app", Location::Applications),
        ("/Users/u/Applications/Mooring.app", Location::Applications),
        ("/Users/u/Desktop/Mooring.app", Location::Other),
        ("/Users/other/Downloads/Mooring.app", Location::Other),
        ("/Users/u/DownloadsX/Mooring.app", Location::Other),
        ("/Users/u/Downloads/mooring", Location::Other),
        ("Mooring.app", Location::Other),
    ] {
        assert_eq!(classify(Path::new(bundle), &r), want, "{bundle}");
    }
    // Downloads unknown: never Downloads.
    let none = Roots { downloads: None, ..roots() };
    assert_eq!(classify(Path::new("/Users/u/Downloads/Mooring.app"), &none), Location::Other);
}

/// A bundle reached through a symlinked `/Applications` is classified by its canonical path.
#[cfg(unix)]
#[test]
fn symlinked_applications_resolve_before_classification() {
    let tmp = tempfile::tempdir().expect("tmp");
    let real = tmp.path().join("Applications");
    std::fs::create_dir_all(real.join("Mooring.app")).expect("bundle");
    let link = tmp.path().join("Apps");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let r = Roots { applications: vec![std::fs::canonicalize(&real).expect("canon")], downloads: None, volumes: p(VOLUMES) };
    let via = link.join("Mooring.app");
    assert_eq!(classify(&via, &r), Location::Other, "the unresolved link is not Applications");
    assert_eq!(classify(&std::fs::canonicalize(&via).expect("canon"), &r), Location::Applications);
}

const HDIUTIL_INFO: &str = "framework       : 671\n\
driver          : 671\n\
================================================\n\
image-path      : /Users/u/Downloads/Mooring_0.2.0_x64.dmg\n\
image-type      : read-only disk image\n\
process ID      : 1234\n\
/dev/disk4\tGUID_partition_scheme\t\n\
/dev/disk4s1\tApple_HFS                     \t/Volumes/Mooring 1\n\
================================================\n\
image-path      : /Users/u/other.dmg\n\
/dev/disk5s1\tApple_HFS\t/Volumes/Tools\r\n\
/dev/disk6s1\tApple_HFS\t/Volumes/a/b\n\
/dev/disk7s1\tApple_HFS\t/Volumes/..\n\
/dev/disk8s1\tApple_HFS\t/private/tmp/x\n\
/dev/disk9s1\n";

#[test]
fn hdiutil_info_lists_image_mounts_only() {
    assert_eq!(parse_hdiutil_info(HDIUTIL_INFO), vec![p("/Volumes/Mooring 1"), p("/Volumes/Tools")]);
    for junk in ["", "\t\t\t", "/dev/disk\t\t", "/dev/disk1\tx\t/Volumes/", "\u{0}/dev/disk1\t\t/Volumes/x", "/dev/disk1\t\t/Volumes/x\ty"] {
        let _ = parse_hdiutil_info(junk);
    }
    assert_eq!(parse_hdiutil_info("/dev/disk1\t\t/Volumes/x\ty"), vec![p("/Volumes/x\ty")], "the mount point is the rest of the line");
    let mounts = parse_hdiutil_info(HDIUTIL_INFO);
    assert_eq!(
        confirm_image(Location::Volume(p("/Volumes/Mooring 1")), &mounts),
        Location::DiskImage(p("/Volumes/Mooring 1"))
    );
    assert_eq!(confirm_image(Location::Volume(p("/Volumes/USB")), &mounts), Location::Other, "a USB stick is not an image");
    assert_eq!(confirm_image(Location::Downloads, &mounts), Location::Downloads);
}

fn facts<'a>(location: &'a Location, declined: Option<&'a str>) -> OfferFacts<'a> {
    OfferFacts {
        channel: Channel::Release,
        location,
        portable: false,
        moved: false,
        cask_present: false,
        declined,
        version: "0.2.0",
    }
}

#[test]
fn offer_rules() {
    let image = Location::DiskImage(p("/Volumes/Mooring"));
    assert!(should_offer(&facts(&image, None)));
    assert!(should_offer(&facts(&Location::Downloads, None)));
    assert!(should_offer(&facts(&image, Some("0.1.2"))), "declined for an older version");
    assert!(!should_offer(&facts(&image, Some("0.2.0"))), "Not now for this version");
    for l in [Location::Applications, Location::Other, Location::Translocated, Location::Volume(p("/Volumes/X"))] {
        assert!(!should_offer(&facts(&l, None)), "{l:?}");
    }
    assert!(!should_offer(&OfferFacts { channel: Channel::Dev, ..facts(&image, None) }), "decision 47");
    assert!(!should_offer(&OfferFacts { portable: true, ..facts(&image, None) }), "a marker: never");
    assert!(!should_offer(&OfferFacts { moved: true, ..facts(&image, None) }), "relaunched copy");
    assert!(!should_offer(&OfferFacts { cask_present: true, ..facts(&image, None) }), "Homebrew");
    // Translocation: the dialog in release builds, never in a relaunched copy (no loop).
    assert!(offer_translocated(Channel::Release, false));
    assert!(!offer_translocated(Channel::Release, true));
    assert!(!offer_translocated(Channel::Dev, false));
}

#[test]
fn replace_guard() {
    let ours = Version::new(0, 2, 0);
    let mine = |v: &str| Existing::Ours(Some(Version::parse(v).expect("v")));
    assert_eq!(plan(&Existing::Absent, &ours, false), Ok(Plan::Copy { replace: false }));
    assert_eq!(plan(&Existing::Absent, &ours, true), Ok(Plan::Copy { replace: false }), "nothing to be running");
    assert_eq!(plan(&mine("0.1.2"), &ours, false), Ok(Plan::Copy { replace: true }));
    assert_eq!(plan(&Existing::Ours(None), &ours, false), Ok(Plan::Copy { replace: true }));
    assert_eq!(plan(&mine("0.2.0"), &ours, false), Ok(Plan::OpenExisting), "same version");
    assert_eq!(plan(&mine("0.3.0"), &ours, true), Ok(Plan::OpenExisting), "newer, even running");
    assert_eq!(plan(&mine("0.1.2"), &ours, true), Err(MoveError::Running));
    assert_eq!(plan(&Existing::Foreign, &ours, false), Err(MoveError::NotOurs));
    for (e, code) in [
        (MoveError::NotOurs, "install.not_ours"),
        (MoveError::Running, "install.running"),
        (MoveError::CopyFailed, "install.copy_failed"),
        (MoveError::NotWritable, "install.not_writable"),
    ] {
        assert_eq!(e.code(), code);
        assert!(!e.message().contains("/Users"), "{}", e.message());
    }
}

#[test]
fn targets() {
    let home = Path::new("/Users/u");
    assert_eq!(Target::choose(true), Target::Applications);
    assert_eq!(Target::choose(false), Target::UserApplications, "decision 44");
    assert_eq!(Target::UserApplications.dir(home), p("/Users/u/Applications"));
    assert_eq!(Target::of_bundle(Path::new("/Applications/Mooring.app"), Some(home)), Some(Target::Applications));
    assert_eq!(Target::of_bundle(Path::new("/Users/u/Applications/Mooring.app"), Some(home)), Some(Target::UserApplications));
    assert_eq!(Target::of_bundle(Path::new("/Volumes/M/Mooring.app"), Some(home)), None);
    assert_eq!((Target::Applications.wire(), Target::UserApplications.wire()), ("applications", "user_applications"));
}

#[test]
fn dialog_slots_and_choice_mapping() {
    let MessageDialogButtons::YesNoCancelCustom(first, middle, cancel) = buttons() else { panic!("three slots") };
    assert_eq!((first.as_str(), middle.as_str(), cancel.as_str()), ("Cancel", MOVE_LABEL, "Not now"));
    assert!(vsphere_confirm::refuses(&first) && vsphere_confirm::refuses(&cancel), "B-6: first and cancel slot refuse");
    let c = |s: &str| MessageDialogResult::Custom(s.to_owned());
    assert_eq!(choice(&c(MOVE_LABEL)), Choice::Move);
    assert_eq!(choice(&c("Not now")), Choice::NotNow, "also Escape / close box (cancel slot)");
    assert_eq!(choice(&c("Cancel")), Choice::Cancel);
    for positional in [MessageDialogResult::Ok, MessageDialogResult::Yes, MessageDialogResult::No, MessageDialogResult::Cancel] {
        assert_eq!(choice(&positional), Choice::Cancel, "positions never move");
    }
    assert_eq!(choice(&c("move to applications")), Choice::Cancel);
}

#[test]
fn dialog_texts() {
    let image = Location::DiskImage(p("/Volumes/Mooring 1"));
    let t = dialog_text(&image, Target::Applications, &Existing::Ours(Some(Version::new(0, 1, 2))));
    assert!(t.contains("“Mooring 1”") && t.contains("/Applications") && t.contains("replaces Mooring 0.1.2"), "{t}");
    let t = dialog_text(&Location::Downloads, Target::UserApplications, &Existing::Absent);
    assert!(t.contains("Downloads") && t.contains("~/Applications") && !t.contains("replaces"), "{t}");
    let t = dialog_text(&Location::Translocated, Target::Applications, &Existing::Absent);
    assert!(t.contains("If this is a portable copy, choose Cancel"), "{t}");
    assert!(!dialog_text(&image, Target::Applications, &Existing::Absent).contains("portable"));
}

#[test]
fn relaunch_flags_round_trip() {
    let flags = relaunch_args(true, Some(Path::new("/Volumes/Mooring 1")));
    assert_eq!(flags, vec![OsString::from("--mooring-moved"), "--mooring-replaced".into(), "--mooring-detach=/Volumes/Mooring 1".into()]);
    let mut argv = vec![OsString::from("-psn_0_12345")];
    argv.extend(flags);
    let parsed = parse_args(argv);
    assert_eq!(parsed, MovedArgs { moved: true, replaced: true, detach: Some(p("/Volumes/Mooring 1")) });
    assert_eq!(parse_args(relaunch_args(false, None)), MovedArgs { moved: true, replaced: false, detach: None });
    assert_eq!(parse_args([OsString::from("--mooring-detach=")]), MovedArgs::default());
    assert_eq!(parse_args(Vec::<OsString>::new()), MovedArgs::default());
}

#[test]
fn detach_candidates() {
    let mounts = vec![p("/Volumes/Mooring 1")];
    assert!(detach_candidate(Path::new("/Volumes/Mooring 1"), &mounts));
    for bad in ["/Volumes/Other", "/Volumes/Mooring 1/sub", "/Volumes/../Volumes/Mooring 1", "/Volumes", "/", "Volumes/Mooring 1", "/private/Volumes/Mooring 1"] {
        assert!(!detach_candidate(Path::new(bad), &mounts), "{bad}");
    }
    assert!(!detach_candidate(Path::new("/Volumes/Mooring 1"), &[]), "not an image mount");
}

#[test]
fn running_check_is_a_prefix_match() {
    let ps = "/sbin/launchd\n/Applications/Mooring.app/Contents/MacOS/mooring\n";
    assert!(running_from(ps, Path::new("/Applications/Mooring.app")));
    assert!(!running_from(ps, Path::new("/Applications/Moor")));
    assert!(!running_from("/Applications/Mooring.app.old/x\n", Path::new("/Applications/Mooring.app")));
}

#[test]
fn tool_argv_is_pinned() {
    let o = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
    let src = Path::new("/Volumes/Mooring 1/Mooring.app");
    let tmp = Path::new("/Applications/.Mooring.app.00ff");
    assert_eq!(ditto_argv(src, tmp), o(&["/Volumes/Mooring 1/Mooring.app", "/Applications/.Mooring.app.00ff"]));
    assert_eq!(codesign_argv(tmp), o(&["--verify", "--deep", "--strict", "/Applications/.Mooring.app.00ff"]));
    let dst = Path::new("/Applications/Mooring.app");
    assert_eq!(
        open_argv(dst, true, &relaunch_args(false, Some(Path::new("/Volumes/Mooring 1")))),
        o(&["-n", "/Applications/Mooring.app", "--args", "--mooring-moved", "--mooring-detach=/Volumes/Mooring 1"])
    );
    assert_eq!(open_argv(dst, false, &[]), o(&["/Applications/Mooring.app"]));
    assert_eq!(hdiutil_info_argv(), o(&["info"]));
    assert_eq!(detach_argv(Path::new("/Volumes/Mooring 1")), o(&["detach", "/Volumes/Mooring 1", "-quiet"]));
    assert_eq!(
        plist_argv(dst, "CFBundleIdentifier"),
        o(&["-c", "Print :CFBundleIdentifier", "/Applications/Mooring.app/Contents/Info.plist"])
    );
    assert_eq!(ps_argv(), o(&["-axww", "-o", "comm="]));
    for tool in [DITTO, CODESIGN, OPEN, HDIUTIL, PLIST_BUDDY, PS] {
        assert!(Path::new(tool).is_absolute(), "{tool}");
    }
    assert_eq!(HDIUTIL, "/usr/bin/hdiutil");
}
