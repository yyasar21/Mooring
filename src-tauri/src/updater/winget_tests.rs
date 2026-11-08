//! ADR-0018 A2: a NSIS install whose `install-source` marker says `winget` never self-updates
//! in-app. The marker is the only signal (no path heuristic: winget runs the same installer).

use std::path::PathBuf;

use super::{
    decide, winget_marker, Bundle, InstallFacts, InstallMode, ManualReason, INSTALL_SOURCE_FILE,
    INSTALL_SOURCE_MAX,
};

fn facts(bundle: Bundle, winget: bool, writable: bool) -> InstallFacts {
    InstallFacts {
        bundle,
        install_path: PathBuf::from("/install/Mooring"),
        writable,
        cask_present: false,
        portable: false,
        dev_build: false,
        winget,
    }
}

#[test]
fn winget_beats_writability_on_nsis_only() {
    for writable in [true, false] {
        assert_eq!(
            decide(&facts(Bundle::Nsis, true, writable)),
            InstallMode::Manual(ManualReason::Winget)
        );
    }
    assert_eq!(decide(&facts(Bundle::Nsis, false, true)), InstallMode::InApp);
    assert_eq!(
        decide(&facts(Bundle::Nsis, false, false)),
        InstallMode::Manual(ManualReason::NotWritable)
    );
    // Other bundles never read the fact.
    assert_eq!(
        decide(&facts(Bundle::Msi, true, true)),
        InstallMode::Manual(ManualReason::PackageManager)
    );
    assert_eq!(decide(&facts(Bundle::AppImage, true, true)), InstallMode::InApp);
    // Dev and portable come first.
    let dev = InstallFacts { dev_build: true, ..facts(Bundle::Nsis, true, true) };
    assert_eq!(decide(&dev), InstallMode::Manual(ManualReason::DevBuild));
    let portable = InstallFacts { portable: true, ..facts(Bundle::Nsis, true, true) };
    assert_eq!(decide(&portable), InstallMode::Manual(ManualReason::Portable));
}

#[test]
fn winget_reason_wire_shape() {
    let r = ManualReason::Winget;
    assert_eq!(r.code(), "update.manual_only");
    assert_eq!(r.message(), "installed by winget: run `winget upgrade yyasar21.Mooring`");
    assert_eq!(serde_json::to_value(r).expect("json"), "winget");
}

#[test]
fn marker_present_absent_and_other_content() {
    let dir = tempfile::tempdir().expect("tmp");
    let marker = dir.path().join(INSTALL_SOURCE_FILE);
    assert!(!winget_marker(dir.path()), "absent");
    for yes in ["winget", "winget\n", "  winget\r\n"] {
        std::fs::write(&marker, yes).expect("write");
        assert!(winget_marker(dir.path()), "{yes:?}");
    }
    for no in ["", "WinGet", "winget-pkgs", "direct", "winget winget", "scoop"] {
        std::fs::write(&marker, no).expect("write");
        assert!(!winget_marker(dir.path()), "{no:?}");
    }
    std::fs::write(&marker, [0xFFu8, 0xFE]).expect("write");
    assert!(!winget_marker(dir.path()), "not UTF-8");
    let padded = format!("winget{}", " ".repeat(usize::try_from(INSTALL_SOURCE_MAX).expect("cap")));
    std::fs::write(&marker, padded).expect("write");
    assert!(!winget_marker(dir.path()), "over the size cap");
    std::fs::remove_file(&marker).expect("rm");
    std::fs::create_dir(&marker).expect("mkdir");
    assert!(!winget_marker(dir.path()), "a directory is not a marker");
}
