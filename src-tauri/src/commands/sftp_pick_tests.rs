//! `sftp_pick_local` and the pick contract of `sftp_download` / `sftp_upload` (review 4, B-4):
//! forged, reused, foreign-session and expired picks are refused; picks die with a lock; the
//! `main` capability grants no dialog or file-system permission.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use mooring_vault::AutoLockPolicy;

use super::*;
use crate::commands::sftp_transfers::{download, upload, Progress, ProgressSink};
use crate::commands::test_session::{close as close_session, connect, pick};
use crate::picks::{PICK_ID_LEN, PICK_TTL};
use crate::test_ssh_server as server;

fn sink() -> ProgressSink {
    Arc::new(|_: Progress| true)
}

fn refused_pick(e: &IpcError) {
    assert_eq!(e.code, "input.invalid", "{e:?}");
    assert!(e.message.contains("pick"), "{e:?}");
}

#[tokio::test]
async fn picks_are_single_use_session_bound_and_expire() {
    let root = tempfile::tempdir().expect("root");
    std::fs::write(root.path().join("f"), b"remote").expect("seed");
    let srv = server::start_with_sftp(91, root.path().to_path_buf()).await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());
    let dst = tempfile::tempdir().expect("dst");
    let src = dst.path().join("up.txt");
    std::fs::write(&src, b"local").expect("src");

    // Only `{ pickId, name }` reaches the WebView: no directory part.
    let chooser = FixedPicker(Some(src.clone()));
    let picked = pick_local(st, &chooser, None, sid, "file").await.expect("ok").expect("some");
    assert_eq!(picked.name, "up.txt");
    assert_eq!(picked.pick_id.len(), PICK_ID_LEN);
    let json = serde_json::to_string(&picked).expect("json");
    assert!(!json.contains(dst.path().to_str().expect("utf8")), "{json}");
    assert!(json.contains(r#""pickId""#) && json.contains(r#""name":"up.txt""#), "{json}");

    // forged ids
    for forged in ["", "../../etc/passwd", &"0".repeat(PICK_ID_LEN), dst.path().to_str().expect("u")] {
        refused_pick(&download(st, sid, "/f", forged, false, sink()).await.expect_err("forged"));
        refused_pick(&upload(st, sid, forged, "/", sink()).await.expect_err("forged"));
    }
    // the wrong kind: a file pick is not a download folder
    refused_pick(&download(st, sid, "/f", &picked.pick_id, false, sink()).await.expect_err("mode"));
    // used once, then gone
    upload(st, sid, &picked.pick_id, "/", sink()).await.expect("first use");
    refused_pick(&upload(st, sid, &picked.pick_id, "/", sink()).await.expect_err("reused"));

    // bound to the session it was made for
    let now = std::time::Instant::now();
    let epoch = st.picks.epoch();
    let foreign =
        st.picks.insert(epoch, "other-session", PickMode::Folder, dst.path().into(), now).expect("id");
    refused_pick(&download(st, sid, "/f", &foreign, false, sink()).await.expect_err("foreign"));

    // expired after ten minutes
    if let Some(old) = now.checked_sub(PICK_TTL + Duration::from_secs(1)) {
        let stale = st.picks.insert(epoch, sid, PickMode::Folder, dst.path().into(), old).expect("id");
        refused_pick(&download(st, sid, "/f", &stale, false, sink()).await.expect_err("expired"));
    }

    // cancelled dialog → null, nothing stored
    let before = st.picks.len();
    assert_eq!(pick_local(st, &FixedPicker(None), None, sid, "folder").await.expect("ok"), None);
    assert_eq!(st.picks.len(), before);
    // validation
    assert_eq!(pick_local(st, &chooser, None, sid, "dir").await.expect_err("mode").code, "input.invalid");
    assert_eq!(
        pick_local(st, &chooser, None, "nope", "file").await.expect_err("session").code,
        "session.not_found"
    );
    close_session(&live).await;
}

#[tokio::test]
async fn lock_clears_picks() {
    let root = tempfile::tempdir().expect("root");
    let srv = server::start_with_sftp(92, root.path().to_path_buf()).await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());
    let dst = tempfile::tempdir().expect("dst");
    let p = pick(&live, "folder", dst.path()).await;
    assert_eq!(st.picks.len(), 1);
    crate::commands::vault::lock(st, None).expect("lock");
    assert!(st.picks.is_empty(), "picks gone after lock");
    refused_pick(&download(st, sid, "/f", &p, false, sink()).await.expect_err("after lock"));
    close_session(&live).await;
}

/// A picker that records whether the auto-lock saw the dialog as open, then answers.
struct Probe<'a> {
    al: &'a AutoLock,
    seen_open: AtomicBool,
    answer: PathBuf,
}

impl LocalPicker for Probe<'_> {
    fn pick(&self, _mode: PickMode, reply: PickReply) {
        self.seen_open.store(self.al.dialog_open(), Ordering::SeqCst);
        reply(Some(self.answer.clone()));
    }
}

#[tokio::test]
async fn the_dialog_is_flagged_open_for_the_auto_lock() {
    let root = tempfile::tempdir().expect("root");
    let srv = server::start_with_sftp(93, root.path().to_path_buf()).await;
    let live = connect(&srv).await;
    let dst = tempfile::tempdir().expect("dst");
    let al = AutoLock::new(AutoLockPolicy::default(), Instant::now(), SystemTime::now());
    let probe = Probe { al: &al, seen_open: AtomicBool::new(false), answer: dst.path().into() };
    let picked = pick_local(&live.f.state, &probe, Some(&al), &live.session_id, "folder")
        .await
        .expect("ok")
        .expect("some");
    assert!(probe.seen_open.load(Ordering::SeqCst), "flag set while the dialog is open");
    assert!(!al.dialog_open(), "flag cleared after");
    assert!(!picked.name.is_empty());
    close_session(&live).await;
}

#[test]
fn main_capability_grants_no_dialog_or_fs_permission() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities/main.json");
    let text = std::fs::read_to_string(&path).expect("capability file");
    let json: serde_json::Value = serde_json::from_str(&text).expect("json");
    let perms: Vec<&str> = json["permissions"]
        .as_array()
        .expect("permissions")
        .iter()
        .map(|p| p.as_str().or_else(|| p["identifier"].as_str()).expect("permission id"))
        .collect();
    assert_eq!(perms, ["core:default"]);
    for banned in ["dialog:", "fs:"] {
        assert!(!text.contains(banned), "{banned} in main.json");
    }
    // No other capability file may widen the main window either.
    let dir = std::fs::read_dir(path.parent().expect("dir")).expect("capabilities");
    for entry in dir {
        let text = std::fs::read_to_string(entry.expect("entry").path()).expect("read");
        assert!(!text.contains("dialog:") && !text.contains("fs:"), "{text}");
    }
}
