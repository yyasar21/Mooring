//! `sftp_download` / `sftp_upload` / `sftp_cancel`: streaming with progress, confinement of
//! the picked paths, cancellation, audit.

use std::time::Duration;

use tokio::sync::mpsc;

use super::*;
use crate::commands::sftp_pick::{pick_local, FixedPicker};
use crate::commands::test_session::{audit_text, close as close_session, connect, pick, Live};
use crate::test_ssh_server as server;

type Events = mpsc::UnboundedReceiver<Progress>;

fn sink() -> (ProgressSink, Events) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Arc::new(move |p| tx.send(p).is_ok()), rx)
}

/// Collect progress until the final event; returns all of them.
async fn finish(rx: &mut Events) -> Vec<Progress> {
    let mut seen = Vec::new();
    loop {
        let p = tokio::time::timeout(Duration::from_secs(30), rx.recv())
            .await
            .expect("progress within 30 s")
            .expect("open");
        let last = p.state != "running";
        seen.push(p);
        if last {
            return seen;
        }
    }
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).expect("u8")).collect()
}

fn s(p: &Path) -> String {
    p.to_str().expect("utf-8").to_owned()
}

/// `sftp_pick_local` answered with `path`: the refusal, if any.
async fn pick_err(live: &Live, mode: &str, path: &Path) -> IpcError {
    let picker = FixedPicker(Some(path.to_path_buf()));
    pick_local(&live.f.state, &picker, None, &live.session_id, mode).await.expect_err("refused")
}

#[tokio::test]
async fn upload_then_download_with_progress_and_audit() {
    let root = tempfile::tempdir().expect("root");
    std::fs::create_dir(root.path().join("in")).expect("mkdir");
    let srv = server::start_with_sftp(81, root.path().to_path_buf()).await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());
    let data = payload(1024 * 1024 + 17); // 5 blocks of 256 KiB

    let src = tempfile::tempdir().expect("src");
    let file = src.path().join("big.bin");
    std::fs::write(&file, &data).expect("write");
    let (tx, mut rx) = sink();
    let up_pick = pick(&live, "file", &file).await;
    let up = upload(st, sid, &up_pick, "/in", tx).await.expect("upload");
    let events = finish(&mut rx).await;
    let last = events.last().expect("last");
    assert_eq!((last.state, last.bytes_done), ("done", data.len() as u64), "{last:?}");
    assert!(events.iter().all(|p| p.transfer_id == up.transfer_id));
    assert!(events.len() >= 6, "progress per block: {}", events.len());
    assert!(events.windows(2).all(|w| w[0].bytes_done <= w[1].bytes_done), "monotonic");
    assert_eq!(std::fs::read(root.path().join("in/big.bin")).expect("remote copy"), data);

    let dst = tempfile::tempdir().expect("dst");
    let (tx, mut rx) = sink();
    let down_pick = pick(&live, "folder", dst.path()).await;
    download(st, sid, "/in/big.bin", &down_pick, tx).await.expect("download");
    let events = finish(&mut rx).await;
    let last = events.last().expect("last");
    assert_eq!(last.state, "done", "{last:?}");
    assert_eq!(events[0].bytes_total, Some(data.len() as u64), "size hint from the server");
    assert_eq!(std::fs::read(dst.path().join("big.bin")).expect("local copy"), data);
    let leftovers = std::fs::read_dir(dst.path()).expect("dir").count();
    assert_eq!(leftovers, 1, "no temp file left behind");

    let json = serde_json::to_value(last).expect("json");
    for key in ["transferId", "bytesDone", "bytesTotal", "state", "error"] {
        assert!(json.get(key).is_some(), "{key} in {json}");
    }
    let log = audit_text(&live);
    assert_eq!(log.matches(r#""event":"sftp_transfer""#).count(), 2, "{log}");
    assert!(log.contains(r#""direction":"upload""#) && log.contains(r#""direction":"download""#));
    assert!(log.contains(r#""outcome":"done""#));
    assert!(!log.contains(&s(src.path())) && !log.contains(&s(dst.path())), "no local paths");
    close_session(&live).await;
}

#[tokio::test]
async fn picked_paths_are_confined() {
    let root = tempfile::tempdir().expect("root");
    std::fs::write(root.path().join("known_hosts"), b"evil").expect("seed");
    std::fs::write(root.path().join("f"), b"x").expect("seed");
    let srv = server::start_with_sftp(82, root.path().to_path_buf()).await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());
    let data_dir = live.f.dir.path().canonicalize().expect("canon");
    let dst = tempfile::tempdir().expect("dst");
    std::fs::write(dst.path().join("file"), b"x").expect("plain file");
    let dir = s(dst.path());

    // What the dialog may return for a folder pick, and is refused anyway.
    let refused_folders = [
        data_dir.clone(),                    // app data dir
        data_dir.join("sub"),                // missing / inside data dir
        PathBuf::from("relative/dir"),       // not absolute
        PathBuf::new(),                      // empty
        dst.path().join("does-not-exist"),   // missing
        dst.path().join("file"),             // not a directory
        PathBuf::from("x".repeat(5000)),     // too long
    ];
    for (i, p) in refused_folders.iter().enumerate() {
        let e = pick_err(&live, "folder", p).await;
        assert_eq!(e.code, "input.invalid", "case {i}: {e:?}");
        assert!(!e.message.contains(&s(&data_dir)) && !e.message.contains(&dir), "no paths");
    }
    // Remote names that cannot be confined in a good folder (the pick is not consumed).
    let good = pick(&live, "folder", dst.path()).await;
    for (i, remote) in ["/", "/a/..", "/a/con.txt", "/a/b:stream"].iter().enumerate() {
        let (tx, _rx) = sink();
        let e = download(st, sid, remote, &good, tx).await.expect_err("refused");
        assert_eq!(e.code, "input.invalid", "remote case {i}: {e:?}");
    }
    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().expect("outside");
        std::os::unix::fs::symlink(outside.path().join("f"), dst.path().join("f")).expect("ln");
        let p = pick(&live, "folder", dst.path()).await;
        let (tx, _rx) = sink();
        let e = download(st, sid, "/f", &p, tx).await.expect_err("symlink target");
        assert_eq!(e.code, "input.invalid");
        assert!(!outside.path().join("f").exists(), "nothing written through the link");
    }

    let audit_file = live.f.dir.path().join(crate::state::AppState::AUDIT_FILE);
    let refused_files = [
        audit_file,                         // inside the app data dir
        PathBuf::from("big.bin"),           // relative
        dst.path().to_path_buf(),           // a directory
        dst.path().join("missing"),         // missing
        PathBuf::from("/"),                 // no file name
        dst.path().join("CON"),             // device name
    ];
    for (i, local) in refused_files.iter().enumerate() {
        let e = pick_err(&live, "file", local).await;
        assert_eq!(e.code, "input.invalid", "case {i}: {e:?}");
    }
    let p = pick(&live, "file", &dst.path().join("file")).await;
    let (tx, _rx) = sink();
    assert_eq!(upload(st, sid, &p, "", tx).await.expect_err("remoteDir").code, "input.invalid");
    let (tx, _rx) = sink();
    let e = download(st, "nope", "/g", &good, tx).await.expect_err("session");
    assert_eq!(e.code, "session.not_found");
    assert_eq!(std::fs::read(root.path().join("known_hosts")).expect("r"), b"evil");
    close_session(&live).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_stops_a_download_and_leaves_no_partial_file() {
    let root = tempfile::tempdir().expect("root");
    std::fs::write(root.path().join("large.bin"), payload(8 * 1024 * 1024)).expect("seed");
    let srv = server::start_with_sftp(83, root.path().to_path_buf()).await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());
    let dst = tempfile::tempdir().expect("dst");

    // The sink holds the transfer on its first block until the test has cancelled it.
    let (first_tx, first_rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let go_rx = std::sync::Mutex::new(go_rx);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let sink: ProgressSink = Arc::new(move |p: Progress| {
        if p.state == "running" && p.bytes_done > 0 && first_tx.send(()).is_ok() {
            let _ = go_rx.lock().expect("lock").recv_timeout(Duration::from_secs(10));
        }
        tx.send(p).is_ok()
    });
    let p = pick(&live, "folder", dst.path()).await;
    let started = download(st, sid, "/large.bin", &p, sink).await.expect("start");
    tokio::task::spawn_blocking(move || first_rx.recv_timeout(Duration::from_secs(20)))
        .await
        .expect("join")
        .expect("first block");
    cancel(st, sid, &started.transfer_id).expect("cancel");
    go_tx.send(()).expect("release");
    let events = finish(&mut rx).await;
    let last = events.last().expect("last");
    assert_eq!(last.state, "cancelled", "{last:?}");
    assert!(last.bytes_done < 8 * 1024 * 1024);
    // The temp file is dropped (deleted) when the in-flight block write returns.
    for _ in 0..100 {
        if std::fs::read_dir(dst.path()).expect("dir").count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(std::fs::read_dir(dst.path()).expect("dir").count(), 0, "no partial file");
    let e = cancel(st, sid, &started.transfer_id).expect_err("already gone");
    assert_eq!(e.code, "transfer.not_found");
    for bad in ["", &"t".repeat(65)] {
        assert_eq!(cancel(st, sid, bad).expect_err("x").code, "input.invalid");
    }
    assert_eq!(cancel(st, "nope", "t").expect_err("x").code, "session.not_found");
    let log = audit_text(&live);
    assert!(log.contains(r#""outcome":"cancelled""#), "{log}");
    close_session(&live).await;
}

#[tokio::test]
async fn failed_download_reports_failed_once() {
    let root = tempfile::tempdir().expect("root");
    let srv = server::start_with_sftp(84, root.path().to_path_buf()).await;
    let live = connect(&srv).await;
    let dst = tempfile::tempdir().expect("dst");
    let (tx, mut rx) = sink();
    let p = pick(&live, "folder", dst.path()).await;
    download(&live.f.state, &live.session_id, "/missing.bin", &p, tx)
        .await
        .expect("starts; the open fails in the task");
    let events = finish(&mut rx).await;
    let last = events.last().expect("last");
    assert_eq!((last.state, last.error.as_deref()), ("failed", Some("remote path not found")));
    assert_eq!(std::fs::read_dir(dst.path()).expect("dir").count(), 0);
    assert!(audit_text(&live).contains(r#""outcome":"failed""#));
    close_session(&live).await;
}
