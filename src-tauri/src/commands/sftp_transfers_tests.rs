//! `sftp_download` / `sftp_upload` / `sftp_cancel`: streaming with progress, confinement of
//! the dialog paths, cancellation, audit.

use std::time::Duration;

use tokio::sync::mpsc;

use super::*;
use crate::commands::test_session::{audit_text, close as close_session, connect};
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
    let up = upload(st, sid, &s(&file), "/in", tx).await.expect("upload");
    let events = finish(&mut rx).await;
    let last = events.last().expect("last");
    assert_eq!((last.state, last.bytes_done), ("done", data.len() as u64), "{last:?}");
    assert!(events.iter().all(|p| p.transfer_id == up.transfer_id));
    assert!(events.len() >= 6, "progress per block: {}", events.len());
    assert!(events.windows(2).all(|w| w[0].bytes_done <= w[1].bytes_done), "monotonic");
    assert_eq!(std::fs::read(root.path().join("in/big.bin")).expect("remote copy"), data);

    let dst = tempfile::tempdir().expect("dst");
    let (tx, mut rx) = sink();
    download(st, sid, "/in/big.bin", &s(dst.path()), tx).await.expect("download");
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
async fn local_paths_are_confined() {
    let root = tempfile::tempdir().expect("root");
    std::fs::write(root.path().join("known_hosts"), b"evil").expect("seed");
    std::fs::write(root.path().join("f"), b"x").expect("seed");
    let srv = server::start_with_sftp(82, root.path().to_path_buf()).await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());
    let data_dir = s(&live.f.dir.path().canonicalize().expect("canon"));
    let dst = tempfile::tempdir().expect("dst");
    let dir = s(dst.path());

    let refused_downloads = [
        ("/known_hosts", data_dir.clone()),                    // app data dir
        ("/f", format!("{data_dir}/sub")),                     // missing / inside data dir
        ("/f", "relative/dir".to_owned()),                     // not absolute
        ("/f", String::new()),                                 // empty
        ("/f", format!("{dir}/does-not-exist")),               // missing
        ("/f", s(&dst.path().join("file"))),                   // set below: not a directory
        ("/", dir.clone()),                                    // names no file
        ("/a/..", dir.clone()),                                // `..`
        ("/a/con.txt", dir.clone()),                           // device name
        ("/a/b:stream", dir.clone()),                          // ADS
        ("/f", "x".repeat(5000)),                              // too long
    ];
    std::fs::write(dst.path().join("file"), b"x").expect("plain file");
    for (i, (remote, local_dir)) in refused_downloads.iter().enumerate() {
        let (tx, _rx) = sink();
        let e = download(st, sid, remote, local_dir, tx).await.expect_err("refused");
        assert_eq!(e.code, "input.invalid", "case {i}: {e:?}");
        assert!(!e.message.contains(&data_dir) && !e.message.contains(&dir), "no paths: {e:?}");
    }
    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().expect("outside");
        std::os::unix::fs::symlink(outside.path().join("f"), dst.path().join("f")).expect("ln");
        let (tx, _rx) = sink();
        let e = download(st, sid, "/f", &dir, tx).await.expect_err("symlink target");
        assert_eq!(e.code, "input.invalid");
        assert!(!outside.path().join("f").exists(), "nothing written through the link");
    }

    let audit_file = live.f.dir.path().join(crate::state::AppState::AUDIT_FILE);
    let refused_uploads = [
        s(&audit_file),                         // inside the app data dir
        "big.bin".to_owned(),                   // relative
        dir.clone(),                            // a directory
        format!("{dir}/missing"),               // missing
        "/".to_owned(),                         // no file name
        format!("{dir}/CON"),                   // device name
    ];
    for (i, local) in refused_uploads.iter().enumerate() {
        let (tx, _rx) = sink();
        let e = upload(st, sid, local, "/", tx).await.expect_err("refused");
        assert_eq!(e.code, "input.invalid", "case {i}: {e:?}");
    }
    let (tx, _rx) = sink();
    let e = upload(st, sid, &s(&dst.path().join("file")), "", tx).await.expect_err("remoteDir");
    assert_eq!(e.code, "input.invalid");
    let (tx, _rx) = sink();
    let e = download(st, "nope", "/g", &dir, tx).await.expect_err("session");
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
    let started = download(st, sid, "/large.bin", &s(dst.path()), sink).await.expect("start");
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
    download(&live.f.state, &live.session_id, "/missing.bin", &s(dst.path()), tx)
        .await
        .expect("starts; the open fails in the task");
    let events = finish(&mut rx).await;
    let last = events.last().expect("last");
    assert_eq!((last.state, last.error.as_deref()), ("failed", Some("remote path not found")));
    assert_eq!(std::fs::read_dir(dst.path()).expect("dir").count(), 0);
    assert!(audit_text(&live).contains(r#""outcome":"failed""#));
    close_session(&live).await;
}
