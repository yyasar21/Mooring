//! `sftp_list/stat/mkdir/rename/remove` against the in-process server's SFTP subsystem.

use super::*;
use crate::commands::test_session::{close as close_session, connect};
use crate::test_ssh_server as server;

#[tokio::test]
async fn browse_mkdir_rename_remove() {
    let root = tempfile::tempdir().expect("root");
    std::fs::write(root.path().join("hello.txt"), b"hello").expect("seed");
    let srv = server::start_with_sftp(71, root.path().to_path_buf()).await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());

    mkdir(st, sid, "/docs").await.expect("mkdir");
    assert!(root.path().join("docs").is_dir());
    let listing = list(st, sid, "/").await.expect("list");
    assert!(!listing.truncated);
    let mut names: Vec<_> = listing.entries.iter().map(|e| (e.name.as_str(), e.kind)).collect();
    names.sort_unstable();
    assert_eq!(names, vec![("docs", "dir"), ("hello.txt", "file")]);
    let json = serde_json::to_value(&listing).expect("json");
    let file = json["entries"].as_array().expect("arr").iter().find(|e| e["name"] == "hello.txt");
    let file = file.expect("file");
    assert_eq!(file["size"], 5);
    assert!(file["mtime"].is_u64() && file["mode"].is_u64(), "{file}");

    let st_entry = stat(st, sid, "/hello.txt").await.expect("stat");
    assert_eq!((st_entry.name.as_str(), st_entry.kind, st_entry.size), ("hello.txt", "file", Some(5)));

    rename(st, sid, "/hello.txt", "/docs/hi.txt").await.expect("rename");
    assert!(root.path().join("docs/hi.txt").is_file());
    let e = remove(st, sid, "/docs").await.expect_err("not empty");
    assert_eq!(e.code, "sftp.failed", "{e:?}");
    remove(st, sid, "/docs/hi.txt").await.expect("remove file");
    remove(st, sid, "/docs").await.expect("remove empty dir");
    assert!(list(st, sid, "/").await.expect("list").entries.is_empty());
    close_session(&live).await;
}

#[tokio::test]
async fn errors_map_to_stable_codes_without_echoing_paths() {
    let root = tempfile::tempdir().expect("root");
    let srv = server::start_with_sftp(72, root.path().to_path_buf()).await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());

    let e = stat(st, sid, "/missing-secret-name").await.expect_err("missing");
    assert_eq!(e.code, "sftp.not_found");
    assert!(!e.message.contains("missing-secret-name"), "{e:?}");
    assert_eq!(list(st, sid, "/nope").await.expect_err("x").code, "sftp.not_found");
    for bad in ["", "a\0b"] {
        assert_eq!(list(st, sid, bad).await.expect_err("x").code, "input.invalid", "{bad:?}");
        assert_eq!(mkdir(st, sid, bad).await.expect_err("x").code, "input.invalid");
        assert_eq!(remove(st, sid, bad).await.expect_err("x").code, "input.invalid");
        assert_eq!(rename(st, sid, "/a", bad).await.expect_err("x").code, "input.invalid");
    }
    let long = format!("/{}", "a".repeat(5000));
    assert_eq!(stat(st, sid, &long).await.expect_err("x").code, "input.invalid");
    // The test server confines paths to its root and answers `..` with permission denied.
    assert_eq!(list(st, sid, "/../..").await.expect_err("x").code, "sftp.denied");
    assert_eq!(list(st, "nope", "/").await.expect_err("x").code, "session.not_found");
    assert_eq!(list(st, &"s".repeat(100), "/").await.expect_err("x").code, "input.invalid");
    close_session(&live).await;
    assert_eq!(list(st, sid, "/").await.expect_err("closed").code, "session.not_found");
}

#[tokio::test]
async fn sftp_refused_by_the_server_maps_to_sftp_failed() {
    let srv = server::start(73).await; // no sftp subsystem
    let live = connect(&srv).await;
    let e = list(&live.f.state, &live.session_id, "/").await.expect_err("refused");
    assert_eq!(e.code, "sftp.failed", "{e:?}");
    close_session(&live).await;
}
