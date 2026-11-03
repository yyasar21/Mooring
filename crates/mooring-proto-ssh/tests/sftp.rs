//! SFTP: list / stat / mkdir / upload / download with progress, rename / remove, local path
//! confinement, listing cap, and close with the session.

mod common;

use common::*;
use mooring_core::session::Session;
use mooring_core::MooringError;
use mooring_proto_ssh::sftp::{MAX_LIST_ENTRIES, MAX_REMOTE_PATH, TRANSFER_BLOCK};
use mooring_proto_ssh::{EntryKind, LocalPath, SshSession};
use russh::MethodKind;

struct Fixture {
    s: SshSession,
    _srv: TestServer,
    _kh: tempfile::TempDir,
    remote: tempfile::TempDir,
    local: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let remote = tempfile::tempdir().expect("remote root");
    let local = tempfile::tempdir().expect("local base");
    let mut spec = ServerSpec::new(&[MethodKind::Password]);
    spec.sftp_root = Some(remote.path().to_path_buf());
    let (s, srv, kh) = connected(spec).await;
    Fixture { s, _srv: srv, _kh: kh, remote, local }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i * 7 % 251).expect("< 251")).collect()
}

#[tokio::test]
async fn list_mkdir_upload_download_with_progress() {
    let mut f = fixture().await;
    let sftp = f.s.sftp().await.expect("sftp");
    let again = f.s.sftp().await.expect("reused");
    drop(again);

    sftp.mkdir("/docs").await.expect("mkdir");
    assert!(sftp.mkdir("/docs").await.is_err(), "already exists");

    // 2.5 blocks: exercises multi-block streaming and a short final block.
    let size = TRANSFER_BLOCK * 2 + TRANSFER_BLOCK / 2;
    let data = pattern(size);
    std::fs::write(f.local.path().join("up.bin"), &data).expect("write local");
    let src = LocalPath::new(f.local.path(), "up.bin").expect("path");
    let mut ticks = Vec::new();
    let sent = sftp.upload(&src, "/docs/file.bin", |d, t| ticks.push((d, t))).await.expect("up");
    assert_eq!(sent, size as u64);
    let total = Some(size as u64);
    assert_eq!(ticks.first(), Some(&(0, total)));
    assert_eq!(ticks.last(), Some(&(size as u64, total)));
    assert_eq!(ticks.len(), 4, "start + one tick per block: {ticks:?}");
    assert!(ticks.windows(2).all(|w| w[0].0 < w[1].0));
    assert_eq!(std::fs::read(f.remote.path().join("docs/file.bin")).expect("remote"), data);

    let listing = sftp.list("/docs").await.expect("list");
    assert!(!listing.truncated);
    assert_eq!(listing.entries.len(), 1);
    let e = &listing.entries[0];
    assert_eq!((e.name.as_str(), e.kind, e.size), ("file.bin", EntryKind::File, Some(size as u64)));
    assert!(e.mtime.is_some() && e.mode.is_some());
    let root = sftp.list("/").await.expect("list root");
    assert!(root.entries.iter().any(|e| e.name == "docs" && e.kind == EntryKind::Dir));
    assert!(root.entries.iter().all(|e| e.name != "." && e.name != ".."));
    assert_eq!(sftp.stat("/docs").await.expect("stat").kind, EntryKind::Dir);

    let dst = LocalPath::new(f.local.path(), "down.bin").expect("path");
    let mut ticks = Vec::new();
    let got = sftp.download("/docs/file.bin", &dst, |d, t| ticks.push((d, t))).await.expect("dl");
    assert_eq!(got, size as u64);
    assert_eq!(std::fs::read(f.local.path().join("down.bin")).expect("local"), data);
    assert_eq!(ticks.first(), Some(&(0, total)));
    assert_eq!(ticks.last(), Some(&(size as u64, total)));

    // Empty file.
    std::fs::write(f.local.path().join("empty"), b"").expect("write");
    let empty = LocalPath::new(f.local.path(), "empty").expect("path");
    assert_eq!(sftp.upload(&empty, "/empty", |_, _| {}).await.expect("up empty"), 0);
    let back = LocalPath::new(f.local.path(), "empty.back").expect("path");
    assert_eq!(sftp.download("/empty", &back, |_, _| {}).await.expect("dl empty"), 0);
    f.s.close().await.expect("close");
}

#[tokio::test]
async fn rename_and_remove() {
    let mut f = fixture().await;
    let sftp = f.s.sftp().await.expect("sftp");
    std::fs::create_dir(f.remote.path().join("d")).expect("mkdir");
    std::fs::write(f.remote.path().join("d/a.txt"), b"a").expect("write");

    sftp.rename("/d/a.txt", "/d/b.txt").await.expect("rename");
    assert!(f.remote.path().join("d/b.txt").exists());
    assert!(matches!(sftp.stat("/d/a.txt").await, Err(MooringError::NotFound { .. })));

    assert!(sftp.remove("/d").await.is_err(), "non-empty directory is not removed");
    sftp.remove("/d/b.txt").await.expect("remove file");
    sftp.remove("/d").await.expect("remove empty dir");
    assert!(!f.remote.path().join("d").exists());
    assert!(matches!(sftp.remove("/d").await, Err(MooringError::NotFound { .. })));
    f.s.close().await.expect("close");
}

#[tokio::test]
async fn local_escapes_are_rejected() {
    let mut f = fixture().await;
    let sftp = f.s.sftp().await.expect("sftp");
    std::fs::write(f.remote.path().join("r"), b"remote").expect("write");
    assert!(LocalPath::new(f.local.path(), "../escape").is_err());
    assert!(LocalPath::new(f.local.path(), "a/../../escape").is_err());
    assert!(LocalPath::new(f.local.path(), "/etc/passwd").is_err());

    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().expect("outside");
        std::os::unix::fs::symlink(outside.path(), f.local.path().join("out")).expect("symlink");
        let via = LocalPath::new(f.local.path(), "out/stolen").expect("lexically fine");
        let err = sftp.download("/r", &via, |_, _| {}).await.expect_err("escape");
        let msg = err.to_string();
        assert!(!msg.contains(&*outside.path().to_string_lossy()), "{msg}");
        assert!(!msg.contains(&*f.local.path().to_string_lossy()), "{msg}");
        assert!(!outside.path().join("stolen").exists());

        std::fs::write(outside.path().join("secret"), b"s").expect("write");
        let up = LocalPath::new(f.local.path(), "out/secret").expect("lexically fine");
        assert!(sftp.upload(&up, "/leak", |_, _| {}).await.is_err());
        assert!(!f.remote.path().join("leak").exists());
    }
    f.s.close().await.expect("close");
}

#[tokio::test]
async fn remote_path_limits_and_errors() {
    let mut f = fixture().await;
    let sftp = f.s.sftp().await.expect("sftp");
    let long = format!("/{}", "a".repeat(MAX_REMOTE_PATH));
    assert!(matches!(sftp.stat(&long).await, Err(MooringError::Invalid { .. })));
    assert!(matches!(sftp.list("/no\0pe").await, Err(MooringError::Invalid { .. })));
    let dst = LocalPath::new(f.local.path(), "x").expect("path");
    assert!(matches!(
        sftp.download("/missing", &dst, |_, _| {}).await,
        Err(MooringError::NotFound { .. })
    ));
    assert!(!f.local.path().join("x").exists(), "no partial file");
    assert!(std::fs::read_dir(f.local.path()).expect("ls").next().is_none(), "no temp left");
    f.s.close().await.expect("close");
}

#[tokio::test]
async fn listing_is_capped_with_truncated_flag() {
    let mut f = fixture().await;
    let dir = f.remote.path().join("many");
    std::fs::create_dir(&dir).expect("mkdir");
    for i in 0..=MAX_LIST_ENTRIES {
        std::fs::write(dir.join(format!("f{i:05}")), b"").expect("write");
    }
    let sftp = f.s.sftp().await.expect("sftp");
    let listing = sftp.list("/many").await.expect("list");
    assert!(listing.truncated);
    assert_eq!(listing.entries.len(), MAX_LIST_ENTRIES);
    f.s.close().await.expect("close");
}

#[tokio::test]
async fn sftp_closes_with_the_session() {
    let mut f = fixture().await;
    let sftp = f.s.sftp().await.expect("sftp");
    sftp.list("/").await.expect("list");
    f.s.close().await.expect("close");
    assert!(sftp.list("/").await.is_err(), "old client unusable after close");
    assert!(matches!(f.s.sftp().await, Err(MooringError::Closed)));
}

#[tokio::test]
async fn refused_subsystem_is_an_error() {
    let (mut s, _srv, _d) = connected(ServerSpec::new(&[MethodKind::Password])).await;
    let err = s.sftp().await.expect_err("no sftp root");
    assert!(matches!(err, MooringError::Protocol { protocol: "sftp", .. }), "{err:?}");
    s.close().await.expect("close");
}
