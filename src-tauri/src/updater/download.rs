//! What `latest.json` may make the client do (review 7 L-40). The manifest is unsigned, so
//! before a byte is downloaded the asset URL must sit under the one release location of
//! this repository ([`RELEASE_DOWNLOAD_PREFIX`], the version segment of the offered version,
//! an asset name of `[A-Za-z0-9._-]+`), and the download itself is read through
//! [`capped`]: at most [`PACKAGE_CAP`] bytes (declared or counted), per-chunk accounting,
//! one [`DOWNLOAD_DEADLINE`] for the whole transfer. The manifest body is bounded by
//! [`MANIFEST_CAP`] while it is read (`super::manifest`, L-40) and again after parsing
//! ([`manifest_within_cap`]).

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use semver::Version;
use tokio::sync::Notify;

use super::source::SourceError;

/// The only place an update asset may come from: this repository's release downloads. The
/// manifest endpoint in `tauri.conf.json` lives under the same `releases/` tree (a test pins
/// that).
pub const RELEASE_DOWNLOAD_PREFIX: &str = "https://github.com/yyasar21/Mooring/releases/download/";
/// Largest manifest the client accepts (bytes of the re-serialised JSON).
pub const MANIFEST_CAP: usize = 64 * 1024;
/// Largest update package (bytes).
pub const PACKAGE_CAP: u64 = 256 * 1024 * 1024;
/// Deadline for the whole download (an 80 MB `AppImage` on a slow link, not 30 s).
pub const DOWNLOAD_DEADLINE: Duration = Duration::from_secs(10 * 60);

/// The asset name of a release download: one path segment of `[A-Za-z0-9._-]+`.
fn asset_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && name != "."
        && name != ".."
}

/// `url` must be exactly `{RELEASE_DOWNLOAD_PREFIX}v{version}/{asset}` — no other host, no
/// other repository, no other tag, no query or fragment, no `..`. Anything else is
/// `update.manifest` before any network.
pub fn check_download_url(url: &str, version: &Version) -> Result<(), SourceError> {
    let Some(rest) = url.strip_prefix(RELEASE_DOWNLOAD_PREFIX) else {
        tracing::warn!("update asset URL is outside the release download prefix");
        return Err(SourceError::Manifest);
    };
    let tag = format!("v{version}/");
    let Some(asset) = rest.strip_prefix(&tag) else {
        tracing::warn!("update asset URL does not name the offered version");
        return Err(SourceError::Manifest);
    };
    if !asset_name_ok(asset) {
        tracing::warn!("update asset name refused");
        return Err(SourceError::Manifest);
    }
    Ok(())
}

/// The parsed manifest, re-serialised, must fit [`MANIFEST_CAP`].
pub fn manifest_within_cap(raw_json: &serde_json::Value) -> Result<(), SourceError> {
    let len = serde_json::to_vec(raw_json).map_or(usize::MAX, |v| v.len());
    if len > MANIFEST_CAP {
        tracing::warn!(len, "update manifest over the cap");
        return Err(SourceError::Manifest);
    }
    Ok(())
}

/// Running byte count of one download, fed per chunk by the source's progress callback.
#[derive(Debug, Default)]
pub struct Progress {
    received: AtomicU64,
    over: Notify,
    too_large: AtomicU64,
}

impl Progress {
    /// Account one chunk against `cap`; a declared `Content-Length` over the cap, or a running
    /// total over it, marks the download oversize and wakes the aborter.
    fn chunk(&self, cap: u64, len: usize, declared: Option<u64>) {
        let total = self.received.fetch_add(len as u64, Ordering::SeqCst) + len as u64;
        if declared.is_some_and(|d| d > cap) || total > cap {
            self.too_large.store(1, Ordering::SeqCst);
            self.over.notify_one();
        } else if total.is_multiple_of(8 * 1024 * 1024) || len as u64 >= 8 * 1024 * 1024 {
            tracing::debug!(received = total, declared, "update download progress");
        }
    }

    /// Bytes seen so far.
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::SeqCst)
    }
}

/// Run `download` (given a per-chunk progress callback) under `cap` bytes and `deadline`.
/// The callback cannot stop the source's own loop, so the download future is dropped — which
/// closes its connection — as soon as the running total or the declared length passes the
/// cap. Oversize and deadline are `update.network`.
pub async fn capped<F, Fut>(cap: u64, deadline: Duration, download: F) -> Result<Vec<u8>, SourceError>
where
    F: FnOnce(Box<dyn FnMut(usize, Option<u64>) + Send>) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, SourceError>>,
{
    let progress = Arc::new(Progress::default());
    let on_chunk = {
        let p = Arc::clone(&progress);
        Box::new(move |len: usize, declared: Option<u64>| p.chunk(cap, len, declared))
            as Box<dyn FnMut(usize, Option<u64>) + Send>
    };
    let fut = download(on_chunk);
    tokio::pin!(fut);
    let run = async {
        tokio::select! {
            biased;
            () = progress.over.notified() => {
                tracing::warn!(received = progress.received(), cap, "update download over the cap; aborted");
                Err(SourceError::Network)
            }
            r = &mut fut => {
                // A cap crossed by the very last chunk has no later await to abort at.
                if progress.too_large.load(Ordering::SeqCst) != 0 {
                    tracing::warn!(received = progress.received(), cap, "update download over the cap");
                    return Err(SourceError::Network);
                }
                r
            }
        }
    };
    let Ok(result) = tokio::time::timeout(deadline, run).await else {
        tracing::warn!(received = progress.received(), "update download deadline passed");
        return Err(SourceError::Network);
    };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).expect("semver")
    }

    #[test]
    fn download_url_must_sit_under_the_release_prefix_for_the_offered_version() {
        let ok = "https://github.com/yyasar21/Mooring/releases/download/v0.2.0/Mooring_0.2.0_amd64.AppImage";
        assert_eq!(check_download_url(ok, &v("0.2.0")), Ok(()));
        assert_eq!(
            check_download_url("https://github.com/yyasar21/Mooring/releases/download/v0.2.0-rc.1/Mooring_x64-setup.exe", &v("0.2.0-rc.1")),
            Ok(())
        );
        let bad = [
            ("https://github.com/yyasar21/Mooring/releases/download/v0.3.0/Mooring.AppImage", "0.2.0"),
            ("https://github.com/yyasar21/Mooring/releases/download/0.2.0/Mooring.AppImage", "0.2.0"),
            ("https://github.com/yyasar21/Mooring/releases/download/v0.2.0/", "0.2.0"),
            ("https://github.com/yyasar21/Mooring/releases/download/v0.2.0/a/b", "0.2.0"),
            ("https://github.com/yyasar21/Mooring/releases/download/v0.2.0/..", "0.2.0"),
            ("https://github.com/yyasar21/Mooring/releases/download/v0.2.0/x.AppImage?x=1", "0.2.0"),
            ("https://github.com/yyasar21/Mooring/releases/download/v0.2.0/x.AppImage#f", "0.2.0"),
            ("https://github.com/yyasar21/Mooring/releases/download/v0.2.0/x%20y", "0.2.0"),
            ("https://github.com/attacker/Mooring/releases/download/v0.2.0/x.AppImage", "0.2.0"),
            ("https://github.com/yyasar21/Mooring-evil/releases/download/v0.2.0/x.AppImage", "0.2.0"),
            ("https://github.com.attacker.example/yyasar21/Mooring/releases/download/v0.2.0/x", "0.2.0"),
            ("http://github.com/yyasar21/Mooring/releases/download/v0.2.0/x.AppImage", "0.2.0"),
            ("https://objects.githubusercontent.com/v0.2.0/x.AppImage", "0.2.0"),
            ("", "0.2.0"),
        ];
        for (url, version) in bad {
            assert_eq!(check_download_url(url, &v(version)), Err(SourceError::Manifest), "{url}");
        }
    }

    #[test]
    fn manifest_cap_is_applied_to_the_parsed_json() {
        assert_eq!(manifest_within_cap(&serde_json::json!({ "version": "0.2.0" })), Ok(()));
        let big = serde_json::json!({ "notes": "x".repeat(MANIFEST_CAP) });
        assert_eq!(manifest_within_cap(&big), Err(SourceError::Manifest));
    }

    /// A scripted download: `chunks` of `size` bytes each, declaring `declared`, yielding
    /// between chunks like a body stream does.
    async fn scripted(mut on_chunk: Box<dyn FnMut(usize, Option<u64>) + Send>, chunks: usize, size: usize, declared: Option<u64>) -> Result<Vec<u8>, SourceError> {
        let mut out = Vec::new();
        for _ in 0..chunks {
            tokio::task::yield_now().await;
            on_chunk(size, declared);
            out.extend(std::iter::repeat_n(7u8, size));
        }
        Ok(out)
    }

    #[tokio::test]
    async fn capped_download_delivers_under_the_cap() {
        let bytes = capped(1024, Duration::from_secs(5), |cb| scripted(cb, 4, 256, Some(1024))).await.expect("under");
        assert_eq!(bytes.len(), 1024, "exactly the cap is fine");
        let bytes = capped(1024, Duration::from_secs(5), |cb| scripted(cb, 2, 100, None)).await.expect("no length");
        assert_eq!(bytes.len(), 200);
    }

    #[tokio::test]
    async fn capped_download_aborts_on_a_declared_or_counted_oversize_body() {
        // Declared over the cap: aborted at the first chunk.
        let e = capped(1024, Duration::from_secs(5), |cb| scripted(cb, 100, 10, Some(4096))).await.expect_err("declared");
        assert_eq!(e, SourceError::Network);
        // Undeclared, counted past the cap: aborted after the chunk that crossed it, not at
        // the end of a 10 000-chunk stream.
        let seen = Arc::new(AtomicU64::new(0));
        let s = Arc::clone(&seen);
        let e = capped(1024, Duration::from_secs(5), move |mut cb| async move {
            let mut out = Vec::new();
            for _ in 0..10_000 {
                tokio::task::yield_now().await;
                s.fetch_add(1, Ordering::SeqCst);
                cb(100, None);
                out.extend([0u8; 100]);
            }
            Ok(out)
        })
        .await
        .expect_err("counted");
        assert_eq!(e, SourceError::Network);
        let n = seen.load(Ordering::SeqCst);
        assert!((11..=12).contains(&n), "aborted right after crossing the cap: {n} chunks");
        // The cap crossed by the last chunk (no later await point) is still refused.
        let e = capped(1024, Duration::from_secs(5), |cb| scripted(cb, 1, 1025, None)).await.expect_err("last chunk");
        assert_eq!(e, SourceError::Network);
    }

    #[tokio::test]
    async fn capped_download_has_one_deadline_for_the_whole_transfer() {
        let e = capped(1 << 20, Duration::from_millis(50), |mut cb| async move {
            cb(10, None);
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(vec![0; 10])
        })
        .await
        .expect_err("deadline");
        assert_eq!(e, SourceError::Network);
        assert_eq!(DOWNLOAD_DEADLINE, Duration::from_secs(600));
        assert_eq!(PACKAGE_CAP, 256 * 1024 * 1024);
        assert_eq!(MANIFEST_CAP, 64 * 1024);
    }

    /// The endpoint checked in next to the prefix is in the same release tree.
    #[test]
    fn configured_endpoint_shares_the_release_tree() {
        // ADR-0028: the updater block lives in the release overlay; the merged config is what a
        // tag build compiles with. The dev base must not carry one at all.
        assert!(crate::test_config::base().pointer("/plugins/updater").is_none(), "dev config has no updater");
        let v = crate::test_config::release();
        let endpoints = v.pointer("/plugins/updater/endpoints").and_then(serde_json::Value::as_array).expect("endpoints");
        let tree = RELEASE_DOWNLOAD_PREFIX.trim_end_matches("download/");
        for e in endpoints {
            assert!(e.as_str().is_some_and(|u| u.starts_with(tree)), "{e} is outside {tree}");
        }
        assert_eq!(v.pointer("/plugins/updater/requireSignedVersion"), Some(&serde_json::Value::Bool(true)), "L-39");
    }
}
