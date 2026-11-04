//! Shared helpers for the test-server self-tests (verification clients, not product code).

// dead_code: each test binary uses a different subset. doc_markdown / many_single_char_names:
// same reasons as the crate's lib.rs (protocol terms; x / y / w / h / r geometry).
#![allow(dead_code, clippy::doc_markdown, clippy::many_single_char_names)]

pub mod rdp_client;
pub mod rfb_client;
pub mod rfb_decode;
pub mod tls;

use std::time::Duration;

/// Bounded wait so a broken server fails the test instead of hanging CI.
pub async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), fut).await.expect("timed out")
}

/// Polls `cond` until it holds (max ~5 s).
pub async fn eventually(mut cond: impl FnMut() -> bool) {
    for _ in 0..500 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached");
}
