//! Object storage behind sync: the [`ObjectStore`] trait (S3 or the in-memory test store)
//! and [`Remote`], the per-vault object layout of ADR-0017 §2:
//!
//! ```text
//! <prefix>/<vault_id>/header              vault header bytes (no keyring wrap)
//! <prefix>/<vault_id>/current             latest MSY1 blob (conditional writes only)
//! <prefix>/<vault_id>/history/<counter>   the last N blobs, counter zero-padded to 20 digits
//! <prefix>/.probe/<random>                capability probe, deleted afterwards
//! ```

pub mod memory;
pub mod s3;

use async_trait::async_trait;
use bytes::Bytes;
use uuid::Uuid;

use crate::blob::MAX_BLOB;
use crate::error::{Result, SyncError};

/// Largest header object accepted.
pub const MAX_HEADER_OBJECT: usize = mooring_vault::MAX_HEADER_BYTES;

/// Precondition of a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond<'a> {
    /// Unconditional.
    None,
    /// `If-None-Match: *` — create only.
    IfNoneMatch,
    /// `If-Match: <etag>` — replace only that version.
    IfMatch(&'a str),
}

/// Result of a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    /// Stored; the new `ETag`.
    Written {
        /// `ETag` of the new object.
        etag: String,
    },
    /// The precondition failed (412, or 409 for a concurrent conditional write).
    PreconditionFailed,
}

/// `HEAD` result. `counter` / `parent` come from object metadata: unauthenticated hints for
/// a cheap "did anything change" check, never trusted for decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteHead {
    /// `ETag`.
    pub etag: String,
    /// `x-amz-meta-mooring-counter`.
    pub counter: Option<u64>,
    /// `x-amz-meta-mooring-parent` (hex blob hash).
    pub parent: Option<String>,
}

/// A downloaded object.
#[derive(Debug, Clone)]
pub struct Object {
    /// Body (at most the cap of the call).
    pub bytes: Vec<u8>,
    /// `ETag`.
    pub etag: String,
}

/// Metadata written with a blob.
#[derive(Debug, Clone, Default)]
pub struct PutMeta {
    /// Counter hint.
    pub counter: Option<u64>,
    /// Parent hash hint (hex).
    pub parent: Option<String>,
}

/// Minimal object storage. Implementations map transport errors to [`SyncError`] and never
/// retry writes (a retried conditional write could misreport its own success as a 412).
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// `HEAD key`; `None` when absent.
    async fn head(&self, key: &str) -> Result<Option<RemoteHead>>;
    /// `GET key` with a body cap; `None` when absent; over the cap → [`SyncError::TooLarge`].
    async fn get(&self, key: &str, cap: usize) -> Result<Option<Object>>;
    /// `PUT key` with a precondition.
    async fn put(
        &self,
        key: &str,
        body: Bytes,
        cond: Cond<'_>,
        meta: &PutMeta,
    ) -> Result<PutOutcome>;
    /// `DELETE key` (absent is fine).
    async fn delete(&self, key: &str) -> Result<()>;
}

/// Validate a key prefix: empty, or `[A-Za-z0-9._-]` segments joined by `/`, ≤ 256 bytes.
pub fn check_prefix(prefix: &str) -> Result<()> {
    let ok = prefix.len() <= 256
        && (prefix.is_empty()
            || prefix.split('/').all(|seg| {
                !seg.is_empty()
                    && seg != "."
                    && seg != ".."
                    && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            }));
    if ok {
        Ok(())
    } else {
        Err(SyncError::Invalid("prefix must be [A-Za-z0-9._-] segments separated by /"))
    }
}

/// One vault's objects in a store.
#[derive(Debug)]
pub struct Remote<S> {
    store: S,
    base: String,
    probe_base: String,
}

impl<S: ObjectStore> Remote<S> {
    /// Layout under `prefix` for `vault_id`.
    pub fn new(store: S, prefix: &str, vault_id: Uuid) -> Result<Self> {
        check_prefix(prefix)?;
        let p = if prefix.is_empty() { String::new() } else { format!("{prefix}/") };
        Ok(Self {
            store,
            base: format!("{p}{}", vault_id.hyphenated()),
            probe_base: format!("{p}.probe"),
        })
    }

    /// The underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    fn key(&self, leaf: &str) -> String {
        format!("{}/{leaf}", self.base)
    }

    fn history_key(&self, counter: u64) -> String {
        self.key(&format!("history/{counter:020}"))
    }

    /// `HEAD current`.
    pub async fn head(&self) -> Result<Option<RemoteHead>> {
        self.store.head(&self.key("current")).await
    }

    /// `GET current` (≤ [`MAX_BLOB`]).
    pub async fn get(&self) -> Result<Option<Object>> {
        self.store.get(&self.key("current"), MAX_BLOB).await
    }

    /// First publish: `If-None-Match: *`. `PreconditionFailed` = another device initialised.
    pub async fn put_new(&self, blob: Bytes, meta: &PutMeta) -> Result<PutOutcome> {
        self.store.put(&self.key("current"), blob, Cond::IfNoneMatch, meta).await
    }

    /// Compare-and-swap publish: `If-Match: <etag>`.
    pub async fn put_cas(&self, etag: &str, blob: Bytes, meta: &PutMeta) -> Result<PutOutcome> {
        self.store.put(&self.key("current"), blob, Cond::IfMatch(etag), meta).await
    }

    /// `GET header` (≤ 64 KiB).
    pub async fn get_header(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.store.get(&self.key("header"), MAX_HEADER_OBJECT).await?.map(|o| o.bytes))
    }

    /// `PUT header` (unconditional: every device of the vault writes the same bytes).
    pub async fn put_header(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_HEADER_OBJECT {
            return Err(SyncError::TooLarge);
        }
        let body = Bytes::copy_from_slice(bytes);
        match self.store.put(&self.key("header"), body, Cond::None, &PutMeta::default()).await? {
            PutOutcome::Written { .. } => Ok(()),
            PutOutcome::PreconditionFailed => Err(SyncError::Backend { status: 412 }),
        }
    }

    /// `GET history/<counter>`.
    pub async fn get_history(&self, counter: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.store.get(&self.history_key(counter), MAX_BLOB).await?.map(|o| o.bytes))
    }

    /// `PUT history/<counter>`.
    pub async fn put_history(&self, counter: u64, blob: Bytes) -> Result<()> {
        self.store.put(&self.history_key(counter), blob, Cond::None, &PutMeta::default()).await?;
        Ok(())
    }

    /// `DELETE history/<counter>`.
    pub async fn delete_history(&self, counter: u64) -> Result<()> {
        self.store.delete(&self.history_key(counter)).await
    }

    /// Delete every object of this vault (`sync_disable { deleteRemote }`), history up to
    /// `last_counter`.
    pub async fn delete_all(&self, last_counter: u64) -> Result<()> {
        self.store.delete(&self.key("current")).await?;
        self.store.delete(&self.key("header")).await?;
        for c in last_counter.saturating_sub(64)..=last_counter {
            self.store.delete(&self.history_key(c)).await?;
        }
        Ok(())
    }

    /// Capability probe (ADR-0017 §3): create a probe object with `If-None-Match: *` (must
    /// succeed), repeat it (must be refused), overwrite with a wrong `If-Match` (must be
    /// refused), then delete it. `Ok(false)` = the backend ignores conditional writes.
    pub async fn probe(&self) -> Result<bool> {
        let key = format!("{}/{}", self.probe_base, Uuid::new_v4().simple());
        let body = || Bytes::from_static(b"mooring conditional write probe");
        let meta = PutMeta::default();
        let first = self.store.put(&key, body(), Cond::IfNoneMatch, &meta).await?;
        let PutOutcome::Written { etag } = first else {
            return Ok(false);
        };
        let second = self.store.put(&key, body(), Cond::IfNoneMatch, &meta).await;
        let wrong = format!("\"{}\"", Uuid::new_v4().simple());
        let third = self.store.put(&key, body(), Cond::IfMatch(&wrong), &meta).await;
        let right = self.store.put(&key, body(), Cond::IfMatch(&etag), &meta).await;
        self.store.delete(&key).await?;
        Ok(matches!(second?, PutOutcome::PreconditionFailed)
            && matches!(third?, PutOutcome::PreconditionFailed)
            && matches!(right?, PutOutcome::Written { .. }))
    }

    /// [`Remote::probe`] as a gate: `Err(UnsupportedBackend)` unless conditional writes work.
    pub async fn require_conditional_writes(&self) -> Result<()> {
        if self.probe().await? {
            Ok(())
        } else {
            Err(SyncError::UnsupportedBackend)
        }
    }
}
