//! In-memory [`ObjectStore`] with S3 semantics (`ETag`s, conditional writes) and test knobs:
//! a mode that ignores preconditions (an unsupported backend), raw access for rollback /
//! tamper scenarios, and write counters. Used by this crate's tests and by the Tauri layer's.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use bytes::Bytes;

use super::{Cond, Object, ObjectStore, PutMeta, PutOutcome, RemoteHead};
use crate::error::{Result, SyncError};

#[derive(Debug, Clone)]
struct Entry {
    bytes: Vec<u8>,
    etag: String,
    meta: PutMeta,
}

#[derive(Debug, Default)]
struct Inner {
    objects: Mutex<BTreeMap<String, Entry>>,
    next_etag: AtomicU64,
    ignore_conditionals: AtomicBool,
    yield_each_call: AtomicBool,
    puts: AtomicU64,
}

/// Shared in-memory bucket; clones see the same objects.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore(Arc<Inner>);

impl MemoryStore {
    /// An empty bucket.
    pub fn new() -> Self {
        Self::default()
    }

    /// Behave like a backend that ignores `If-None-Match` / `If-Match`.
    pub fn set_ignore_conditionals(&self, on: bool) {
        self.0.ignore_conditionals.store(on, Ordering::SeqCst);
    }

    /// Yield to the scheduler before every call, so two engines joined on one task
    /// interleave like real network clients.
    pub fn set_yield(&self, on: bool) {
        self.0.yield_each_call.store(on, Ordering::SeqCst);
    }

    async fn maybe_yield(&self) {
        if self.0.yield_each_call.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    }

    /// Raw read (tests).
    pub fn raw_get(&self, key: &str) -> Option<Vec<u8>> {
        self.lock().get(key).map(|e| e.bytes.clone())
    }

    /// Raw write that bypasses preconditions and gets a fresh `ETag` (tests: rollback, tamper).
    pub fn raw_put(&self, key: &str, bytes: Vec<u8>) {
        let etag = self.etag();
        self.lock().insert(key.to_owned(), Entry { bytes, etag, meta: PutMeta::default() });
    }

    /// Raw delete (tests: a vanished `current`).
    pub fn delete_raw(&self, key: &str) {
        self.lock().remove(key);
    }

    /// Every key, sorted.
    pub fn keys(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    /// Number of successful writes so far.
    pub fn puts(&self) -> u64 {
        self.0.puts.load(Ordering::SeqCst)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Entry>> {
        self.0.objects.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn etag(&self) -> String {
        format!("\"m{}\"", self.0.next_etag.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

#[async_trait]
impl ObjectStore for MemoryStore {
    async fn head(&self, key: &str) -> Result<Option<RemoteHead>> {
        self.maybe_yield().await;
        Ok(self.lock().get(key).map(|e| RemoteHead {
            etag: e.etag.clone(),
            counter: e.meta.counter,
            parent: e.meta.parent.clone(),
        }))
    }

    async fn get(&self, key: &str, cap: usize) -> Result<Option<Object>> {
        self.maybe_yield().await;
        let Some(e) = self.lock().get(key).cloned() else { return Ok(None) };
        if e.bytes.len() > cap {
            return Err(SyncError::TooLarge);
        }
        Ok(Some(Object { bytes: e.bytes, etag: e.etag }))
    }

    async fn put(
        &self,
        key: &str,
        body: Bytes,
        cond: Cond<'_>,
        meta: &PutMeta,
    ) -> Result<PutOutcome> {
        self.maybe_yield().await;
        let etag = self.etag();
        let mut objects = self.lock();
        if !self.0.ignore_conditionals.load(Ordering::SeqCst) {
            let have = objects.get(key).map(|e| e.etag.as_str());
            let ok = match cond {
                Cond::None => true,
                Cond::IfNoneMatch => have.is_none(),
                Cond::IfMatch(want) => have == Some(want),
            };
            if !ok {
                return Ok(PutOutcome::PreconditionFailed);
            }
        }
        objects.insert(
            key.to_owned(),
            Entry { bytes: body.to_vec(), etag: etag.clone(), meta: meta.clone() },
        );
        self.0.puts.fetch_add(1, Ordering::SeqCst);
        Ok(PutOutcome::Written { etag })
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.lock().remove(key);
        Ok(())
    }
}
