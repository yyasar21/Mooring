//! In-memory token cache (ADR-0016 §3). One token per source, `Zeroizing`, never written
//! anywhere. A token is refreshed when less than 10 % or 30 s of its lifetime remains:
//! `renew-self` when renewable, otherwise it is dropped and the next resolve logs in again.
//! On lock / exit [`TokenCache::revoke_all`] revokes the tokens Mooring minted (`AppRole`,
//! OIDC) with `revoke-self` (best effort, 3 s) and drops every token; a stored `token`-method
//! token is the user's and is only forgotten.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use mooring_core::SecretSourceId;
use zeroize::Zeroizing;

use crate::audit::{SecretEvent, SecretsAudit};
use crate::client::{VaultClient, VaultToken, NO_TTL_RECHECK};

/// Deadline of one `revoke-self` on lock / exit.
pub const REVOKE_TIMEOUT: Duration = Duration::from_secs(3);
/// Refresh when less than this remains, whatever the TTL.
pub const REFRESH_FLOOR: Duration = Duration::from_secs(30);
/// Longest time a token stays cached without a refresh (a re-check bound).
pub const MAX_CACHE: Duration = Duration::from_secs(24 * 3600);

/// Monotonic time source; a fake one drives the tests.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Time since an arbitrary fixed origin.
    fn now(&self) -> Duration;
}

/// `Instant`-based clock.
#[derive(Debug)]
pub struct SystemClock(Instant);

impl Default for SystemClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

/// Manually advanced clock (tests, previews).
#[derive(Debug, Default)]
pub struct FakeClock(Mutex<Duration>);

impl FakeClock {
    /// Move time forward.
    pub fn advance(&self, by: Duration) {
        let mut t = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *t += by;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Duration {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Whether a token with `remaining` of `lifetime` left is due for a refresh.
#[must_use]
pub fn refresh_due(remaining: Duration, lifetime: Duration) -> bool {
    remaining < lifetime / 10 || remaining < REFRESH_FLOOR
}

struct Entry {
    token: Zeroizing<String>,
    client: VaultClient,
    expires: Duration,
    lifetime: Duration,
    renewable: bool,
    /// Minted by Mooring (`AppRole` / OIDC): revoked on lock.
    ours: bool,
}

/// What [`TokenCache::maintain`] did for one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maintenance {
    /// `renew-self` succeeded.
    Renewed,
    /// Not renewable or the renewal failed: forgotten (and revoked when ours).
    Dropped,
}

/// The cache. Share it as `Arc<TokenCache>`.
pub struct TokenCache {
    clock: Arc<dyn Clock>,
    audit: Arc<dyn SecretsAudit>,
    entries: Mutex<HashMap<SecretSourceId, Entry>>,
}

impl fmt::Debug for TokenCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenCache").field("tokens", &self.len()).finish_non_exhaustive()
    }
}

fn lifetime_of(t: &VaultToken) -> Duration {
    if t.ttl.is_zero() {
        NO_TTL_RECHECK
    } else {
        t.ttl.min(MAX_CACHE)
    }
}

impl TokenCache {
    /// An empty cache.
    pub fn new(clock: Arc<dyn Clock>, audit: Arc<dyn SecretsAudit>) -> Self {
        Self { clock, audit, entries: Mutex::new(HashMap::new()) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SecretSourceId, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The clock.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Number of cached tokens.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// No cached token.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A live token for `source` and its client (an expired one is dropped).
    pub fn get(&self, source: SecretSourceId) -> Option<(VaultClient, Zeroizing<String>)> {
        let now = self.clock.now();
        let mut map = self.lock();
        match map.get(&source) {
            Some(e) if e.expires > now => Some((e.client.clone(), e.token.clone())),
            Some(_) => {
                map.remove(&source);
                None
            }
            None => None,
        }
    }

    /// Cache a fresh token (replacing any previous one, which is dropped, not revoked).
    pub fn put(&self, source: SecretSourceId, client: VaultClient, t: VaultToken, ours: bool) {
        let lifetime = lifetime_of(&t);
        let entry = Entry {
            expires: self.clock.now() + lifetime,
            lifetime,
            renewable: t.renewable,
            ours,
            client,
            token: t.token,
        };
        self.lock().insert(source, entry);
    }

    /// Seconds left for `source`, if cached.
    pub fn remaining(&self, source: SecretSourceId) -> Option<Duration> {
        let now = self.clock.now();
        self.lock().get(&source).map(|e| e.expires.saturating_sub(now))
    }

    /// Renew or drop every token that is due. Never holds the lock across a request.
    pub async fn maintain(&self) -> Vec<(SecretSourceId, Maintenance)> {
        let now = self.clock.now();
        let due: Vec<SecretSourceId> = self
            .lock()
            .iter()
            .filter(|(_, e)| refresh_due(e.expires.saturating_sub(now), e.lifetime))
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::with_capacity(due.len());
        for id in due {
            let Some((client, token, renewable)) =
                self.lock().get(&id).map(|e| (e.client.clone(), e.token.clone(), e.renewable))
            else {
                continue;
            };
            let renewed = if renewable { client.renew_self(&token).await.ok() } else { None };
            if let Some(t) = renewed {
                let lifetime = lifetime_of(&t);
                if let Some(e) = self.lock().get_mut(&id) {
                    e.expires = self.clock.now() + lifetime;
                    e.lifetime = lifetime;
                    e.renewable = t.renewable;
                }
                self.audit.record(SecretEvent::Renewed { source: id, ttl: lifetime.as_secs() });
                out.push((id, Maintenance::Renewed));
            } else {
                self.forget(id).await;
                out.push((id, Maintenance::Dropped));
            }
        }
        out
    }

    /// Drop the token of `source`; revoke it first when Mooring minted it.
    pub async fn forget(&self, source: SecretSourceId) -> bool {
        let Some(entry) = self.lock().remove(&source) else {
            return false;
        };
        Self::retire(entry).await;
        self.audit.record(SecretEvent::Revoked { source });
        true
    }

    async fn retire(entry: Entry) {
        if entry.ours {
            let revoke = entry.client.revoke_self(&entry.token);
            if !matches!(tokio::time::timeout(REVOKE_TIMEOUT, revoke).await, Ok(Ok(()))) {
                tracing::warn!("token revoke-self failed or timed out; dropped from memory");
            }
        }
        // `entry.token` is Zeroizing: wiped here.
    }

    /// Lock / exit: revoke ours (in parallel, 3 s each), forget all. Returns how many tokens
    /// were dropped.
    pub async fn revoke_all(&self) -> usize {
        let drained: Vec<(SecretSourceId, Entry)> = self.lock().drain().collect();
        let n = drained.len();
        let mut set = tokio::task::JoinSet::new();
        for (id, e) in drained {
            self.audit.record(SecretEvent::Revoked { source: id });
            set.spawn(Self::retire(e));
        }
        while set.join_next().await.is_some() {}
        n
    }

    /// Run [`Self::maintain`] every `every` until the cache is dropped.
    pub fn spawn_renewer(self: &Arc<Self>, every: Duration) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let Some(cache) = weak.upgrade() else { return };
                cache.maintain().await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_rule() {
        let h = Duration::from_secs(3600);
        assert!(!refresh_due(Duration::from_secs(400), h));
        assert!(refresh_due(Duration::from_secs(359), h), "< 10 %");
        let short = Duration::from_secs(60);
        assert!(!refresh_due(Duration::from_secs(31), short));
        assert!(refresh_due(Duration::from_secs(29), short), "< 30 s floor");
        assert!(refresh_due(Duration::ZERO, h));
    }
}
