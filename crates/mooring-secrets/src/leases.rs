//! Lease lifecycle of the Vault dynamic engines (ADR-0026 §2). Memory only: a lease id is not
//! a secret value but is kept like one (`Zeroizing`, never logged, never sent to the UI).
//!
//! * [`LeaseRegistry::maintain`] (every 30 s) renews a renewable lease once 2/3 of its TTL
//!   have passed; a failed renewal leaves the session running and is audited.
//! * [`LeaseRegistry::release`] (session close, reconnect) and [`LeaseRegistry::drain_for_lock`]
//!   (vault lock, exit) take the leases out synchronously; [`Released::retire`] then revokes
//!   them (best effort, 3 s each) with the token that issued them.
//! * The lock epoch (as in the token cache, L-34): a lease issued by a resolve that started
//!   before a lock is refused by [`LeaseRegistry::register`] and revoked at once.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use mooring_core::credential::VaultEngine;
use mooring_core::SecretSourceId;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::audit::{SecretEvent, SecretsAudit};
use crate::cache::{Clock, REVOKE_TIMEOUT};
use crate::client::VaultClient;

/// Maintenance tick (ADR-0026 §2).
pub const LEASE_TICK: Duration = Duration::from_secs(30);

/// Whether a lease issued `age` ago with `ttl` is due for renewal (2/3 of the TTL passed).
#[must_use]
pub fn renew_due(age: Duration, ttl: Duration) -> bool {
    !ttl.is_zero() && age.saturating_mul(3) >= ttl.saturating_mul(2)
}

/// The PKI certificate to revoke by serial when the lease is released
/// (`revokeCertOnDisconnect`, owner decision 37: default off).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRevoke {
    /// PKI mount.
    pub mount: String,
    /// Serial (`xx:xx:…`).
    pub serial: String,
}

/// One lease (or one PKI certificate to revoke).
pub struct Lease {
    pub(crate) id: Option<Zeroizing<String>>,
    pub(crate) source: SecretSourceId,
    pub(crate) owner: Option<String>,
    pub(crate) engine: VaultEngine,
    pub(crate) client: VaultClient,
    pub(crate) token: Zeroizing<String>,
    pub(crate) issued: Duration,
    pub(crate) ttl: Duration,
    pub(crate) renewable: bool,
    pub(crate) failed: bool,
    pub(crate) cert: Option<CertRevoke>,
}

impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("source", &self.source)
            .field("engine", &self.engine)
            .field("ttl", &self.ttl)
            .field("renewable", &self.renewable)
            .finish_non_exhaustive()
    }
}

/// What the UI may know about a session's leases (ADR-0026 T5: expiry, never ids).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseStatus {
    /// Engine.
    pub engine: VaultEngine,
    /// Time left (`None`: the lease reports no TTL).
    pub expires_in: Option<Duration>,
    /// Renewable.
    pub renewable: bool,
    /// `active` | `renew_failed` | `expired`.
    pub state: &'static str,
}

/// Leases taken out of the registry; [`Released::retire`] revokes them.
pub struct Released {
    leases: Vec<Lease>,
    reason: &'static str,
    audit: Arc<dyn SecretsAudit>,
}

impl fmt::Debug for Released {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Released").field("leases", &self.leases.len()).finish_non_exhaustive()
    }
}

impl Released {
    /// How many.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    /// Nothing was taken.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    /// Revoke every lease (and certificate) in order, 3 s each, best effort; audited.
    pub async fn retire(self) {
        for lease in self.leases {
            retire_one(lease, self.reason, self.audit.as_ref()).await;
        }
    }
}

pub(crate) async fn retire_one(lease: Lease, reason: &'static str, audit: &dyn SecretsAudit) {
    let mut ok = true;
    if let Some(id) = &lease.id {
        let r = tokio::time::timeout(REVOKE_TIMEOUT, lease.client.lease_revoke(&lease.token, id));
        ok = matches!(r.await, Ok(Ok(())));
    }
    if let Some(c) = &lease.cert {
        let r = tokio::time::timeout(
            REVOKE_TIMEOUT,
            lease.client.pki_revoke(&lease.token, &c.mount, &c.serial),
        );
        ok &= matches!(r.await, Ok(Ok(())));
    }
    if !ok {
        tracing::info!(engine = lease.engine.name(), "lease revoke did not complete");
    }
    audit.record(SecretEvent::LeaseRevoked {
        owner: lease.owner.clone(),
        source: lease.source,
        reason,
        ok,
    });
}

/// A lease due for renewal, copied out of the registry.
struct Due {
    client: VaultClient,
    token: Zeroizing<String>,
    id: Zeroizing<String>,
    ttl: Duration,
}

/// The registry. Share it as `Arc<LeaseRegistry>`.
pub struct LeaseRegistry {
    clock: Arc<dyn Clock>,
    audit: Arc<dyn SecretsAudit>,
    entries: Mutex<Vec<Lease>>,
    epoch: AtomicU64,
}

impl fmt::Debug for LeaseRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseRegistry").field("leases", &self.len()).finish_non_exhaustive()
    }
}

impl LeaseRegistry {
    /// An empty registry.
    pub fn new(clock: Arc<dyn Clock>, audit: Arc<dyn SecretsAudit>) -> Self {
        Self { clock, audit, entries: Mutex::new(Vec::new()), epoch: AtomicU64::new(0) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Lease>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of leases held.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// No lease is held.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Lock epoch (read before a resolve starts).
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Now on the registry's clock.
    pub(crate) fn now(&self) -> Duration {
        self.clock.now()
    }

    /// Keep `lease` unless a lock happened since `epoch`: then it comes back for revocation.
    #[allow(clippy::result_large_err)] // the refused lease is handed back to be revoked
    pub(crate) fn register(&self, lease: Lease, epoch: u64) -> Result<(), Lease> {
        let mut g = self.lock();
        if self.epoch() != epoch {
            return Err(lease);
        }
        g.push(lease);
        Ok(())
    }

    /// Take every lease of `owner` (session close / reconnect).
    pub fn release(&self, owner: &str, reason: &'static str) -> Released {
        let mut g = self.lock();
        let (mine, rest): (Vec<Lease>, Vec<Lease>) =
            g.drain(..).partition(|l| l.owner.as_deref() == Some(owner));
        *g = rest;
        Released { leases: mine, reason, audit: Arc::clone(&self.audit) }
    }

    /// Vault lock / exit: bump the epoch and take every lease.
    pub fn drain_for_lock(&self, reason: &'static str) -> Released {
        let mut g = self.lock();
        self.epoch.fetch_add(1, Ordering::SeqCst);
        Released { leases: g.drain(..).collect(), reason, audit: Arc::clone(&self.audit) }
    }

    /// The lease state of `owner` (no ids).
    pub fn status(&self, owner: &str) -> Vec<LeaseStatus> {
        let now = self.clock.now();
        self.lock()
            .iter()
            .filter(|l| l.owner.as_deref() == Some(owner) && l.id.is_some())
            .map(|l| {
                let left = (!l.ttl.is_zero()).then(|| (l.issued + l.ttl).saturating_sub(now));
                let state = match left {
                    Some(d) if d.is_zero() => "expired",
                    _ if l.failed => "renew_failed",
                    _ => "active",
                };
                LeaseStatus { engine: l.engine, expires_in: left, renewable: l.renewable, state }
            })
            .collect()
    }

    /// Renew every due lease. Returns how many renewals were attempted.
    pub async fn maintain(&self) -> usize {
        let now = self.clock.now();
        // The due leases, copied out: the lock is not held across I/O.
        let due: Vec<Due> = self
            .lock()
            .iter()
            .filter(|l| l.renewable && !l.failed && renew_due(now.saturating_sub(l.issued), l.ttl))
            .filter_map(|l| {
                l.id.as_ref().map(|id| Due {
                    client: l.client.clone(),
                    token: l.token.clone(),
                    id: id.clone(),
                    ttl: l.ttl,
                })
            })
            .collect();
        let attempted = due.len();
        for d in due {
            let result = d.client.lease_renew(&d.token, &d.id, d.ttl).await;
            let mut entries = self.lock();
            let same = |l: &&mut Lease| l.id.as_deref().map(String::as_str) == Some(d.id.as_str());
            let Some(lease) = entries.iter_mut().find(same) else {
                continue; // released meanwhile
            };
            let owner = lease.owner.clone().unwrap_or_default();
            match result {
                Ok((new_ttl, renewable)) => {
                    lease.issued = self.clock.now();
                    lease.ttl = new_ttl;
                    lease.renewable = renewable && !new_ttl.is_zero();
                    self.audit.record(SecretEvent::LeaseRenewed {
                        owner,
                        source: lease.source,
                        ttl: new_ttl.as_secs(),
                    });
                }
                Err(e) => {
                    lease.failed = true;
                    self.audit.record(SecretEvent::LeaseRenewFailed {
                        owner,
                        source: lease.source,
                        category: e.category(),
                    });
                }
            }
        }
        attempted
    }

    /// Run [`Self::maintain`] every `every` until the handle is aborted.
    pub fn spawn_maintainer(self: &Arc<Self>, every: Duration) -> JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                me.maintain().await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(owner: &str) -> Lease {
        use mooring_core::secret_source::{SecretSourceAuth, SourceKind, SourceOptions};
        let src = mooring_core::secret_source::SecretSource {
            id: SecretSourceId::new(),
            name: "v".into(),
            kind: SourceKind::Vault,
            address: "https://vault.example.test".into(),
            namespace: None,
            auth: SecretSourceAuth::Token { credential_id: mooring_core::CredentialId::new() },
            options: SourceOptions::default(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let cfg = crate::client::ClientConfig::new("known_vault_certs".into());
        Lease {
            id: Some(Zeroizing::new("database/creds/r/1".into())),
            source: src.id,
            owner: Some(owner.into()),
            engine: VaultEngine::Database,
            client: VaultClient::new(&src, &cfg).expect("client"),
            token: Zeroizing::new("hvs.test-only".into()),
            issued: Duration::ZERO,
            ttl: Duration::from_secs(60),
            renewable: true,
            failed: false,
            cert: None,
        }
    }

    /// L-34 for leases: a resolve that started before a lock cannot register its lease.
    #[test]
    fn a_lock_refuses_leases_of_resolves_that_started_before_it() {
        let clock = Arc::new(crate::cache::FakeClock::default());
        let reg = LeaseRegistry::new(clock.clone(), Arc::new(crate::audit::NoAudit));
        let epoch = reg.epoch();
        reg.register(lease("a"), epoch).expect("same epoch");
        assert!(format!("{reg:?}").contains("leases: 1"));
        assert!(!format!("{:?}", lease("x")).contains("hvs."), "no token in Debug");
        let drained = reg.drain_for_lock("locked");
        assert_eq!((drained.len(), reg.len()), (1, 0));
        assert!(reg.register(lease("b"), epoch).is_err(), "stale epoch");
        reg.register(lease("c"), reg.epoch()).expect("new epoch");
        reg.register(lease("d"), reg.epoch()).expect("d");
        assert_eq!(reg.release("c", "closed").len(), 1);
        assert_eq!(reg.len(), 1, "other owners stay");
        clock.advance(Duration::from_secs(61));
        assert_eq!(reg.status("d")[0].state, "expired");
        assert_eq!(reg.status("d")[0].expires_in, Some(Duration::ZERO));
        assert!(reg.status("nobody").is_empty());
    }

    #[test]
    fn two_thirds_rule() {
        let s = Duration::from_secs;
        assert!(!renew_due(s(0), s(60)));
        assert!(!renew_due(s(39), s(60)));
        assert!(renew_due(s(40), s(60)));
        assert!(renew_due(s(500), s(60)), "overdue");
        assert!(!renew_due(s(500), s(0)), "no TTL: never renewed");
        assert!(renew_due(Duration::MAX, s(3)), "no overflow");
        assert!(!renew_due(s(1), Duration::MAX), "no overflow");
    }
}
