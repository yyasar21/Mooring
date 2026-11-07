//! ADR-0016 E2: the process-wide external-secrets runtime held by `AppState`.
//!
//! * one [`SecretsEngine`] over one in-memory [`TokenCache`] (nothing is written to disk);
//! * a renewer task (15 s tick) started from the first async context;
//! * [`SecretsRuntime::on_lock`] closes the OIDC windows and revokes / forgets every token,
//!   [`SecretsRuntime::shutdown`] does the same at exit (bounded by the 3 s revoke deadline);
//! * every [`SecretEvent`] goes to the hash-chained audit log; `secret_resolved` and
//!   `secret_failed` carry the connection of the connect that triggered them
//!   ([`with_connection`]);
//! * ADR-0026: a lease maintainer (30 s) renews dynamic leases; a session's leases are
//!   revoked when it ends ([`SecretsRuntime::release_session`]) and every lease on lock and
//!   exit, **before** the tokens that issued them.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use mooring_audit::{AuditEvent, AuditLog};
use mooring_core::known_certs::CertProtocol;
use mooring_core::secret_source::{SecretSource, SecretSourceAuth, SourceKind};
use mooring_core::SecretName;
use mooring_secrets::{
    Category, ClientConfig, Clock, LoginMaterial, LoginProvider, SecretEvent, SecretsAudit,
    SecretsEngine, SecretsError, SystemClock, TokenCache, LEASE_TICK, REVOKE_TIMEOUT,
};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::error::IpcError;
use crate::oidc_window::OidcSessions;
use crate::state::{record_audit, Ready};

/// Renewer tick.
pub const RENEW_EVERY: Duration = Duration::from_secs(15);

tokio::task_local! {
    static CONNECTION: Option<String>;
}

/// Run `f` with `connection` attached to the secret events it records.
pub async fn with_connection<F: std::future::Future>(connection: String, f: F) -> F::Output {
    CONNECTION.scope(Some(connection), f).await
}

fn current_connection() -> Option<String> {
    CONNECTION.try_with(Clone::clone).ok().flatten()
}

/// [`SecretEvent`] → `mooring-audit`.
struct AuditBridge(Arc<Mutex<AuditLog>>);

/// The audit row of one secret event (the connection comes from [`with_connection`]).
pub fn audit_event(e: SecretEvent, connection: Option<String>) -> AuditEvent {
    match e {
        SecretEvent::Login { source, method, ttl } => {
            AuditEvent::SecretLogin { source: source.to_string(), method: method.name().into(), ttl }
        }
        SecretEvent::Renewed { source, ttl } => {
            AuditEvent::SecretLogin { source: source.to_string(), method: "renew".into(), ttl }
        }
        SecretEvent::Resolved {
            credential,
            source,
            reference,
            version,
            target_kind,
            fields,
            provider,
            engine,
        } => AuditEvent::SecretResolved {
            connection,
            credential: credential.to_string(),
            source: source.to_string(),
            reference,
            version,
            target_kind: target_kind.name().into(),
            fields: fields.into_iter().map(str::to_owned).collect(),
            provider: Some(provider.to_owned()),
            engine: Some(engine.name().to_owned()),
        },
        SecretEvent::LeaseIssued { owner, source, engine, ttl, renewable } => {
            AuditEvent::SecretLeaseIssued {
                session: owner,
                source: source.to_string(),
                engine: engine.name().into(),
                ttl,
                renewable,
            }
        }
        SecretEvent::LeaseRenewed { owner, source, ttl } => {
            AuditEvent::SecretLeaseRenewed { session: owner, source: source.to_string(), ttl }
        }
        SecretEvent::LeaseRenewFailed { owner, source, category } => {
            AuditEvent::SecretLeaseRenewFailed {
                session: owner,
                source: source.to_string(),
                category: category.as_str().into(),
            }
        }
        SecretEvent::LeaseRevoked { owner, source, reason, ok } => AuditEvent::SecretLeaseRevoked {
            session: owner,
            source: source.to_string(),
            reason: reason.into(),
            ok,
        },
        SecretEvent::ToolSpawned { provider, action, exit } => AuditEvent::SecretToolSpawned {
            provider: provider.into(),
            action: action.into(),
            exit,
        },
        SecretEvent::ToolChanged { provider, sha256 } => {
            AuditEvent::SecretToolChanged { provider: provider.into(), sha256 }
        }
        SecretEvent::Failed { source, category } => AuditEvent::SecretFailed {
            connection,
            source: source.to_string(),
            category: category.as_str().into(),
        },
        SecretEvent::Revoked { source } => AuditEvent::SecretRevoked { source: source.to_string() },
    }
}

impl SecretsAudit for AuditBridge {
    fn record(&self, event: SecretEvent) {
        record_audit(&self.0, audit_event(event, current_connection()));
    }
}

/// `SecretsError` → IPC with literal codes, so the golden `ipc-codes.json` scanner lists
/// them (it reads literals in this crate only). The match mirrors `SecretsError::code()`
/// (ADR-0016 §7); a test asserts the two agree for every variant. Every message is
/// value-free by construction (mooring-secrets).
pub fn ipc_error(e: &SecretsError) -> IpcError {
    let code = match e {
        SecretsError::Unavailable { .. } | SecretsError::Trust(_) => "credential.external_unavailable",
        SecretsError::RootToken => "credential.external_root_token",
        SecretsError::NotFound => "credential.external_not_found",
        SecretsError::Shape { .. } => "credential.external_shape",
        SecretsError::Invalid(_) => "input.invalid",
        SecretsError::Engine(_) => "credential.external_engine",
        SecretsError::Lease(_) => "secret.lease_failed",
        SecretsError::ToolMissing => "secret.tool_missing",
        SecretsError::ToolVersion => "secret.tool_version",
        SecretsError::ToolFailed { .. } => "secret.tool_failed",
        SecretsError::KindUnsupported(_) => "source.kind_unsupported",
    };
    debug_assert_eq!(code, e.code(), "ipc_error drifted from SecretsError::code()");
    IpcError::new(code, e.to_string())
}

/// `credential.external_unavailable` with the `locked` category.
pub fn locked() -> SecretsError {
    SecretsError::Unavailable { category: Category::Locked, detail: "the Mooring vault is locked" }
}

fn text(bytes: &[u8]) -> Result<Zeroizing<String>, SecretsError> {
    std::str::from_utf8(bytes)
        .map(|s| Zeroizing::new(s.to_owned()))
        .map_err(|_| SecretsError::Invalid("login credential"))
}

/// Opens a source's login credential from the Mooring vault (only when a login is needed).
pub fn login_provider(ready: Ready) -> impl LoginProvider {
    move |s: &SecretSource| -> Result<LoginMaterial, SecretsError> {
        let id = s.auth.credential_id().ok_or(SecretsError::Invalid("login credential"))?;
        let opened = ready.with_ready(|vault, store| {
            let open = |n| store.open_secret(vault, id, n).map_err(IpcError::from);
            Ok(match &s.auth {
                // ADR-0026 §4: a Bitwarden source logs in with its machine access token.
                SecretSourceAuth::Token { .. } if s.kind == SourceKind::Bitwarden => LoginMaterial::Token(
                    text(&open(SecretName::AccessToken)?).map_err(|e| ipc_error(&e))?,
                ),
                SecretSourceAuth::Token { .. } => {
                    LoginMaterial::Token(text(&open(SecretName::Token)?).map_err(|e| ipc_error(&e))?)
                }
                SecretSourceAuth::AppRole { .. } => LoginMaterial::AppRole {
                    role_id: text(&open(SecretName::RoleId)?).map_err(|e| ipc_error(&e))?,
                    secret_id: text(&open(SecretName::SecretId)?).map_err(|e| ipc_error(&e))?,
                },
                SecretSourceAuth::Oidc { .. } => {
                    return Err(IpcError::invalid("source", "OIDC has no login credential"))
                }
            })
        });
        opened.map_err(|e| match e.code {
            "vault.locked" => locked(),
            _ => SecretsError::Unavailable {
                category: Category::AuthFailed,
                detail: "the login credential could not be opened",
            },
        })
    }
}

/// The runtime. Shared as `Arc<SecretsRuntime>` (`AppState::secrets`, `Ready`).
pub struct SecretsRuntime {
    engine: Arc<SecretsEngine>,
    audit: Arc<Mutex<AuditLog>>,
    /// OIDC flows and their windows.
    pub oidc: OidcSessions,
    renewer: Mutex<Option<JoinHandle<()>>>,
    leases: Mutex<Option<JoinHandle<()>>>,
    background: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for SecretsRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretsRuntime").field("engine", &self.engine).finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl SecretsRuntime {
    /// Production runtime: system clock, `$APP_DATA/known_vault_certs`.
    pub fn new(data_dir: &Path, audit: Arc<Mutex<AuditLog>>) -> Self {
        Self::with_clock(data_dir, audit, Arc::new(SystemClock::default()))
    }

    /// Runtime on `clock` (tests drive a `FakeClock`).
    pub fn with_clock(data_dir: &Path, audit: Arc<Mutex<AuditLog>>, clock: Arc<dyn Clock>) -> Self {
        let bridge: Arc<dyn SecretsAudit> = Arc::new(AuditBridge(Arc::clone(&audit)));
        let cache = Arc::new(TokenCache::new(clock, Arc::clone(&bridge)));
        let cfg = ClientConfig::new(data_dir.join(CertProtocol::Vault.file_name()));
        Self {
            engine: Arc::new(SecretsEngine::new(cache, bridge, cfg)),
            audit,
            oidc: OidcSessions::default(),
            renewer: Mutex::new(None),
            leases: Mutex::new(None),
            background: Mutex::new(Vec::new()),
        }
    }

    /// The engine. Starts the renewer on first use inside a Tokio runtime.
    pub fn engine(&self) -> &Arc<SecretsEngine> {
        self.ensure_renewer();
        &self.engine
    }

    /// Audit one row.
    pub fn audit(&self, event: AuditEvent) {
        record_audit(&self.audit, event);
    }

    /// Audit a refusal (`secret_refused`).
    pub fn refused(&self, source: Option<String>, action: &str, detail: &str) {
        self.audit(AuditEvent::SecretRefused { source, action: action.into(), detail: detail.into() });
    }

    /// Start the renewer task if a Tokio runtime is current and it is not running.
    pub fn ensure_renewer(&self) {
        let mut slot = lock(&self.renewer);
        if slot.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }
        if tokio::runtime::Handle::try_current().is_ok() {
            *slot = Some(self.engine.cache().spawn_renewer(RENEW_EVERY));
            let mut leases = lock(&self.leases);
            if leases.as_ref().is_none_or(tokio::task::JoinHandle::is_finished) {
                *leases = Some(self.engine.leases().spawn_maintainer(LEASE_TICK));
            }
        }
    }

    /// ADR-0026 §2: a session ended (or reconnects): revoke its leases in the background.
    pub fn release_session(&self, session: &str, reason: &'static str) {
        let released = self.engine.leases().release(session, reason);
        if !released.is_empty() {
            self.spawn(released.retire());
        }
    }

    /// The lease state of a session (expiry only, never ids; ADR-0026 T5).
    pub fn lease_status(&self, session: &str) -> Vec<mooring_secrets::LeaseStatus> {
        self.engine.leases().status(session)
    }

    /// Run `f` in the background (current runtime, else Tauri's); [`Self::flush`] awaits it.
    pub fn spawn(&self, f: impl std::future::Future<Output = ()> + Send + 'static) {
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(rt) => rt.spawn(f),
            Err(_) => match tauri::async_runtime::spawn(f) {
                tauri::async_runtime::JoinHandle::Tokio(h) => h,
            },
        };
        let mut bg = lock(&self.background);
        bg.retain(|h| !h.is_finished());
        bg.push(handle);
    }

    /// Wait for every background job (revokes, OIDC completions).
    pub async fn flush(&self) {
        loop {
            let jobs: Vec<JoinHandle<()>> = lock(&self.background).drain(..).collect();
            if jobs.is_empty() {
                return;
            }
            for j in jobs {
                let _ = j.await;
            }
        }
    }

    /// Vault lock: close every OIDC window, bump the lock epoch and empty the cache **before
    /// returning** (L-34: a login that completes later is refused by `TokenCache::put`), then
    /// revoke ours in the background. Nothing that needs the vault is touched, so this may run
    /// after the key is gone. The drain comes first (6b L-34 b): once the epoch is bumped no
    /// `begin` can pass its post-open re-check and leave an `IdP` window over the lock screen.
    pub fn on_lock(&self) {
        // ADR-0026 §2: leases are taken first and revoked with the tokens they hold, before
        // the tokens themselves are revoked.
        let leases = self.engine.leases().drain_for_lock("locked");
        let drained = self.engine.cache().drain_for_lock();
        self.oidc.fail_all(self, "locked");
        if drained.is_empty() && leases.is_empty() {
            return;
        }
        let n = drained.len();
        self.spawn(async move {
            leases.retire().await;
            drained.retire().await;
            tracing::info!(tokens = n, "secret source tokens dropped on lock");
        });
    }

    /// App exit: like [`Self::on_lock`], but waits (bounded) for the revocations.
    pub fn shutdown(&self) {
        self.oidc.fail_all(self, "exit");
        if let Some(h) = lock(&self.renewer).take() {
            h.abort();
        }
        if let Some(h) = lock(&self.leases).take() {
            h.abort();
        }
        if self.engine.cache().is_empty() && self.engine.leases().is_empty() {
            return;
        }
        let engine = Arc::clone(&self.engine);
        let leases = engine.leases().drain_for_lock("exit");
        let revoke = async move {
            let deadline = REVOKE_TIMEOUT + Duration::from_secs(1);
            let _ = tokio::time::timeout(deadline * 2, leases.retire()).await;
            let _ = tokio::time::timeout(deadline, engine.cache().revoke_all()).await;
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            self.spawn(revoke);
        } else {
            tauri::async_runtime::block_on(revoke);
        }
    }
}

#[cfg(test)]
#[path = "secrets_runtime_tests.rs"]
mod tests;
