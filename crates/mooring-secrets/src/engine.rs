//! [`SecretsEngine`]: source → token (cache or login) → KV v2 read → target credential, with
//! audit events and no fallback. Login material is opened from the Mooring vault by the
//! caller only when a login is actually needed ([`LoginProvider`]).

use std::sync::Arc;

use mooring_core::credential::{parse_vault_reference, ExternalRefFields, RefProvider};
use mooring_core::secret_source::{SecretSource, SecretSourceAuth, OIDC_REDIRECT_URI};
use mooring_core::{CredentialId, SecretSourceId};
use zeroize::Zeroizing;

use crate::audit::{SecretEvent, SecretsAudit};
use crate::cache::TokenCache;
use crate::client::{ClientConfig, VaultClient, VaultToken};
use crate::error::{Category, SecretsError};
use crate::oidc::{new_nonce, parse_auth_url, Navigation, OidcFlow};
use crate::resolve::{build, presence, ResolvedSecrets};

/// Login material opened from the Mooring vault for one login.
pub enum LoginMaterial {
    /// `token` method: the `api_token` credential's `token` secret.
    Token(Zeroizing<String>),
    /// `approle` method: the `vault_approle` credential's secrets.
    AppRole {
        /// `role_id`.
        role_id: Zeroizing<String>,
        /// `secret_id`.
        secret_id: Zeroizing<String>,
    },
}

impl std::fmt::Debug for LoginMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Token(_) => "LoginMaterial::Token(<redacted>)",
            Self::AppRole { .. } => "LoginMaterial::AppRole(<redacted>)",
        })
    }
}

/// Opens the login credential of a source. Return `Unavailable { Locked }` when the vault is
/// locked. Called only when no cached token exists.
pub trait LoginProvider: Send + Sync {
    /// Material for `source`.
    fn login_material(&self, source: &SecretSource) -> Result<LoginMaterial, SecretsError>;
}

impl<F> LoginProvider for F
where
    F: Fn(&SecretSource) -> Result<LoginMaterial, SecretsError> + Send + Sync,
{
    fn login_material(&self, source: &SecretSource) -> Result<LoginMaterial, SecretsError> {
        self(source)
    }
}

/// `secret_source_test` result (ADR-0016 §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTest {
    /// Method name.
    pub method: &'static str,
    /// Cached lifetime.
    pub ttl_seconds: Option<u64>,
    /// Renewable.
    pub renewable: bool,
    /// Number of policies.
    pub policies_count: usize,
}

/// `external_ref_test` result: names only, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefTest {
    /// Version read.
    pub version: u64,
    /// Names of the target kind present in KV.
    pub present: Vec<String>,
    /// Required names missing.
    pub missing: Vec<String>,
    /// KV keys the kind does not use.
    pub extra: Vec<String>,
}

/// The resolver. Share it as `Arc<SecretsEngine>`.
pub struct SecretsEngine {
    cache: Arc<TokenCache>,
    audit: Arc<dyn SecretsAudit>,
    cfg: ClientConfig,
}

impl std::fmt::Debug for SecretsEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretsEngine").field("cache", &self.cache).finish_non_exhaustive()
    }
}

/// The vault locked while a login or an OIDC flow was in flight (L-34).
fn locked_during_login() -> SecretsError {
    SecretsError::unavailable(Category::Locked, "the Mooring vault locked during the sign-in")
}

impl SecretsEngine {
    /// An engine over `cache` (which owns the clock).
    pub fn new(cache: Arc<TokenCache>, audit: Arc<dyn SecretsAudit>, cfg: ClientConfig) -> Self {
        Self { cache, audit, cfg }
    }

    /// The token cache (lock / exit: `cache().revoke_all()`).
    pub fn cache(&self) -> &Arc<TokenCache> {
        &self.cache
    }

    fn failed<T>(&self, source: SecretSourceId, e: SecretsError) -> Result<T, SecretsError> {
        self.audit.record(SecretEvent::Failed { source, category: e.category() });
        Err(e)
    }

    async fn login(
        &self,
        source: &SecretSource,
        provider: &dyn LoginProvider,
    ) -> Result<(VaultClient, Zeroizing<String>), SecretsError> {
        if matches!(source.auth, SecretSourceAuth::Oidc { .. }) {
            return Err(SecretsError::unavailable(Category::AuthFailed, "OIDC sign-in required"));
        }
        let epoch = self.cache.epoch();
        let client = VaultClient::new(source, &self.cfg)?;
        let material = provider.login_material(source)?;
        let (token, ours): (VaultToken, bool) = match (&source.auth, material) {
            (SecretSourceAuth::Token { .. }, LoginMaterial::Token(t)) => {
                (client.lookup_self(&t).await?, false)
            }
            (
                SecretSourceAuth::AppRole { mount, .. },
                LoginMaterial::AppRole { role_id, secret_id },
            ) => (client.login_approle(mount, &role_id, &secret_id).await?, true),
            _ => return Err(SecretsError::Invalid("login material does not match the method")),
        };
        self.remember(source, client, token, ours, epoch).await
    }

    /// Cache `token` unless the vault locked since `epoch` (L-34): then it is revoked (when
    /// ours), wiped and the login fails `locked`.
    async fn remember(
        &self,
        source: &SecretSource,
        client: VaultClient,
        token: VaultToken,
        ours: bool,
        epoch: u64,
    ) -> Result<(VaultClient, Zeroizing<String>), SecretsError> {
        let secret = token.token.clone();
        if let Err(rejected) = self.cache.put(source.id, client.clone(), token, ours, epoch) {
            drop(secret);
            rejected.retire().await;
            return self.failed(source.id, locked_during_login());
        }
        let ttl = self.cache.remaining(source.id).map_or(0, |d| d.as_secs());
        self.audit.record(SecretEvent::Login {
            source: source.id,
            method: source.auth.method(),
            ttl,
        });
        Ok((client, secret))
    }

    /// A token for `source`: cached, or a fresh login. `bool` = it came from the cache.
    async fn token(
        &self,
        source: &SecretSource,
        provider: &dyn LoginProvider,
    ) -> Result<(VaultClient, Zeroizing<String>, bool), SecretsError> {
        if let Some((c, t)) = self.cache.get(source.id) {
            return Ok((c, t, true));
        }
        let (c, t) = self.login(source, provider).await?;
        Ok((c, t, false))
    }

    async fn read(
        &self,
        source: &SecretSource,
        fields: &ExternalRefFields,
        provider: &dyn LoginProvider,
    ) -> Result<crate::client::KvSecret, SecretsError> {
        if fields.provider != RefProvider::Vault {
            return Err(SecretsError::Invalid("provider"));
        }
        if fields.source != Some(source.id) {
            return Err(SecretsError::Invalid("source"));
        }
        let at = parse_vault_reference(&fields.reference)
            .map_err(|_| SecretsError::Invalid("reference"))?;
        let (client, token, cached) = self.token(source, provider).await?;
        match client.read_kv2(&token, &at, fields.version).await {
            // A cached token revoked server-side: forget it and log in once more.
            Err(e) if cached && e.token_refused() => {
                drop(token);
                self.cache.forget(source.id).await;
                let (client, token, _) = self.token(source, provider).await?;
                client.read_kv2(&token, &at, fields.version).await
            }
            other => other,
        }
    }

    /// Resolve an `external_ref` credential for one connect. Nothing is cached; the result
    /// must be dropped after the handshake. Any failure closes (no fallback).
    pub async fn resolve(
        &self,
        source: &SecretSource,
        credential: CredentialId,
        fields: &ExternalRefFields,
        provider: &dyn LoginProvider,
    ) -> Result<ResolvedSecrets, SecretsError> {
        let result = async {
            let kv = self.read(source, fields, provider).await?;
            build(fields.target_kind, fields.field_map.as_ref(), &kv.data, kv.metadata.version)
        }
        .await;
        match result {
            Ok(r) => {
                self.audit.record(SecretEvent::Resolved {
                    credential,
                    source: source.id,
                    reference: fields.reference.clone(),
                    version: r.version,
                    target_kind: r.kind,
                    fields: r.names(),
                });
                Ok(r)
            }
            Err(e) => self.failed(source.id, e),
        }
    }

    /// `external_ref_test`: which names KV provides (no values leave this function).
    pub async fn test_ref(
        &self,
        source: &SecretSource,
        fields: &ExternalRefFields,
        provider: &dyn LoginProvider,
    ) -> Result<RefTest, SecretsError> {
        match self.read(source, fields, provider).await {
            Ok(kv) => {
                let (present, missing, extra) =
                    presence(fields.target_kind, fields.field_map.as_ref(), &kv.data);
                Ok(RefTest { version: kv.metadata.version, present, missing, extra })
            }
            Err(e) => self.failed(source.id, e),
        }
    }

    /// `secret_source_test`: log in afresh (the cached token is replaced).
    pub async fn test_source(
        &self,
        source: &SecretSource,
        provider: &dyn LoginProvider,
    ) -> Result<SourceTest, SecretsError> {
        let probe = async {
            let (client, token) = if matches!(source.auth, SecretSourceAuth::Oidc { .. }) {
                self.cache.get(source.id).ok_or(SecretsError::unavailable(
                    Category::AuthFailed,
                    "OIDC sign-in required",
                ))?
            } else {
                self.cache.forget(source.id).await;
                self.login(source, provider).await?
            };
            client.lookup_self(&token).await
        };
        match probe.await {
            Ok(t) => Ok(SourceTest {
                method: source.auth.method().name(),
                ttl_seconds: self.cache.remaining(source.id).map(|d| d.as_secs()),
                renewable: t.renewable,
                policies_count: t.policies,
            }),
            Err(e) => self.failed(source.id, e),
        }
    }

    /// `secret_source_logout`: revoke (when ours) and forget the cached token.
    pub async fn logout(&self, source: SecretSourceId) -> bool {
        self.cache.forget(source).await
    }

    /// Start an OIDC flow: the `auth_url` for the window, bound to a fresh nonce and the
    /// `state` Vault put into it.
    pub async fn begin_oidc(&self, source: &SecretSource) -> Result<OidcFlow, SecretsError> {
        let SecretSourceAuth::Oidc { mount, role } = &source.auth else {
            return Err(SecretsError::Invalid("source is not an OIDC source"));
        };
        let client = VaultClient::new(source, &self.cfg)?;
        let nonce = new_nonce();
        let url = match client.oidc_auth_url(mount, role, OIDC_REDIRECT_URI, &nonce).await {
            Ok(u) => u,
            Err(e) => return self.failed(source.id, e),
        };
        let (idp, state) = parse_auth_url(&url)?;
        let mut allowed_origins = vec![idp];
        for o in &source.options.allowed_origins {
            if !allowed_origins.contains(o) {
                allowed_origins.push(o.clone());
            }
        }
        Ok(OidcFlow {
            source: source.id,
            mount: mount.clone(),
            auth_url: url,
            allowed_origins,
            state,
            nonce,
            started: self.cache.clock().now(),
            epoch: self.cache.epoch(),
        })
    }

    /// Finish an OIDC flow with the intercepted redirect URL: `state` must match, the flow
    /// must be younger than 5 min; the token is cached (and revoked on lock).
    pub async fn complete_oidc(
        &self,
        source: &SecretSource,
        flow: OidcFlow,
        redirect_url: &str,
    ) -> Result<(), SecretsError> {
        let refused = |d| SecretsError::unavailable(Category::AuthFailed, d);
        if flow.source != source.id {
            return Err(SecretsError::Invalid("flow belongs to another source"));
        }
        if flow.expired(self.cache.clock().now()) {
            return self.failed(source.id, refused("OIDC sign-in timed out"));
        }
        if flow.epoch != self.cache.epoch() {
            return self.failed(source.id, locked_during_login());
        }
        let Navigation::Callback { code } = flow.navigation(redirect_url) else {
            return self
                .failed(source.id, refused("OIDC redirect refused (state mismatch or error)"));
        };
        let client = VaultClient::new(source, &self.cfg)?;
        match client.oidc_callback(&flow.mount, &code, flow.state(), &flow.nonce).await {
            Ok(t) => self.remember(source, client, t, true, flow.epoch).await.map(drop),
            Err(e) => self.failed(source.id, e),
        }
    }
}
