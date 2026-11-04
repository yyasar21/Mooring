//! [`VaultClient`]: the seven Vault / `OpenBao` endpoints of ADR-0016 §6 over `mooring-http`
//! (`CertProtocol::Vault`, our verifier, `known_vault_certs`, body cap 1 MiB). The token
//! travels in `X-Vault-Token` (marked sensitive, printed `<redacted>`), the namespace in
//! `X-Vault-Namespace`. Paths are built from validated segments and percent-encoded.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use mooring_core::credential::VaultPath;
use mooring_core::secret_source::SecretSource;
use mooring_http::{
    decode_json, CertProtocol, Headers, HttpClient, HttpConfig, Method, RawResponse, RetryPolicy,
    Timeouts, TrustDecision,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::error::{from_status, Category, Ctx, SecretsError};
use crate::wire::{
    AuthResponse, AuthUrlData, DataResponse, KvData, KvMetadata, LookupData, SecretMap,
};

/// Body cap of every Vault response (ADR-0016 §3).
pub const MAX_RESPONSE: usize = 1024 * 1024;
/// Cache lifetime of a token that reports no TTL (re-checked by `lookup-self` afterwards).
pub const NO_TTL_RECHECK: Duration = Duration::from_secs(15 * 60);

/// Per-process client settings (the source supplies address, namespace and CA).
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// `$APP_DATA/known_vault_certs` (read only here; the Gate writes pins).
    pub known_certs_path: PathBuf,
    /// A leaf the user accepted once (trust prompt).
    pub trusted_once: Option<[u8; 32]>,
    /// Deadlines.
    pub timeouts: Timeouts,
    /// Retries of GETs after connect failures / 429 / 502–504 (`1` disables).
    pub retry: RetryPolicy,
    /// Handshake decisions for the audit feed.
    pub trust_events: Option<mpsc::Sender<TrustDecision>>,
}

impl ClientConfig {
    /// Defaults for `known_certs_path`.
    #[must_use]
    pub fn new(known_certs_path: PathBuf) -> Self {
        Self {
            known_certs_path,
            trusted_once: None,
            timeouts: Timeouts::default(),
            retry: RetryPolicy::default(),
            trust_events: None,
        }
    }
}

/// A token from a login or `lookup-self`.
pub struct VaultToken {
    /// The token.
    pub token: Zeroizing<String>,
    /// Remaining lifetime as reported (0 = none reported).
    pub ttl: Duration,
    /// `renew-self` is allowed.
    pub renewable: bool,
    /// Number of policies (names are not kept).
    pub policies: usize,
}

impl std::fmt::Debug for VaultToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultToken")
            .field("ttl", &self.ttl)
            .field("renewable", &self.renewable)
            .finish_non_exhaustive()
    }
}

/// One KV v2 read.
#[derive(Debug)]
pub struct KvSecret {
    /// The key/value pairs (zeroized on drop).
    pub data: SecretMap,
    /// Version metadata.
    pub metadata: KvMetadata,
}

/// Percent-encode one path or query component (RFC 3986 unreserved set kept).
#[must_use]
pub fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn mount_path(mount: &str) -> String {
    mount.split('/').map(pct_encode).collect::<Vec<_>>().join("/")
}

/// Client bound to one source. Cheap to clone.
#[derive(Clone)]
pub struct VaultClient {
    http: HttpClient,
    namespace: Option<String>,
}

impl std::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultClient").field("http", &self.http).finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct AppRoleBody<'a> {
    role_id: &'a str,
    secret_id: &'a str,
}

#[derive(Serialize)]
struct AuthUrlBody<'a> {
    role: &'a str,
    redirect_uri: &'a str,
    client_nonce: &'a str,
}

impl VaultClient {
    /// Build the client for `source` (no I/O).
    pub fn new(source: &SecretSource, cfg: &ClientConfig) -> Result<Self, SecretsError> {
        let mut h =
            HttpConfig::new(CertProtocol::Vault, &source.address, cfg.known_certs_path.clone());
        h.extra_ca_pem.clone_from(&source.options.ca_pem);
        h.allow_plaintext = source.options.allow_http;
        h.trusted_once = cfg.trusted_once;
        h.timeouts = cfg.timeouts;
        h.retry = cfg.retry;
        h.max_body = MAX_RESPONSE;
        h.trust_events.clone_from(&cfg.trust_events);
        Ok(Self { http: HttpClient::new(h)?, namespace: source.namespace.clone() })
    }

    fn headers(&self, token: Option<&str>) -> Result<Headers, SecretsError> {
        let mut h = Headers::new().insert("Accept", "application/json")?;
        if let Some(ns) = &self.namespace {
            h = h.insert("X-Vault-Namespace", ns)?;
        }
        if let Some(t) = token {
            h = h.insert("X-Vault-Token", t).map_err(|_| SecretsError::Invalid("token"))?;
        }
        Ok(h)
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Zeroizing<Vec<u8>>>,
        ctx: Ctx,
    ) -> Result<RawResponse, SecretsError> {
        let mut headers = self.headers(token)?;
        if body.is_some() {
            headers = headers.insert("Content-Type", "application/json")?;
        }
        // R-EXT-STR: `Bytes` is not zeroized; the request body lives until hyper drops it.
        let body = body.map(|b| Bytes::copy_from_slice(&b));
        let r = self.http.request(method, path, &headers, body, MAX_RESPONSE).await?;
        if !r.status.is_success() {
            return Err(from_status(r.status, ctx));
        }
        Ok(r)
    }

    fn json<T: DeserializeOwned>(r: &RawResponse) -> Result<T, SecretsError> {
        Ok(decode_json(&r.body)?)
    }

    fn body<B: Serialize>(b: &B) -> Result<Zeroizing<Vec<u8>>, SecretsError> {
        serde_json::to_vec(b).map(Zeroizing::new).map_err(|_| SecretsError::Invalid("body"))
    }

    fn token_from(r: &RawResponse) -> Result<VaultToken, SecretsError> {
        let auth: AuthResponse = Self::json(r)?;
        let a = auth.auth.ok_or_else(|| SecretsError::shape("login response without auth"))?;
        if a.policies.has_root() || a.token_policies.has_root() {
            return Err(SecretsError::RootToken);
        }
        if a.client_token.expose().is_empty() {
            return Err(SecretsError::shape("empty token"));
        }
        Ok(VaultToken {
            policies: a.policies.0.len().max(a.token_policies.0.len()),
            ttl: Duration::from_secs(a.lease_duration),
            renewable: a.renewable,
            token: a.client_token.into_inner(),
        })
    }

    /// `GET /v1/auth/token/lookup-self`: TTL and renewability of a stored token. A token
    /// with the `root` policy is refused.
    pub async fn lookup_self(&self, token: &str) -> Result<VaultToken, SecretsError> {
        let r = self.call(Method::GET, "/v1/auth/token/lookup-self", Some(token), None, Ctx::Login);
        let r = r.await?;
        let d: DataResponse<LookupData> = Self::json(&r)?;
        let d = d.data.ok_or_else(|| SecretsError::shape("lookup without data"))?;
        if d.policies.has_root() || d.identity_policies.has_root() {
            return Err(SecretsError::RootToken);
        }
        Ok(VaultToken {
            token: Zeroizing::new(token.to_owned()),
            ttl: Duration::from_secs(d.ttl),
            renewable: d.renewable,
            policies: d.policies.0.len() + d.identity_policies.0.len(),
        })
    }

    /// `POST /v1/auth/<mount>/login { role_id, secret_id }` (never retried).
    pub async fn login_approle(
        &self,
        mount: &str,
        role_id: &str,
        secret_id: &str,
    ) -> Result<VaultToken, SecretsError> {
        let body = Self::body(&AppRoleBody { role_id, secret_id })?;
        let path = format!("/v1/auth/{}/login", mount_path(mount));
        let r = self.call(Method::POST, &path, None, Some(body), Ctx::Login).await?;
        Self::token_from(&r)
    }

    /// `POST /v1/auth/token/renew-self`: the new lease.
    pub async fn renew_self(&self, token: &str) -> Result<VaultToken, SecretsError> {
        let body = Some(Zeroizing::new(b"{}".to_vec()));
        let r = self.call(Method::POST, "/v1/auth/token/renew-self", Some(token), body, Ctx::Login);
        Self::token_from(&r.await?)
    }

    /// `POST /v1/auth/token/revoke-self`.
    pub async fn revoke_self(&self, token: &str) -> Result<(), SecretsError> {
        let body = Some(Zeroizing::new(b"{}".to_vec()));
        self.call(Method::POST, "/v1/auth/token/revoke-self", Some(token), body, Ctx::Login)
            .await
            .map(drop)
    }

    /// `POST /v1/auth/<mount>/oidc/auth_url`: the `IdP` URL to open.
    pub async fn oidc_auth_url(
        &self,
        mount: &str,
        role: &str,
        redirect_uri: &str,
        client_nonce: &str,
    ) -> Result<String, SecretsError> {
        let body = Self::body(&AuthUrlBody { role, redirect_uri, client_nonce })?;
        let path = format!("/v1/auth/{}/oidc/auth_url", mount_path(mount));
        let r = self.call(Method::POST, &path, None, Some(body), Ctx::Login).await?;
        let d: DataResponse<AuthUrlData> = Self::json(&r)?;
        d.data
            .map(|d| d.auth_url)
            .filter(|u| !u.is_empty())
            .ok_or(SecretsError::unavailable(Category::AuthFailed, "OIDC role refused"))
    }

    /// `GET /v1/auth/<mount>/oidc/callback?code&state&client_nonce`: the token.
    pub async fn oidc_callback(
        &self,
        mount: &str,
        code: &str,
        state: &str,
        client_nonce: &str,
    ) -> Result<VaultToken, SecretsError> {
        let path = format!(
            "/v1/auth/{}/oidc/callback?code={}&state={}&client_nonce={}",
            mount_path(mount),
            pct_encode(code),
            pct_encode(state),
            pct_encode(client_nonce)
        );
        let path = Zeroizing::new(path);
        let r = self.call(Method::GET, &path, None, None, Ctx::Login).await?;
        Self::token_from(&r)
    }

    /// `GET /v1/<mount>/data/<path>[?version=N]`. A deleted or destroyed version, or a
    /// response without data, is `NotFound`; there is no fallback to another version.
    pub async fn read_kv2(
        &self,
        token: &str,
        at: &VaultPath,
        version: Option<u64>,
    ) -> Result<KvSecret, SecretsError> {
        let path: Vec<String> = at.path.iter().map(|s| pct_encode(s)).collect();
        let mut url = format!("/v1/{}/data/{}", mount_path(&at.mount), path.join("/"));
        if let Some(v) = version {
            let _ = write!(url, "?version={v}");
        }
        let r = self.call(Method::GET, &url, Some(token), None, Ctx::Read).await?;
        let d: DataResponse<KvData> = Self::json(&r)?;
        let d = d.data.ok_or(SecretsError::NotFound)?;
        let metadata = d.metadata.unwrap_or_default();
        if !metadata.deletion_time.is_empty() || metadata.destroyed {
            return Err(SecretsError::NotFound);
        }
        let data = d.data.ok_or(SecretsError::NotFound)?;
        if version.is_some_and(|v| metadata.version != 0 && metadata.version != v) {
            return Err(SecretsError::shape("server returned another version"));
        }
        Ok(KvSecret { data, metadata })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding() {
        assert_eq!(pct_encode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(pct_encode("a/b c&d=é"), "a%2Fb%20c%26d%3D%C3%A9");
        assert_eq!(mount_path("team/kv"), "team/kv");
    }

    #[test]
    fn token_header_is_redacted_and_namespace_sent() {
        use mooring_core::secret_source::{SecretSourceAuth, SourceKind, SourceOptions};
        let src = SecretSource {
            id: mooring_core::SecretSourceId::new(),
            name: "v".into(),
            kind: SourceKind::Vault,
            address: "https://vault.example.test".into(),
            namespace: Some("team".into()),
            auth: SecretSourceAuth::Token { credential_id: mooring_core::CredentialId::new() },
            options: SourceOptions::default(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let c = VaultClient::new(&src, &ClientConfig::new(PathBuf::from("known_vault_certs")))
            .expect("c");
        let h = c.headers(Some("hvs.test-only-secret")).expect("headers");
        let dump = format!("{:?}", mooring_http::Redacted(h.as_map()));
        assert!(!dump.contains("hvs.test-only-secret"), "{dump}");
        assert!(dump.contains("team"));
        assert!(c.headers(Some("bad\ntoken")).is_err());
        let mut http_src = src.clone();
        http_src.address = "http://vault.example.test".into();
        http_src.options.allow_http = true;
        assert!(
            VaultClient::new(&http_src, &ClientConfig::new(PathBuf::from("k"))).is_err(),
            "plaintext off loopback"
        );
    }
}
