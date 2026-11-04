//! vCenter session (ADR-0015 §1): `POST /api/session` with Basic `upn:password` →
//! `vmware-api-session-id` (memory only, zeroized), `DELETE /api/session` on logout, and one
//! re-login on 401 with a credential fetched from a caller closure (the vault), never stored.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use mooring_http::{
    decode_json, retry_after, CertProtocol, Headers, HttpClient, HttpConfig, Method, RawResponse,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::de::DeserializeOwned;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{status_error, VsphereError};

/// Body cap of every vCenter call (ADR-0015 §1).
pub const MAX_BODY: usize = 8 * 1024 * 1024;
/// Longest session token accepted.
pub const MAX_TOKEN: usize = 256;
/// Longest UPN accepted.
pub const MAX_UPN: usize = 256;
/// Ceiling for a `Retry-After` reported in [`VsphereError::RateLimited`].
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);

/// The `vsphere_user` credential (ADR-0009), handed over for one login. `Debug` is redacted.
pub struct Credential {
    /// `user@domain`.
    pub upn: String,
    /// Password.
    pub password: SecretString,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential").finish_non_exhaustive()
    }
}

/// Supplies the credential for a re-login after a 401; `None` (vault locked) ends the session
/// with [`VsphereError::Auth`]. Called at most once per expired token.
pub type CredentialSource = Arc<dyn Fn() -> Option<Credential> + Send + Sync>;

/// Entry point: `VsphereClient::login(..)`.
#[derive(Debug, Clone, Copy)]
pub struct VsphereClient;

/// A logged-in vCenter session. `Debug` shows the host only.
pub struct Session {
    pub(crate) http: HttpClient,
    pub(crate) base: Url,
    token: Mutex<Zeroizing<String>>,
    generation: AtomicU64,
    relogin: tokio::sync::Mutex<()>,
    reauth: Option<CredentialSource>,
    pub(crate) power_in_flight: Mutex<std::collections::HashSet<crate::ids::MoId>>,
    ticket_hosts: Mutex<Vec<String>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("host", &self.base.host_str())
            .field("generation", &self.generation.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

fn check_upn(upn: &str) -> Result<(), VsphereError> {
    let bad = VsphereError::Invalid("upn must be user@domain, ≤ 256 visible characters, no ':'");
    let Some((user, domain)) = upn.split_once('@') else { return Err(bad) };
    if upn.len() > MAX_UPN
        || user.is_empty()
        || domain.is_empty()
        || upn.contains(':')
        || upn.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(bad);
    }
    Ok(())
}

/// Validate the vCenter base URL: `https://host[:port][/]`, no user info, query or fragment.
pub(crate) fn check_base(base: &Url) -> Result<(), VsphereError> {
    if !matches!(base.scheme(), "https" | "http")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || !matches!(base.path(), "" | "/")
    {
        return Err(VsphereError::Invalid("vCenter URL must be https://host[:port]/"));
    }
    Ok(())
}

/// Parse the body of `POST /api/session`: a JSON string of 1..=256 visible ASCII characters.
pub fn parse_session_token(body: &[u8]) -> Result<Zeroizing<String>, VsphereError> {
    if body.len() > 4 * 1024 {
        return Err(VsphereError::BadResponse("session token"));
    }
    let token: Zeroizing<String> = Zeroizing::new(
        decode_json::<String>(body).map_err(|_| VsphereError::BadResponse("session token"))?,
    );
    if token.is_empty() || token.len() > MAX_TOKEN || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(VsphereError::BadResponse("session token"));
    }
    Ok(token)
}

async fn create_session(
    http: &HttpClient,
    upn: &str,
    password: &SecretString,
) -> Result<Zeroizing<String>, VsphereError> {
    check_upn(upn)?;
    let mut pair = Zeroizing::new(String::with_capacity(upn.len() + 64));
    pair.push_str(upn);
    pair.push(':');
    pair.push_str(password.expose_secret());
    let mut basic = Zeroizing::new(String::from("Basic "));
    base64::engine::general_purpose::STANDARD.encode_string(pair.as_bytes(), &mut basic);
    let h = Headers::new().insert("authorization", &basic)?.insert("accept", "application/json")?;
    let r = http.request(Method::POST, "/api/session", &h, None, 4 * 1024).await?;
    match r.status.as_u16() {
        200 | 201 => parse_session_token(&r.body),
        401 | 403 => Err(VsphereError::Auth),
        s => Err(status_error(s, &r.body, None)),
    }
}

impl VsphereClient {
    /// Log in. `http.protocol` must be [`CertProtocol::Vsphere`]; its `base_url` is replaced
    /// by `base`, and its body cap is lowered to [`MAX_BODY`]. Trust prompts surface as
    /// [`VsphereError::Http`] (`http.trust_prompt`), exactly as from mooring-http.
    pub async fn login(
        base: Url,
        upn: &str,
        password: &SecretString,
        mut http: HttpConfig,
    ) -> Result<Session, VsphereError> {
        check_base(&base)?;
        check_upn(upn)?;
        if http.protocol != CertProtocol::Vsphere {
            return Err(VsphereError::Invalid("HttpConfig.protocol must be Vsphere"));
        }
        http.base_url = base.origin().ascii_serialization();
        http.max_body = http.max_body.min(MAX_BODY);
        let client = HttpClient::new(http)?;
        let token = create_session(&client, upn, password).await?;
        Ok(Session {
            http: client,
            base,
            token: Mutex::new(token),
            generation: AtomicU64::new(0),
            relogin: tokio::sync::Mutex::new(()),
            reauth: None,
            power_in_flight: Mutex::new(std::collections::HashSet::new()),
            ticket_hosts: Mutex::new(Vec::new()),
        })
    }
}

impl Session {
    /// Allow one re-login per expired token with the credential `source` returns.
    #[must_use]
    pub fn with_reauth(mut self, source: CredentialSource) -> Self {
        self.reauth = Some(source);
        self
    }

    /// Extra host names a VMRC ticket may name: the DNS names of the vCenter certificate the
    /// caller trusted for this session (at most 16, each a DNS name of at most 253 bytes).
    pub fn allow_ticket_hosts(&self, hosts: impl IntoIterator<Item = String>) {
        let ok = |h: &String| {
            !h.is_empty()
                && h.len() <= 253
                && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
                && !h.starts_with('*')
        };
        let list: Vec<String> = hosts.into_iter().filter(ok).take(16).collect();
        *self.ticket_hosts.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = list;
    }

    pub(crate) fn ticket_hosts(&self) -> Vec<String> {
        self.ticket_hosts.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    /// The vCenter base URL.
    pub fn base(&self) -> &Url {
        &self.base
    }

    /// How many times the session was re-established (0 after login).
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    fn current(&self) -> (u64, Zeroizing<String>) {
        let guard = self.token.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        (self.generation.load(Ordering::SeqCst), Zeroizing::new(guard.as_str().to_owned()))
    }

    async fn relogin(&self, seen: u64) -> Result<(), VsphereError> {
        let _one = self.relogin.lock().await;
        if self.generation.load(Ordering::SeqCst) != seen {
            return Ok(()); // another call already re-logged in
        }
        let source = self.reauth.as_ref().ok_or(VsphereError::Auth)?;
        let cred = source().ok_or(VsphereError::Auth)?;
        let token = create_session(&self.http, &cred.upn, &cred.password).await?;
        drop(cred);
        *self.token.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = token;
        self.generation.fetch_add(1, Ordering::SeqCst);
        tracing::debug!("vsphere session re-established");
        Ok(())
    }

    async fn send(
        &self,
        method: &Method,
        path: &str,
        body: Option<&Bytes>,
        token: &str,
    ) -> Result<RawResponse, VsphereError> {
        let mut h = Headers::new()
            .insert("vmware-api-session-id", token)?
            .insert("accept", "application/json")?;
        if body.is_some() {
            h = h.insert("content-type", "application/json")?;
        }
        let cap = self.http.max_body();
        Ok(self.http.request(method.clone(), path, &h, body.cloned(), cap).await?)
    }

    /// One call with the session header and one re-login on 401; the response is returned
    /// for any other status. GETs are retried by mooring-http's policy (429/502–504/connect);
    /// POSTs never are (a 401 means the action did not run, so resending it is safe).
    pub(crate) async fn call_any(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<RawResponse, VsphereError> {
        let (seen, token) = self.current();
        let r = self.send(&method, path, body.as_ref(), &token).await?;
        if r.status.as_u16() != 401 {
            return Ok(r);
        }
        self.relogin(seen).await?;
        let (_, token) = self.current();
        let r = self.send(&method, path, body.as_ref(), &token).await?;
        if r.status.as_u16() == 401 {
            return Err(VsphereError::Auth);
        }
        Ok(r)
    }

    /// [`Session::call_any`] with non-2xx mapped to [`VsphereError`].
    pub(crate) async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<RawResponse, VsphereError> {
        let r = self.call_any(method, path, body).await?;
        if r.status.is_success() {
            return Ok(r);
        }
        let wait = retry_after(&r.headers, MAX_RETRY_AFTER);
        Err(status_error(r.status.as_u16(), &r.body, wait))
    }

    /// `GET` → typed JSON.
    pub(crate) async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, VsphereError> {
        let r = self.call(Method::GET, path, None).await?;
        Ok(decode_json(&r.body)?)
    }

    /// Close the session (`DELETE /api/session`). An already expired token is not an error.
    pub async fn logout(self) -> Result<(), VsphereError> {
        self.logout_shared().await
    }

    /// [`Session::logout`] through a shared handle (V2 keeps sessions in an `Arc` and logs
    /// them out on vault lock); drop the handle afterwards.
    pub async fn logout_shared(&self) -> Result<(), VsphereError> {
        let (_, token) = self.current();
        let r = self.send(&Method::DELETE, "/api/session", None, &token).await?;
        match r.status.as_u16() {
            200..=299 | 401 => Ok(()),
            s => Err(status_error(s, &r.body, None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upn_and_base_rules() {
        assert!(check_upn("administrator@vsphere.local").is_ok());
        for bad in ["admin", "@x", "a@", "a:b@x", "a b@x", "a@x\n"] {
            assert!(check_upn(bad).is_err(), "{bad:?}");
        }
        let ok = Url::parse("https://vc.example.test/").expect("url");
        assert!(check_base(&ok).is_ok());
        for bad in [
            "https://u:p@vc.example.test/",
            "https://vc.example.test/ui",
            "https://vc.example.test/?a=b",
            "ftp://vc.example.test/",
        ] {
            assert!(check_base(&Url::parse(bad).expect("url")).is_err(), "{bad}");
        }
    }

    #[test]
    fn session_tokens() {
        assert_eq!(parse_session_token(br#""b00a1f2e""#).expect("tok").as_str(), "b00a1f2e");
        for bad in [&b"\"\""[..], b"\"a b\"", b"42", b"{\"value\":\"x\"}", b"\"\\u0000\""] {
            assert!(parse_session_token(bad).is_err());
        }
        let long = format!("\"{}\"", "a".repeat(MAX_TOKEN + 1));
        assert!(parse_session_token(long.as_bytes()).is_err());
    }

    #[test]
    fn credential_debug_is_redacted() {
        let c = Credential { upn: "u@x".into(), password: SecretString::from("SECRET".to_owned()) };
        assert!(!format!("{c:?}").contains("SECRET") && !format!("{c:?}").contains("u@x"));
    }
}
