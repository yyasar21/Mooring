//! Authentication and trust wiring (ADR-0014 §3): `Resolved` (K2) → `HttpConfig` (K1).
//!
//! * CA data present → anchored mode (`ca_exclusive`): the chain must validate against it; no
//!   system roots, no pins, no TOFU.
//! * No CA data, or `insecure-skip-tls-verify: true` → system roots, then the ADR-0011 TOFU
//!   prompt (`HttpError::TrustPrompt`); never a silent skip.
//! * Bearer tokens go into a sensitive `Authorization` header added by [`BearerLayer`] under
//!   the guard; client certificates become the mTLS identity.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{HeaderValue, Request};
use mooring_core::credential::kubeconfig::{CaSource, KubeAuth, Resolved};
use mooring_core::known_certs::CertProtocol;
use mooring_http::{ClientIdentity, HttpConfig};
use secrecy::{ExposeSecret as _, SecretString};
use tower::{BoxError, Layer, Service};
use zeroize::Zeroizing;

use crate::error::KubeError;

/// Turn the resolved context into the HTTP client configuration. `template` carries what the
/// caller owns: `known_certs_path`, `trusted_once`, `trust_events`, timeouts.
pub fn http_config(resolved: &Resolved, template: HttpConfig) -> Result<HttpConfig, KubeError> {
    let mut cfg = template;
    cfg.protocol = CertProtocol::Kube;
    resolved.server.as_str().clone_into(&mut cfg.base_url);
    cfg.tls_server_name.clone_from(&resolved.tls_server_name);
    cfg.allow_plaintext = false;
    if let (CaSource::Pem(pem), false) = (&resolved.ca, resolved.insecure_skip) {
        let pem = String::from_utf8(pem.clone())
            .map_err(|_| KubeError::Invalid("certificate-authority-data is not text"))?;
        cfg.extra_ca_pem = Some(pem);
        cfg.ca_exclusive = true;
    } else {
        // insecure-skip-tls-verify is "no CA data" → TOFU (K2 refuses CA + skip together).
        cfg.extra_ca_pem = None;
        cfg.ca_exclusive = false;
        cfg.use_system_roots = true;
    }
    cfg.client_identity = match &resolved.auth {
        KubeAuth::Token(_) => None,
        KubeAuth::ClientCert { cert_pem, key_pem } => Some(identity(cert_pem, key_pem)?),
    };
    Ok(cfg)
}

/// The bearer token of `auth`, if any.
pub(crate) fn bearer(auth: &KubeAuth) -> Option<SecretString> {
    match auth {
        KubeAuth::Token(t) => Some(t.clone()),
        KubeAuth::ClientCert { .. } => None,
    }
}

/// Split PEM text into its `-----BEGIN …-----` … `-----END …-----` blocks.
fn pem_blocks(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let tail = &rest[start..];
        let Some(end_tag) = tail.find("-----END ") else { break };
        let after = &tail[end_tag + 9..];
        let Some(close) = after.find("-----") else { break };
        let len = end_tag + 9 + close + 5;
        out.push(&tail[..len]);
        rest = &tail[len..];
        if out.len() > 16 {
            break;
        }
    }
    out
}

fn identity(cert_pem: &str, key_pem: &SecretString) -> Result<ClientIdentity, KubeError> {
    let bad = KubeError::UnsupportedAuth;
    let mut chain = Vec::new();
    for block in pem_blocks(cert_pem) {
        let (label, der) = pem_rfc7468::decode_vec(block.as_bytes())
            .map_err(|_| bad("client certificate PEM is malformed"))?;
        if label != "CERTIFICATE" {
            return Err(bad("client-certificate-data holds a non-certificate block"));
        }
        chain.push(der);
    }
    if chain.is_empty() || chain.len() > 16 {
        return Err(bad("client-certificate-data holds no usable certificate"));
    }
    let key = key_pem.expose_secret();
    let blocks = pem_blocks(key);
    let [block] = blocks.as_slice() else {
        return Err(bad("client-key-data must hold exactly one key"));
    };
    let (label, der) = pem_rfc7468::decode_vec(block.as_bytes())
        .map_err(|_| bad("client key PEM is malformed"))?;
    let der = Zeroizing::new(der);
    if !matches!(label, "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY") {
        return Err(bad("client-key-data is not an unencrypted private key"));
    }
    Ok(ClientIdentity { cert_chain_der: chain, key_der: der })
}

/// Adds `Authorization: Bearer …` (marked sensitive) to every request.
#[derive(Clone)]
pub(crate) struct BearerLayer(pub(crate) Option<Arc<SecretString>>);

impl std::fmt::Debug for BearerLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerLayer(<redacted>)")
    }
}

impl<S> Layer<S> for BearerLayer {
    type Service = Bearer<S>;

    fn layer(&self, inner: S) -> Bearer<S> {
        Bearer { inner, token: self.0.clone() }
    }
}

#[derive(Clone)]
pub(crate) struct Bearer<S> {
    inner: S,
    token: Option<Arc<SecretString>>,
}

impl<S> std::fmt::Debug for Bearer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Bearer(<redacted>)")
    }
}

impl<S, B> Service<Request<B>> for Bearer<S>
where
    S: Service<Request<B>>,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if let Some(t) = &self.token {
            let secret = t.expose_secret();
            let mut value = Zeroizing::new(String::with_capacity(7 + secret.len()));
            value.push_str("Bearer ");
            value.push_str(secret);
            let Ok(mut v) = HeaderValue::from_str(&value) else {
                let e: BoxError = Box::new(KubeError::UnsupportedAuth("token is not ASCII"));
                return Box::pin(std::future::ready(Err(e)));
            };
            v.set_sensitive(true);
            req.headers_mut().insert(http::header::AUTHORIZATION, v);
        }
        let fut = self.inner.call(req);
        Box::pin(async move { fut.await.map_err(Into::into) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_blocks_split_and_cap() {
        let one = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_blocks(&one.repeat(3)).len(), 3);
        assert_eq!(pem_blocks(&one.repeat(40)).len(), 17);
        assert!(pem_blocks("junk").is_empty());
        assert!(pem_blocks("-----BEGIN X-----\nno end").is_empty());
    }

    fn resolved(ca: CaSource, insecure_skip: bool) -> Resolved {
        Resolved {
            context_name: "ctx".into(),
            server: mooring_core::credential::kubeconfig::KubeServer::parse(
                "https://api.example.test:6443",
            )
            .expect("server"),
            ca,
            tls_server_name: Some("kubernetes.default".into()),
            auth: KubeAuth::Token(SecretString::from("t")),
            namespace: None,
            insecure_skip,
        }
    }

    #[test]
    fn ca_and_tofu_decision_table() {
        let tpl = || {
            let mut t = HttpConfig::new(CertProtocol::Vault, "https://x.example.test", "k".into());
            t.allow_plaintext = true;
            t.extra_ca_pem = Some("stale".into());
            t
        };
        let pem = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec();
        let anchored = http_config(&resolved(CaSource::Pem(pem), false), tpl()).expect("cfg");
        assert!(anchored.ca_exclusive && anchored.extra_ca_pem.is_some());
        assert_eq!(anchored.protocol, CertProtocol::Kube);
        assert_eq!(anchored.base_url, "https://api.example.test:6443");
        assert_eq!(anchored.tls_server_name.as_deref(), Some("kubernetes.default"));
        assert!(!anchored.allow_plaintext && anchored.client_identity.is_none());
        for (ca, skip) in [(CaSource::None, false), (CaSource::None, true)] {
            let tofu = http_config(&resolved(ca, skip), tpl()).expect("cfg");
            assert!(!tofu.ca_exclusive && tofu.extra_ca_pem.is_none() && tofu.use_system_roots);
        }
        assert!(bearer(&resolved(CaSource::None, false).auth).is_some());
    }

    #[test]
    fn identity_rejects_wrong_labels() {
        let cert = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
        let key = SecretString::from("x");
        assert!(matches!(identity(cert, &key), Err(KubeError::UnsupportedAuth(_))));
        assert!(matches!(identity("", &key), Err(KubeError::UnsupportedAuth(_))));
    }
}
