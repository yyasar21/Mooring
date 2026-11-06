//! A rustls `ClientConfig` carrying **our** verifier for TLS clients that are not HTTP
//! (ADR-0019 §4: the LDAPS directory importer hands it to `ldap3` through `set_config`).
//! Same trust model as every HTTPS client: pin before CA, `known_<protocol>_certs` reloaded
//! per connect and failing closed, `extra_ca_pem`, `trusted_once`, the handshake decision in
//! a slot the caller reads after the handshake and maps to the `http.trust_*` codes with
//! [`TlsClient::trust_error`]. Session resumption is off so the verifier runs every time; no
//! ALPN is offered.

use std::path::PathBuf;
use std::sync::Arc;

use mooring_core::known_certs::CertProtocol;
use rustls::client::Resumption;
use rustls::ClientConfig;

use crate::config::MAX_CA_PEM;
use crate::connect::{build_chain, load_known, trust_error};
use crate::error::HttpError;
use crate::verify::{provider, server_name, take_decision, DecisionSlot, HttpVerifier};
use crate::TrustDecision;

/// One `host:port` to build a client config for.
#[derive(Debug, Clone)]
pub struct TlsTarget {
    /// Pin store, TOFU file and audit protocol.
    pub protocol: CertProtocol,
    /// DNS name or IP literal (what the peer's certificate must name; also the SNI).
    pub host: String,
    /// Port (`1..=65535`).
    pub port: u16,
    /// `$APP_DATA/known_<protocol>_certs` (read only; the Gate writes pins).
    pub known_certs_path: PathBuf,
    /// Extra PEM roots (`caPem`), certificates only, ≤ 64 KiB.
    pub extra_ca_pem: Option<String>,
    /// A leaf the user accepted for this connect only; never overrides a pin of the host.
    pub trusted_once: Option<[u8; 32]>,
}

/// The config plus the slot its verifier writes.
#[derive(Debug, Clone)]
pub struct TlsClient {
    /// Hand this to the TLS connector (`tokio_rustls::TlsConnector::from`, `ldap3`
    /// `set_config`). Usable for one connect: the pin store was loaded for it.
    pub config: Arc<ClientConfig>,
    slot: DecisionSlot,
}

impl TlsClient {
    /// The verifier's record of the handshake, taken once (`None` before any handshake, or
    /// when the connection failed before the certificate arrived).
    pub fn decision(&self) -> Option<TrustDecision> {
        take_decision(&self.slot)
    }

    /// After a failed handshake: the `Trust*` error for the recorded decision, or `None` when
    /// the verifier accepted the certificate (the failure is elsewhere) or saw none.
    pub fn trust_error(&self) -> Option<HttpError> {
        self.decision().and_then(trust_error)
    }
}

/// Build the client config for `target` (TOFU mode: system roots plus `extra_ca_pem`, pins
/// consulted first). Loads the pin store and the OS roots on the blocking pool.
pub async fn client_config(target: &TlsTarget) -> Result<TlsClient, HttpError> {
    let bad = HttpError::InvalidConfig;
    let host = target.host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if host.is_empty() || server_name(&host).is_none() {
        return Err(bad("host is not a valid TLS server name"));
    }
    if target.port == 0 {
        return Err(bad("port must be 1..=65535"));
    }
    if target.extra_ca_pem.as_ref().is_some_and(|p| p.len() > MAX_CA_PEM) {
        return Err(bad("extra_ca_pem exceeds 64 KiB"));
    }
    let known =
        load_known(target.known_certs_path.clone(), host.clone(), target.port, target.trusted_once)
            .await?;
    let chain = build_chain(true, false, target.extra_ca_pem.clone()).await?;
    let slot = DecisionSlot::default();
    let verifier = Arc::new(HttpVerifier {
        protocol: target.protocol,
        host,
        port: target.port,
        known,
        chain,
        anchored: false,
        slot: Arc::clone(&slot),
    });
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| HttpError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    Ok(TlsClient { config: Arc::new(config), slot })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(dir: &std::path::Path) -> TlsTarget {
        TlsTarget {
            protocol: CertProtocol::Ldap,
            host: "dc.example.test".to_owned(),
            port: 636,
            known_certs_path: dir.join("known_ldap_certs"),
            extra_ca_pem: None,
            trusted_once: None,
        }
    }

    #[tokio::test]
    async fn rejects_bad_targets_and_builds_a_config() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut t = target(dir.path());
        t.port = 0;
        assert!(matches!(client_config(&t).await, Err(HttpError::InvalidConfig(_))));
        t.port = 636;
        t.host = "not a host".to_owned();
        assert!(matches!(client_config(&t).await, Err(HttpError::InvalidConfig(_))));
        t.host = "[2001:db8::1]".to_owned();
        t.extra_ca_pem = Some("x".repeat(MAX_CA_PEM + 1));
        assert!(matches!(client_config(&t).await, Err(HttpError::InvalidConfig(_))));
        t.extra_ca_pem = None;
        let c = client_config(&t).await.expect("config");
        assert!(c.decision().is_none() && c.trust_error().is_none());
        assert!(c.config.alpn_protocols.is_empty());
    }

    #[tokio::test]
    async fn unreadable_store_fails_closed() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut t = target(dir.path());
        std::fs::create_dir(&t.known_certs_path).expect("dir in place of the file");
        t.known_certs_path = t.known_certs_path.clone();
        assert!(matches!(client_config(&t).await, Err(HttpError::TrustStore)));
    }
}
