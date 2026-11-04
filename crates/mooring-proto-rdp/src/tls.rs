//! Our TLS client for the RDP security upgrade (ADR-0011 §Trust).
//!
//! `ironrdp-tls` is not used: its default policy accepts any certificate and its callback runs
//! synchronously inside the handshake. Here rustls (ring provider, TLS 1.2+) runs with
//! [`TofuVerifier`], which:
//! 1. checks the chain with `WebPkiServerVerifier` against the OS roots plus `caPem`,
//! 2. looks the leaf up in `known_rdp_certs`,
//! 3. applies `mooring_core::known_certs::decide` and records the [`Decision`] for the driver,
//! 4. accepts (pinned / CA-valid) or fails the handshake (unknown + invalid chain → prompt,
//!    changed pin → hard stop). It never waits for the UI.
//!
//! Handshake signatures are always verified with ring (`verify_tls12/13_signature`), whatever
//! the chain decision was: a pin only replaces the CA, never proof of key possession.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use mooring_core::known_certs::{
    decide, fingerprint, CertProblem, CertTrust, CertVerdict, KnownCerts,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};

/// What the verifier decided about the presented leaf; read by the driver after the
/// handshake (success or failure).
#[derive(Debug, Clone)]
pub(crate) struct Decision {
    pub(crate) der: Vec<u8>,
    pub(crate) fingerprint: [u8; 32],
    pub(crate) verdict: CertVerdict,
    /// Chain problems reported by webpki (empty when the chain validated).
    pub(crate) problems: Vec<CertProblem>,
}

/// Shared slot the verifier writes its [`Decision`] into.
pub(crate) type DecisionSlot = Arc<Mutex<Option<Decision>>>;

pub(crate) fn take_decision(slot: &DecisionSlot) -> Option<Decision> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

/// The ring provider (ADR-0001: no aws-lc-rs).
pub(crate) fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())))
}

/// The OS trust store, loaded once per process (blocking: first call from `spawn_blocking`).
pub(crate) fn system_roots() -> &'static [CertificateDer<'static>] {
    static ROOTS: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let loaded = rustls_native_certs::load_native_certs();
        if !loaded.errors.is_empty() {
            tracing::debug!(
                errors = loaded.errors.len(),
                "some system root certificates failed to load"
            );
        }
        loaded.certs
    })
}

/// Roots for one connection: `system` plus every `CERTIFICATE` block of `ca_pem` (already
/// validated by `RdpConnOptions::validate`: certificates only, ≤ 64 KiB).
pub(crate) fn root_store(
    system: &[CertificateDer<'static>],
    ca_pem: Option<&str>,
) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let (_, ignored) = roots.add_parsable_certificates(system.iter().cloned());
    if ignored > 0 {
        tracing::debug!(ignored, "unparsable system root certificates skipped");
    }
    if let Some(pem) = ca_pem {
        let extra = CertificateDer::pem_slice_iter(pem.as_bytes()).filter_map(Result::ok);
        let (added, ignored) = roots.add_parsable_certificates(extra);
        tracing::debug!(added, ignored, "connection CA certificates");
    }
    roots
}

/// Map a webpki chain error onto the dialog's `problems`.
pub(crate) fn chain_problems(err: &rustls::Error) -> Vec<CertProblem> {
    let p = match err {
        rustls::Error::InvalidCertificate(e) => match e {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                CertProblem::Expired
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                CertProblem::NotYetValid
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                CertProblem::NameMismatch
            }
            _ => CertProblem::UnknownIssuer,
        },
        _ => CertProblem::UnknownIssuer,
    };
    vec![p]
}

/// Certificate TOFU verifier for one `host:port` and one connection attempt.
pub(crate) struct TofuVerifier {
    host: String,
    port: u16,
    known: KnownCerts,
    chain: Option<Arc<WebPkiServerVerifier>>,
    provider: Arc<CryptoProvider>,
    slot: DecisionSlot,
}

impl std::fmt::Debug for TofuVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TofuVerifier")
            .field("port", &self.port)
            .field("pins", &self.known.len())
            .field("has_roots", &self.chain.is_some())
            .finish_non_exhaustive()
    }
}

impl TofuVerifier {
    /// `roots` may be empty (no system store, no `caPem`): every chain is then invalid and
    /// only a pin (or the prompt) can establish trust.
    pub(crate) fn new(
        host: &str,
        port: u16,
        known: KnownCerts,
        roots: RootCertStore,
        slot: DecisionSlot,
    ) -> Self {
        let provider = provider();
        let chain = if roots.is_empty() {
            None
        } else {
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .ok()
        };
        Self { host: host.to_owned(), port, known, chain, provider, slot }
    }

    fn record(&self, decision: Decision) {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(decision);
    }
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let chain = match &self.chain {
            Some(v) => v
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .map(|_| ()),
            None => Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)),
        };
        let fp = fingerprint(end_entity.as_ref());
        let trust: CertTrust = self.known.check(&self.host, self.port, &fp);
        let verdict = decide(trust, chain.is_ok());
        let mut problems = chain.as_ref().err().map(chain_problems).unwrap_or_default();
        // N-24: webpki reports only its first error; check the name on the leaf as VNC does.
        let name_ok = rustls::server::ParsedCertificate::try_from(end_entity)
            .and_then(|p| rustls::client::verify_server_name(&p, server_name))
            .is_ok();
        if !name_ok && !problems.contains(&CertProblem::NameMismatch) {
            problems.push(CertProblem::NameMismatch);
        }
        self.record(Decision {
            der: end_entity.as_ref().to_vec(),
            fingerprint: fp,
            verdict,
            problems,
        });
        match verdict {
            CertVerdict::AcceptPinned { .. } | CertVerdict::AcceptCa => {
                Ok(ServerCertVerified::assertion())
            }
            CertVerdict::Mismatch { .. } | CertVerdict::Prompt | CertVerdict::Conflict => Err(
                rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
            ),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// rustls client config around `verifier`: ring, TLS 1.2 + 1.3, no client auth, no session
/// resumption (every connect runs the verifier; Windows `CredSSP` dislikes resumed sessions).
pub(crate) fn client_config(verifier: Arc<TofuVerifier>) -> Result<ClientConfig, rustls::Error> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    Ok(config)
}

/// The rustls server name for `host` (DNS name or IP literal, brackets stripped).
pub(crate) fn server_name(host: &str) -> Option<ServerName<'static>> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(bare.to_owned()).ok()
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
