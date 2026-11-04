//! `VeNCrypt` X509 transport: rustls (ring) with the ADR-0011 trust decision.
//!
//! [`TofuVerifier`] validates the chain against the system roots plus `options.caPem`, looks
//! the leaf up in `known_vnc_certs` and applies `known_certs::decide`. It never blocks on the
//! UI: an unknown certificate (or a changed pin) fails the TLS handshake and leaves a
//! [`TrustOutcome`] behind, from which the session raises the `certificate_trust` prompt (and
//! reconnects on `yes`) or hard-stops with `trust_mismatch`.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use mooring_core::known_certs::{
    decide, display_fingerprint, fingerprint, CertProblem, CertVerdict, CertificateInfo, KnownCerts,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use time::OffsetDateTime;

use crate::error::VncError;

/// What the verifier decided about the presented leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustOutcome {
    /// A pin matched (`chain_valid` false = shown as a warning only).
    Pinned {
        /// SHA-256 of the leaf.
        fp: [u8; 32],
        /// Whether the chain validated too.
        chain_valid: bool,
    },
    /// No pin; the chain validated against the roots (audit `trust.cert.ca_valid`).
    CaValid {
        /// SHA-256 of the leaf.
        fp: [u8; 32],
    },
    /// A pin exists and differs: hard stop.
    Mismatch {
        /// Stored pin.
        expected: [u8; 32],
        /// Presented leaf.
        presented: [u8; 32],
    },
    /// More than one distinct pin for the host (review 6b L-35): hard stop, never prompted.
    Conflict {
        /// Presented leaf.
        presented: [u8; 32],
    },
    /// No pin and the chain does not validate: prompt.
    Unknown {
        /// SHA-256 of the leaf.
        fp: [u8; 32],
        /// What the prompt shows.
        info: Box<CertificateInfo>,
    },
}

impl TrustOutcome {
    /// Whether the handshake may continue.
    pub const fn accepted(&self) -> bool {
        matches!(self, Self::Pinned { .. } | Self::CaValid { .. })
    }

    /// The fingerprint of the leaf.
    pub fn presented(&self) -> [u8; 32] {
        match self {
            Self::Pinned { fp, .. }
            | Self::CaValid { fp }
            | Self::Mismatch { presented: fp, .. }
            | Self::Conflict { presented: fp }
            | Self::Unknown { fp, .. } => *fp,
        }
    }
}

/// Map a rustls chain error onto the problems shown in the prompt.
pub fn chain_problems(err: &rustls::Error) -> Vec<CertProblem> {
    match err {
        rustls::Error::InvalidCertificate(e) => match e {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                vec![CertProblem::Expired]
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                vec![CertProblem::NotYetValid]
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                vec![CertProblem::NameMismatch]
            }
            _ => vec![CertProblem::UnknownIssuer],
        },
        _ => vec![CertProblem::UnknownIssuer],
    }
}

/// Build the prompt's [`CertificateInfo`] from the leaf DER. Subject, issuer and SANs are
/// server-controlled; `CertificateInfo::new` sanitises them. An unparsable leaf still gets a
/// fingerprint (the user decides on that).
pub fn certificate_info(
    der: &[u8],
    mut problems: Vec<CertProblem>,
    name_ok: bool,
    now: OffsetDateTime,
) -> CertificateInfo {
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
    if !name_ok {
        problems.push(CertProblem::NameMismatch);
    }
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        let epoch = OffsetDateTime::UNIX_EPOCH;
        return CertificateInfo::new(
            der,
            "(unparsable certificate)",
            "",
            epoch,
            epoch,
            &[],
            problems,
        );
    };
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    if now > not_after {
        problems.push(CertProblem::Expired);
    }
    if now < not_before {
        problems.push(CertProblem::NotYetValid);
    }
    if cert.subject().as_raw() == cert.issuer().as_raw() {
        problems.push(CertProblem::SelfSigned);
    }
    let mut san = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(d) => san.push((*d).to_owned()),
                GeneralName::IPAddress(ip) => san.push(ip_text(ip)),
                _ => {}
            }
        }
    }
    CertificateInfo::new(
        der,
        &cert.subject().to_string(),
        &cert.issuer().to_string(),
        not_before,
        not_after,
        &san,
        problems,
    )
}

fn ip_text(raw: &[u8]) -> String {
    if let Ok(v4) = <[u8; 4]>::try_from(raw) {
        std::net::Ipv4Addr::from(v4).to_string()
    } else if let Ok(v6) = <[u8; 16]>::try_from(raw) {
        std::net::Ipv6Addr::from(v6).to_string()
    } else {
        "(invalid IP)".to_owned()
    }
}

/// The ADR-0011 decision for one presented leaf. `chain_err` is the `WebPKI` failure, if any (system roots +
/// `caPem`), `name_ok` whether the leaf names the host.
pub fn evaluate(
    known: &KnownCerts,
    host: &str,
    port: u16,
    der: &[u8],
    chain_err: Option<&rustls::Error>,
    name_ok: bool,
    now: OffsetDateTime,
) -> TrustOutcome {
    let fp = fingerprint(der);
    match decide(known.check(host, port, &fp), chain_err.is_none()) {
        CertVerdict::AcceptPinned { chain_valid } => TrustOutcome::Pinned { fp, chain_valid },
        CertVerdict::AcceptCa => TrustOutcome::CaValid { fp },
        CertVerdict::Mismatch { expected } => TrustOutcome::Mismatch { expected, presented: fp },
        CertVerdict::Conflict => TrustOutcome::Conflict { presented: fp },
        CertVerdict::Prompt => {
            let problems = chain_err.map(chain_problems).unwrap_or_default();
            let info = Box::new(certificate_info(der, problems, name_ok, now));
            TrustOutcome::Unknown { fp, info }
        }
    }
}

/// The OS trust store, loaded once per process.
fn system_roots() -> &'static Vec<CertificateDer<'static>> {
    static ROOTS: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let loaded = rustls_native_certs::load_native_certs();
        if !loaded.errors.is_empty() {
            tracing::warn!(count = loaded.errors.len(), "some system roots unreadable");
        }
        loaded.certs
    })
}

/// Root store: system roots (unless `system` is false, for tests) plus the `caPem` bundle.
pub fn root_store(ca_pem: Option<&str>, system: bool) -> Result<RootCertStore, VncError> {
    let mut store = RootCertStore::empty();
    if system {
        let (_ok, _bad) = store.add_parsable_certificates(system_roots().iter().cloned());
    }
    if let Some(pem) = ca_pem {
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = cert.map_err(|_| VncError::protocol("caPem is not valid PEM"))?;
            store
                .add(cert)
                .map_err(|_| VncError::protocol("caPem holds an invalid certificate"))?;
        }
    }
    Ok(store)
}

/// rustls verifier implementing TOFU + CA on top of `WebPKI`.
#[derive(Debug)]
pub struct TofuVerifier {
    inner: Option<Arc<WebPkiServerVerifier>>,
    provider: Arc<CryptoProvider>,
    known: KnownCerts,
    host: String,
    port: u16,
    outcome: Mutex<Option<TrustOutcome>>,
}

impl TofuVerifier {
    /// A verifier for `host:port` with this pin store and root store.
    pub fn new(known: KnownCerts, host: &str, port: u16, roots: RootCertStore) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        // An empty root store (no system roots on this machine and no caPem) means "no chain
        // validates": pins and TOFU still work.
        let inner = (!roots.is_empty())
            .then(|| {
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                    .build()
                    .ok()
            })
            .flatten();
        Self { inner, provider, known, host: host.to_owned(), port, outcome: Mutex::new(None) }
    }

    /// The decision taken during the last handshake.
    pub fn outcome(&self) -> Option<TrustOutcome> {
        self.outcome.lock().unwrap_or_else(PoisonError::into_inner).clone()
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
        let chain = match &self.inner {
            Some(v) => v
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .map(|_| ()),
            None => Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)),
        };
        let name_ok = rustls::server::ParsedCertificate::try_from(end_entity)
            .and_then(|p| rustls::client::verify_server_name(&p, server_name))
            .is_ok();
        let now = i64::try_from(now.as_secs())
            .ok()
            .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
            .unwrap_or_else(OffsetDateTime::now_utc);
        let outcome = evaluate(
            &self.known,
            &self.host,
            self.port,
            end_entity,
            chain.as_ref().err(),
            name_ok,
            now,
        );
        let accepted = outcome.accepted();
        if let TrustOutcome::Mismatch { expected, presented } = &outcome {
            tracing::warn!(
                expected = %display_fingerprint(expected),
                presented = %display_fingerprint(presented),
                "vnc certificate pin mismatch"
            );
        }
        *self.outcome.lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome);
        if accepted {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A rustls client config using `verifier` (ring provider, TLS 1.2 + 1.3, no client auth).
pub fn client_config(verifier: Arc<TofuVerifier>) -> Result<ClientConfig, VncError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| VncError::protocol("TLS configuration"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// The TLS server name for `host` (DNS name or IP literal).
pub fn server_name(host: &str) -> Result<ServerName<'static>, VncError> {
    ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']').to_owned())
        .map_err(|_| VncError::protocol("host is not a valid TLS server name"))
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
