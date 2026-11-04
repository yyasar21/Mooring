//! Our `ServerCertVerifier` (ADR-0011 table, ADR-0014 §1 and §3), mirroring the RDP one.
//!
//! Per connection it
//! 1. checks the chain with `WebPkiServerVerifier` (system roots + `extra_ca_pem`, or **only**
//!    `extra_ca_pem` in anchored mode) — this includes the host-name check,
//! 2. looks the leaf up in the protocol's `known_*_certs` (pin before CA),
//! 3. records a [`TrustDecision`] in a slot the connector reads after the handshake,
//! 4. accepts (pinned / CA-valid) or fails the handshake (unknown + invalid → prompt, changed
//!    pin → hard stop, anchored + invalid → rejected). It never waits for the UI.
//!
//! Handshake signatures are always verified with ring, whatever the chain decision was.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use mooring_core::known_certs::{
    decide, fingerprint, CertProblem, CertProtocol, CertTrust, CertVerdict, CertificateInfo,
    KnownCerts,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme};
use time::OffsetDateTime;

use crate::cert::certificate_info;

/// What happened to the presented leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TrustVerdict {
    /// A pin matched (`chain_valid == false` is a warning, e.g. expiry). Also the outcome of
    /// `trusted_once`.
    Pinned {
        /// Whether the chain validated too.
        chain_valid: bool,
    },
    /// No pin, the chain validated against the roots. The Gate may write a "TLS seen" marker.
    CaValid,
    /// The pin differs: hard stop (`trust_mismatch`).
    Mismatch {
        /// The stored pin.
        #[serde(skip)]
        expected: [u8; 32],
    },
    /// No pin, invalid chain: the caller prompts and retries with `trusted_once` or a pin.
    Prompt,
    /// Anchored mode (an explicit CA such as kubeconfig `certificate-authority-data`) and the
    /// chain did not validate against it: never promptable (`trust_rejected`).
    Rejected,
}

impl TrustVerdict {
    /// Whether the handshake is allowed to continue.
    pub const fn accepted(self) -> bool {
        matches!(self, Self::Pinned { .. } | Self::CaValid)
    }

    fn from_core(v: CertVerdict) -> Self {
        match v {
            CertVerdict::AcceptPinned { chain_valid } => Self::Pinned { chain_valid },
            CertVerdict::AcceptCa => Self::CaValid,
            CertVerdict::Mismatch { expected } => Self::Mismatch { expected },
            CertVerdict::Prompt => Self::Prompt,
        }
    }
}

/// The verifier's record of one handshake: what the Tauri layer shows, audits and pins.
/// Attached to every response of that connection (`Response::extensions`), sent to
/// [`crate::HttpConfig::trust_events`], and carried by the `Trust*` errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDecision {
    /// Store the pin belongs to.
    pub protocol: CertProtocol,
    /// Host as in the base URL (lowercase, IPv6 without brackets).
    pub host: String,
    /// Port.
    pub port: u16,
    /// SHA-256 of the leaf DER (what the Gate pins).
    pub fingerprint: [u8; 32],
    /// The store lookup (always `Unknown` in anchored mode, where pins are not consulted).
    pub trust: CertTrust,
    /// The outcome.
    pub verdict: TrustVerdict,
    /// Sanitised certificate fields and chain problems for the dialog.
    pub info: CertificateInfo,
}

pub(crate) type DecisionSlot = Arc<Mutex<Option<TrustDecision>>>;

pub(crate) fn take_decision(slot: &DecisionSlot) -> Option<TrustDecision> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

/// The ring provider (ADR-0001: no aws-lc-rs).
pub(crate) fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())))
}

/// The OS trust store, loaded once per process. Blocking: call from `spawn_blocking`.
pub(crate) fn system_roots() -> &'static [CertificateDer<'static>] {
    static ROOTS: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let loaded = rustls_native_certs::load_native_certs();
        if !loaded.errors.is_empty() {
            tracing::debug!(errors = loaded.errors.len(), "some system roots failed to load");
        }
        loaded.certs
    })
}

/// `system` plus every `CERTIFICATE` block of `extra_pem`. Returns the store and how many
/// extra certificates were usable.
pub(crate) fn root_store(
    system: &[CertificateDer<'static>],
    extra_pem: Option<&str>,
) -> (RootCertStore, usize) {
    let mut roots = RootCertStore::empty();
    let _ = roots.add_parsable_certificates(system.iter().cloned());
    let mut added = 0;
    if let Some(pem) = extra_pem {
        let extra = CertificateDer::pem_slice_iter(pem.as_bytes()).filter_map(Result::ok);
        (added, _) = roots.add_parsable_certificates(extra);
    }
    (roots, added)
}

/// Build the chain verifier, `None` when there are no roots at all.
pub(crate) fn chain_verifier(roots: RootCertStore) -> Option<Arc<WebPkiServerVerifier>> {
    if roots.is_empty() {
        return None;
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider()).build().ok()
}

fn chain_problem(err: &rustls::Error) -> CertProblem {
    match err {
        rustls::Error::InvalidCertificate(
            CertificateError::Expired | CertificateError::ExpiredContext { .. },
        ) => CertProblem::Expired,
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. },
        ) => CertProblem::NotYetValid,
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
        ) => CertProblem::NameMismatch,
        _ => CertProblem::UnknownIssuer,
    }
}

/// Certificate verifier for one `host:port` and one connection.
pub(crate) struct HttpVerifier {
    pub(crate) protocol: CertProtocol,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) known: KnownCerts,
    pub(crate) chain: Option<Arc<WebPkiServerVerifier>>,
    /// Anchored mode: the chain must validate, pins and TOFU are not used.
    pub(crate) anchored: bool,
    pub(crate) slot: DecisionSlot,
}

impl std::fmt::Debug for HttpVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpVerifier")
            .field("protocol", &self.protocol)
            .field("port", &self.port)
            .field("pins", &self.known.len())
            .field("anchored", &self.anchored)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for HttpVerifier {
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
        let (trust, verdict) = if self.anchored {
            let v = if chain.is_ok() { TrustVerdict::CaValid } else { TrustVerdict::Rejected };
            (CertTrust::Unknown, v)
        } else {
            let trust = self.known.check(&self.host, self.port, &fp);
            (trust, TrustVerdict::from_core(decide(trust, chain.is_ok())))
        };
        let mut problems: Vec<CertProblem> =
            chain.as_ref().err().map(chain_problem).into_iter().collect();
        // webpki reports only its first error; check the name on the leaf as RDP / VNC do.
        let name_ok = rustls::server::ParsedCertificate::try_from(end_entity)
            .and_then(|p| rustls::client::verify_server_name(&p, server_name))
            .is_ok();
        if !name_ok {
            problems.push(CertProblem::NameMismatch);
        }
        let when = i64::try_from(now.as_secs())
            .ok()
            .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let info = certificate_info(end_entity.as_ref(), problems, when);
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(TrustDecision {
            protocol: self.protocol,
            host: self.host.clone(),
            port: self.port,
            fingerprint: fp,
            trust,
            verdict,
            info,
        });
        if verdict.accepted() {
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
        verify_tls12_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

/// The rustls server name for `host` (DNS name or IP literal, brackets stripped).
pub(crate) fn server_name(host: &str) -> Option<ServerName<'static>> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(bare.to_owned()).ok()
}
