//! HTTP NTLM to the RD Gateway (ADR-0027 §1) through the `sspi::Ntlm` `IronRDP` already links
//! (re-exported by `ironrdp-connector`; no `network_client`, so no KDC traffic). Two legs:
//! `NEGOTIATE` → the gateway's `CHALLENGE` → `AUTHENTICATE`. The password lives in `sspi`'s
//! `Secret` for the exchange only (as for `CredSSP`, R-RDP-STR).
//!
//! Channel binding (EPA / CBT, review 9 M-19): the `AUTHENTICATE_MESSAGE` carries
//! `MsvAvChannelBindings` over the RFC 5929 `tls-server-end-point` of the gateway leaf the
//! TLS session presented, so the exchange cannot be relayed out of that TLS session and a
//! gateway with Extended Protection `Require` accepts it.

use ironrdp_connector::sspi::{
    AuthIdentity, AuthIdentityBuffers, BufferType, ClientRequestFlags, CredentialUse,
    DataRepresentation, Ntlm, SecurityBuffer, SecurityStatus, Sspi, SspiImpl, Username,
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_parser::signature_algorithm::SignatureAlgorithm;

use super::GatewayAccount;

/// Why NTLM could not proceed (no secret, no server text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NtlmError {
    /// The user name could not be expressed for NTLM.
    BadUser,
    /// `sspi` refused the exchange (malformed challenge, internal error).
    Failed,
}

/// One client-side NTLM exchange.
pub(crate) struct NtlmClient {
    ntlm: Ntlm,
    handle: Option<AuthIdentityBuffers>,
}

impl std::fmt::Debug for NtlmClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NtlmClient")
    }
}

fn username(a: &GatewayAccount) -> Result<Username, NtlmError> {
    let r = match a.domain.as_deref().filter(|d| !d.is_empty()) {
        Some(d) => Username::new(&a.username, Some(d)),
        None if a.username.contains('@') || a.username.contains('\\') => {
            Username::parse(&a.username)
        }
        None => Username::new(&a.username, None),
    };
    r.map_err(|_| NtlmError::BadUser)
}

/// The hash RFC 5929 §4.1 picks for a certificate's signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndPointHash {
    Sha256,
    Sha384,
    Sha512,
}

fn hash_for_oid(oid: &str) -> Option<EndPointHash> {
    match oid {
        // ecdsa-with-SHA384, sha384WithRSAEncryption, id-sha384 (RSASSA-PSS parameter)
        "1.2.840.10045.4.3.3" | "1.2.840.113549.1.1.12" | "2.16.840.1.101.3.4.2.2" => {
            Some(EndPointHash::Sha384)
        }
        // ecdsa-with-SHA512, sha512WithRSAEncryption, id-sha512
        "1.2.840.10045.4.3.4" | "1.2.840.113549.1.1.13" | "2.16.840.1.101.3.4.2.3" => {
            Some(EndPointHash::Sha512)
        }
        _ => None,
    }
}

/// RFC 5929 §4.1: the signature's own hash for SHA-384 / SHA-512; SHA-256 for MD5, SHA-1,
/// SHA-256 and anything without a single hash (Ed25519, unparsable — rustls already verified
/// the leaf, so the last case does not occur in practice).
pub(crate) fn end_point_hash(der: &[u8]) -> EndPointHash {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return EndPointHash::Sha256;
    };
    let alg = &cert.signature_algorithm;
    if let Some(h) = hash_for_oid(&alg.algorithm.to_id_string()) {
        return h;
    }
    if let Ok(SignatureAlgorithm::RSASSA_PSS(p)) = SignatureAlgorithm::try_from(alg) {
        if let Some(h) = hash_for_oid(&p.hash_algorithm_oid().to_id_string()) {
            return h;
        }
    }
    EndPointHash::Sha256
}

/// The `gss_channel_bindings_struct` application data for the gateway leaf:
/// `tls-server-end-point:` ‖ hash(leaf DER).
pub(crate) fn tls_server_end_point(der: &[u8]) -> Vec<u8> {
    let mut out = b"tls-server-end-point:".to_vec();
    match end_point_hash(der) {
        EndPointHash::Sha256 => out.extend_from_slice(&Sha256::digest(der)),
        EndPointHash::Sha384 => out.extend_from_slice(&Sha384::digest(der)),
        EndPointHash::Sha512 => out.extend_from_slice(&Sha512::digest(der)),
    }
    out
}

impl NtlmClient {
    /// Acquire the credentials handle for `account`, bound to the TLS session whose server
    /// leaf is `leaf_der` (RFC 5929 `tls-server-end-point`).
    pub(crate) fn new(account: &GatewayAccount, leaf_der: &[u8]) -> Result<Self, NtlmError> {
        let mut ntlm = Ntlm::new();
        ntlm.set_channel_bindings(&tls_server_end_point(leaf_der));
        let identity = AuthIdentity {
            username: username(account)?,
            password: account.password.expose_secret().to_owned().into(),
        };
        let acquired = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(&mut ntlm)
            .map_err(|_| NtlmError::Failed)?;
        Ok(Self { ntlm, handle: acquired.credentials_handle })
    }

    fn step(&mut self, input: Option<&[u8]>, target: &str) -> Result<Vec<u8>, NtlmError> {
        let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut input_buf =
            vec![SecurityBuffer::new(input.unwrap_or_default().to_vec(), BufferType::Token)];
        let builder = self
            .ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut self.handle)
            .with_context_requirements(ClientRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(target)
            .with_output(&mut output);
        let mut builder =
            if input.is_some() { builder.with_input(&mut input_buf) } else { builder };
        let result = self
            .ntlm
            .initialize_security_context_impl(&mut builder)
            .and_then(|mut g| g.resolve_to_result())
            .map_err(|_| NtlmError::Failed)?;
        if matches!(
            result.status,
            SecurityStatus::CompleteAndContinue | SecurityStatus::CompleteNeeded
        ) {
            self.ntlm.complete_auth_token(&mut output).map_err(|_| NtlmError::Failed)?;
        }
        output.pop().map(|b| b.buffer).filter(|b| !b.is_empty()).ok_or(NtlmError::Failed)
    }

    /// The `NEGOTIATE_MESSAGE`.
    pub(crate) fn negotiate(&mut self, target: &str) -> Result<Vec<u8>, NtlmError> {
        self.step(None, target)
    }

    /// The `AUTHENTICATE_MESSAGE` for the gateway's `CHALLENGE_MESSAGE`.
    pub(crate) fn authenticate(
        &mut self,
        challenge: &[u8],
        target: &str,
    ) -> Result<Vec<u8>, NtlmError> {
        self.step(Some(challenge), target)
    }
}
