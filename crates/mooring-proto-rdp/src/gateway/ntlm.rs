//! HTTP NTLM to the RD Gateway (ADR-0027 §1) through the `sspi::Ntlm` `IronRDP` already links
//! (re-exported by `ironrdp-connector`; no `network_client`, so no KDC traffic). Two legs:
//! `NEGOTIATE` → the gateway's `CHALLENGE` → `AUTHENTICATE`. The password lives in `sspi`'s
//! `Secret` for the exchange only (as for `CredSSP`, R-RDP-STR).

use ironrdp_connector::sspi::{
    AuthIdentity, AuthIdentityBuffers, BufferType, ClientRequestFlags, CredentialUse,
    DataRepresentation, Ntlm, SecurityBuffer, SecurityStatus, Sspi, SspiImpl, Username,
};
use secrecy::ExposeSecret;

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

impl NtlmClient {
    /// Acquire the credentials handle for `account`.
    pub(crate) fn new(account: &GatewayAccount) -> Result<Self, NtlmError> {
        let mut ntlm = Ntlm::new();
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
