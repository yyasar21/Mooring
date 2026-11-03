//! Per-kind plaintext field structs (ADR-0009 §1). Every struct is `deny_unknown_fields`; wire
//! names are `snake_case`. Derived values (`fingerprint`, `contexts`) are stored here but are
//! refused on input (see [`super::CredentialFields::from_input`]).

use serde::{Deserialize, Serialize};

use super::{AccountForm, CredentialKind, OtpParams};

/// `user_password`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPasswordFields {
    /// Username, stored verbatim (may contain `\` or `@`; no guessing).
    pub username: String,
    /// Optional domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// TOTP parameters when an `otp_seed` is attached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otp: Option<OtpParams>,
}

/// `domain_user`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainUserFields {
    /// User part.
    pub user: String,
    /// `NetBIOS` domain or UPN suffix.
    pub domain: String,
    /// Which form.
    pub form: AccountForm,
    /// TOTP parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otp: Option<OtpParams>,
}

/// `ssh_key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshKeyFields {
    /// Login name.
    pub username: String,
    /// OpenSSH public key line (public).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// OpenSSH certificate line (`*-cert.pub`, public).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// Derived `SHA256:` fingerprint of the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// TOTP parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otp: Option<OtpParams>,
}

/// `ssh_agent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshAgentFields {
    /// Login name.
    pub username: String,
    /// Pin one agent key by `SHA256:` fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_fingerprint: Option<String>,
}

/// `x509`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X509Fields {
    /// Optional user name (some services want one beside the certificate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Certificate (chain) PEM, public.
    pub cert_pem: String,
    /// Derived `SHA256:` fingerprint of the leaf certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// `api_token`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ApiTokenFields {
    /// Header name, default `Authorization`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    /// Scheme, default `Bearer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// `oauth_client`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OauthClientFields {
    /// `https://` token endpoint.
    pub token_url: String,
    /// Client id.
    pub client_id: String,
    /// Scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// `kubeconfig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct KubeconfigFields {
    /// Selected context (must be one of `contexts`); `None` = `current-context`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Derived context names (names only).
    #[serde(default)]
    pub contexts: Vec<String>,
}

/// `kube_token`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct KubeTokenFields {
    /// Display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// `vsphere_user`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VsphereUserFields {
    /// `user@domain` (required form).
    pub upn: String,
    /// TOTP parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otp: Option<OtpParams>,
}

/// `vnc_password`: no plain fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct VncPasswordFields {}

/// `vnc_user_password`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VncUserPasswordFields {
    /// Username.
    pub username: String,
}

/// `prompt`: pre-fills for the connect-time form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PromptFields {
    /// Pre-filled username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Pre-filled domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// Secret manager of an `external_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefProvider {
    /// `HashiCorp` Vault.
    Vault,
    /// 1Password (`op://…`).
    Onepassword,
    /// Bitwarden Secrets Manager.
    Bitwarden,
}

/// `external_ref`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRefFields {
    /// Provider.
    pub provider: RefProvider,
    /// Reference (path / URI / id), no secret.
    pub reference: String,
    /// Kind the reference resolves to; drives the matrix.
    pub target_kind: CredentialKind,
}

/// Privilege escalation method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BecomeMethod {
    /// `sudo`.
    Sudo,
    /// `su`.
    Su,
    /// `doas`.
    Doas,
}

impl BecomeMethod {
    /// Command name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sudo => "sudo",
            Self::Su => "su",
            Self::Doas => "doas",
        }
    }
}

/// `sudo_become`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SudoBecomeFields {
    /// Method.
    pub method: BecomeMethod,
    /// Target user; blank input becomes `root`.
    #[serde(default = "root")]
    pub become_user: String,
}

fn root() -> String {
    "root".to_owned()
}
