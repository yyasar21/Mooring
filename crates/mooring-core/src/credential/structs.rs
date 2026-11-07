//! Per-kind plaintext field structs (ADR-0009 §1). Every struct is `deny_unknown_fields`; wire
//! names are `snake_case`. Derived values (`fingerprint`, `contexts`, `migrated`) are stored here but are
//! refused on input (see [`super::CredentialFields::from_input`]).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{AccountForm, CredentialKind, OtpParams};
use crate::model::SecretSourceId;

/// `user_password`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPasswordFields {
    /// Username, stored verbatim (may contain `\` or `@`; no guessing). Empty only while
    /// [`Self::migrated`] is set.
    #[serde(default)]
    pub username: String,
    /// Optional domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// TOTP parameters when an `otp_seed` is attached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otp: Option<OtpParams>,
    /// Derived: a v2 row migrated without a username (ADR-0009 §4). The username may stay
    /// empty while this is set; it is never carried across an update, so the next
    /// `update_fields` must supply a username.
    #[serde(default, skip_serializing_if = "is_false")]
    pub migrated: bool,
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
    /// Login name. Empty only while [`Self::migrated`] is set.
    #[serde(default)]
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
    /// Derived: a v2 row migrated without a username (see [`UserPasswordFields::migrated`]).
    #[serde(default, skip_serializing_if = "is_false")]
    pub migrated: bool,
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

/// `ssh_sk_key` (ADR-0024 §1): a FIDO2 key. Every signature needs the authenticator, through
/// the ssh-agent (`backend: agent`) or OpenSSH's `ssh-sk-helper` (`helper`, flagged).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshSkKeyFields {
    /// Login name.
    pub username: String,
    /// `sk-ssh-ed25519@openssh.com …` / `sk-ecdsa-sha2-nistp256@openssh.com …` line (public).
    pub public_key: String,
    /// OpenSSH user certificate of this key (`sk-*-cert-v01@openssh.com`, public).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// Signing backend.
    #[serde(default)]
    pub backend: SkBackend,
    /// Resident (discoverable) key; replaced by the key-handle flags when a clear handle is
    /// stored.
    #[serde(default, skip_serializing_if = "is_false", deserialize_with = "bool_or_text")]
    pub resident: bool,
    /// Derived FIDO application of the key (`ssh:` by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    /// Derived `SHA256:` fingerprint of the key (the agent identity is pinned to it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// Who talks to the authenticator for an `ssh_sk_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SkBackend {
    /// The user's ssh-agent (`ssh-add` loaded the key); every OS.
    #[default]
    Agent,
    /// OpenSSH's `ssh-sk-helper` with the stored key handle (Windows / Linux, behind the
    /// `sshSkHelper` setting, ADR-0024 §3).
    Helper,
}

impl SkBackend {
    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Helper => "helper",
        }
    }
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

impl RefProvider {
    /// Wire name (`vault`, `onepassword`, `bitwarden`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::Onepassword => "onepassword",
            Self::Bitwarden => "bitwarden",
        }
    }
}

/// `external_ref` (ADR-0009 §1, amended by ADR-0016 §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRefFields {
    /// Provider.
    pub provider: RefProvider,
    /// Reference, no secret. For `vault`: `<mount>/<path>` ([`super::parse_vault_reference`]).
    pub reference: String,
    /// Kind the reference resolves to; drives the matrix.
    pub target_kind: CredentialKind,
    /// The secret source (`vault`; required on input for that provider).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SecretSourceId>,
    /// Pinned KV v2 version (else latest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// Renames: `{ <target kind field or secret name>: <KV key> }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_map: Option<BTreeMap<String, String>>,
    /// Vault secret engine (ADR-0026 §1); `kv2` when absent (stored rows stay unchanged).
    #[serde(default, skip_serializing_if = "VaultEngine::is_kv2")]
    pub engine: VaultEngine,
    /// `ssh_sign`: `valid_principals` (≤ 16, ≤ 64 B each).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principals: Option<Vec<String>>,
    /// `ssh_sign` / `pki`: requested TTL in seconds (≤ 24 h).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    /// `pki`: `common_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    /// `pki`: `alt_names` (≤ 16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt_names: Option<Vec<String>>,
    /// `ssh_otp`: the login the one-time password is issued for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

impl ExternalRefFields {
    /// A reference with every optional field unset (KV v2, latest version).
    #[must_use]
    pub fn new(provider: RefProvider, reference: String, target_kind: CredentialKind) -> Self {
        Self {
            provider,
            reference,
            target_kind,
            source: None,
            version: None,
            field_map: None,
            engine: VaultEngine::Kv2,
            principals: None,
            ttl: None,
            common_name: None,
            alt_names: None,
            username: None,
        }
    }
}

/// Vault secret engine of an `external_ref` (ADR-0026 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VaultEngine {
    /// KV v2 (`GET <mount>/data/<path>`).
    #[default]
    Kv2,
    /// Dynamic database credentials (`<mount>/creds/<role>`, leased).
    Database,
    /// SSH CA signing of the SSH key credential's public key (`<mount>/sign/<role>`).
    SshSign,
    /// SSH one-time password (`<mount>/creds/<role>`).
    SshOtp,
    /// X.509 issuance (`<mount>/issue/<role>`).
    Pki,
}

impl VaultEngine {
    /// Every engine.
    pub const ALL: [Self; 5] = [Self::Kv2, Self::Database, Self::SshSign, Self::SshOtp, Self::Pki];

    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kv2 => "kv2",
            Self::Database => "database",
            Self::SshSign => "ssh_sign",
            Self::SshOtp => "ssh_otp",
            Self::Pki => "pki",
        }
    }

    /// `true` for the default engine.
    #[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
    #[must_use]
    pub const fn is_kv2(&self) -> bool {
        matches!(self, Self::Kv2)
    }
}

/// `vault_approle`: no plain fields; `role_id` and `secret_id` are both sealed (ADR-0016 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct VaultApproleFields {}

/// `bitwarden_access_token`: no plain fields; the machine access token is sealed
/// (ADR-0026 §4). Valid only as a secret-source login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BitwardenAccessTokenFields {}

/// `s3_access_key` (ADR-0017 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3AccessKeyFields {
    /// Access key id (public half).
    pub access_key_id: String,
    /// Signing region (`us-east-1` when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
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

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_false(b: &bool) -> bool {
    !*b
}

/// A bool, or the UI's enum text `"true"` / `"false"`.
fn bool_or_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum B {
        Bool(bool),
        Text(String),
    }
    match B::deserialize(d)? {
        B::Bool(b) => Ok(b),
        B::Text(t) if t == "true" => Ok(true),
        B::Text(t) if t == "false" => Ok(false),
        B::Text(_) => Err(serde::de::Error::custom("expected true or false")),
    }
}

fn root() -> String {
    "root".to_owned()
}
