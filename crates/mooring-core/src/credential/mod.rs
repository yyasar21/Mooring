//! Typed credential model (ADR-0009).
//!
//! A credential has a closed [`CredentialKind`], plaintext typed [`CredentialFields`] and a set
//! of sealed secrets named by [`SecretName`]. The kind table ([`credential_kinds`]) and the
//! protocol matrix ([`valid_for`]) are the only source of truth; the UI renders its forms from
//! the same table over IPC.
//!
//! Parsers for untrusted input live here too, each capped and panic-free: account split
//! ([`parse_account`]), TOTP seeds ([`otp`]), OpenSSH keys / certificates and X.509 PEM
//! ([`fingerprint`]) and kubeconfig YAML ([`kubeconfig`]).

mod account;
mod error;
mod fields;
pub mod fingerprint;
pub mod kubeconfig;
mod matrix;
pub mod otp;
mod schema;
mod secrets;
mod structs;
#[doc(hidden)]
pub mod testdata;
mod text;
mod validate;

use serde::{Deserialize, Serialize};

pub use account::{parse_account, Account, AccountForm};
pub use error::CredentialError;
pub use fields::{CredentialFields, MAX_FIELDS_JSON};
pub use matrix::{check_compatible, incompatibility_reason, protocol_label, valid_for};
pub use otp::{OtpAlgorithm, OtpParams};
pub use schema::{
    credential_kinds, FieldFormat, FieldSchema, KindProtocol, KindSchema, Validation,
};
pub use secrets::{validate_secret, MAX_SECRET_BYTES};
pub use structs::*;
pub use text::is_forbidden;

/// The closed set of credential kinds. Wire names are `snake_case`; kind is immutable after
/// creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// Username + password (+ optional domain).
    UserPassword,
    /// Windows account in `DOMAIN\user` or `user@domain` form.
    DomainUser,
    /// OpenSSH private key (+ optional public key / certificate).
    SshKey,
    /// Login through the local ssh-agent.
    SshAgent,
    /// X.509 client certificate + key.
    X509,
    /// HTTP bearer / header token.
    ApiToken,
    /// OAuth 2.0 client credentials.
    OauthClient,
    /// Self-contained kubeconfig.
    Kubeconfig,
    /// Kubernetes bearer token.
    KubeToken,
    /// vSphere SSO account (`user@domain`).
    VsphereUser,
    /// RFB security type 2 password (8 bytes max).
    VncPassword,
    /// VNC username + password (ARD / `VeNCrypt` Plain).
    VncUserPassword,
    /// Ask the user at connect time.
    Prompt,
    /// Reference into an external secret manager (resolution in A3).
    ExternalRef,
    /// Privilege escalation (`sudo` / `su` / `doas`) after an SSH login.
    SudoBecome,
    /// S3 access key; valid only as the vault-sync credential (ADR-0017 §4).
    S3AccessKey,
}

impl CredentialKind {
    /// Every kind, in table order.
    pub const ALL: [Self; 16] = [
        Self::UserPassword,
        Self::DomainUser,
        Self::SshKey,
        Self::SshAgent,
        Self::X509,
        Self::ApiToken,
        Self::OauthClient,
        Self::Kubeconfig,
        Self::KubeToken,
        Self::VsphereUser,
        Self::VncPassword,
        Self::VncUserPassword,
        Self::Prompt,
        Self::ExternalRef,
        Self::SudoBecome,
        Self::S3AccessKey,
    ];

    /// Stable wire / database name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UserPassword => "user_password",
            Self::DomainUser => "domain_user",
            Self::SshKey => "ssh_key",
            Self::SshAgent => "ssh_agent",
            Self::X509 => "x509",
            Self::ApiToken => "api_token",
            Self::OauthClient => "oauth_client",
            Self::Kubeconfig => "kubeconfig",
            Self::KubeToken => "kube_token",
            Self::VsphereUser => "vsphere_user",
            Self::VncPassword => "vnc_password",
            Self::VncUserPassword => "vnc_user_password",
            Self::Prompt => "prompt",
            Self::ExternalRef => "external_ref",
            Self::SudoBecome => "sudo_become",
            Self::S3AccessKey => "s3_access_key",
        }
    }

    /// Parse a wire / database name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == s)
    }

    /// The kind's schema row.
    #[must_use]
    pub fn schema(self) -> &'static KindSchema {
        schema::schema_of(self)
    }

    /// Whether the optional TOTP slot (`otp_seed` + `otp`) is accepted.
    #[must_use]
    pub fn supports_otp(self) -> bool {
        self.schema().supports_otp
    }

    /// Kinds an `external_ref` may resolve to.
    #[must_use]
    pub const fn is_ref_target(self) -> bool {
        !matches!(self, Self::Prompt | Self::ExternalRef | Self::SshAgent | Self::S3AccessKey)
    }
}

/// The role a credential plays on a connection (ADR-0009 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The sign-in credential (inherited through folders).
    Primary,
    /// RD Gateway (per connection).
    Gateway,
    /// Privilege escalation after login (per connection).
    Become,
}

impl Role {
    /// Wire / database name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Gateway => "gateway",
            Self::Become => "become",
        }
    }

    /// Parse a wire name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Primary, Self::Gateway, Self::Become].into_iter().find(|r| r.name() == s)
    }
}

/// Name of one sealed secret. Closed set; which names a kind accepts is in its schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretName {
    /// Password (login, VNC, vSphere, become).
    Password,
    /// TOTP seed (base32 text).
    OtpSeed,
    /// OpenSSH / PEM private key.
    PrivateKey,
    /// SSH key passphrase.
    Passphrase,
    /// X.509 private key PEM.
    KeyPem,
    /// X.509 key passphrase.
    KeyPassphrase,
    /// API / Kubernetes bearer token.
    Token,
    /// OAuth client secret.
    ClientSecret,
    /// OAuth refresh token.
    RefreshToken,
    /// Whole kubeconfig file.
    KubeconfigYaml,
    /// S3 secret access key (`s3_access_key`).
    SecretAccessKey,
    /// STS session token (`s3_access_key`, optional).
    SessionToken,
}

impl SecretName {
    /// Every name.
    pub const ALL: [Self; 12] = [
        Self::Password,
        Self::OtpSeed,
        Self::PrivateKey,
        Self::Passphrase,
        Self::KeyPem,
        Self::KeyPassphrase,
        Self::Token,
        Self::ClientSecret,
        Self::RefreshToken,
        Self::KubeconfigYaml,
        Self::SecretAccessKey,
        Self::SessionToken,
    ];

    /// Wire / database name, also the vault AAD field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::OtpSeed => "otp_seed",
            Self::PrivateKey => "private_key",
            Self::Passphrase => "passphrase",
            Self::KeyPem => "key_pem",
            Self::KeyPassphrase => "key_passphrase",
            Self::Token => "token",
            Self::ClientSecret => "client_secret",
            Self::RefreshToken => "refresh_token",
            Self::KubeconfigYaml => "kubeconfig_yaml",
            Self::SecretAccessKey => "secret_access_key",
            Self::SessionToken => "session_token",
        }
    }

    /// Parse a name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|n| n.as_str() == s)
    }
}

impl std::fmt::Display for SecretName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip_on_the_wire() {
        for k in CredentialKind::ALL {
            let json = serde_json::to_string(&k).expect("ser");
            assert_eq!(json, format!("\"{}\"", k.name()));
            assert_eq!(serde_json::from_str::<CredentialKind>(&json).expect("de"), k);
            assert_eq!(CredentialKind::parse(k.name()), Some(k));
        }
        assert_eq!(CredentialKind::parse("password"), None, "legacy names are not kinds");
    }

    #[test]
    fn secret_names_and_roles_round_trip() {
        for n in SecretName::ALL {
            assert_eq!(SecretName::parse(n.as_str()), Some(n));
            assert_eq!(serde_json::to_string(&n).expect("ser"), format!("\"{n}\""));
        }
        assert_eq!(SecretName::parse("secret"), None, "legacy column names are not secret names");
        for r in [Role::Primary, Role::Gateway, Role::Become] {
            assert_eq!(Role::parse(r.name()), Some(r));
        }
        assert_eq!(Role::parse("owner"), None);
    }
}
