//! [`CredentialFields`]: the typed, validated plaintext of one credential, and its JSON form
//! (`credential.fields_json`). The same parser runs on IPC input and on every database read, so
//! a row that does not match its kind is refused, never partially used.

use serde::de::DeserializeOwned;
use serde_json::Value;

#[allow(clippy::wildcard_imports)]
use super::structs::*;
use super::validate::{normalise, validate_context};
use super::{
    fingerprint, kubeconfig, AccountForm, CredentialError, CredentialKind, OtpParams, SecretName,
};

/// Largest serialised `fields_json` (bytes, ADR-0009 §5).
pub const MAX_FIELDS_JSON: usize = 128 * 1024;

/// Keys the store derives; input carrying them is refused.
const DERIVED_KEYS: &[&str] = &["fingerprint", "contexts", "migrated"];

macro_rules! fields_enum {
    ($($variant:ident($ty:ty)),* $(,)?) => {
        /// Plaintext fields of one credential, one variant per kind.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum CredentialFields {
            $(
                #[doc = concat!("`", stringify!($variant), "` fields.")]
                $variant($ty),
            )*
        }

        impl CredentialFields {
            /// The kind these fields belong to.
            #[must_use]
            pub const fn kind(&self) -> CredentialKind {
                match self { $(Self::$variant(_) => CredentialKind::$variant,)* }
            }

            fn decode(kind: CredentialKind, v: Value) -> Result<Self, CredentialError> {
                Ok(match kind { $(CredentialKind::$variant => Self::$variant(typed(v)?),)* })
            }

            /// JSON object of the fields (what `CredentialMeta.fields` carries).
            #[must_use]
            pub fn to_value(&self) -> Value {
                match self {
                    $(Self::$variant(f) => serde_json::to_value(f).unwrap_or(Value::Null),)*
                }
            }
        }
    };
}

fields_enum!(
    UserPassword(UserPasswordFields),
    DomainUser(DomainUserFields),
    SshKey(SshKeyFields),
    SshAgent(SshAgentFields),
    X509(X509Fields),
    ApiToken(ApiTokenFields),
    OauthClient(OauthClientFields),
    Kubeconfig(KubeconfigFields),
    KubeToken(KubeTokenFields),
    VsphereUser(VsphereUserFields),
    VncPassword(VncPasswordFields),
    VncUserPassword(VncUserPasswordFields),
    Prompt(PromptFields),
    ExternalRef(ExternalRefFields),
    SudoBecome(SudoBecomeFields),
    S3AccessKey(S3AccessKeyFields),
);

fn typed<T: DeserializeOwned>(v: Value) -> Result<T, CredentialError> {
    // serde's message names the offending key or type, never a value of ours.
    serde_json::from_value(v).map_err(|e| {
        let msg = e.to_string();
        let reason = if msg.contains("unknown field") {
            "has an unknown field for this kind"
        } else if msg.contains("missing field") {
            "is missing a required field"
        } else {
            "has a field of the wrong type or value"
        };
        CredentialError::invalid("fields", reason)
    })
}

fn object(v: &Value) -> Result<&serde_json::Map<String, Value>, CredentialError> {
    v.as_object().ok_or_else(|| CredentialError::invalid("fields", "must be an object"))
}

impl CredentialFields {
    /// Parse fields sent by the UI: derived keys are refused, blank optional strings dropped,
    /// values trimmed and validated, then derived values recomputed from public material.
    /// `previous` carries derived values that need a secret to recompute (the SSH private key
    /// fingerprint, kubeconfig contexts) across an update.
    pub fn from_input(
        kind: CredentialKind,
        value: &Value,
        previous: Option<&Self>,
    ) -> Result<Self, CredentialError> {
        let map = object(value)?;
        if map.keys().any(|k| DERIVED_KEYS.contains(&k.as_str())) {
            return Err(CredentialError::invalid("fields", "derived values cannot be set"));
        }
        let cleaned: serde_json::Map<String, Value> = map
            .iter()
            .filter(|(_, v)| {
                !matches!(v, Value::Null) && v.as_str().is_none_or(|s| !s.trim().is_empty())
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut f = Self::decode(kind, Value::Object(cleaned))?;
        normalise(&mut f)?;
        f.carry_derived(previous);
        f.derive_public()?;
        f.check_size()?;
        Ok(f)
    }

    /// Parse a stored `fields_json`. Re-validates everything; any failure means a corrupt row.
    pub fn from_stored(kind: CredentialKind, json: &str) -> Result<Self, CredentialError> {
        if json.len() > MAX_FIELDS_JSON {
            return Err(CredentialError::invalid("fields", "stored fields are too large"));
        }
        let v: Value = serde_json::from_str(json)
            .map_err(|_| CredentialError::invalid("fields", "stored fields are not JSON"))?;
        object(&v)?;
        let mut f = Self::decode(kind, v)?;
        normalise(&mut f)?;
        Ok(f)
    }

    /// Serialised `fields_json`, capped at [`MAX_FIELDS_JSON`].
    pub fn to_json(&self) -> Result<String, CredentialError> {
        let s = self.to_value().to_string();
        if s.len() > MAX_FIELDS_JSON {
            return Err(CredentialError::invalid("fields", "larger than 128 KiB"));
        }
        Ok(s)
    }

    fn check_size(&self) -> Result<(), CredentialError> {
        self.to_json().map(drop)
    }

    fn carry_derived(&mut self, previous: Option<&Self>) {
        match (self, previous) {
            (Self::SshKey(f), Some(Self::SshKey(p))) => f.fingerprint.clone_from(&p.fingerprint),
            (Self::Kubeconfig(f), Some(Self::Kubeconfig(p))) => f.contexts.clone_from(&p.contexts),
            _ => {}
        }
    }

    /// Recompute fingerprints from public material in the fields.
    fn derive_public(&mut self) -> Result<(), CredentialError> {
        match self {
            Self::SshKey(f) => {
                if let Some(pk) = &f.public_key {
                    f.fingerprint = Some(fingerprint::ssh_public_key(pk)?);
                } else if let Some(cert) = &f.certificate {
                    f.fingerprint = Some(fingerprint::ssh_certificate(cert)?);
                }
                if let (Some(pk), Some(cert)) = (&f.public_key, &f.certificate) {
                    if fingerprint::ssh_public_key(pk)? != fingerprint::ssh_certificate(cert)? {
                        return Err(CredentialError::invalid(
                            "certificate",
                            "certifies a different key than public_key",
                        ));
                    }
                }
            }
            Self::X509(f) => f.fingerprint = Some(fingerprint::x509_pem(&f.cert_pem)?),
            Self::Kubeconfig(f) => validate_context(f)?,
            _ => {}
        }
        Ok(())
    }

    /// Update derived values from a secret being stored (private key fingerprint, kubeconfig
    /// contexts) and validate the secret's structure. Called before sealing.
    pub fn derive_from_secret(
        &mut self,
        name: SecretName,
        plain: &[u8],
    ) -> Result<(), CredentialError> {
        match (self, name) {
            (Self::SshKey(f), SecretName::PrivateKey) => {
                let info = fingerprint::ssh_private_key(plain)?;
                match (&f.public_key, &f.certificate, info.fingerprint) {
                    (None, None, fp) => f.fingerprint = fp,
                    (_, _, Some(fp)) if f.fingerprint.as_deref() != Some(fp.as_str()) => {
                        return Err(CredentialError::invalid(
                            "private_key",
                            "does not match the public key or certificate",
                        ));
                    }
                    _ => {}
                }
            }
            (Self::Kubeconfig(f), SecretName::KubeconfigYaml) => {
                let info = kubeconfig::parse(plain)?;
                f.contexts = info.contexts;
                if f.context.as_ref().is_some_and(|c| !f.contexts.contains(c)) {
                    f.context = None;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// `SHA256:` fingerprint for `ssh_key` / `x509`.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&str> {
        match self {
            Self::SshKey(f) => f.fingerprint.as_deref(),
            Self::X509(f) => f.fingerprint.as_deref(),
            _ => None,
        }
    }

    /// TOTP parameters, when attached.
    #[must_use]
    pub fn otp(&self) -> Option<OtpParams> {
        match self {
            Self::UserPassword(f) => f.otp,
            Self::DomainUser(f) => f.otp,
            Self::SshKey(f) => f.otp,
            Self::VsphereUser(f) => f.otp,
            _ => None,
        }
    }

    /// Set or clear the TOTP parameters. Refused for kinds without the slot.
    pub fn set_otp(&mut self, otp: Option<OtpParams>) -> Result<(), CredentialError> {
        let slot = match self {
            Self::UserPassword(f) => &mut f.otp,
            Self::DomainUser(f) => &mut f.otp,
            Self::SshKey(f) => &mut f.otp,
            Self::VsphereUser(f) => &mut f.otp,
            _ if otp.is_none() => return Ok(()),
            _ => return Err(CredentialError::invalid("otp", "this kind has no second factor")),
        };
        *slot = otp;
        Ok(())
    }

    /// Whether `username` / `domain` overrides apply to this kind (ADR-0009 §3).
    #[must_use]
    pub const fn supports_override(kind: CredentialKind, domain: bool) -> bool {
        use CredentialKind as K;
        if domain {
            matches!(kind, K::UserPassword | K::DomainUser | K::Prompt)
        } else {
            matches!(
                kind,
                K::UserPassword
                    | K::DomainUser
                    | K::SshKey
                    | K::SshAgent
                    | K::X509
                    | K::VncUserPassword
                    | K::Prompt
            )
        }
    }

    /// Apply per-connection overrides (already validated by the caller's `normalise` rules).
    pub fn apply_overrides(
        &mut self,
        username: Option<&str>,
        domain: Option<&str>,
    ) -> Result<(), CredentialError> {
        if let Some(u) = username {
            match self {
                Self::UserPassword(f) => u.clone_into(&mut f.username),
                Self::SshKey(f) => u.clone_into(&mut f.username),
                Self::SshAgent(f) => u.clone_into(&mut f.username),
                Self::VncUserPassword(f) => u.clone_into(&mut f.username),
                Self::X509(f) => f.username = Some(u.to_owned()),
                Self::Prompt(f) => f.username = Some(u.to_owned()),
                Self::DomainUser(f) => u.clone_into(&mut f.user),
                _ => {
                    return Err(CredentialError::invalid(
                        "usernameOverride",
                        "this kind has no username",
                    ))
                }
            }
        }
        if let Some(d) = domain {
            match self {
                Self::UserPassword(f) => f.domain = Some(d.to_owned()),
                Self::Prompt(f) => f.domain = Some(d.to_owned()),
                Self::DomainUser(f) => d.clone_into(&mut f.domain),
                _ => {
                    return Err(CredentialError::invalid(
                        "domainOverride",
                        "this kind has no domain",
                    ))
                }
            }
        }
        normalise(self)
    }

    /// Login name and domain as a protocol sees them (`None` when the kind has none).
    #[must_use]
    pub fn account(&self) -> (Option<String>, Option<String>) {
        match self {
            Self::UserPassword(f) => (Some(f.username.clone()), f.domain.clone()),
            Self::DomainUser(f) => (Some(f.user.clone()), Some(f.domain.clone())),
            Self::SshKey(f) => (Some(f.username.clone()), None),
            Self::SshAgent(f) => (Some(f.username.clone()), None),
            Self::X509(f) => (f.username.clone(), None),
            Self::VsphereUser(f) => (Some(f.upn.clone()), None),
            Self::VncUserPassword(f) => (Some(f.username.clone()), None),
            Self::Prompt(f) => (f.username.clone(), f.domain.clone()),
            _ => (None, None),
        }
    }

    /// `domain_user` form, when relevant.
    #[must_use]
    pub fn account_form(&self) -> Option<AccountForm> {
        match self {
            Self::DomainUser(f) => Some(f.form),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "fields_tests.rs"]
mod tests;
