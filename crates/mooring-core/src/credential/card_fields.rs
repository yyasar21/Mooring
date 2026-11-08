//! The `smart_card` kind (ADR-0027 §2): a PIV / smart-card key. Nothing is sealed (the PIN is
//! asked at every use and never stored). `fingerprint` is derived from `public_key`, the
//! OpenSSH line of the card's key that the ssh-agent must hold (the SSH identity is pinned to
//! it, as for `ssh_sk_key`). `pkcs11_module` names one provider of a fixed list; the path is
//! resolved per OS by the SSH crate, never taken from input.

use serde::{Deserialize, Serialize};

use super::account::MAX_USER;
use super::fingerprint::{is_sha256_fingerprint, ssh_public_key, MAX_PUBLIC_KEY};
use super::text::{multiline, opt_line};
use super::CredentialError;

/// Longest `reader_hint`.
pub const MAX_READER_HINT: usize = 128;
/// Longest `domain`.
const MAX_DOMAIN: usize = 253;

/// PKCS#11 provider the ssh-agent loads for the card (`ssh-add -s`). A closed list: the module
/// path is resolved from it per OS, so input never names a library to load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pkcs11Module {
    /// `OpenSC` `opensc-pkcs11.{so,dylib,dll}`.
    Opensc,
    /// Yubico `libykcs11`.
    Ykcs11,
    /// Windows smart-card minidriver (`msclmd`): not PKCS#11; the agent cannot load it, so
    /// the key must already be in the agent.
    Cryptoapi,
}

impl Pkcs11Module {
    /// Every module, in display order.
    pub const ALL: [Self; 3] = [Self::Opensc, Self::Ykcs11, Self::Cryptoapi];

    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Opensc => "opensc",
            Self::Ykcs11 => "ykcs11",
            Self::Cryptoapi => "cryptoapi",
        }
    }
}

/// `smart_card` fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SmartCardFields {
    /// Login name hint (SSH needs one, from here or the connection override).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Windows domain hint (kept for the later Kerberos smart-card logon).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Reader name hint shown in the PIN dialog (display only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reader_hint: Option<String>,
    /// OpenSSH public key line of the card's key (`ssh-keygen -D <module>`); required for SSH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Provider the agent loads with the PIN when it does not hold the key yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkcs11_module: Option<Pkcs11Module>,
    /// Derived `SHA256:` fingerprint of `public_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// Trim and cap (runs on input and on every stored read).
pub(crate) fn normalise(f: &mut SmartCardFields) -> Result<(), CredentialError> {
    f.username = opt_line("username", f.username.as_deref(), MAX_USER)?;
    f.domain = opt_line("domain", f.domain.as_deref(), MAX_DOMAIN)?;
    f.reader_hint = opt_line("reader_hint", f.reader_hint.as_deref(), MAX_READER_HINT)?;
    if let Some(pk) = f.public_key.as_deref() {
        multiline("public_key", pk, MAX_PUBLIC_KEY)?;
        let t = pk.trim();
        if t.is_empty() || t.contains(['\n', '\r']) {
            return Err(CredentialError::invalid("public_key", "must be one OpenSSH line"));
        }
        f.public_key = Some(t.to_owned());
    }
    if f.fingerprint.as_deref().is_some_and(|fp| !is_sha256_fingerprint(fp)) {
        return Err(CredentialError::invalid("fingerprint", "malformed"));
    }
    Ok(())
}

/// Recompute `fingerprint` from `public_key`. FIDO2 lines belong to `ssh_sk_key`.
pub(crate) fn derive_public(f: &mut SmartCardFields) -> Result<(), CredentialError> {
    f.fingerprint = match f.public_key.as_deref() {
        Some(pk) if pk.trim_start().starts_with("sk-") => {
            return Err(CredentialError::UseSkKind);
        }
        Some(pk) => Some(ssh_public_key(pk)?),
        None => None,
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{CredentialFields, CredentialKind};

    use crate::credential::testdata::{ED25519_FP, ED25519_PUB as ED};

    #[test]
    fn fingerprint_is_derived_and_input_cannot_set_it() {
        let v = serde_json::json!({
            "username": " alice ", "public_key": ED, "pkcs11_module": "ykcs11",
            "reader_hint": "Yubico YubiKey"
        });
        let f = CredentialFields::from_input(CredentialKind::SmartCard, &v, None).expect("ok");
        let CredentialFields::SmartCard(c) = &f else { panic!("kind") };
        assert_eq!(c.username.as_deref(), Some("alice"));
        assert_eq!(c.fingerprint.as_deref(), Some(ED25519_FP));
        assert_eq!(c.pkcs11_module, Some(Pkcs11Module::Ykcs11));
        assert!(CredentialKind::SmartCard.schema().secret_names().next().is_none(), "no secret");
        let derived = serde_json::json!({ "fingerprint": "SHA256:x" });
        assert!(CredentialFields::from_input(CredentialKind::SmartCard, &derived, None).is_err());
        let empty =
            CredentialFields::from_input(CredentialKind::SmartCard, &serde_json::json!({}), None)
                .expect("all optional");
        assert_eq!(empty, CredentialFields::SmartCard(SmartCardFields::default()));
    }

    #[test]
    fn hostile_and_wrong_material_is_refused() {
        let k = CredentialKind::SmartCard;
        for bad in [
            serde_json::json!({ "public_key": "not a key" }),
            serde_json::json!({ "public_key": "sk-ssh-ed25519@openssh.com AAAA" }),
            serde_json::json!({ "pkcs11_module": "/tmp/evil.so" }),
            serde_json::json!({ "reader_hint": "x".repeat(MAX_READER_HINT + 1) }),
            serde_json::json!({ "pin": "1234" }),
        ] {
            assert!(CredentialFields::from_input(k, &bad, None).is_err(), "{bad}");
        }
        let names: Vec<_> = Pkcs11Module::ALL.iter().map(|m| m.name()).collect();
        assert_eq!(names, ["opensc", "ykcs11", "cryptoapi"]);
    }
}
